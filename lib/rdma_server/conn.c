/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "spdk_internal/rdma_client.h"
#include "spdk/rdma_client.h"
#include "spdk/string.h"

#define CLIENT_CMD_DPTR_STR_SIZE 256

static int client_qpair_resubmit_request(struct spdk_client_qpair *qpair, struct client_request *req);

struct client_string
{
	uint16_t value;
	const char *str;
};

static const struct client_string io_opcode[] = {
	{SPDK_CLIENT_OPC_FLUSH, "FLUSH"},
	{SPDK_CLIENT_OPC_WRITE, "WRITE"},
	{SPDK_CLIENT_OPC_READ, "READ"},
	{SPDK_CLIENT_OPC_RPC_WRITE, "RPC WRITE"},
	{SPDK_CLIENT_OPC_RPC_READ, "RPC READ"},

	{0xFFFF, "IO COMMAND"}};

static const struct client_string sgl_type[] = {
	{SPDK_CLIENT_SGL_TYPE_DATA_BLOCK, "DATA BLOCK"},
	{SPDK_CLIENT_SGL_TYPE_BIT_BUCKET, "BIT BUCKET"},
	{SPDK_CLIENT_SGL_TYPE_SEGMENT, "SEGMENT"},
	{SPDK_CLIENT_SGL_TYPE_LAST_SEGMENT, "LAST SEGMENT"},
	{SPDK_CLIENT_SGL_TYPE_TRANSPORT_DATA_BLOCK, "TRANSPORT DATA BLOCK"},
	{SPDK_CLIENT_SGL_TYPE_VENDOR_SPECIFIC, "VENDOR SPECIFIC"},
	{0xFFFF, "RESERVED"}};

static const struct client_string sgl_subtype[] = {
	{SPDK_CLIENT_SGL_SUBTYPE_ADDRESS, "ADDRESS"},
	{SPDK_CLIENT_SGL_SUBTYPE_OFFSET, "OFFSET"},
	{SPDK_CLIENT_SGL_SUBTYPE_TRANSPORT, "TRANSPORT"},
	{SPDK_CLIENT_SGL_SUBTYPE_INVALIDATE_KEY, "INVALIDATE KEY"},
	{0xFFFF, "RESERVED"}};

static const char *
client_get_string(const struct client_string *strings, uint16_t value)
{
	const struct client_string *entry;

	entry = strings;

	while (entry->value != 0xFFFF)
	{
		if (entry->value == value)
		{
			return entry->str;
		}
		entry++;
	}
	return entry->str;
}

static void
client_get_sgl_unkeyed(char *buf, size_t size, struct spdk_rpc_req_cmd *cmd)
{
	struct spdk_req_sgl_descriptor *sgl = &cmd->sgld;

	snprintf(buf, size, " len:0x%x", sgl->unkeyed.length);
}

static void
client_get_sgl_keyed(char *buf, size_t size, struct spdk_rpc_req_cmd *cmd)
{
	struct spdk_req_sgl_descriptor *sgl = &cmd->sgld;

	snprintf(buf, size, " len:0x%x key:0x%x", sgl->keyed.length, sgl->keyed.key);
}

static void
client_get_sgl(char *buf, size_t size, struct spdk_rpc_req_cmd *cmd)
{
	struct spdk_req_sgl_descriptor *sgl = &cmd->sgld;
	int c;

	c = snprintf(buf, size, "SGL %s %s 0x%" PRIx64, client_get_string(sgl_type, sgl->generic.type),
				 client_get_string(sgl_subtype, sgl->generic.subtype), sgl->address);
	assert(c >= 0 && (size_t)c < size);

	if (sgl->generic.type == SPDK_CLIENT_SGL_TYPE_KEYED_DATA_BLOCK)
	{
		client_get_sgl_unkeyed(buf + c, size - c, cmd);
	}

	if (sgl->generic.type == SPDK_CLIENT_SGL_TYPE_DATA_BLOCK)
	{
		client_get_sgl_keyed(buf + c, size - c, cmd);
	}
}

static void
client_qpair_manual_complete_request(struct spdk_client_qpair *qpair,
									 struct client_request *req, uint32_t sct, uint32_t sc,
									 uint32_t dnr, bool print_on_error)
{
	struct spdk_rpc_req_cpl cpl;
	bool error;

	memset(&cpl, 0, sizeof(cpl));
	cpl.sqid = qpair->id;
	cpl.status.sct = sct;
	cpl.status.sc = sc;
	cpl.status.dnr = dnr;

	error = spdk_req_cpl_is_error(&cpl);

	if (error && print_on_error && !qpair->ctrlr->opts.disable_error_logging)
	{
		SPDK_NOTICELOG("Command completed manually: error occurred\n");
	}

	client_complete_request(req->cb_fn, req->cb_arg, qpair, req, &cpl);
	client_free_request(req);
}

void client_qpair_abort_queued_reqs(struct spdk_client_qpair *qpair, uint32_t dnr)
{
	struct client_request *req;
	STAILQ_HEAD(, client_request)
	tmp;

	STAILQ_INIT(&tmp);
	STAILQ_SWAP(&tmp, &qpair->queued_req, client_request);

	while (!STAILQ_EMPTY(&tmp))
	{
		req = STAILQ_FIRST(&tmp);
		STAILQ_REMOVE_HEAD(&tmp, stailq);
		if (!qpair->ctrlr->opts.disable_error_logging)
		{
			SPDK_ERRLOG("aborting queued i/o\n");
		}
		//(fixme)
		client_qpair_manual_complete_request(qpair, req, SPDK_CLIENT_SCT_GENERIC,
											 SPDK_CLIENT_SC_QUEUE_ABORTED, dnr, true);
	}
}

/* The callback to a request may submit the next request which is queued and
 * then the same callback may abort it immediately. This repetition may cause
 * infinite recursive calls. Hence move aborting requests to another list here
 * and abort them later at resubmission.
 */
static void
_client_qpair_complete_abort_queued_reqs(struct spdk_client_qpair *qpair)
{
	struct client_request *req;
	STAILQ_HEAD(, client_request)
	tmp;

	if (spdk_likely(STAILQ_EMPTY(&qpair->aborting_queued_req)))
	{
		return;
	}

	STAILQ_INIT(&tmp);
	STAILQ_SWAP(&tmp, &qpair->aborting_queued_req, client_request);

	while (!STAILQ_EMPTY(&tmp))
	{
		req = STAILQ_FIRST(&tmp);
		STAILQ_REMOVE_HEAD(&tmp, stailq);
		//(fixme) use aborted sq
		client_qpair_manual_complete_request(qpair, req, SPDK_CLIENT_SCT_GENERIC,
											 SPDK_CLIENT_SC_QUEUE_ABORTED, 1, true);
	}
}

uint32_t
client_qpair_abort_queued_reqs_with_cbarg(struct spdk_client_qpair *qpair, void *cmd_cb_arg)
{
	struct client_request *req, *tmp;
	uint32_t aborting = 0;

	STAILQ_FOREACH_SAFE(req, &qpair->queued_req, stailq, tmp)
	{
		if (req->cb_arg == cmd_cb_arg)
		{
			STAILQ_REMOVE(&qpair->queued_req, req, client_request, stailq);
			STAILQ_INSERT_TAIL(&qpair->aborting_queued_req, req, stailq);
			if (!qpair->ctrlr->opts.disable_error_logging)
			{
				SPDK_ERRLOG("aborting queued i/o\n");
			}
			aborting++;
		}
	}

	return aborting;
}

static inline bool
client_qpair_check_enabled(struct spdk_client_qpair *qpair)
{
	struct client_request *req;

	/*
	 * Either during initial connect or reset, the qpair should follow the given state machine.
	 * QPAIR_DISABLED->QPAIR_CONNECTING->QPAIR_CONNECTED->QPAIR_ENABLING->QPAIR_ENABLED. In the
	 * reset case, once the qpair is properly connected, we need to abort any outstanding requests
	 * from the old transport connection and encourage the application to retry them. We also need
	 * to submit any queued requests that built up while we were in the connected or enabling state.
	 */
	if (client_qpair_get_state(qpair) == CLIENT_QPAIR_CONNECTED && !qpair->ctrlr->is_resetting)
	{
		client_qpair_set_state(qpair, CLIENT_QPAIR_ENABLED);
		while (!STAILQ_EMPTY(&qpair->queued_req))
		{
			req = STAILQ_FIRST(&qpair->queued_req);
			STAILQ_REMOVE_HEAD(&qpair->queued_req, stailq);
			if (client_qpair_resubmit_request(qpair, req))
			{
				break;
			}
		}
	}

	/*
	 * When doing a reset, we must disconnect the qpair on the proper core.
	 * Note, reset is the only case where we set the failure reason without
	 * setting the qpair state since reset is done at the generic layer on the
	 * controller thread and we can't disconnect I/O qpairs from the controller
	 * thread.
	 */
	if (qpair->transport_failure_reason != SPDK_CLIENT_QPAIR_FAILURE_NONE &&
		client_qpair_get_state(qpair) == CLIENT_QPAIR_ENABLED)
	{
		return false;
	}

	return client_qpair_get_state(qpair) == CLIENT_QPAIR_ENABLED;
}

void client_qpair_resubmit_requests(struct spdk_client_qpair *qpair, uint32_t num_requests)
{
	uint32_t i;
	int resubmit_rc;
	struct client_request *req;

	assert(num_requests > 0);

	for (i = 0; i < num_requests; i++)
	{
		if (qpair->ctrlr->is_resetting)
		{
			break;
		}
		if ((req = STAILQ_FIRST(&qpair->queued_req)) == NULL)
		{
			break;
		}
		STAILQ_REMOVE_HEAD(&qpair->queued_req, stailq);
		resubmit_rc = client_qpair_resubmit_request(qpair, req);
		if (spdk_unlikely(resubmit_rc != 0))
		{
			SPDK_DEBUGLOG(client, "Unable to resubmit as many requests as we completed.\n");
			break;
		}
	}

	_client_qpair_complete_abort_queued_reqs(qpair);
}

int32_t
spdk_client_qpair_process_completions(struct spdk_client_qpair *qpair, uint32_t max_completions)
{
	int32_t ret;
	struct client_request *req, *tmp;

	if (spdk_unlikely(qpair->ctrlr->is_failed))
	{
		if (qpair->ctrlr->is_removed)
		{
			client_qpair_set_state(qpair, CLIENT_QPAIR_DESTROYING);
			client_qpair_abort_all_queued_reqs(qpair, 0);
			client_transport_qpair_abort_reqs(qpair, 0);
		}
		return -ENXIO;
	}

	if (spdk_unlikely(!client_qpair_check_enabled(qpair) &&
					  !(client_qpair_get_state(qpair) == CLIENT_QPAIR_CONNECTING)))
	{
		/*
		 * qpair is not enabled, likely because a controller reset is
		 *  in progress.
		 */
		return -ENXIO;
	}

	/* error injection for those queued error requests */
	if (spdk_unlikely(!STAILQ_EMPTY(&qpair->err_req_head)))
	{
		STAILQ_FOREACH_SAFE(req, &qpair->err_req_head, stailq, tmp)
		{
			if (spdk_get_ticks() - req->submit_tick > req->timeout_tsc)
			{
				STAILQ_REMOVE(&qpair->err_req_head, req, client_request, stailq);
				client_qpair_manual_complete_request(qpair, req,
													 req->cpl.status.sct,
													 req->cpl.status.sc, 0, true);
			}
		}
	}

	qpair->in_completion_context = 1;
	ret = client_transport_qpair_process_completions(qpair, max_completions);
	if (ret < 0)
	{
		SPDK_ERRLOG("CQ transport error %d (%s) on qpair id %hu\n", ret, spdk_strerror(-ret), qpair->id);
	}
	qpair->in_completion_context = 0;
	if (qpair->delete_after_completion_context)
	{
		/*
		 * A request to delete this qpair was made in the context of this completion
		 *  routine - so it is safe to delete it now.
		 */
		spdk_client_ctrlr_free_io_qpair(qpair);
		return ret;
	}

	/*
	 * At this point, ret must represent the number of completions we reaped.
	 * submit as many queued requests as we completed.
	 */
	if (ret > 0)
	{
		client_qpair_resubmit_requests(qpair, ret);
	}

	return ret;
}

spdk_client_qp_failure_reason
spdk_client_qpair_get_failure_reason(struct spdk_client_qpair *qpair)
{
	return qpair->transport_failure_reason;
}

int client_qpair_init(struct spdk_client_qpair *qpair, uint16_t id,
					  struct spdk_client_ctrlr *ctrlr,
					  enum spdk_client_qprio qprio,
					  uint32_t num_requests, bool async)
{
	size_t req_size_padded;
	uint32_t i;

	qpair->id = id;
	qpair->qprio = qprio;

	qpair->in_completion_context = 0;
	qpair->delete_after_completion_context = 0;
	qpair->no_deletion_notification_needed = 0;

	qpair->ctrlr = ctrlr;
	qpair->trtype = ctrlr->trtype;
	qpair->is_new_qpair = true;
	qpair->async = async;
	qpair->poll_status = NULL;

	STAILQ_INIT(&qpair->free_req);
	STAILQ_INIT(&qpair->queued_req);
	STAILQ_INIT(&qpair->aborting_queued_req);
	TAILQ_INIT(&qpair->err_cmd_head);
	STAILQ_INIT(&qpair->err_req_head);

	STAILQ_INIT(&qpair->free_rpc_req);

	req_size_padded = (sizeof(struct client_request) + 63) & ~(size_t)63;

	/* Add one for the reserved_req */
	num_requests++;

	qpair->req_buf = spdk_zmalloc(req_size_padded * num_requests, 64, NULL,
								  SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_SHARE);
	if (qpair->req_buf == NULL)
	{
		SPDK_ERRLOG("no memory to allocate qpair(cntlid:0x%x sqid:%d) req_buf with %d request\n",
					ctrlr->cntlid, qpair->id, num_requests);
		return -ENOMEM;
	}

	for (i = 0; i < num_requests; i++)
	{
		struct client_request *req = qpair->req_buf + i * req_size_padded;

		req->qpair = qpair;
		if (i == 0)
		{
			qpair->reserved_req = req;
		}
		else
		{
			STAILQ_INSERT_HEAD(&qpair->free_req, req, stailq);
		}
	}

	// 暂时写死4096的rpc request队列深度
	req_size_padded = (sizeof(struct rpc_request) + 63) & ~(size_t)63;
	qpair->rpc_req_buf = spdk_zmalloc(req_size_padded * 4096, 64, NULL,
									  SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_SHARE);
	if (qpair->rpc_req_buf == NULL)
	{
		SPDK_ERRLOG("no memory to allocate qpair(cntlid:0x%x sqid:%d) rpc_req_buf with %d request\n",
					ctrlr->cntlid, qpair->id, 4096);
		spdk_free(qpair->req_buf);
		return -ENOMEM;
	}

	for (i = 0; i < 4096; i++)
	{
		struct rpc_request *req = qpair->rpc_req_buf + i * req_size_padded;
		req->qpair = qpair;
		req->request_id = i;
		STAILQ_INSERT_TAIL(&qpair->free_rpc_req, req, stailq);
	}

	return 0;
}

void client_qpair_complete_error_reqs(struct spdk_client_qpair *qpair)
{
	struct client_request *req;

	while (!STAILQ_EMPTY(&qpair->err_req_head))
	{
		req = STAILQ_FIRST(&qpair->err_req_head);
		STAILQ_REMOVE_HEAD(&qpair->err_req_head, stailq);
		client_qpair_manual_complete_request(qpair, req,
											 req->cpl.status.sct,
											 req->cpl.status.sc, 0, true);
	}
}

void client_qpair_deinit(struct spdk_client_qpair *qpair)
{
	struct client_error_cmd *cmd, *entry;

	client_qpair_abort_queued_reqs(qpair, 0);
	_client_qpair_complete_abort_queued_reqs(qpair);
	client_qpair_complete_error_reqs(qpair);

	TAILQ_FOREACH_SAFE(cmd, &qpair->err_cmd_head, link, entry)
	{
		TAILQ_REMOVE(&qpair->err_cmd_head, cmd, link);
		spdk_free(cmd);
	}

	spdk_free(qpair->req_buf);
}

static inline int
_client_qpair_submit_request(struct spdk_client_qpair *qpair, struct client_request *req)
{
	int rc = 0;
	struct client_request *child_req, *tmp;
	struct client_error_cmd *cmd;
	struct spdk_client_ctrlr *ctrlr = qpair->ctrlr;
	bool child_req_failed = false;

	client_qpair_check_enabled(qpair);

	if (spdk_unlikely(client_qpair_get_state(qpair) == CLIENT_QPAIR_DISCONNECTED ||
					  client_qpair_get_state(qpair) == CLIENT_QPAIR_DISCONNECTING ||
					  client_qpair_get_state(qpair) == CLIENT_QPAIR_DESTROYING))
	{
		TAILQ_FOREACH_SAFE(child_req, &req->children, child_tailq, tmp)
		{
			client_request_remove_child(req, child_req);
			client_request_free_children(child_req);
			client_free_request(child_req);
		}
		if (req->parent != NULL)
		{
			client_request_remove_child(req->parent, req);
		}
		client_free_request(req);
		return -ENXIO;
	}

	if (req->num_children)
	{
		/*
		 * This is a split (parent) request. Submit all of the children but not the parent
		 * request itself, since the parent is the original unsplit request.
		 */
		TAILQ_FOREACH_SAFE(child_req, &req->children, child_tailq, tmp)
		{
			if (spdk_likely(!child_req_failed))
			{
				rc = client_qpair_submit_request(qpair, child_req);
				if (spdk_unlikely(rc != 0))
				{
					child_req_failed = true;
				}
			}
			else
			{ /* free remaining child_reqs since one child_req fails */
				client_request_remove_child(req, child_req);
				client_request_free_children(child_req);
				client_free_request(child_req);
			}
		}

		if (spdk_unlikely(child_req_failed))
		{
			/* part of children requests have been submitted,
			 * return success since we must wait for those children to complete,
			 * but set the parent request to failure.
			 */
			if (req->num_children)
			{
				req->cpl.status.sct = SPDK_CLIENT_SCT_GENERIC;
				//(fixme wuxingyi)
				req->cpl.status.sc = SPDK_CLIENT_SC_QUEUE_ABORTED;
				return 0;
			}
			goto error;
		}

		return rc;
	}

	/* queue those requests which matches with opcode in err_cmd list */
	if (spdk_unlikely(!TAILQ_EMPTY(&qpair->err_cmd_head)))
	{
		TAILQ_FOREACH(cmd, &qpair->err_cmd_head, link)
		{
			if (!cmd->do_not_submit)
			{
				continue;
			}

			if ((cmd->opc == req->cmd.opc) && cmd->err_count)
			{
				/* add to error request list and set cpl */
				req->timeout_tsc = cmd->timeout_tsc;
				req->submit_tick = spdk_get_ticks();
				req->cpl.status.sct = cmd->status.sct;
				req->cpl.status.sc = cmd->status.sc;
				STAILQ_INSERT_TAIL(&qpair->err_req_head, req, stailq);
				cmd->err_count--;
				return 0;
			}
		}
	}

	if (spdk_unlikely(ctrlr->is_failed))
	{
		rc = -ENXIO;
		goto error;
	}

	/* assign submit_tick before submitting req to specific transport */
	if (spdk_unlikely(ctrlr->timeout_enabled))
	{
		if (req->submit_tick == 0)
		{ /* req submitted for the first time */
			req->submit_tick = spdk_get_ticks();
			req->timed_out = false;
		}
	}
	else
	{
		req->submit_tick = 0;
	}

	if (spdk_likely(client_qpair_get_state(qpair) == CLIENT_QPAIR_ENABLED))
	{
		rc = client_transport_qpair_submit_request(qpair, req);
	}
	else
	{
		/* The controller is being reset - queue this request and
		 *  submit it later when the reset is completed.
		 */
		return -EAGAIN;
	}

	if (spdk_likely(rc == 0))
	{
		req->queued = false;
		return 0;
	}

	if (rc == -EAGAIN)
	{
		return -EAGAIN;
	}

error:
	if (req->parent != NULL)
	{
		client_request_remove_child(req->parent, req);
	}

	/* The request is from queued_req list we should trigger the callback from caller */
	if (spdk_unlikely(req->queued))
	{
		//(fixme wuxingyi)
		client_qpair_manual_complete_request(qpair, req, SPDK_CLIENT_SCT_GENERIC,
											 SPDK_CLIENT_SC_QUEUE_ABORTED, true, true);
		return rc;
	}

	client_free_request(req);

	return rc;
}

int client_qpair_submit_request(struct spdk_client_qpair *qpair, struct client_request *req)
{
	int rc;

	if (spdk_unlikely(!STAILQ_EMPTY(&qpair->queued_req) && req->num_children == 0))
	{

		if (client_qpair_get_state(qpair) != CLIENT_QPAIR_CONNECTING)
		{
			STAILQ_INSERT_TAIL(&qpair->queued_req, req, stailq);
			req->queued = true;
			return 0;
		}
	}

	rc = _client_qpair_submit_request(qpair, req);
	if (rc == -EAGAIN)
	{
		STAILQ_INSERT_TAIL(&qpair->queued_req, req, stailq);
		req->queued = true;
		rc = 0;
	}

	return rc;
}

static int
client_qpair_resubmit_request(struct spdk_client_qpair *qpair, struct client_request *req)
{
	int rc;

	/*
	 * We should never have a request with children on the queue.
	 * This is necessary to preserve the 1:1 relationship between
	 * completions and resubmissions.
	 */
	assert(req->num_children == 0);
	assert(req->queued);
	rc = _client_qpair_submit_request(qpair, req);
	if (spdk_unlikely(rc == -EAGAIN))
	{
		STAILQ_INSERT_HEAD(&qpair->queued_req, req, stailq);
	}

	return rc;
}

void client_qpair_abort_all_queued_reqs(struct spdk_client_qpair *qpair, uint32_t dnr)
{
	client_qpair_complete_error_reqs(qpair);
	client_qpair_abort_queued_reqs(qpair, dnr);
	_client_qpair_complete_abort_queued_reqs(qpair);
}

uint16_t
spdk_client_qpair_get_id(struct spdk_client_qpair *qpair)
{
	return qpair->id;
}
