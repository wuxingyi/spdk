/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation. All rights reserved.
 *   Copyright (c) 2019-2021 Mellanox Technologies LTD. All rights reserved.
 *   Copyright (c) 2021, 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "spdk/stdinc.h"

#include "spdk_internal/rdma_client.h"

#include "spdk/env.h"
#include "spdk/string.h"
#include "spdk/endian.h"
#include "spdk/rdma_common.h"

pid_t g_spdk_client_pid;

#define CTRLR_STRING(ctrlr) \
	("")

#define CLIENT_CTRLR_ERRLOG(ctrlr, format, ...) \
	SPDK_ERRLOG("[%s] " format, CTRLR_STRING(ctrlr), ##__VA_ARGS__);

#define CLIENT_CTRLR_WARNLOG(ctrlr, format, ...) \
	SPDK_WARNLOG("[%s] " format, CTRLR_STRING(ctrlr), ##__VA_ARGS__);

#define CLIENT_CTRLR_NOTICELOG(ctrlr, format, ...) \
	SPDK_NOTICELOG("[%s] " format, CTRLR_STRING(ctrlr), ##__VA_ARGS__);

#define CLIENT_CTRLR_INFOLOG(ctrlr, format, ...) \
	SPDK_INFOLOG(client, "[%s] " format, CTRLR_STRING(ctrlr), ##__VA_ARGS__);

#ifdef DEBUG
#define CLIENT_CTRLR_DEBUGLOG(ctrlr, format, ...) \
	SPDK_DEBUGLOG(client, "[%s] " format, CTRLR_STRING(ctrlr), ##__VA_ARGS__);
#else
#define CLIENT_CTRLR_DEBUGLOG(ctrlr, ...) \
	do                                    \
	{                                     \
	} while (0)
#endif

/* When the field in spdk_client_ctrlr_opts are changed and you change this function, please
 * also update the client_ctrl_opts_init function in client_ctrlr.c
 */
void spdk_client_ctrlr_get_default_ctrlr_opts(struct spdk_client_ctrlr_opts *opts, size_t opts_size)
{
	char host_id_str[SPDK_UUID_STRING_LEN];

	assert(opts);

	opts->opts_size = opts_size;

#define FIELD_OK(field) \
	offsetof(struct spdk_client_ctrlr_opts, field) + sizeof(opts->field) <= opts_size

#define SET_FIELD(field, value)                                                            \
	if (offsetof(struct spdk_client_ctrlr_opts, field) + sizeof(opts->field) <= opts_size) \
	{                                                                                      \
		opts->field = value;                                                               \
	}

	SET_FIELD(num_io_queues, DEFAULT_MAX_IO_QUEUES);
	SET_FIELD(use_cmb_sqs, false);
	SET_FIELD(no_shn_notification, false);
	SET_FIELD(keep_alive_timeout_ms, MIN_KEEP_ALIVE_TIMEOUT_IN_MS);
	SET_FIELD(transport_retry_count, SPDK_CLIENT_DEFAULT_RETRY_COUNT);
	SET_FIELD(io_queue_size, DEFAULT_IO_QUEUE_SIZE);

	g_spdk_client_pid = getpid();

	SET_FIELD(io_queue_requests, DEFAULT_IO_QUEUE_REQUESTS);

	if (FIELD_OK(src_addr))
	{
		memset(opts->src_addr, 0, sizeof(opts->src_addr));
	}

	if (FIELD_OK(src_svcid))
	{
		memset(opts->src_svcid, 0, sizeof(opts->src_svcid));
	}

	if (FIELD_OK(host_id))
	{
		memset(opts->host_id, 0, sizeof(opts->host_id));
	}

	SET_FIELD(command_set, CHAR_BIT);
	SET_FIELD(header_digest, false);
	SET_FIELD(data_digest, false);
	SET_FIELD(disable_error_logging, false);
	SET_FIELD(transport_ack_timeout, SPDK_CLIENT_DEFAULT_TRANSPORT_ACK_TIMEOUT);
	SET_FIELD(admin_queue_size, DEFAULT_ADMIN_QUEUE_SIZE);
	SET_FIELD(fabrics_connect_timeout_us, CLIENT_FABRIC_CONNECT_COMMAND_TIMEOUT);
	SET_FIELD(disable_read_ana_log_page, false);
	SET_FIELD(sector_size, DEFAULT_SECTOR_SIZE);
	SET_FIELD(extended_lba_size, DEFAULT_EXTENDED_LBA_SIZE);
	SET_FIELD(md_size, DEFAULT_MD_SIZE);
	SET_FIELD(sectors_per_max_io, DEFAULT_SECTORS_PER_MAX_IO);
	SET_FIELD(sectors_per_stripe, DEFAULT_SECTORS_PER_STRIPE);

#undef FIELD_OK
#undef SET_FIELD
}

struct spdk_client_ctrlr *spdk_client_transport_ctrlr_construct(const char *trstring,
																const struct spdk_client_ctrlr_opts *opts,
																void *devhandle)
{
	return client_transport_ctrlr_construct(trstring, opts, devhandle);
}

const struct spdk_client_ctrlr_opts *
spdk_client_ctrlr_get_opts(struct spdk_client_ctrlr *ctrlr)
{
	return &ctrlr->opts;
}

/**
 * This function will be called when the process allocates the IO qpair.
 * Note: the ctrlr_lock must be held when calling this function.
 */
static void
client_ctrlr_proc_add_io_qpair(struct spdk_client_qpair *qpair)
{
	struct spdk_client_ctrlr_process *active_proc;
	struct spdk_client_ctrlr *ctrlr = qpair->ctrlr;

	active_proc = client_ctrlr_get_current_process(ctrlr);
	if (active_proc)
	{
		TAILQ_INSERT_TAIL(&active_proc->allocated_io_qpairs, qpair, per_process_tailq);
		qpair->active_proc = active_proc;
	}
}

/**
 * This function will be called when the process frees the IO qpair.
 * Note: the ctrlr_lock must be held when calling this function.
 */
static void
client_ctrlr_proc_remove_io_qpair(struct spdk_client_qpair *qpair)
{
	struct spdk_client_ctrlr_process *active_proc;
	struct spdk_client_ctrlr *ctrlr = qpair->ctrlr;
	struct spdk_client_qpair *active_qpair, *tmp_qpair;

	active_proc = client_ctrlr_get_current_process(ctrlr);
	if (!active_proc)
	{
		return;
	}

	TAILQ_FOREACH_SAFE(active_qpair, &active_proc->allocated_io_qpairs,
					   per_process_tailq, tmp_qpair)
	{
		if (active_qpair == qpair)
		{
			TAILQ_REMOVE(&active_proc->allocated_io_qpairs,
						 active_qpair, per_process_tailq);

			break;
		}
	}
}

void spdk_client_ctrlr_get_default_io_qpair_opts(struct spdk_client_ctrlr *ctrlr,
												 struct spdk_client_io_qpair_opts *opts,
												 size_t opts_size)
{
	assert(ctrlr);

	assert(opts);

	memset(opts, 0, opts_size);

#define FIELD_OK(field) \
	offsetof(struct spdk_client_io_qpair_opts, field) + sizeof(opts->field) <= opts_size

	if (FIELD_OK(io_queue_size))
	{
		opts->io_queue_size = ctrlr->opts.io_queue_size;
	}

	if (FIELD_OK(io_queue_requests))
	{
		opts->io_queue_requests = ctrlr->opts.io_queue_requests;
	}

	if (FIELD_OK(delay_cmd_submit))
	{
		opts->delay_cmd_submit = false;
	}

	if (FIELD_OK(sq.vaddr))
	{
		opts->sq.vaddr = NULL;
	}

	if (FIELD_OK(sq.paddr))
	{
		opts->sq.paddr = 0;
	}

	if (FIELD_OK(sq.buffer_size))
	{
		opts->sq.buffer_size = 0;
	}

	if (FIELD_OK(cq.vaddr))
	{
		opts->cq.vaddr = NULL;
	}

	if (FIELD_OK(cq.paddr))
	{
		opts->cq.paddr = 0;
	}

	if (FIELD_OK(cq.buffer_size))
	{
		opts->cq.buffer_size = 0;
	}

	if (FIELD_OK(create_only))
	{
		opts->create_only = false;
	}

	if (FIELD_OK(async_mode))
	{
		opts->async_mode = false;
	}

#undef FIELD_OK
}

static struct spdk_client_qpair *
client_ctrlr_create_io_qpair(struct spdk_client_ctrlr *ctrlr,
							 const struct spdk_client_io_qpair_opts *opts)
{
	int32_t qid;
	struct spdk_client_qpair *qpair;

	if (!ctrlr)
	{
		return NULL;
	}

	client_robust_mutex_lock(&ctrlr->ctrlr_lock);

	qid = spdk_client_ctrlr_alloc_qid(ctrlr);
	if (qid < 0)
	{
		client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
		return NULL;
	}

	qpair = client_transport_ctrlr_create_io_qpair(ctrlr, qid, opts);
	if (qpair == NULL)
	{
		CLIENT_CTRLR_ERRLOG(ctrlr, "client_transport_ctrlr_create_io_qpair() failed\n");
		spdk_client_ctrlr_free_qid(ctrlr, qid);
		client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
		return NULL;
	}

	TAILQ_INSERT_TAIL(&ctrlr->active_io_qpairs, qpair, tailq);

	client_ctrlr_proc_add_io_qpair(qpair);

	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);

	return qpair;
}

int spdk_client_ctrlr_connect_io_qpair(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair)
{
	int rc;

	if (client_qpair_get_state(qpair) != CLIENT_QPAIR_DISCONNECTED)
	{
		return -EISCONN;
	}

	client_robust_mutex_lock(&ctrlr->ctrlr_lock);
	rc = client_transport_ctrlr_connect_qpair(ctrlr, qpair);
	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);

	return rc;
}

int spdk_client_ctrlr_connect_io_qpair_async(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair)
{
	int rc;

	if (client_qpair_get_state(qpair) != CLIENT_QPAIR_DISCONNECTED)
	{
		return -EISCONN;
	}

	client_robust_mutex_lock(&ctrlr->ctrlr_lock);
	rc = client_transport_ctrlr_connect_qpair_async(ctrlr, qpair);
	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);

	return rc;
}

void spdk_client_ctrlr_disconnect_io_qpair(struct spdk_client_qpair *qpair)
{
	struct spdk_client_ctrlr *ctrlr = qpair->ctrlr;

	client_robust_mutex_lock(&ctrlr->ctrlr_lock);
	client_transport_ctrlr_disconnect_qpair(ctrlr, qpair);
	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
}

struct spdk_mempool* spdk_client_ctrlr_get_mempool(struct spdk_client_qpair *qpair) {
    return qpair->ctrlr->rpc_data_mp;
}

struct spdk_client_qpair *
spdk_client_ctrlr_alloc_io_qpair(struct spdk_client_ctrlr *ctrlr,
								 const struct spdk_client_io_qpair_opts *user_opts,
								 size_t opts_size, struct spdk_client_transport_id *id, struct spdk_client_poll_group *client_pg)
{

	struct spdk_client_qpair *qpair;
	struct spdk_client_io_qpair_opts opts;
	int rc;

	if (spdk_unlikely(ctrlr->state != CLIENT_CTRLR_STATE_READY))
	{
		/* When controller is resetting or initializing, free_io_qids is deleted or not created yet.
		 * We can't create IO qpair in that case */
		return NULL;
	}

	/*
	 * Get the default options, then overwrite them with the user-provided options
	 * up to opts_size.
	 *
	 * This allows for extensions of the opts structure without breaking
	 * ABI compatibility.
	 */
	spdk_client_ctrlr_get_default_io_qpair_opts(ctrlr, &opts, sizeof(opts));
	if (user_opts)
	{
		memcpy(&opts, user_opts, spdk_min(sizeof(opts), opts_size));

		/* If user passes buffers, make sure they're big enough for the requested queue size */
		if (opts.sq.vaddr)
		{
			if (opts.sq.buffer_size < (opts.io_queue_size * sizeof(struct spdk_req_cmd)))
			{
				CLIENT_CTRLR_ERRLOG(ctrlr, "sq buffer size %" PRIx64 " is too small for sq size %zx\n",
									opts.sq.buffer_size, (opts.io_queue_size * sizeof(struct spdk_req_cmd)));
				return NULL;
			}
		}
		if (opts.cq.vaddr)
		{
			if (opts.cq.buffer_size < (opts.io_queue_size * sizeof(struct spdk_req_cpl)))
			{
				CLIENT_CTRLR_ERRLOG(ctrlr, "cq buffer size %" PRIx64 " is too small for cq size %zx\n",
									opts.cq.buffer_size, (opts.io_queue_size * sizeof(struct spdk_req_cpl)));
				return NULL;
			}
		}
	}
	SPDK_NOTICELOG("spdk_client_ctrlr_alloc_io_qpair : io_queue_size %d\n", opts.io_queue_size);
	qpair = client_ctrlr_create_io_qpair(ctrlr, &opts);

	if (qpair == NULL || opts.create_only == true)
	{
		return qpair;
	}
	// save id in qpair
	qpair->trid = id;

	rc = spdk_client_poll_group_add(client_pg, qpair);
	if (rc != 0)
	{
		CLIENT_CTRLR_ERRLOG(ctrlr, "spdk_client_poll_group_add() failed\n");
		goto err;
	}
	rc = spdk_client_ctrlr_connect_io_qpair(ctrlr, qpair);
	if (rc != 0)
	{
		CLIENT_CTRLR_ERRLOG(ctrlr, "spdk_client_ctrlr_connect_io_qpair() failed\n");
		goto err;
	}
	return qpair;
err:
	client_robust_mutex_lock(&ctrlr->ctrlr_lock);
	client_ctrlr_proc_remove_io_qpair(qpair);
	TAILQ_REMOVE(&ctrlr->active_io_qpairs, qpair, tailq);
	spdk_bit_array_set(ctrlr->free_io_qids, qpair->id);
	client_transport_ctrlr_delete_io_qpair(ctrlr, qpair);
	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
	return NULL;
}

struct spdk_client_qpair *
spdk_client_ctrlr_alloc_io_qpair_async(struct spdk_client_ctrlr *ctrlr,
									   const struct spdk_client_io_qpair_opts *user_opts,
									   size_t opts_size, struct spdk_client_transport_id *id, struct spdk_client_poll_group *client_pg, spdk_connected_cb cb_fn, void *cb_arg)
{

	struct spdk_client_qpair *qpair;
	struct spdk_client_io_qpair_opts opts;
	int rc;

	if (spdk_unlikely(ctrlr->state != CLIENT_CTRLR_STATE_READY))
	{
		/* When controller is resetting or initializing, free_io_qids is deleted or not created yet.
		 * We can't create IO qpair in that case */
		return NULL;
	}

	/*
	 * Get the default options, then overwrite them with the user-provided options
	 * up to opts_size.
	 *
	 * This allows for extensions of the opts structure without breaking
	 * ABI compatibility.
	 */
	spdk_client_ctrlr_get_default_io_qpair_opts(ctrlr, &opts, sizeof(opts));
	if (user_opts)
	{
		memcpy(&opts, user_opts, spdk_min(sizeof(opts), opts_size));

		/* If user passes buffers, make sure they're big enough for the requested queue size */
		if (opts.sq.vaddr)
		{
			if (opts.sq.buffer_size < (opts.io_queue_size * sizeof(struct spdk_req_cmd)))
			{
				CLIENT_CTRLR_ERRLOG(ctrlr, "sq buffer size %" PRIx64 " is too small for sq size %zx\n",
									opts.sq.buffer_size, (opts.io_queue_size * sizeof(struct spdk_req_cmd)));
				return NULL;
			}
		}
		if (opts.cq.vaddr)
		{
			if (opts.cq.buffer_size < (opts.io_queue_size * sizeof(struct spdk_req_cpl)))
			{
				CLIENT_CTRLR_ERRLOG(ctrlr, "cq buffer size %" PRIx64 " is too small for cq size %zx\n",
									opts.cq.buffer_size, (opts.io_queue_size * sizeof(struct spdk_req_cpl)));
				return NULL;
			}
		}
	}
	SPDK_NOTICELOG("spdk_client_ctrlr_alloc_io_qpair : io_queue_size %d\n", opts.io_queue_size);
	qpair = client_ctrlr_create_io_qpair(ctrlr, &opts);

	if (qpair == NULL || opts.create_only == true)
	{
		return qpair;
	}
	// save id in qpair
	qpair->trid = id;

	rc = spdk_client_poll_group_add(client_pg, qpair);
	if (rc != 0)
	{
		CLIENT_CTRLR_ERRLOG(ctrlr, "spdk_client_poll_group_add() failed\n");
		goto err;
	}

	qpair->cb = cb_fn;
	qpair->cb_args = cb_arg;

	rc = spdk_client_ctrlr_connect_io_qpair_async(ctrlr, qpair);
	if (rc != 0)
	{
		CLIENT_CTRLR_ERRLOG(ctrlr, "spdk_client_ctrlr_connect_io_qpair() failed\n");
		goto err;
	}
	return qpair;
err:
	client_robust_mutex_lock(&ctrlr->ctrlr_lock);
	client_ctrlr_proc_remove_io_qpair(qpair);
	TAILQ_REMOVE(&ctrlr->active_io_qpairs, qpair, tailq);
	spdk_bit_array_set(ctrlr->free_io_qids, qpair->id);
	client_transport_ctrlr_delete_io_qpair(ctrlr, qpair);
	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
	return NULL;
}

int spdk_client_ctrlr_reconnect_io_qpair(struct spdk_client_qpair *qpair)
{
	struct spdk_client_ctrlr *ctrlr;
	enum client_qpair_state qpair_state;
	int rc;

	assert(qpair != NULL);
	assert(qpair->ctrlr != NULL);

	ctrlr = qpair->ctrlr;
	client_robust_mutex_lock(&ctrlr->ctrlr_lock);
	qpair_state = client_qpair_get_state(qpair);

	if (ctrlr->is_removed)
	{
		rc = -ENODEV;
		goto out;
	}

	if (ctrlr->is_resetting || qpair_state == CLIENT_QPAIR_DISCONNECTING)
	{
		rc = -EAGAIN;
		goto out;
	}

	if (ctrlr->is_failed || qpair_state == CLIENT_QPAIR_DESTROYING)
	{
		rc = -ENXIO;
		goto out;
	}

	if (qpair_state != CLIENT_QPAIR_DISCONNECTED)
	{
		rc = 0;
		goto out;
	}

	rc = client_transport_ctrlr_connect_qpair(ctrlr, qpair);
	if (rc)
	{
		rc = -EAGAIN;
		goto out;
	}

out:
	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
	return rc;
}

/*
 * This internal function will attempt to take the controller
 * lock before calling disconnect on a controller qpair.
 * Functions already holding the controller lock should
 * call client_transport_ctrlr_disconnect_qpair directly.
 */
void client_ctrlr_disconnect_qpair(struct spdk_client_qpair *qpair)
{
	struct spdk_client_ctrlr *ctrlr = qpair->ctrlr;

	assert(ctrlr != NULL);
	client_robust_mutex_lock(&ctrlr->ctrlr_lock);
	client_transport_ctrlr_disconnect_qpair(ctrlr, qpair);
	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
}

int spdk_client_ctrlr_free_io_qpair(struct spdk_client_qpair *qpair)
{
	struct spdk_client_ctrlr *ctrlr;

	if (qpair == NULL)
	{
		return 0;
	}

	ctrlr = qpair->ctrlr;

	if (qpair->in_completion_context)
	{
		/*
		 * There are many cases where it is convenient to delete an io qpair in the context
		 *  of that qpair's completion routine.  To handle this properly, set a flag here
		 *  so that the completion routine will perform an actual delete after the context
		 *  unwinds.
		 */
		qpair->delete_after_completion_context = 1;
		return 0;
	}

	if (qpair->poll_group && qpair->poll_group->in_completion_context)
	{
		/* Same as above, but in a poll group. */
		qpair->poll_group->num_qpairs_to_delete++;
		qpair->delete_after_completion_context = 1;
		return 0;
	}

	client_transport_ctrlr_disconnect_qpair(ctrlr, qpair);

	if (qpair->poll_group)
	{
		spdk_client_poll_group_remove(qpair->poll_group->group, qpair);
	}

	/* Do not retry. */
	client_qpair_set_state(qpair, CLIENT_QPAIR_DESTROYING);

	/* In the multi-process case, a process may call this function on a foreign
	 * I/O qpair (i.e. one that this process did not create) when that qpairs process
	 * exits unexpectedly.  In that case, we must not try to abort any reqs associated
	 * with that qpair, since the callbacks will also be foreign to this process.
	 */
	if (qpair->active_proc == client_ctrlr_get_current_process(ctrlr))
	{
		client_qpair_abort_all_queued_reqs(qpair, 0);
	}

	client_robust_mutex_lock(&ctrlr->ctrlr_lock);

	client_ctrlr_proc_remove_io_qpair(qpair);

	TAILQ_REMOVE(&ctrlr->active_io_qpairs, qpair, tailq);
	spdk_client_ctrlr_free_qid(ctrlr, qpair->id);

	client_transport_ctrlr_delete_io_qpair(ctrlr, qpair);
	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
	return 0;
}

bool spdk_client_ctrlr_is_failed(struct spdk_client_ctrlr *ctrlr)
{
	return ctrlr->is_failed;
}

void client_ctrlr_fail(struct spdk_client_ctrlr *ctrlr, bool hot_remove)
{
	/*
	 * Set the flag here and leave the work failure of qpairs to
	 * spdk_client_qpair_process_completions().
	 */
	if (hot_remove)
	{
		ctrlr->is_removed = true;
	}

	if (ctrlr->is_failed)
	{
		CLIENT_CTRLR_NOTICELOG(ctrlr, "already in failed state\n");
		return;
	}

	ctrlr->is_failed = true;
	client_transport_ctrlr_disconnect_qpair(ctrlr, ctrlr->adminq);
	CLIENT_CTRLR_ERRLOG(ctrlr, "in failed state.\n");
}

static void
client_ctrlr_shutdown_async(struct spdk_client_ctrlr *ctrlr,
							struct client_ctrlr_detach_ctx *ctx)
{
	int rc;

	if (ctrlr->is_removed)
	{
		ctx->shutdown_complete = true;
		return;
	}
}

static int
client_ctrlr_shutdown_poll_async(struct spdk_client_ctrlr *ctrlr,
								 struct client_ctrlr_detach_ctx *ctx)
{
	union spdk_client_csts_register csts;
	uint32_t ms_waited;

	switch (ctx->state)
	{
	case CLIENT_CTRLR_DETACH_SET_CC:
	case CLIENT_CTRLR_DETACH_GET_CSTS:
		/* We're still waiting for the register operation to complete */
		spdk_client_qpair_process_completions(ctrlr->adminq, 0);
		return -EAGAIN;

	case CLIENT_CTRLR_DETACH_GET_CSTS_DONE:
		ctx->state = CLIENT_CTRLR_DETACH_CHECK_CSTS;
		break;

	default:
		assert(0 && "Should never happen");
		return -EINVAL;
	}

	ms_waited = (spdk_get_ticks() - ctx->shutdown_start_tsc) * 1000 / spdk_get_ticks_hz();
	csts.raw = ctx->csts.raw;

	if (csts.bits.shst == SPDK_CLIENT_SHST_COMPLETE)
	{
		CLIENT_CTRLR_DEBUGLOG(ctrlr, "shutdown complete in %u milliseconds\n", ms_waited);
		return 0;
	}

	if (ms_waited < ctx->shutdown_timeout_ms)
	{
		return -EAGAIN;
	}

	CLIENT_CTRLR_ERRLOG(ctrlr, "did not shutdown within %u milliseconds\n",
						ctx->shutdown_timeout_ms);

	return 0;
}

static int
client_ctrlr_enable(struct spdk_client_ctrlr *ctrlr)
{
	int rc;

	rc = client_transport_ctrlr_enable(ctrlr);
	if (rc != 0)
	{
		CLIENT_CTRLR_ERRLOG(ctrlr, "transport ctrlr_enable failed\n");
		return rc;
	}

	return 0;
}

static void
client_ctrlr_abort_queued_aborts(struct spdk_client_ctrlr *ctrlr)
{
	struct client_request *req, *tmp;
	struct spdk_req_cpl cpl = {};

	cpl.status.sc = SPDK_CLIENT_SC_ABORTED_SQ_DELETION;
	cpl.status.sct = SPDK_CLIENT_SCT_GENERIC;

	STAILQ_FOREACH_SAFE(req, &ctrlr->queued_aborts, stailq, tmp)
	{
		STAILQ_REMOVE_HEAD(&ctrlr->queued_aborts, stailq);

		client_complete_request(req->cb_fn, req->cb_arg, req->qpair, req, &cpl);
		client_free_request(req);
	}
}

int spdk_client_ctrlr_disconnect(struct spdk_client_ctrlr *ctrlr)
{
	struct spdk_client_qpair *qpair;

	client_robust_mutex_lock(&ctrlr->ctrlr_lock);
	ctrlr->prepare_for_reset = false;

	if (ctrlr->is_resetting || ctrlr->is_removed)
	{
		/*
		 * Controller is already resetting or has been removed. Return
		 *  immediately since there is no need to kick off another
		 *  reset in these cases.
		 */
		client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
		return ctrlr->is_resetting ? -EBUSY : -ENXIO;
	}

	ctrlr->is_resetting = true;
	ctrlr->is_failed = false;

	CLIENT_CTRLR_NOTICELOG(ctrlr, "resetting controller\n");

	/* Disable keep-alive, it'll be re-enabled as part of the init process */
	ctrlr->keep_alive_interval_ticks = 0;

	/* Abort all of the queued abort requests */
	client_ctrlr_abort_queued_aborts(ctrlr);

	/* Disable all queues before disabling the controller hardware. */
	TAILQ_FOREACH(qpair, &ctrlr->active_io_qpairs, tailq)
	{
		qpair->transport_failure_reason = SPDK_CLIENT_QPAIR_FAILURE_LOCAL;
	}

	ctrlr->adminq->transport_failure_reason = SPDK_CLIENT_QPAIR_FAILURE_LOCAL;
	client_transport_ctrlr_disconnect_qpair(ctrlr, ctrlr->adminq);

	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
	return 0;
}

struct spdk_client_ctrlr_process *
client_ctrlr_get_process(struct spdk_client_ctrlr *ctrlr, pid_t pid)
{
	struct spdk_client_ctrlr_process *active_proc;

	TAILQ_FOREACH(active_proc, &ctrlr->active_procs, tailq)
	{
		if (active_proc->pid == pid)
		{
			return active_proc;
		}
	}

	return NULL;
}

struct spdk_client_ctrlr_process *
client_ctrlr_get_current_process(struct spdk_client_ctrlr *ctrlr)
{
	return client_ctrlr_get_process(ctrlr, getpid());
}

/**
 * This function will be called when a process is using the controller.
 *  1. For the primary process, it is called when constructing the controller.
 *  2. For the secondary process, it is called at probing the controller.
 * Note: will check whether the process is already added for the same process.
 */
int client_ctrlr_add_process(struct spdk_client_ctrlr *ctrlr, void *devhandle)
{
	struct spdk_client_ctrlr_process *ctrlr_proc;
	pid_t pid = getpid();

	/* Check whether the process is already added or not */
	if (client_ctrlr_get_process(ctrlr, pid))
	{
		return 0;
	}

	/* Initialize the per process properties for this ctrlr */
	ctrlr_proc = spdk_zmalloc(sizeof(struct spdk_client_ctrlr_process),
							  64, NULL, SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_SHARE);
	if (ctrlr_proc == NULL)
	{
		CLIENT_CTRLR_ERRLOG(ctrlr, "failed to allocate memory to track the process props\n");

		return -1;
	}

	ctrlr_proc->is_primary = spdk_process_is_primary();
	ctrlr_proc->pid = pid;
	STAILQ_INIT(&ctrlr_proc->active_reqs);
	ctrlr_proc->devhandle = devhandle;
	ctrlr_proc->ref = 0;
	TAILQ_INIT(&ctrlr_proc->allocated_io_qpairs);
	STAILQ_INIT(&ctrlr_proc->async_events);

	TAILQ_INSERT_TAIL(&ctrlr->active_procs, ctrlr_proc, tailq);

	return 0;
}

/**
 * This function will be called when the process detaches the controller.
 * Note: the ctrlr_lock must be held when calling this function.
 */
static void
client_ctrlr_remove_process(struct spdk_client_ctrlr *ctrlr,
							struct spdk_client_ctrlr_process *proc)
{
	struct spdk_client_qpair *qpair, *tmp_qpair;

	assert(STAILQ_EMPTY(&proc->active_reqs));

	TAILQ_FOREACH_SAFE(qpair, &proc->allocated_io_qpairs, per_process_tailq, tmp_qpair)
	{
		spdk_client_ctrlr_free_io_qpair(qpair);
	}

	TAILQ_REMOVE(&ctrlr->active_procs, proc, tailq);

	spdk_free(proc);
}

/**
 * This function will be called when the process exited unexpectedly
 *  in order to free any incomplete client request, allocated IO qpairs
 *  and allocated memory.
 * Note: the ctrlr_lock must be held when calling this function.
 */
static void
client_ctrlr_cleanup_process(struct spdk_client_ctrlr_process *proc)
{
	struct client_request *req, *tmp_req;
	struct spdk_client_qpair *qpair, *tmp_qpair;
	struct spdk_client_ctrlr_aer_completion_list *event;

	STAILQ_FOREACH_SAFE(req, &proc->active_reqs, stailq, tmp_req)
	{
		STAILQ_REMOVE(&proc->active_reqs, req, client_request, stailq);

		assert(req->pid == proc->pid);

		client_free_request(req);
	}

	/* Remove async event from each process objects event list */
	while (!STAILQ_EMPTY(&proc->async_events))
	{
		event = STAILQ_FIRST(&proc->async_events);
		STAILQ_REMOVE_HEAD(&proc->async_events, link);
		spdk_free(event);
	}

	TAILQ_FOREACH_SAFE(qpair, &proc->allocated_io_qpairs, per_process_tailq, tmp_qpair)
	{
		TAILQ_REMOVE(&proc->allocated_io_qpairs, qpair, per_process_tailq);

		/*
		 * The process may have been killed while some qpairs were in their
		 *  completion context.  Clear that flag here to allow these IO
		 *  qpairs to be deleted.
		 */
		qpair->in_completion_context = 0;

		qpair->no_deletion_notification_needed = 1;

		spdk_client_ctrlr_free_io_qpair(qpair);
	}

	spdk_free(proc);
}

/**
 * This function will be called when destructing the controller.
 *  1. There is no more admin request on this controller.
 *  2. Clean up any left resource allocation when its associated process is gone.
 */
void client_ctrlr_free_processes(struct spdk_client_ctrlr *ctrlr)
{
	struct spdk_client_ctrlr_process *active_proc, *tmp;

	/* Free all the processes' properties and make sure no pending admin IOs */
	TAILQ_FOREACH_SAFE(active_proc, &ctrlr->active_procs, tailq, tmp)
	{
		TAILQ_REMOVE(&ctrlr->active_procs, active_proc, tailq);

		assert(STAILQ_EMPTY(&active_proc->active_reqs));

		spdk_free(active_proc);
	}
}

/**
 * This function will be called when any other process attaches or
 *  detaches the controller in order to cleanup those unexpectedly
 *  terminated processes.
 * Note: the ctrlr_lock must be held when calling this function.
 */
static int
client_ctrlr_remove_inactive_proc(struct spdk_client_ctrlr *ctrlr)
{
	struct spdk_client_ctrlr_process *active_proc, *tmp;
	int active_proc_count = 0;

	TAILQ_FOREACH_SAFE(active_proc, &ctrlr->active_procs, tailq, tmp)
	{
		if ((kill(active_proc->pid, 0) == -1) && (errno == ESRCH))
		{
			CLIENT_CTRLR_ERRLOG(ctrlr, "process %d terminated unexpected\n", active_proc->pid);

			TAILQ_REMOVE(&ctrlr->active_procs, active_proc, tailq);

			client_ctrlr_cleanup_process(active_proc);
		}
		else
		{
			active_proc_count++;
		}
	}

	return active_proc_count;
}

void client_ctrlr_proc_get_ref(struct spdk_client_ctrlr *ctrlr)
{
	struct spdk_client_ctrlr_process *active_proc;

	client_robust_mutex_lock(&ctrlr->ctrlr_lock);

	client_ctrlr_remove_inactive_proc(ctrlr);

	active_proc = client_ctrlr_get_current_process(ctrlr);
	if (active_proc)
	{
		active_proc->ref++;
	}

	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
}

void client_ctrlr_proc_put_ref(struct spdk_client_ctrlr *ctrlr)
{
	struct spdk_client_ctrlr_process *active_proc;
	int proc_count;

	client_robust_mutex_lock(&ctrlr->ctrlr_lock);

	proc_count = client_ctrlr_remove_inactive_proc(ctrlr);

	active_proc = client_ctrlr_get_current_process(ctrlr);
	if (active_proc)
	{
		active_proc->ref--;
		assert(active_proc->ref >= 0);

		/*
		 * The last active process will be removed at the end of
		 * the destruction of the controller.
		 */
		if (active_proc->ref == 0 && proc_count != 1)
		{
			client_ctrlr_remove_process(ctrlr, active_proc);
		}
	}

	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
}

int client_ctrlr_get_ref_count(struct spdk_client_ctrlr *ctrlr)
{
	struct spdk_client_ctrlr_process *active_proc;
	int ref = 0;

	client_robust_mutex_lock(&ctrlr->ctrlr_lock);

	client_ctrlr_remove_inactive_proc(ctrlr);

	TAILQ_FOREACH(active_proc, &ctrlr->active_procs, tailq)
	{
		ref += active_proc->ref;
	}

	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);

	return ref;
}

int client_robust_mutex_init_recursive_shared(pthread_mutex_t *mtx)
{
	pthread_mutexattr_t attr;
	int rc = 0;

	if (pthread_mutexattr_init(&attr))
	{
		return -1;
	}
	if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) ||
#ifndef __FreeBSD__
		pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) ||
		pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) ||
#endif
		pthread_mutex_init(mtx, &attr))
	{
		rc = -1;
	}
	pthread_mutexattr_destroy(&attr);
	return rc;
}

int client_ctrlr_construct(struct spdk_client_ctrlr *ctrlr)
{
	int rc;

	ctrlr->flags = 0;
	ctrlr->free_io_qids = NULL;
	ctrlr->is_resetting = false;
	ctrlr->is_failed = false;
	ctrlr->is_destructed = false;

	ctrlr->free_io_qids = spdk_bit_array_create(ctrlr->opts.num_io_queues + 1);

	for (int i = 1; i <= ctrlr->opts.num_io_queues; i++)
	{
		spdk_client_ctrlr_free_qid(ctrlr, i);
	}

	TAILQ_INIT(&ctrlr->active_io_qpairs);
	STAILQ_INIT(&ctrlr->queued_aborts);
	STAILQ_INIT(&ctrlr->pending_rpc_requests);
	ctrlr->outstanding_aborts = 0;

	rc = client_robust_mutex_init_recursive_shared(&ctrlr->ctrlr_lock);
	if (rc != 0)
	{
		return rc;
	}

	TAILQ_INIT(&ctrlr->active_procs);
	STAILQ_INIT(&ctrlr->register_operations);

	return rc;
}

void client_ctrlr_destruct_finish(struct spdk_client_ctrlr *ctrlr)
{
	pthread_mutex_destroy(&ctrlr->ctrlr_lock);
}

void client_ctrlr_destruct_async(struct spdk_client_ctrlr *ctrlr,
								 struct client_ctrlr_detach_ctx *ctx)
{
	struct spdk_client_qpair *qpair, *tmp;

	CLIENT_CTRLR_DEBUGLOG(ctrlr, "Prepare to destruct SSD\n");

	ctrlr->is_destructed = true;

	client_ctrlr_abort_queued_aborts(ctrlr);

	TAILQ_FOREACH_SAFE(qpair, &ctrlr->active_io_qpairs, tailq, tmp)
	{
		spdk_client_ctrlr_free_io_qpair(qpair);
	}

	client_ctrlr_shutdown_async(ctrlr, ctx);
}

int client_ctrlr_destruct_poll_async(struct spdk_client_ctrlr *ctrlr,
									 struct client_ctrlr_detach_ctx *ctx)
{
	int rc = 0;

	if (!ctx->shutdown_complete)
	{
		rc = client_ctrlr_shutdown_poll_async(ctrlr, ctx);
		if (rc == -EAGAIN)
		{
			return -EAGAIN;
		}
		/* Destruct ctrlr forcefully for any other error. */
	}

	if (ctx->cb_fn)
	{
		ctx->cb_fn(ctrlr);
	}

	spdk_bit_array_free(&ctrlr->free_io_qids);

	client_transport_ctrlr_destruct(ctrlr);

	return rc;
}

void client_ctrlr_destruct(struct spdk_client_ctrlr *ctrlr)
{
	struct client_ctrlr_detach_ctx ctx = {.ctrlr = ctrlr};
	int rc;

	client_ctrlr_destruct_async(ctrlr, &ctx);

	while (1)
	{
		rc = client_ctrlr_destruct_poll_async(ctrlr, &ctx);
		if (rc != -EAGAIN)
		{
			break;
		}
		client_delay(1000);
	}
}

int client_ctrlr_submit_admin_request(struct spdk_client_ctrlr *ctrlr,
									  struct client_request *req)
{
	return client_qpair_submit_request(ctrlr->adminq, req);
}

uint64_t
spdk_client_ctrlr_get_pmrsz(struct spdk_client_ctrlr *ctrlr)
{
	return ctrlr->pmr_size;
}

uint32_t
spdk_client_ctrlr_get_max_xfer_size(const struct spdk_client_ctrlr *ctrlr)
{
	return ctrlr->max_xfer_size;
}

void spdk_client_ctrlr_register_timeout_callback(struct spdk_client_ctrlr *ctrlr,
												 uint64_t timeout_io_us, uint64_t timeout_admin_us,
												 spdk_client_timeout_cb cb_fn, void *cb_arg)
{
	struct spdk_client_ctrlr_process *active_proc;

	client_robust_mutex_lock(&ctrlr->ctrlr_lock);

	active_proc = client_ctrlr_get_current_process(ctrlr);
	if (active_proc)
	{
		active_proc->timeout_io_ticks = timeout_io_us * spdk_get_ticks_hz() / 1000000ULL;
		active_proc->timeout_admin_ticks = timeout_admin_us * spdk_get_ticks_hz() / 1000000ULL;
		active_proc->timeout_cb_fn = cb_fn;
		active_proc->timeout_cb_arg = cb_arg;
	}

	ctrlr->timeout_enabled = true;

	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
}

int client_request_check_timeout(struct client_request *req, uint16_t cid,
								 struct spdk_client_ctrlr_process *active_proc,
								 uint64_t now_tick)
{
	struct spdk_client_qpair *qpair = req->qpair;
	struct spdk_client_ctrlr *ctrlr = qpair->ctrlr;
	uint64_t timeout_ticks = active_proc->timeout_io_ticks;

	assert(active_proc->timeout_cb_fn != NULL);

	if (req->timed_out || req->submit_tick == 0)
	{
		return 0;
	}

	if (req->pid != g_spdk_client_pid)
	{
		return 0;
	}

	if (req->submit_tick + timeout_ticks > now_tick)
	{
		return 1;
	}

	req->timed_out = true;

	/*
	 * We don't want to expose the admin queue to the user,
	 * so when we're timing out admin commands set the
	 * qpair to NULL.
	 */
	active_proc->timeout_cb_fn(active_proc->timeout_cb_arg, ctrlr,
							   qpair,
							   cid);
	return 0;
}

bool spdk_client_ctrlr_is_fabrics(struct spdk_client_ctrlr *ctrlr)
{
	assert(ctrlr);

	return true;
}

uint64_t
spdk_client_ctrlr_get_flags(struct spdk_client_ctrlr *ctrlr)
{
	return ctrlr->flags;
}

int32_t
spdk_client_ctrlr_alloc_qid(struct spdk_client_ctrlr *ctrlr)
{
	uint32_t qid;

	assert(ctrlr->free_io_qids);
	client_robust_mutex_lock(&ctrlr->ctrlr_lock);
	qid = spdk_bit_array_find_first_set(ctrlr->free_io_qids, 1);
	if (qid > ctrlr->opts.num_io_queues)
	{
		CLIENT_CTRLR_ERRLOG(ctrlr, "No free I/O queue IDs %d %d\n", qid, ctrlr->opts.num_io_queues);
		client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
		return -1;
	}

	spdk_bit_array_clear(ctrlr->free_io_qids, qid);
	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
	return qid;
}

void spdk_client_ctrlr_free_qid(struct spdk_client_ctrlr *ctrlr, uint16_t qid)
{
	assert(qid <= ctrlr->opts.num_io_queues);

	client_robust_mutex_lock(&ctrlr->ctrlr_lock);

	if (spdk_likely(ctrlr->free_io_qids))
	{
		spdk_bit_array_set(ctrlr->free_io_qids, qid);
	}

	client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
}

int spdk_client_ctrlr_get_memory_domains(const struct spdk_client_ctrlr *ctrlr,
										 struct spdk_memory_domain **domains, int array_size)
{
	return client_transport_ctrlr_get_memory_domains(ctrlr, domains, array_size);
}

struct spdk_client_poll_group *
spdk_client_poll_group_create(void *ctx, struct spdk_client_accel_fn_table *table)
{
	struct spdk_client_poll_group *group;

	group = calloc(1, sizeof(*group));
	if (group == NULL)
	{
		return NULL;
	}

	group->accel_fn_table.table_size = sizeof(struct spdk_client_accel_fn_table);
	if (table && table->table_size != 0)
	{
		group->accel_fn_table.table_size = table->table_size;
#define SET_FIELD(field)                                                                                \
	if (offsetof(struct spdk_client_accel_fn_table, field) + sizeof(table->field) <= table->table_size) \
	{                                                                                                   \
		group->accel_fn_table.field = table->field;                                                     \
	}

		SET_FIELD(submit_accel_crc32c);
		/* Do not remove this statement, you should always update this statement when you adding a new field,
		 * and do not forget to add the SET_FIELD statement for your added field. */
		SPDK_STATIC_ASSERT(sizeof(struct spdk_client_accel_fn_table) == 16, "Incorrect size");

#undef SET_FIELD
	}

	group->ctx = ctx;
	STAILQ_INIT(&group->tgroups);

	return group;
}

struct spdk_client_poll_group *
spdk_client_qpair_get_optimal_poll_group(struct spdk_client_qpair *qpair)
{
	struct spdk_client_transport_poll_group *tgroup;

	tgroup = client_transport_qpair_get_optimal_poll_group(qpair->transport, qpair);

	if (tgroup == NULL)
	{
		return NULL;
	}

	return tgroup->group;
}

int spdk_client_poll_group_add(struct spdk_client_poll_group *group, struct spdk_client_qpair *qpair)
{
	struct spdk_client_transport_poll_group *tgroup;
	const struct spdk_client_transport *transport;

	if (client_qpair_get_state(qpair) != CLIENT_QPAIR_DISCONNECTED)
	{
		return -EINVAL;
	}

	STAILQ_FOREACH(tgroup, &group->tgroups, link)
	{
		if (tgroup->transport == qpair->transport)
		{
			break;
		}
	}

	/* See if a new transport has been added (dlopen style) and we need to update the poll group */
	if (!tgroup)
	{
		transport = client_get_first_transport();
		while (transport != NULL)
		{
			if (transport == qpair->transport)
			{
				tgroup = client_transport_poll_group_create(transport);
				if (tgroup == NULL)
				{
					return -ENOMEM;
				}
				tgroup->group = group;
				STAILQ_INSERT_TAIL(&group->tgroups, tgroup, link);
				break;
			}
			transport = client_get_next_transport(transport);
		}
	}

	return tgroup ? client_transport_poll_group_add(tgroup, qpair) : -ENODEV;
}

int spdk_client_poll_group_remove(struct spdk_client_poll_group *group, struct spdk_client_qpair *qpair)
{
	struct spdk_client_transport_poll_group *tgroup;

	STAILQ_FOREACH(tgroup, &group->tgroups, link)
	{
		if (tgroup->transport == qpair->transport)
		{
			return client_transport_poll_group_remove(tgroup, qpair);
		}
	}

	return -ENODEV;
}

int client_poll_group_connect_qpair(struct spdk_client_qpair *qpair)
{
	return client_transport_poll_group_connect_qpair(qpair);
}

int client_poll_group_disconnect_qpair(struct spdk_client_qpair *qpair)
{
	return client_transport_poll_group_disconnect_qpair(qpair);
}

int64_t
spdk_client_poll_group_process_completions(struct spdk_client_poll_group *group,
										   uint32_t completions_per_qpair, spdk_client_disconnected_qpair_cb disconnected_qpair_cb)
{
	struct spdk_client_transport_poll_group *tgroup;
	int64_t local_completions = 0, error_reason = 0, num_completions = 0;

	if (disconnected_qpair_cb == NULL)
	{
		return -EINVAL;
	}

	STAILQ_FOREACH(tgroup, &group->tgroups, link)
	{
		local_completions = client_transport_poll_group_process_completions(tgroup, completions_per_qpair,
																			disconnected_qpair_cb);
		if (local_completions < 0 && error_reason == 0)
		{
			error_reason = local_completions;
		}
		else
		{
			num_completions += local_completions;
			/* Just to be safe */
			assert(num_completions >= 0);
		}
	}

	return error_reason ? error_reason : num_completions;
}

void *
spdk_client_poll_group_get_ctx(struct spdk_client_poll_group *group)
{
	return group->ctx;
}

int spdk_client_poll_group_destroy(struct spdk_client_poll_group *group)
{
	struct spdk_client_transport_poll_group *tgroup, *tmp_tgroup;

	STAILQ_FOREACH_SAFE(tgroup, &group->tgroups, link, tmp_tgroup)
	{
		STAILQ_REMOVE(&group->tgroups, tgroup, spdk_client_transport_poll_group, link);
		if (client_transport_poll_group_destroy(tgroup) != 0)
		{
			STAILQ_INSERT_TAIL(&group->tgroups, tgroup, link);
			return -EBUSY;
		}
	}

	free(group);

	return 0;
}

int spdk_client_poll_group_get_stats(struct spdk_client_poll_group *group,
									 struct spdk_client_poll_group_stat **stats)
{
	struct spdk_client_transport_poll_group *tgroup;
	struct spdk_client_poll_group_stat *result;
	uint32_t transports_count = 0;
	/* Not all transports used by this poll group may support statistics reporting */
	uint32_t reported_stats_count = 0;
	int rc;

	assert(group);
	assert(stats);

	result = calloc(1, sizeof(*result));
	if (!result)
	{
		SPDK_ERRLOG("Failed to allocate memory for poll group statistics\n");
		return -ENOMEM;
	}

	STAILQ_FOREACH(tgroup, &group->tgroups, link)
	{
		transports_count++;
	}

	result->transport_stat = calloc(transports_count, sizeof(*result->transport_stat));
	if (!result->transport_stat)
	{
		SPDK_ERRLOG("Failed to allocate memory for poll group statistics\n");
		free(result);
		return -ENOMEM;
	}

	STAILQ_FOREACH(tgroup, &group->tgroups, link)
	{
		rc = client_transport_poll_group_get_stats(tgroup, &result->transport_stat[reported_stats_count]);
		if (rc == 0)
		{
			reported_stats_count++;
		}
	}

	if (reported_stats_count == 0)
	{
		free(result->transport_stat);
		free(result);
		SPDK_DEBUGLOG(client, "No transport statistics available\n");
		return -ENOTSUP;
	}

	result->num_transports = reported_stats_count;
	*stats = result;

	return 0;
}

void spdk_client_poll_group_free_stats(struct spdk_client_poll_group *group,
									   struct spdk_client_poll_group_stat *stat)
{
	struct spdk_client_transport_poll_group *tgroup;
	uint32_t i;
	uint32_t freed_stats __attribute__((unused)) = 0;

	assert(group);
	assert(stat);

	for (i = 0; i < stat->num_transports; i++)
	{
		STAILQ_FOREACH(tgroup, &group->tgroups, link)
		{
			if (client_transport_get_trtype(tgroup->transport) == stat->transport_stat[i]->trtype)
			{
				client_transport_poll_group_free_stats(tgroup, stat->transport_stat[i]);
				freed_stats++;
				break;
			}
		}
	}

	assert(freed_stats == stat->num_transports);

	free(stat->transport_stat);
	free(stat);
}

void client_disconnected_qpair_cb(struct spdk_client_qpair *qpair, void *poll_group_ctx)
{
	struct client_poll_group *group = poll_group_ctx;

	client_transport_ctrlr_delete_io_qpair(group->ctrlr, qpair);
}

SPDK_LOG_REGISTER_COMPONENT(client)