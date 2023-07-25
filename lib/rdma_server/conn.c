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
client_get_sgl_unkeyed(char *buf, size_t size, struct spdk_req_cmd *cmd)
{
	struct spdk_req_sgl_descriptor *sgl = &cmd->dptr.sgl1;

	snprintf(buf, size, " len:0x%x", sgl->unkeyed.length);
}

static void
client_get_sgl_keyed(char *buf, size_t size, struct spdk_req_cmd *cmd)
{
	struct spdk_req_sgl_descriptor *sgl = &cmd->dptr.sgl1;

	snprintf(buf, size, " len:0x%x key:0x%x", sgl->keyed.length, sgl->keyed.key);
}

static void
client_get_sgl(char *buf, size_t size, struct spdk_req_cmd *cmd)
{
	struct spdk_req_sgl_descriptor *sgl = &cmd->dptr.sgl1;
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
client_get_prp(char *buf, size_t size, struct spdk_req_cmd *cmd)
{
	snprintf(buf, size, "PRP1 0x%" PRIx64 " PRP2 0x%" PRIx64, cmd->dptr.prp.prp1, cmd->dptr.prp.prp2);
}

static void
client_get_dptr(char *buf, size_t size, struct spdk_req_cmd *cmd)
{
	if (spdk_client_opc_get_data_transfer(cmd->opc) != SPDK_CLIENT_DATA_NONE)
	{
		switch (cmd->psdt)
		{
		case SPDK_CLIENT_PSDT_PRP:
			client_get_prp(buf, size, cmd);
			break;
		case SPDK_CLIENT_PSDT_SGL_MPTR_CONTIG:
		case SPDK_CLIENT_PSDT_SGL_MPTR_SGL:
			client_get_sgl(buf, size, cmd);
			break;
		default:;
		}
	}
}

static void
client_io_qpair_print_command(uint16_t qid, struct spdk_req_cmd *cmd)
{
	char dptr[CLIENT_CMD_DPTR_STR_SIZE] = {'\0'};

	assert(cmd != NULL);

	client_get_dptr(dptr, sizeof(dptr), cmd);

	switch ((int)cmd->opc)
	{
	case SPDK_CLIENT_OPC_WRITE:
	case SPDK_CLIENT_OPC_READ:
	case SPDK_CLIENT_OPC_RPC_WRITE:
	case SPDK_CLIENT_OPC_RPC_READ:
		SPDK_NOTICELOG("%s sqid:%d cid:%d "
					   "lba:%llu len:%d %s\n",
					   client_get_string(io_opcode, cmd->opc), qid, cmd->cid,
					   ((unsigned long long)cmd->cdw11 << 32) + cmd->cdw10,
					   (cmd->cdw12 & 0xFFFF) + 1, dptr);
		break;
	case SPDK_CLIENT_OPC_FLUSH:
		SPDK_NOTICELOG("%s sqid:%d cid:%d\n",
					   client_get_string(io_opcode, cmd->opc), qid, cmd->cid);
		break;
	default:
		SPDK_NOTICELOG("%s (%02x) sqid:%d cid:%d\n",
					   client_get_string(io_opcode, cmd->opc), cmd->opc, qid, cmd->cid);
		break;
	}
}

void spdk_client_print_command(uint16_t qid, struct spdk_req_cmd *cmd)
{
	assert(cmd != NULL);

	client_io_qpair_print_command(qid, cmd);
}

void spdk_client_qpair_print_command(struct spdk_client_qpair *qpair, struct spdk_req_cmd *cmd)
{
	assert(qpair != NULL);
	assert(cmd != NULL);

	spdk_client_print_command(qpair->id, cmd);
}

static const struct client_string generic_status[] = {
	{SPDK_CLIENT_SC_SUCCESS, "SUCCESS"},
	{SPDK_CLIENT_SC_INVALID_OPCODE, "INVALID OPCODE"},
	{SPDK_CLIENT_SC_INVALID_FIELD, "INVALID FIELD"},
	{SPDK_CLIENT_SC_COMMAND_ID_CONFLICT, "COMMAND ID CONFLICT"},
	{SPDK_CLIENT_SC_DATA_TRANSFER_ERROR, "DATA TRANSFER ERROR"},
	{SPDK_CLIENT_SC_ABORTED_POWER_LOSS, "ABORTED - POWER LOSS"},
	{SPDK_CLIENT_SC_INTERNAL_DEVICE_ERROR, "INTERNAL DEVICE ERROR"},
	{SPDK_CLIENT_SC_ABORTED_BY_REQUEST, "ABORTED - BY REQUEST"},
	{SPDK_CLIENT_SC_ABORTED_SQ_DELETION, "ABORTED - SQ DELETION"},
	{SPDK_CLIENT_SC_ABORTED_FAILED_FUSED, "ABORTED - FAILED FUSED"},
	{SPDK_CLIENT_SC_ABORTED_MISSING_FUSED, "ABORTED - MISSING FUSED"},
	{SPDK_CLIENT_SC_INVALID_NAMESPACE_OR_FORMAT, "INVALID NAMESPACE OR FORMAT"},
	{SPDK_CLIENT_SC_COMMAND_SEQUENCE_ERROR, "COMMAND SEQUENCE ERROR"},
	{SPDK_CLIENT_SC_INVALID_SGL_SEG_DESCRIPTOR, "INVALID SGL SEGMENT DESCRIPTOR"},
	{SPDK_CLIENT_SC_INVALID_NUM_SGL_DESCIRPTORS, "INVALID NUMBER OF SGL DESCRIPTORS"},
	{SPDK_CLIENT_SC_DATA_SGL_LENGTH_INVALID, "DATA SGL LENGTH INVALID"},
	{SPDK_CLIENT_SC_METADATA_SGL_LENGTH_INVALID, "METADATA SGL LENGTH INVALID"},
	{SPDK_CLIENT_SC_SGL_DESCRIPTOR_TYPE_INVALID, "SGL DESCRIPTOR TYPE INVALID"},
	{SPDK_CLIENT_SC_INVALID_CONTROLLER_MEM_BUF, "INVALID CONTROLLER MEMORY BUFFER"},
	{SPDK_CLIENT_SC_INVALID_PRP_OFFSET, "INVALID PRP OFFSET"},
	{SPDK_CLIENT_SC_ATOMIC_WRITE_UNIT_EXCEEDED, "ATOMIC WRITE UNIT EXCEEDED"},
	{SPDK_CLIENT_SC_OPERATION_DENIED, "OPERATION DENIED"},
	{SPDK_CLIENT_SC_INVALID_SGL_OFFSET, "INVALID SGL OFFSET"},
	{SPDK_CLIENT_SC_HOSTID_INCONSISTENT_FORMAT, "HOSTID INCONSISTENT FORMAT"},
	{SPDK_CLIENT_SC_ABORTED_PREEMPT, "ABORTED - PREEMPT AND ABORT"},
	{SPDK_CLIENT_SC_SANITIZE_FAILED, "SANITIZE FAILED"},
	{SPDK_CLIENT_SC_SANITIZE_IN_PROGRESS, "SANITIZE IN PROGRESS"},
	{SPDK_CLIENT_SC_SGL_DATA_BLOCK_GRANULARITY_INVALID, "DATA BLOCK GRANULARITY INVALID"},
	{SPDK_CLIENT_SC_COMMAND_INVALID_IN_CMB, "COMMAND NOT SUPPORTED FOR QUEUE IN CMB"},
	{SPDK_CLIENT_SC_LBA_OUT_OF_RANGE, "LBA OUT OF RANGE"},
	{SPDK_CLIENT_SC_CAPACITY_EXCEEDED, "CAPACITY EXCEEDED"},
	{SPDK_CLIENT_SC_NAMESPACE_NOT_READY, "NAMESPACE NOT READY"},
	{SPDK_CLIENT_SC_RESERVATION_CONFLICT, "RESERVATION CONFLICT"},
	{SPDK_CLIENT_SC_FORMAT_IN_PROGRESS, "FORMAT IN PROGRESS"},
	{0xFFFF, "GENERIC"}};

static const struct client_string command_specific_status[] = {
	{SPDK_CLIENT_SC_COMPLETION_QUEUE_INVALID, "INVALID COMPLETION QUEUE"},
	{SPDK_CLIENT_SC_INVALID_QUEUE_IDENTIFIER, "INVALID QUEUE IDENTIFIER"},
	{SPDK_CLIENT_SC_INVALID_QUEUE_SIZE, "INVALID QUEUE SIZE"},
	{SPDK_CLIENT_SC_ABORT_COMMAND_LIMIT_EXCEEDED, "ABORT CMD LIMIT EXCEEDED"},
	{SPDK_CLIENT_SC_ASYNC_EVENT_REQUEST_LIMIT_EXCEEDED, "ASYNC LIMIT EXCEEDED"},
	{SPDK_CLIENT_SC_INVALID_FIRMWARE_SLOT, "INVALID FIRMWARE SLOT"},
	{SPDK_CLIENT_SC_INVALID_FIRMWARE_IMAGE, "INVALID FIRMWARE IMAGE"},
	{SPDK_CLIENT_SC_INVALID_INTERRUPT_VECTOR, "INVALID INTERRUPT VECTOR"},
	{SPDK_CLIENT_SC_INVALID_LOG_PAGE, "INVALID LOG PAGE"},
	{SPDK_CLIENT_SC_INVALID_FORMAT, "INVALID FORMAT"},
	{SPDK_CLIENT_SC_FIRMWARE_REQ_CONVENTIONAL_RESET, "FIRMWARE REQUIRES CONVENTIONAL RESET"},
	{SPDK_CLIENT_SC_INVALID_QUEUE_DELETION, "INVALID QUEUE DELETION"},
	{SPDK_CLIENT_SC_FEATURE_ID_NOT_SAVEABLE, "FEATURE ID NOT SAVEABLE"},
	{SPDK_CLIENT_SC_FEATURE_NOT_CHANGEABLE, "FEATURE NOT CHANGEABLE"},
	{SPDK_CLIENT_SC_FEATURE_NOT_NAMESPACE_SPECIFIC, "FEATURE NOT NAMESPACE SPECIFIC"},
	{SPDK_CLIENT_SC_FIRMWARE_REQ_NVM_RESET, "FIRMWARE REQUIRES NVM RESET"},
	{SPDK_CLIENT_SC_FIRMWARE_REQ_RESET, "FIRMWARE REQUIRES RESET"},
	{SPDK_CLIENT_SC_FIRMWARE_REQ_MAX_TIME_VIOLATION, "FIRMWARE REQUIRES MAX TIME VIOLATION"},
	{SPDK_CLIENT_SC_FIRMWARE_ACTIVATION_PROHIBITED, "FIRMWARE ACTIVATION PROHIBITED"},
	{SPDK_CLIENT_SC_OVERLAPPING_RANGE, "OVERLAPPING RANGE"},
	{SPDK_CLIENT_SC_NAMESPACE_INSUFFICIENT_CAPACITY, "NAMESPACE INSUFFICIENT CAPACITY"},
	{SPDK_CLIENT_SC_NAMESPACE_ID_UNAVAILABLE, "NAMESPACE ID UNAVAILABLE"},
	{SPDK_CLIENT_SC_NAMESPACE_ALREADY_ATTACHED, "NAMESPACE ALREADY ATTACHED"},
	{SPDK_CLIENT_SC_NAMESPACE_IS_PRIVATE, "NAMESPACE IS PRIVATE"},
	{SPDK_CLIENT_SC_NAMESPACE_NOT_ATTACHED, "NAMESPACE NOT ATTACHED"},
	{SPDK_CLIENT_SC_THINPROVISIONING_NOT_SUPPORTED, "THINPROVISIONING NOT SUPPORTED"},
	{SPDK_CLIENT_SC_CONTROLLER_LIST_INVALID, "CONTROLLER LIST INVALID"},
	{SPDK_CLIENT_SC_DEVICE_SELF_TEST_IN_PROGRESS, "DEVICE SELF-TEST IN PROGRESS"},
	{SPDK_CLIENT_SC_BOOT_PARTITION_WRITE_PROHIBITED, "BOOT PARTITION WRITE PROHIBITED"},
	{SPDK_CLIENT_SC_INVALID_CTRLR_ID, "INVALID CONTROLLER ID"},
	{SPDK_CLIENT_SC_INVALID_SECONDARY_CTRLR_STATE, "INVALID SECONDARY CONTROLLER STATE"},
	{SPDK_CLIENT_SC_INVALID_NUM_CTRLR_RESOURCES, "INVALID NUMBER OF CONTROLLER RESOURCES"},
	{SPDK_CLIENT_SC_INVALID_RESOURCE_ID, "INVALID RESOURCE IDENTIFIER"},
	{SPDK_CLIENT_SC_STREAM_RESOURCE_ALLOCATION_FAILED, "STREAM RESOURCE ALLOCATION FAILED"},
	{SPDK_CLIENT_SC_CONFLICTING_ATTRIBUTES, "CONFLICTING ATTRIBUTES"},
	{SPDK_CLIENT_SC_INVALID_PROTECTION_INFO, "INVALID PROTECTION INFO"},
	{SPDK_CLIENT_SC_ATTEMPTED_WRITE_TO_RO_RANGE, "WRITE TO RO RANGE"},
	{0xFFFF, "COMMAND SPECIFIC"}};

static const struct client_string media_error_status[] = {
	{SPDK_CLIENT_SC_WRITE_FAULTS, "WRITE FAULTS"},
	{SPDK_CLIENT_SC_UNRECOVERED_READ_ERROR, "UNRECOVERED READ ERROR"},
	{SPDK_CLIENT_SC_GUARD_CHECK_ERROR, "GUARD CHECK ERROR"},
	{SPDK_CLIENT_SC_APPLICATION_TAG_CHECK_ERROR, "APPLICATION TAG CHECK ERROR"},
	{SPDK_CLIENT_SC_REFERENCE_TAG_CHECK_ERROR, "REFERENCE TAG CHECK ERROR"},
	{SPDK_CLIENT_SC_COMPARE_FAILURE, "COMPARE FAILURE"},
	{SPDK_CLIENT_SC_ACCESS_DENIED, "ACCESS DENIED"},
	{SPDK_CLIENT_SC_DEALLOCATED_OR_UNWRITTEN_BLOCK, "DEALLOCATED OR UNWRITTEN BLOCK"},

	{0xFFFF, "MEDIA ERROR"}};

static const struct client_string path_status[] = {
	{SPDK_CLIENT_SC_INTERNAL_PATH_ERROR, "INTERNAL PATH ERROR"},
	{SPDK_CLIENT_SC_CONTROLLER_PATH_ERROR, "CONTROLLER PATH ERROR"},
	{SPDK_CLIENT_SC_HOST_PATH_ERROR, "HOST PATH ERROR"},
	{SPDK_CLIENT_SC_ABORTED_BY_HOST, "ABORTED BY HOST"},
	{0xFFFF, "PATH ERROR"}};

const char *
spdk_req_cpl_get_status_string(const struct spdk_req_status *status)
{
	const struct client_string *entry;

	switch (status->sct)
	{
	case SPDK_CLIENT_SCT_GENERIC:
		entry = generic_status;
		break;
	case SPDK_CLIENT_SCT_COMMAND_SPECIFIC:
		entry = command_specific_status;
		break;
	case SPDK_CLIENT_SCT_MEDIA_ERROR:
		entry = media_error_status;
		break;
	case SPDK_CLIENT_SCT_PATH:
		entry = path_status;
		break;
	case SPDK_CLIENT_SCT_VENDOR_SPECIFIC:
		return "VENDOR SPECIFIC";
	default:
		return "RESERVED";
	}

	return client_get_string(entry, status->sc);
}

void spdk_client_print_completion(uint16_t qid, struct spdk_req_cpl *cpl)
{
	assert(cpl != NULL);

	/* Check that sqid matches qid. Note that sqid is reserved
	 * for fabrics so don't print an error when sqid is 0. */
	if (cpl->sqid != qid && cpl->sqid != 0)
	{
		SPDK_ERRLOG("sqid %u doesn't match qid\n", cpl->sqid);
	}

	SPDK_NOTICELOG("%s (%02x/%02x) qid:%d cid:%d cdw0:%x sqhd:%04x p:%x m:%x dnr:%x\n",
				   spdk_req_cpl_get_status_string(&cpl->status),
				   cpl->status.sct, cpl->status.sc, qid, cpl->cid, cpl->cdw0,
				   cpl->sqhd, cpl->status.p, cpl->status.m, cpl->status.dnr);
}

void spdk_client_qpair_print_completion(struct spdk_client_qpair *qpair, struct spdk_req_cpl *cpl)
{
	spdk_client_print_completion(qpair->id, cpl);
}

bool client_completion_is_retry(const struct spdk_req_cpl *cpl)
{
	/*
	 * TODO: spec is not clear how commands that are aborted due
	 *  to TLER will be marked.  So for now, it seems
	 *  NAMESPACE_NOT_READY is the only case where we should
	 *  look at the DNR bit.
	 */
	switch ((int)cpl->status.sct)
	{
	case SPDK_CLIENT_SCT_GENERIC:
		switch ((int)cpl->status.sc)
		{
		case SPDK_CLIENT_SC_NAMESPACE_NOT_READY:
		case SPDK_CLIENT_SC_FORMAT_IN_PROGRESS:
			if (cpl->status.dnr)
			{
				return false;
			}
			else
			{
				return true;
			}
		case SPDK_CLIENT_SC_INVALID_OPCODE:
		case SPDK_CLIENT_SC_INVALID_FIELD:
		case SPDK_CLIENT_SC_COMMAND_ID_CONFLICT:
		case SPDK_CLIENT_SC_DATA_TRANSFER_ERROR:
		case SPDK_CLIENT_SC_ABORTED_POWER_LOSS:
		case SPDK_CLIENT_SC_INTERNAL_DEVICE_ERROR:
		case SPDK_CLIENT_SC_ABORTED_BY_REQUEST:
		case SPDK_CLIENT_SC_ABORTED_SQ_DELETION:
		case SPDK_CLIENT_SC_ABORTED_FAILED_FUSED:
		case SPDK_CLIENT_SC_ABORTED_MISSING_FUSED:
		case SPDK_CLIENT_SC_INVALID_NAMESPACE_OR_FORMAT:
		case SPDK_CLIENT_SC_COMMAND_SEQUENCE_ERROR:
		case SPDK_CLIENT_SC_LBA_OUT_OF_RANGE:
		case SPDK_CLIENT_SC_CAPACITY_EXCEEDED:
		default:
			return false;
		}
	case SPDK_CLIENT_SCT_PATH:
		/*
		 * Per Client TP 4028 (Path and Transport Error Enhancements), retries should be
		 * based on the setting of the DNR bit for Internal Path Error
		 */
		switch ((int)cpl->status.sc)
		{
		case SPDK_CLIENT_SC_INTERNAL_PATH_ERROR:
			return !cpl->status.dnr;
		default:
			return false;
		}
	case SPDK_CLIENT_SCT_COMMAND_SPECIFIC:
	case SPDK_CLIENT_SCT_MEDIA_ERROR:
	case SPDK_CLIENT_SCT_VENDOR_SPECIFIC:
	default:
		return false;
	}
}

static void
client_qpair_manual_complete_request(struct spdk_client_qpair *qpair,
									 struct client_request *req, uint32_t sct, uint32_t sc,
									 uint32_t dnr, bool print_on_error)
{
	struct spdk_req_cpl cpl;
	bool error;

	memset(&cpl, 0, sizeof(cpl));
	cpl.sqid = qpair->id;
	cpl.status.sct = sct;
	cpl.status.sc = sc;
	cpl.status.dnr = dnr;

	error = spdk_req_cpl_is_error(&cpl);

	if (error && print_on_error && !qpair->ctrlr->opts.disable_error_logging)
	{
		SPDK_NOTICELOG("Command completed manually:\n");
		spdk_client_qpair_print_command(qpair, &req->cmd);
		spdk_client_qpair_print_completion(qpair, &cpl);
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
		client_qpair_manual_complete_request(qpair, req, SPDK_CLIENT_SCT_GENERIC,
											 SPDK_CLIENT_SC_ABORTED_SQ_DELETION, dnr, true);
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
		client_qpair_manual_complete_request(qpair, req, SPDK_CLIENT_SCT_GENERIC,
											 SPDK_CLIENT_SC_ABORTED_BY_REQUEST, 1, true);
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
				req->cpl.status.sc = SPDK_CLIENT_SC_INTERNAL_DEVICE_ERROR;
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
		if (SPDK_DEBUGLOG_FLAG_ENABLED("client"))
		{
			spdk_client_print_command(qpair->id, &req->cmd);
		}
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
		client_qpair_manual_complete_request(qpair, req, SPDK_CLIENT_SCT_GENERIC,
											 SPDK_CLIENT_SC_INTERNAL_DEVICE_ERROR, true, true);
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

void spdk_client_qpair_remove_cmd_error_injection(struct spdk_client_ctrlr *ctrlr,
												  struct spdk_client_qpair *qpair,
												  uint8_t opc)
{
	struct client_error_cmd *cmd, *entry;

	TAILQ_FOREACH_SAFE(cmd, &qpair->err_cmd_head, link, entry)
	{
		if (cmd->opc == opc)
		{
			TAILQ_REMOVE(&qpair->err_cmd_head, cmd, link);
			spdk_free(cmd);
			break;
		}
	}
}

uint16_t
spdk_client_qpair_get_id(struct spdk_client_qpair *qpair)
{
	return qpair->id;
}
