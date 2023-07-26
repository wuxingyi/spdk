/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2021 Mellanox Technologies LTD. All rights reserved.
 *   Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "spdk/rdma_client.h"
#include "spdk_internal/rdma_client.h"

static inline struct client_request *_client_ns_cmd_rw(
	struct spdk_client_qpair *qpair,
	const struct client_payload *payload, uint32_t payload_offset, uint32_t md_offset,
	uint64_t lba, uint32_t lba_count, spdk_req_cmd_cb cb_fn,
	void *cb_arg, uint32_t opc,
	bool check_sgl, int *rc);

static bool
client_ns_check_request_length(uint32_t lba_count, uint32_t sectors_per_max_io,
							   uint32_t sectors_per_stripe, uint32_t qdepth)
{
	uint32_t child_per_io = UINT32_MAX;

	/* After a namespace is destroyed(e.g. hotplug), all the fields associated with the
	 * namespace will be cleared to zero, the function will return TRUE for this case,
	 * and -EINVAL will be returned to caller.
	 */
	if (sectors_per_stripe > 0)
	{
		child_per_io = (lba_count + sectors_per_stripe - 1) / sectors_per_stripe;
	}
	else if (sectors_per_max_io > 0)
	{
		child_per_io = (lba_count + sectors_per_max_io - 1) / sectors_per_max_io;
	}

	SPDK_DEBUGLOG(client, "checking maximum i/o length %d\n", child_per_io);

	return child_per_io >= qdepth;
}

static inline int
client_ns_map_failure_rc(uint32_t lba_count, uint32_t sectors_per_max_io,
						 uint32_t sectors_per_stripe, uint32_t qdepth, int rc)
{
	assert(rc);
	if (rc == -ENOMEM &&
		client_ns_check_request_length(lba_count, sectors_per_max_io, sectors_per_stripe, qdepth))
	{
		return -EINVAL;
	}
	return rc;
}

static struct client_request *
_client_add_child_request(struct spdk_client_qpair *qpair,
						  const struct client_payload *payload,
						  uint32_t payload_offset, uint32_t md_offset,
						  uint64_t lba, uint32_t lba_count, spdk_req_cmd_cb cb_fn, void *cb_arg, uint32_t opc,
						  struct client_request *parent, bool check_sgl, int *rc)
{
	struct client_request *child;

	child = _client_ns_cmd_rw(qpair, payload, payload_offset, md_offset, lba, lba_count, cb_fn,
							  cb_arg, opc, check_sgl, rc);
	if (child == NULL)
	{
		client_request_free_children(parent);
		client_free_request(parent);
		return NULL;
	}

	client_request_add_child(parent, child);
	return child;
}

static struct client_request *
_client_ns_cmd_split_request(
	struct spdk_client_qpair *qpair,
	const struct client_payload *payload,
	uint32_t payload_offset, uint32_t md_offset,
	uint64_t lba, uint32_t lba_count,
	spdk_req_cmd_cb cb_fn, void *cb_arg, uint32_t opc,
	struct client_request *req,
	uint32_t sectors_per_max_io, uint32_t sector_mask,
	int *rc)
{
	uint32_t sector_size = qpair->ctrlr->opts.sector_size;
	uint32_t remaining_lba_count = lba_count;
	struct client_request *child;

	while (remaining_lba_count > 0)
	{
		lba_count = sectors_per_max_io - (lba & sector_mask);
		lba_count = spdk_min(remaining_lba_count, lba_count);

		child = _client_add_child_request(qpair, payload, payload_offset, md_offset,
										  lba, lba_count, cb_fn, cb_arg, opc,
										  req, true, rc);
		if (child == NULL)
		{
			return NULL;
		}

		remaining_lba_count -= lba_count;
		lba += lba_count;
		payload_offset += lba_count * sector_size;
		md_offset += lba_count * qpair->ctrlr->opts.md_size;
	}

	return req;
}

static void
_client_ns_cmd_setup_request(struct client_request *req,
							 uint32_t opc, uint64_t lba, uint32_t lba_count)
{
	struct spdk_req_cmd *cmd;

	cmd = &req->cmd;
	cmd->opc = opc;

	*(uint64_t *)&cmd->cdw10 = lba;

	cmd->cdw12 = lba_count - 1;

	if (opc == SPDK_CLIENT_OPC_RPC_READ || opc == SPDK_CLIENT_OPC_RPC_WRITE)
	{
		cmd->rsvd2 = req->payload.rpc_request_id;
		cmd->rsvd3 = req->payload.data_length;
		cmd->cdw13 = req->payload.submit_type;
		cmd->rpc_opc = req->payload.rpc_opc;
		if (req->payload.md5sum != NULL)
		{
			cmd->cdw14 = (uint32_t)1;
			memcpy(cmd->md5sum, req->payload.md5sum, 16);
		}
	}
}

static struct client_request *
_client_ns_cmd_split_request_sgl(
	struct spdk_client_qpair *qpair,
	const struct client_payload *payload,
	uint32_t payload_offset, uint32_t md_offset,
	uint64_t lba, uint32_t lba_count,
	spdk_req_cmd_cb cb_fn, void *cb_arg, uint32_t opc,
	struct client_request *req,
	int *rc)
{
	spdk_client_req_reset_sgl_cb reset_sgl_fn = req->payload.reset_sgl_fn;
	spdk_client_req_next_sge_cb next_sge_fn = req->payload.next_sge_fn;
	void *sgl_cb_arg = req->payload.contig_or_cb_arg;
	uint64_t child_lba = lba;
	uint32_t req_current_length = 0;
	uint32_t child_length = 0;
	uint32_t sge_length;
	uint16_t max_sges, num_sges;
	uintptr_t address;

	max_sges = qpair->ctrlr->max_sges;

	reset_sgl_fn(sgl_cb_arg, payload_offset);
	num_sges = 0;

	while (req_current_length < req->payload_size)
	{
		next_sge_fn(sgl_cb_arg, (void **)&address, &sge_length);

		if (req_current_length + sge_length > req->payload_size)
		{
			sge_length = req->payload_size - req_current_length;
		}

		child_length += sge_length;
		req_current_length += sge_length;
		num_sges++;

		if (num_sges < max_sges && req_current_length < req->payload_size)
		{
			continue;
		}

		/*
		 * We need to create a split here.  Send what we have accumulated so far as a child
		 *  request.  Checking if the child equals the full payload allows us to *not*
		 *  create a child request when no splitting is required - in that case we will
		 *  fall-through and just create a single request with no children for the entire I/O.
		 */
		if (child_length != req->payload_size)
		{
			struct client_request *child;
			uint32_t child_lba_count;

			child_lba_count = SPDK_CEIL_DIV(child_length, qpair->ctrlr->opts.sector_size);
			/*
			 * Note the last parameter is set to "false" - this tells the recursive
			 *  call to _client_ns_cmd_rw() to not bother with checking for SGL splitting
			 *  since we have already verified it here.
			 */
			child = _client_add_child_request(qpair, payload, payload_offset, md_offset,
											  child_lba, child_lba_count,
											  cb_fn, cb_arg, opc,
											  req, false, rc);
			if (child == NULL)
			{
				return NULL;
			}
			payload_offset += child_length;
			md_offset += child_lba_count * qpair->ctrlr->opts.md_size;
			child_lba += child_lba_count;
			child_length = 0;
			num_sges = 0;
		}
	}

	if (child_length == req->payload_size)
	{
		/* No splitting was required, so setup the whole payload as one request. */
		_client_ns_cmd_setup_request(req, opc, lba, lba_count);
	}

	return req;
}

static inline struct client_request *
_client_ns_cmd_rw(struct spdk_client_qpair *qpair,
				  const struct client_payload *payload, uint32_t payload_offset, uint32_t md_offset,
				  uint64_t lba, uint32_t lba_count, spdk_req_cmd_cb cb_fn, void *cb_arg, uint32_t opc,
				  bool check_sgl, int *rc)
{
	struct client_request *req;
	uint32_t sector_size = qpair->ctrlr->opts.sector_size;
	uint32_t sectors_per_max_io = qpair->ctrlr->opts.sectors_per_max_io;
	uint32_t sectors_per_stripe = qpair->ctrlr->opts.sectors_per_stripe;

	assert(rc != NULL);
	assert(*rc == 0);

	uint32_t max_payload_size = lba_count * sector_size;
	max_payload_size = spdk_min(max_payload_size, payload->data_length - payload_offset);
	req = client_allocate_request(qpair, payload, max_payload_size, lba_count * qpair->ctrlr->opts.md_size,
								  cb_fn, cb_arg);
	if (req == NULL)
	{
		*rc = -ENOMEM;
		return NULL;
	}

	req->payload_offset = payload_offset;
	req->md_offset = md_offset;

	/*
	 * Intel DC P3*00 Client controllers benefit from driver-assisted striping.
	 * If this controller defines a stripe boundary and this I/O spans a stripe
	 *  boundary, split the request into multiple requests and submit each
	 *  separately to hardware.
	 */
	if (sectors_per_stripe > 0 &&
		(((lba & (sectors_per_stripe - 1)) + lba_count) > sectors_per_stripe))
	{

		return _client_ns_cmd_split_request(qpair, payload, payload_offset, md_offset, lba, lba_count,
											cb_fn,
											cb_arg, opc,
											req, sectors_per_stripe, sectors_per_stripe - 1, rc);
	}
	else if (lba_count > sectors_per_max_io)
	{
		return _client_ns_cmd_split_request(qpair, payload, payload_offset, md_offset, lba, lba_count,
											cb_fn,
											cb_arg, opc,
											req, sectors_per_max_io, 0, rc);
	}
	else if (client_payload_type(&req->payload) == CLIENT_PAYLOAD_TYPE_SGL && check_sgl)
	{
		return _client_ns_cmd_split_request_sgl(qpair, payload, payload_offset, md_offset,
												lba, lba_count, cb_fn, cb_arg, opc,
												req, rc);
	}

	_client_ns_cmd_setup_request(req, opc, lba, lba_count);
	return req;
}

int spdk_client_ns_cmd_read(struct spdk_client_qpair *qpair, void *buffer,
							uint64_t lba,
							uint32_t lba_count, spdk_req_cmd_cb cb_fn, void *cb_arg)
{
	struct client_request *req;
	struct client_payload payload;
	int rc = 0;

	payload = CLIENT_PAYLOAD_CONTIG(buffer, NULL);

	req = _client_ns_cmd_rw(qpair, &payload, 0, 0, lba, lba_count, cb_fn, cb_arg, SPDK_CLIENT_OPC_READ,
							false, &rc);
	if (req != NULL)
	{
		return client_qpair_submit_request(qpair, req);
	}
	else
	{
		return client_ns_map_failure_rc(lba_count,
										qpair->ctrlr->opts.sectors_per_max_io,
										qpair->ctrlr->opts.sectors_per_stripe,
										qpair->ctrlr->opts.io_queue_requests,
										rc);
	}
}

int spdk_client_ns_cmd_readv(struct spdk_client_qpair *qpair,
							 uint64_t lba, uint32_t lba_count,
							 spdk_req_cmd_cb cb_fn, void *cb_arg,
							 spdk_client_req_reset_sgl_cb reset_sgl_fn,
							 spdk_client_req_next_sge_cb next_sge_fn)
{
	struct client_request *req;
	struct client_payload payload;
	int rc = 0;

	if (reset_sgl_fn == NULL || next_sge_fn == NULL)
	{
		return -EINVAL;
	}

	payload = CLIENT_PAYLOAD_SGL(reset_sgl_fn, next_sge_fn, cb_arg, NULL, 0, 0, 0, 0, NULL);

	req = _client_ns_cmd_rw(qpair, &payload, 0, 0, lba, lba_count, cb_fn, cb_arg, SPDK_CLIENT_OPC_READ,
							true, &rc);
	if (req != NULL)
	{
		return client_qpair_submit_request(qpair, req);
	}
	else
	{
		return client_ns_map_failure_rc(lba_count,
										qpair->ctrlr->opts.sectors_per_max_io,
										qpair->ctrlr->opts.sectors_per_stripe,
										qpair->ctrlr->opts.io_queue_requests,
										rc);
	}
}

int spdk_client_ns_cmd_write(struct spdk_client_qpair *qpair,
							 void *buffer, uint64_t lba,
							 uint32_t lba_count, spdk_req_cmd_cb cb_fn, void *cb_arg)
{
	struct client_request *req;
	struct client_payload payload;
	int rc = 0;

	payload = CLIENT_PAYLOAD_CONTIG(buffer, NULL);

	req = _client_ns_cmd_rw(qpair, &payload, 0, 0, lba, lba_count, cb_fn, cb_arg, SPDK_CLIENT_OPC_WRITE,
							false, &rc);
	if (req != NULL)
	{
		return client_qpair_submit_request(qpair, req);
	}
	else
	{
		return client_ns_map_failure_rc(lba_count,
										qpair->ctrlr->opts.sectors_per_max_io,
										qpair->ctrlr->opts.sectors_per_stripe,
										qpair->ctrlr->opts.io_queue_requests,
										rc);
	}
}

int spdk_client_ns_cmd_writev(struct spdk_client_qpair *qpair,
							  uint64_t lba, uint32_t lba_count,
							  spdk_req_cmd_cb cb_fn, void *cb_arg,
							  spdk_client_req_reset_sgl_cb reset_sgl_fn,
							  spdk_client_req_next_sge_cb next_sge_fn)
{
	struct client_request *req;
	struct client_payload payload;
	int rc = 0;

	if (reset_sgl_fn == NULL || next_sge_fn == NULL)
	{
		return -EINVAL;
	}

	payload = CLIENT_PAYLOAD_SGL(reset_sgl_fn, next_sge_fn, cb_arg, NULL, 0, 0, 0, 0, NULL);

	req = _client_ns_cmd_rw(qpair, &payload, 0, 0, lba, lba_count, cb_fn, cb_arg, SPDK_CLIENT_OPC_WRITE,
							true, &rc);
	if (req != NULL)
	{
		return client_qpair_submit_request(qpair, req);
	}
	else
	{
		return client_ns_map_failure_rc(lba_count,
										qpair->ctrlr->opts.sectors_per_max_io,
										qpair->ctrlr->opts.sectors_per_stripe,
										qpair->ctrlr->opts.io_queue_requests,
										rc);
	}
}

void rpc_reclaim_out_iovs(struct rpc_request *req)
{
	struct iovec *iov;
	for (int i = 0; i < req->out_iovcnt; i++)
	{
		iov = &req->out_iovs[i];
		if (iov->iov_base != NULL)
		{
			spdk_mempool_put(req->qpair->ctrlr->rpc_data_mp, iov->iov_base);
		}
		else
		{
			break;
		}
	}
	return;
}

void rpc_reclaim_in_iovs(struct rpc_request *req)
{
	struct iovec *iov;
	for (int i = 0; i < req->in_iovcnt; i++)
	{
		iov = &req->in_iovs[i];
		if (iov->iov_base != NULL)
		{
			spdk_mempool_put(req->qpair->ctrlr->rpc_data_mp, iov->iov_base);
		}
		else
		{
			break;
		}
	}
	return;
}

int rpc_prepare_out_iovs(struct rpc_request *req)
{
	void *raw_data = req->raw_data;
	uint32_t length = req->out_length;
	int iovpos = 0;

	// used when submit_type == SPDK_CLIENT_SUBMIT_IOVES
	int iovpos_dst = 0;
	int iovpos_src = 0;
	int offset_dst = 0;
	int offset_src = 0;
	int iov_remain_length_dst = 0;
	int iov_remain_length_src = 0;
	struct iovec *iov_src;
	struct iovec *iov_dst;
	int copy_len = 0;
	int copy_len_total = 0;

	struct iovec *iov;
	uint32_t offset = 0;
	int sectors = 0;
	char *addr = 0;
	uint64_t io_unit_size = req->qpair->ctrlr->io_unit_size;
	uint64_t sector_size = req->qpair->ctrlr->opts.sector_size;
	req->out_iovcnt = SPDK_CEIL_DIV(length, io_unit_size);
	req->out_iovs = calloc(req->out_iovcnt, sizeof(struct iovec));
	if (!req->out_iovs)
	{
		return -1;
	}
	while (length > 0)
	{
		if (req->submit_type == SPDK_CLIENT_SUBMIT_CONTING)
		{
			iov = &req->out_iovs[iovpos];
			iov->iov_len = spdk_min(length, io_unit_size);
			addr = req->raw_data + offset;
			iov->iov_base = spdk_mempool_get(req->qpair->ctrlr->rpc_data_mp);
			if (iov->iov_base == NULL)
			{
				rpc_reclaim_out_iovs(req);
				free(req->out_iovs);
				return -1;
			}
			memcpy(iov->iov_base, addr, iov->iov_len);
			copy_len_total = copy_len_total + iov->iov_len;
			length -= iov->iov_len;
			offset += iov->iov_len;
			iovpos++;
		}
		else
		{
			iov_dst = &req->out_iovs[iovpos_dst];
			iov_dst->iov_len = spdk_min(length, io_unit_size);
			iov_dst->iov_base = spdk_mempool_get(req->qpair->ctrlr->rpc_data_mp);
			if (iov_dst->iov_base == NULL)
			{
				rpc_reclaim_out_iovs(req);
				free(req->out_iovs);
				return -1;
			}
			iov_remain_length_dst = iov_dst->iov_len - offset_dst;
			while (iov_remain_length_dst > 0)
			{
				iov_src = &req->raw_ioves[iovpos_src];
				iov_remain_length_src = iov_src->iov_len - offset_src;
				copy_len = spdk_min(iov_remain_length_dst, iov_remain_length_src);
				memcpy(iov_dst->iov_base + offset_dst, iov_src->iov_base + offset_src, copy_len);
				copy_len_total = copy_len_total + copy_len;
				offset_dst = offset_dst + copy_len;
				offset_src = offset_src + copy_len;
				iov_remain_length_dst = iov_remain_length_dst - copy_len;
				iov_remain_length_src = iov_remain_length_src - copy_len;
				length = length - copy_len;
				if (iov_remain_length_dst == 0)
				{
					iovpos_dst++;
					offset_dst = 0;
				}
				else if (iov_remain_length_src == 0)
				{
					iovpos_src++;
					offset_src = 0;
				}
				else
				{
					assert(iov_remain_length_dst == 0 || iov_remain_length_src == 0);
					SPDK_ERRLOG("rpc_prepare_out_iovs HIT CRITIAL ERROR\n");
				}
			}
		}
	}
	assert(copy_len_total == req->out_length);

	for (int i = 0; i < req->out_iovcnt; i++)
	{
		req->out_payload_length += req->out_iovs[i].iov_len;
	}
	SPDK_DEBUGLOG(rdma, "req->out_payload_length=%d, iov_cnt=%d\n", req->out_payload_length, req->out_iovcnt);
	return 0;
}

int rpc_prepare_in_iovs(struct rpc_request *req)
{
	void *raw_data = req->raw_data;
	uint32_t length = req->in_length;
	int iovpos = 0;
	struct iovec *iov;
	uint64_t io_unit_size = req->qpair->ctrlr->io_unit_size;
	uint64_t sector_size = req->qpair->ctrlr->opts.sector_size;
	int sectors;
	req->in_iovcnt = SPDK_CEIL_DIV(length, io_unit_size);
	req->in_iovs = calloc(req->in_iovcnt, sizeof(struct iovec));
	if (!req->in_iovs)
	{
		return -EAGAIN;
	}
	while (length > 0)
	{
		iov = &req->in_iovs[iovpos];
		iov->iov_len = spdk_min(length, io_unit_size);
		iov->iov_base = spdk_mempool_get(req->qpair->ctrlr->rpc_data_mp);
		if (iov->iov_base == NULL)
		{
			rpc_reclaim_in_iovs(req);
			free(req->in_iovs);
			return -EAGAIN;
		}
		length -= iov->iov_len;
		iovpos++;
	}

	for (int i = 0; i < req->in_iovcnt; i++)
	{
		req->in_payload_length += req->in_iovs[i].iov_len;
	}
	SPDK_DEBUGLOG(rdma, "req->in_payload_length=%d, iov_cnt=%d\n", req->in_payload_length, req->in_iovcnt);

	return 0;
}

static int md5init(struct spdk_md5ctx *md5ctx)
{
	int rc;

	if (md5ctx == NULL)
	{
		return -1;
	}

	md5ctx->md5ctx = EVP_MD_CTX_create();
	if (md5ctx->md5ctx == NULL)
	{
		return -1;
	}

	rc = EVP_DigestInit_ex(md5ctx->md5ctx, EVP_md5(), NULL);
	/* For EVP_DigestInit_ex, 1 == success, 0 == failure. */
	if (rc == 0)
	{
		EVP_MD_CTX_destroy(md5ctx->md5ctx);
		md5ctx->md5ctx = NULL;
	}
	return rc;
}

static int md5final(void *md5, struct spdk_md5ctx *md5ctx)
{
	int rc;

	if (md5ctx == NULL || md5 == NULL)
	{
		return -1;
	}
	rc = EVP_DigestFinal_ex(md5ctx->md5ctx, (unsigned char *)md5, NULL);
	EVP_MD_CTX_destroy(md5ctx->md5ctx);
	md5ctx->md5ctx = NULL;
	return rc;
}

static int md5update(struct spdk_md5ctx *md5ctx, const void *data, size_t len)
{
	int rc;

	if (md5ctx == NULL)
	{
		return -1;
	}
	if (data == NULL || len == 0)
	{
		return 0;
	}
	rc = EVP_DigestUpdate(md5ctx->md5ctx, data, len);
	return rc;
}

void spdk_client_reclaim_rpc_request(struct rpc_request *req)
{
	rpc_reclaim_in_iovs(req);
	free(req->in_iovs);
	STAILQ_INSERT_TAIL(&req->qpair->free_rpc_req, req, stailq);
}

static void
rpc_request_reset_out_sgl(void *ref, uint32_t sgl_offset)
{
	struct iovec *iov;
	struct rpc_request *req = (struct rpc_request *)ref;

	req->iov_offset = sgl_offset;
	for (req->iovpos = 0; req->iovpos < req->out_iovcnt; req->iovpos++)
	{
		iov = &req->out_iovs[req->iovpos];
		if (req->iov_offset < iov->iov_len)
		{
			break;
		}

		req->iov_offset -= iov->iov_len;
	}
}

static int
rpc_request_next_out_sge(void *ref, void **address, uint32_t *length)
{
	struct iovec *iov;
	struct rpc_request *req = (struct rpc_request *)ref;
	assert(req->iovpos < req->out_iovcnt);

	iov = &req->out_iovs[req->iovpos];
	assert(req->iov_offset <= iov->iov_len);

	*address = iov->iov_base + req->iov_offset;
	*length = iov->iov_len - req->iov_offset;
	req->iovpos++;
	req->iov_offset = 0;

	return 0;
}

static void
rpc_request_reset_in_sgl(void *ref, uint32_t sgl_offset)
{
	struct iovec *iov;
	struct rpc_request *req = (struct rpc_request *)ref;

	req->iov_offset = sgl_offset;
	for (req->iovpos = 0; req->iovpos < req->in_iovcnt; req->iovpos++)
	{
		iov = &req->in_iovs[req->iovpos];
		if (req->iov_offset < iov->iov_len)
		{
			break;
		}

		req->iov_offset -= iov->iov_len;
	}
}

static int
rpc_request_next_in_sge(void *ref, void **address, uint32_t *length)
{
	struct iovec *iov;
	struct rpc_request *req = (struct rpc_request *)ref;

	assert(req->iovpos < req->in_iovcnt);

	iov = &req->in_iovs[req->iovpos];
	assert(req->iov_offset <= iov->iov_len);

	*address = iov->iov_base + req->iov_offset;
	*length = iov->iov_len - req->iov_offset;
	req->iovpos++;
	req->iov_offset = 0;

	return 0;
}

int spdk_client_rpc_request_write(struct spdk_client_qpair *qpair,
								  uint64_t lba, uint32_t lba_count, uint32_t rpc_request_id, uint32_t data_length,
								  uint32_t rpc_opc,
								  uint32_t submit_type,
								  uint8_t *md5sum,
								  spdk_req_cmd_cb cb_fn, void *cb_arg,
								  spdk_client_req_reset_sgl_cb reset_sgl_fn,
								  spdk_client_req_next_sge_cb next_sge_fn)
{
	struct client_request *req;
	struct client_payload payload;
	int rc = 0;

	if (reset_sgl_fn == NULL || next_sge_fn == NULL)
	{
		return -EINVAL;
	}

	payload = CLIENT_PAYLOAD_SGL(reset_sgl_fn, next_sge_fn, cb_arg, NULL, rpc_request_id, data_length, rpc_opc, submit_type, md5sum);
	SPDK_DEBUGLOG(rdma, "spdk_client_rpc_request_write send parent request lba_start=%d, lba_end=%d\n", 0, lba_count - 1);
	req = _client_ns_cmd_rw(qpair, &payload, 0, 0, 0, lba_count, cb_fn, cb_arg, SPDK_CLIENT_OPC_RPC_WRITE,
							true, &rc);
	if (req != NULL)
	{
		return client_qpair_submit_request(qpair, req);
	}
	else
	{
		return client_ns_map_failure_rc(lba_count,
										qpair->ctrlr->opts.sectors_per_max_io,
										qpair->ctrlr->opts.sectors_per_stripe,
										qpair->ctrlr->opts.io_queue_requests,
										rc);
	}
}

int spdk_client_rpc_request_read(struct spdk_client_qpair *qpair,
								 uint64_t lba, uint32_t lba_count, uint32_t rpc_request_id, uint32_t data_length,
								 uint32_t rpc_opc,
								 uint32_t submit_type,
								 spdk_req_cmd_cb cb_fn, void *cb_arg,
								 spdk_client_req_reset_sgl_cb reset_sgl_fn,
								 spdk_client_req_next_sge_cb next_sge_fn)
{
	struct client_request *req;
	struct client_payload payload;
	int rc = 0;

	if (reset_sgl_fn == NULL || next_sge_fn == NULL)
	{
		return -EINVAL;
	}

	payload = CLIENT_PAYLOAD_SGL(reset_sgl_fn, next_sge_fn, cb_arg, NULL, rpc_request_id, data_length, rpc_opc, submit_type, NULL);

	req = _client_ns_cmd_rw(qpair, &payload, 0, 0, lba, lba_count, cb_fn, cb_arg, SPDK_CLIENT_OPC_RPC_READ,
							true, &rc);
	if (req != NULL)
	{
		return client_qpair_submit_request(qpair, req);
	}
	else
	{
		return client_ns_map_failure_rc(lba_count,
										qpair->ctrlr->opts.sectors_per_max_io,
										qpair->ctrlr->opts.sectors_per_stripe,
										qpair->ctrlr->opts.io_queue_requests,
										rc);
	}
}

void rpc_read_cb(void *ctx, const struct spdk_req_cpl *cpl)
{
	struct spdk_md5ctx md5ctx;
	uint8_t md5sum[SPDK_MD5DIGEST_LEN];
	// TODO: check rpc status,  maybe use sqhd field
	int status = cpl->cdw0;
	struct rpc_request *req = (struct rpc_request *)ctx;
	int md5_batch_len = 0;
	int md5_total_len = req->in_length;
	if (req->check_md5)
	{
		md5init(&md5ctx);
		for (int i = 0; i < req->in_iovcnt; i++)
		{
			md5_batch_len = spdk_min(req->in_iovs[i].iov_len, md5_total_len);
			md5update(&md5ctx, req->in_iovs[i].iov_base, md5_batch_len);
			md5_total_len -= md5_batch_len;
			SPDK_DEBUGLOG(rdma, "checking md5sum iov_len:%d, md5_total_len:%d\n", req->in_iovs[i].iov_len, md5_total_len);
		}
		assert(md5_total_len == 0);
		md5final(md5sum, &md5ctx);
		for (int i = 0; i < SPDK_MD5DIGEST_LEN; i++)
		{
			assert(md5sum[i] == cpl->md5sum[i]);
			SPDK_DEBUGLOG(rdma, "check md5sum compare caled:%d, receved:%d\n", md5sum[i], cpl->md5sum[i]);
		}
		SPDK_DEBUGLOG(rdma, "check md5sum success\n");
	}

	req->cb(req->cb_args, status, req->in_iovs, req->in_iovcnt, req->in_length);
	rpc_reclaim_in_iovs(req);
	free(req->in_iovs);
	STAILQ_INSERT_TAIL(&req->qpair->free_rpc_req, req, stailq);

	return;
}

void rpc_write_cb(void *ctx, const struct spdk_req_cpl *cpl)
{
	int ret = 0;
	int lba_count = 0;
	uint32_t required_data_length = cpl->cdw1;
	int status = cpl->cdw0;
	struct rpc_request *req = (struct rpc_request *)ctx;
	if (required_data_length == 0)
	{
		req->cb(req->cb_args, status, NULL, 0, 0);
		return;
	}
	assert(required_data_length != 0);

	uint32_t sector_size = req->qpair->ctrlr->opts.sector_size;
	// free out_iovs now to save memory
	rpc_reclaim_out_iovs(req);
	free(req->out_iovs);

	req->in_length = required_data_length;
	if (rpc_prepare_in_iovs(req) == -EAGAIN)
	{
		SPDK_ERRLOG("rpc_write_cb get buffer failed %d\n", required_data_length);
		STAILQ_INSERT_TAIL(&req->qpair->ctrlr->pending_rpc_requests, req, stailq);
		return;
	}

	lba_count = SPDK_CEIL_DIV(req->in_payload_length, sector_size);
	ret = spdk_client_rpc_request_read(req->qpair, 0, lba_count, req->request_id, req->in_length, req->opc, req->submit_type, rpc_read_cb, req, rpc_request_reset_in_sgl, rpc_request_next_in_sge);
	if (ret != 0)
	{
		SPDK_ERRLOG("spdk_client_rpc_request_read failed %d\n", ret);
		// TODO: 关闭这个qpair
		assert(0);
	}
	return;
}
int spdk_client_submit_rpc_request(struct spdk_client_qpair *qpair, uint32_t opc, char *raw_data, uint32_t length,
								   spdk_rpc_request_cb cb_fn, void *cb_arg, bool chek_md5)
{
	struct rpc_request *req;
	struct spdk_md5ctx md5ctx;
	int lba_count = 0;
	req = STAILQ_FIRST(&qpair->free_rpc_req);
	if (req == NULL)
	{
		printf("no enough rpc req\n");
		return -EAGAIN;
	}
	STAILQ_REMOVE_HEAD(&qpair->free_rpc_req, stailq);
	memset(req, 0, offsetof(struct rpc_request, request_id));

	req->cb = cb_fn;
	req->cb_args = cb_arg;
	req->qpair = qpair;
	req->raw_data = raw_data;
	req->submit_type = SPDK_CLIENT_SUBMIT_CONTING;
	req->out_length = length;
	req->opc = opc;
	req->qpair = qpair;
	req->tsc_last = spdk_get_ticks();

	if (rpc_prepare_out_iovs(req) != 0)
	{
		STAILQ_INSERT_HEAD(&qpair->free_rpc_req, req, stailq);
		return 0;
	}

	if (chek_md5)
	{
		req->check_md5 = true;
		md5init(&md5ctx);
		md5update(&md5ctx, raw_data, length);
		md5final(req->md5sum, &md5ctx);
	}
	else
	{
		req->check_md5 = false;
	}

	uint32_t sector_size = req->qpair->ctrlr->opts.sector_size;
	lba_count = SPDK_CEIL_DIV(req->out_payload_length, sector_size);
	uint8_t *md5sum = NULL;
	if (req->check_md5)
	{
		md5sum = req->md5sum;
	}
	return spdk_client_rpc_request_write(req->qpair, 0, lba_count, req->request_id, req->out_length, req->opc, req->submit_type, md5sum, rpc_write_cb, req, rpc_request_reset_out_sgl, rpc_request_next_out_sge);
}

int spdk_client_empty_free_request(struct spdk_client_qpair *qpair) {
	return STAILQ_EMPTY(&qpair->free_rpc_req);
}

int spdk_client_submit_rpc_request_iovs_directly(struct spdk_client_qpair *qpair, struct iovec *out_ioves, int out_iov_cnt, uint32_t length, spdk_rpc_request_cb cb_fn, void *cb_arg)
{
	struct rpc_request *req;
	int lba_count = 0;
	req = STAILQ_FIRST(&qpair->free_rpc_req);
	if (req == NULL)
	{
		printf("no enough rpc req\n");
		return -EAGAIN;
	}

	STAILQ_REMOVE_HEAD(&qpair->free_rpc_req, stailq);
	memset(req, 0, offsetof(struct rpc_request, request_id));

	req->cb = cb_fn;
	req->cb_args = cb_arg;
	req->qpair = qpair;
	req->submit_type = SPDK_CLIENT_SUBMIT_IOVES;
	req->qpair = qpair;
	req->out_iovcnt = out_iov_cnt;
	req->out_iovs = out_ioves;
	req->out_payload_length = length;
	req->check_md5 = false;
	req->tsc_last = spdk_get_ticks();

	SPDK_DEBUGLOG(rdma, "req->out_payload_length=%d, iov_cnt=%d\n", req->out_payload_length, req->out_iovcnt);

	uint32_t sector_size = req->qpair->ctrlr->opts.sector_size;
	lba_count = SPDK_CEIL_DIV(req->out_payload_length, sector_size);

	return spdk_client_rpc_request_write(req->qpair, 0, lba_count, req->request_id, req->out_payload_length, req->opc, req->submit_type, NULL, rpc_write_cb, req, rpc_request_reset_out_sgl, rpc_request_next_out_sge);
}

int spdk_client_submit_rpc_request_iovs(struct spdk_client_qpair *qpair, uint32_t opc, struct iovec *raw_ioves, int raw_iov_cnt, uint32_t length,
										spdk_rpc_request_cb cb_fn, void *cb_arg, bool chek_md5)
{
	struct rpc_request *req;
	struct spdk_md5ctx md5ctx;
	int lba_count = 0;
	req = STAILQ_FIRST(&qpair->free_rpc_req);
	if (req == NULL)
	{
		printf("no enough rpc req\n");
		return -EAGAIN;
	}
	STAILQ_REMOVE_HEAD(&qpair->free_rpc_req, stailq);
	memset(req, 0, offsetof(struct rpc_request, request_id));

	req->cb = cb_fn;
	req->cb_args = cb_arg;
	req->qpair = qpair;
	req->raw_ioves = raw_ioves;
	req->raw_iov_cnt = raw_iov_cnt;
	req->submit_type = SPDK_CLIENT_SUBMIT_IOVES;
	req->out_length = length;
	req->opc = opc;
	req->qpair = qpair;
	req->tsc_last = spdk_get_ticks();

	if (rpc_prepare_out_iovs(req) != 0)
	{
		STAILQ_INSERT_HEAD(&qpair->free_rpc_req, req, stailq);
		return 0;
	}

	if (chek_md5)
	{
		req->check_md5 = true;
		md5init(&md5ctx);
		for (int i = 0; i < raw_iov_cnt; i++)
		{
			md5update(&md5ctx, raw_ioves[i].iov_base, raw_ioves[i].iov_len);
		}
		md5final(req->md5sum, &md5ctx);
	}
	else
	{
		req->check_md5 = false;
	}

	uint32_t sector_size = req->qpair->ctrlr->opts.sector_size;
	lba_count = SPDK_CEIL_DIV(req->out_payload_length, sector_size);
	uint8_t *md5sum = NULL;
	if (req->check_md5)
	{
		md5sum = req->md5sum;
	}
	return spdk_client_rpc_request_write(req->qpair, 0, lba_count, req->request_id, req->out_length, req->opc, req->submit_type, md5sum, rpc_write_cb, req, rpc_request_reset_out_sgl, rpc_request_next_out_sge);
}