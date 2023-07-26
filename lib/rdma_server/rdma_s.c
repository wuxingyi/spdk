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

#include "spdk/config.h"
#include "spdk/thread.h"
#include "spdk/likely.h"

#include "spdk/string.h"
#include "spdk/trace.h"
#include "spdk/util.h"

#include "spdk_internal/assert.h"
#include "spdk/log.h"
#include "spdk_internal/rdma.h"
#include "spdk_internal/rdma_server.h"
#include "spdk_internal/trace_defs.h"

const struct spdk_srv_transport_ops spdk_srv_transport_rdma;
void *g_rpc_dispatcher[SPDK_CLIENT_SUBMIT_TYPES_TOTAL] = {NULL, NULL};

/*
 RDMA Connection Resource Defaults
 */
#define SRV_DEFAULT_TX_SGE SPDK_SRV_MAX_SGL_ENTRIES
#define SRV_DEFAULT_RSP_SGE 1
#define SRV_DEFAULT_RX_SGE 2

/* The RDMA completion queue size */
#define DEFAULT_SRV_RDMA_CQ_SIZE 4096
#define MAX_WR_PER_QP(queue_depth) (queue_depth * 3 + 2)

#define MAX_RPC_REQ_QUEUE_DEPTH 4096

static int g_spdk_srv_ibv_query_mask =
	IBV_QP_STATE |
	IBV_QP_PKEY_INDEX |
	IBV_QP_PORT |
	IBV_QP_ACCESS_FLAGS |
	IBV_QP_AV |
	IBV_QP_PATH_MTU |
	IBV_QP_DEST_QPN |
	IBV_QP_RQ_PSN |
	IBV_QP_MAX_DEST_RD_ATOMIC |
	IBV_QP_MIN_RNR_TIMER |
	IBV_QP_SQ_PSN |
	IBV_QP_TIMEOUT |
	IBV_QP_RETRY_CNT |
	IBV_QP_RNR_RETRY |
	IBV_QP_MAX_QP_RD_ATOMIC;

enum spdk_srv_rdma_request_state
{
	/* The request is not currently in use */
	RDMA_REQUEST_STATE_FREE = 0,

	/* Initial state when request first received */
	RDMA_REQUEST_STATE_NEW,

	/* The request is queued until a data buffer is available. */
	RDMA_REQUEST_STATE_NEED_BUFFER,

	/* The request is waiting on RDMA queue depth availability
	 * to transfer data from the host to the controller.
	 */
	RDMA_REQUEST_STATE_DATA_TRANSFER_TO_CONTROLLER_PENDING,

	/* The request is currently transferring data from the host to the controller. */
	RDMA_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER,

	/* The request is ready to execute at the block device */
	RDMA_REQUEST_STATE_READY_TO_EXECUTE,

	/* The request is currently executing at the block device */
	RDMA_REQUEST_STATE_EXECUTING,

	/* The request finished executing at the block device */
	RDMA_REQUEST_STATE_EXECUTED,

	/* The request is waiting on RDMA queue depth availability
	 * to transfer data from the controller to the host.
	 */
	RDMA_REQUEST_STATE_DATA_TRANSFER_TO_HOST_PENDING,

	/* The request is ready to send a completion */
	RDMA_REQUEST_STATE_READY_TO_COMPLETE,

	/* The request is currently transferring data from the controller to the host. */
	RDMA_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST,

	/* The request currently has an outstanding completion without an
	 * associated data transfer.
	 */
	RDMA_REQUEST_STATE_COMPLETING,

	/* The request completed and can be marked free. */
	RDMA_REQUEST_STATE_COMPLETED,

	/* Terminator */
	RDMA_REQUEST_NUM_STATES,
};

enum spdk_srv_rdma_wr_type
{
	RDMA_WR_TYPE_RECV,
	RDMA_WR_TYPE_SEND,
	RDMA_WR_TYPE_DATA,
};

struct spdk_srv_rdma_wr
{
	enum spdk_srv_rdma_wr_type type;
};

/* This structure holds commands as they are received off the wire.
 * It must be dynamically paired with a full request object
 * (spdk_srv_rdma_request) to service a request. It is separate
 * from the request because RDMA does not appear to order
 * completions, so occasionally we'll get a new incoming
 * command when there aren't any free request objects.
 */
struct spdk_srv_rdma_recv
{
	struct ibv_recv_wr wr;
	struct ibv_sge sgl[SRV_DEFAULT_RX_SGE];

	struct spdk_srv_rdma_conn *conn;

	/* In-capsule data buffer */
	uint8_t *buf;

	struct spdk_srv_rdma_wr rdma_wr;
	uint64_t receive_tsc;

	STAILQ_ENTRY(spdk_srv_rdma_recv)
	link;
};

struct spdk_srv_rdma_request_data
{
	struct spdk_srv_rdma_wr rdma_wr;
	struct ibv_send_wr wr;
	struct ibv_sge sgl[SPDK_SRV_MAX_SGL_ENTRIES];
};

struct spdk_srv_rdma_request
{
	struct spdk_srv_request req;

	enum spdk_srv_rdma_request_state state;

	/* Data offset in req.iov */
	uint32_t offset;

	struct spdk_srv_rdma_recv *recv;

	struct
	{
		struct spdk_srv_rdma_wr rdma_wr;
		struct ibv_send_wr wr;
		struct ibv_sge sgl[SRV_DEFAULT_RSP_SGE];
	} rsp;

	struct spdk_srv_rdma_request_data data;

	uint32_t iovpos;

	uint32_t num_outstanding_data_wr;
	uint64_t receive_tsc;

	STAILQ_ENTRY(spdk_srv_rdma_request)
	state_link;
};

struct spdk_srv_rdma_resource_opts
{
	struct spdk_srv_rdma_conn *conn;
	/* qp points either to an ibv_qp object or an ibv_srq object depending on the value of shared. */
	void *qp;
	struct ibv_pd *pd;
	uint32_t max_queue_depth;
	uint32_t in_capsule_data_size;
	bool shared;
};

struct spdk_srv_rpc_request;

struct spdk_srv_rdma_resources
{
	/* Array of size "max_queue_depth" containing RDMA requests. */
	struct spdk_srv_rdma_request *reqs;

	/* Array of size "max_queue_depth" containing RDMA recvs. */
	struct spdk_srv_rdma_recv *recvs;

	/* Array of size "max_queue_depth" containing 64 byte capsules
	 * used for receive.
	 */
	struct spdk_req_cmd *cmds;
	struct ibv_mr *cmds_mr;

	/* Array of size "max_queue_depth" containing 16 byte completions
	 * to be sent back to the user.
	 */
	struct spdk_req_cpl *cpls;
	struct ibv_mr *cpls_mr;

	/* Array of size "max_queue_depth * InCapsuleDataSize" containing
	 * buffers to be used for in capsule data.
	 */
	void *bufs;
	struct ibv_mr *bufs_mr;

	/* Receives that are waiting for a request object */
	STAILQ_HEAD(, spdk_srv_rdma_recv)
	incoming_queue;

	/* Queue to track free requests */
	STAILQ_HEAD(, spdk_srv_rdma_request)
	free_queue;

	struct spdk_srv_rpc_request *rpc_reqs;
	/* Queue to track inflight requests */
	STAILQ_HEAD(, spdk_srv_rpc_request)
	inflight_rpc_queue;
};

typedef void (*spdk_srv_rdma_conn_ibv_event)(struct spdk_srv_rdma_conn *rconn);

struct spdk_srv_rdma_ibv_event_ctx
{
	struct spdk_srv_rdma_conn *rconn;
	spdk_srv_rdma_conn_ibv_event cb_fn;
	/* Link to other ibv events associated with this conn */
	STAILQ_ENTRY(spdk_srv_rdma_ibv_event_ctx)
	link;
};

struct spdk_srv_rdma_conn
{
	struct spdk_srv_conn conn;

	struct spdk_srv_rdma_device *device;
	struct spdk_srv_rdma_poller *poller;

	struct spdk_rdma_qp *rdma_qp;
	struct rdma_cm_id *cm_id;
	struct spdk_rdma_srq *srq;
	struct rdma_cm_id *listen_id;

	/* The maximum number of I/O outstanding on this connection at one time */
	uint16_t max_queue_depth;

	/* The maximum number of active RDMA READ and ATOMIC operations at one time */
	uint16_t max_read_depth;

	/* The maximum number of RDMA SEND operations at one time */
	uint32_t max_send_depth;

	/* The current number of outstanding WRs from this conn's
	 * recv queue. Should not exceed device->attr.max_queue_depth.
	 */
	uint16_t current_recv_depth;

	/* The current number of active RDMA READ operations */
	uint16_t current_read_depth;

	/* The current number of posted WRs from this conn's
	 * send queue. Should not exceed max_send_depth.
	 */
	uint32_t current_send_depth;

	/* The maximum number of SGEs per WR on the send queue */
	uint32_t max_send_sge;

	/* The maximum number of SGEs per WR on the recv queue */
	uint32_t max_recv_sge;

	struct spdk_srv_rdma_resources *resources;

	STAILQ_HEAD(, spdk_srv_rdma_request)
	pending_rdma_read_queue;

	STAILQ_HEAD(, spdk_srv_rdma_request)
	pending_rdma_write_queue;

	// rpc 请求完成后,将对应的rdma_request,放在这个队列里面等待执行
	STAILQ_HEAD(, spdk_srv_rdma_request)
	pending_complete_queue;

	/* Number of requests not in the free state */
	uint32_t qd;

	TAILQ_ENTRY(spdk_srv_rdma_conn)
	link;

	STAILQ_ENTRY(spdk_srv_rdma_conn)
	recv_link;

	STAILQ_ENTRY(spdk_srv_rdma_conn)
	send_link;

	/* IBV queue pair attributes: they are used to manage
	 * qp state and recover from errors.
	 */
	enum ibv_qp_state ibv_state;

	/*
	 * io_channel which is used to destroy conn when it is removed from poll group
	 */
	struct spdk_io_channel *destruct_channel;

	/* List of ibv async events */
	STAILQ_HEAD(, spdk_srv_rdma_ibv_event_ctx)
	ibv_events;

	/* Lets us know that we have received the last_wqe event. */
	bool last_wqe_reached;

	/* Indicate that srv_rdma_close_conn is called */
	bool to_close;
};

enum rpc_request_state
{
	FREE,
	WAIT_OTHER_SUBREQUEST,
	PROCESS_DATA,
	PENDING_READ,
	READ_COMPLETE,
	FINISH,
};

struct spdk_srv_rpc_request
{
	uint32_t rpc_opc;
	uint32_t submit_type;
	// 用于接收全部的rpc请求数据
	struct iovec *in_iovs;
	uint32_t in_iov_cnt_total;
	uint32_t in_iov_cnt_left;
	uint32_t in_real_length;
	uint32_t iov_offset;

	void *out_data;

	// submit = 1时使用out_ioves和out_iov_cnt
	struct iovec *out_iovs;
	int out_iov_cnt;

	uint32_t out_status;
	uint32_t out_real_length;

	uint32_t out_rdma_send_left;

	// 通知服务端 RPC请求响应发送完毕的回调
	spdk_srv_rpc_service_complete_cb service_cb;
	void *service_cb_arg;
	STAILQ_ENTRY(spdk_srv_rpc_request)
	stq_link;
	enum rpc_request_state state;

	bool check_md5;						// true 表示response需要计算MD5
	uint8_t md5sum[SPDK_MD5DIGEST_LEN]; // 用于存储response的MD5

	struct spdk_srv_rdma_conn *rconn;
	STAILQ_HEAD(, spdk_srv_rdma_request)
	wait_rpc_handle_queue;
	uint32_t rpc_index;
};

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

// TODO:完成RPC 回调注册
void spdk_srv_rpc_register_dispatcher(void *dispatcher, int submit_type)
{
	if (g_rpc_dispatcher[submit_type] == NULL)
	{
		g_rpc_dispatcher[submit_type] = dispatcher;
		SPDK_INFOLOG(rdma, "rpc dispatcher successfull registered\n");
	}
	else
	{
		SPDK_ERRLOG("rpc dispatcher already registered\n");
	}
}

void spdk_srv_rpc_request_handle_complete_cb(void *cb_arg, int status, char *rsp_data, int len, spdk_srv_rpc_service_complete_cb service_cb, void *service_cb_arg)
{
	int ret = 0;
	struct spdk_srv_rdma_request *rdma_req, *temp_rdma_req;
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_req_cpl *rsp;
	struct spdk_md5ctx md5ctx;

	/* If the number of buffers is too large, then we know the I/O is larger than allowed.
	 *  Fail it.
	 */

	struct spdk_srv_rpc_request *req = cb_arg;
	SPDK_DEBUGLOG(rdma, "spdk_srv_rpc_request_handle_complete_cb req addr:%p, index:%d, state:%d\n", (uintptr_t)req, req->rpc_index, req->state);
	rconn = req->rconn;
	if (req->rconn == NULL)
	{
		SPDK_ERRLOG("Fatal error req addr:%p, index:%d, state:%d\n", (uintptr_t)req, req->rpc_index, req->state);
	}
	uint32_t max_io_size = req->rconn->conn.transport->opts.max_io_size;

	// 提前计算好client要切分的子请求个数，也就是要响应的次数
	req->out_rdma_send_left = SPDK_CEIL_DIV(len, max_io_size);
	req->out_real_length = len;
	req->out_data = rsp_data;
	req->out_status = status;
	req->service_cb = service_cb;
	req->service_cb_arg = service_cb_arg;

	SPDK_DEBUGLOG(rdma, "spdk_srv_rpc_request_handle_complete_cb %d %p %p %p\n", len, rsp_data, service_cb, service_cb_arg);

	if (req->check_md5)
	{
		md5init(&md5ctx);
		md5update(&md5ctx, rsp_data, len);
		md5final(req->md5sum, &md5ctx);
	}

	// TODO: 把链表上rdma request放到pending_complete_queue上
	rdma_req = STAILQ_FIRST(&req->wait_rpc_handle_queue);
	assert(rdma_req->recv != NULL);
	SPDK_DEBUGLOG(rdma, "spdk_srv_rpc_request_handle_complete_cb rconn=%p\n", rconn);
	SPDK_DEBUGLOG(rdma, "spdk_srv_rpc_request_handle_complete_cb queue_head=%p\n", &rconn->pending_complete_queue);
	while (rdma_req)
	{
		SPDK_DEBUGLOG(rdma, "000 rdma_req=%p\n", rdma_req);
		// 提前处理rsp的一些字段
		rsp = rdma_req->req.rsp;
		rsp->sqid = 0;
		rsp->status.p = 0;
		rsp->cdw0 = status; // 这个其实没什么用，因为在rpc_read的时候,会把这个status再带回去
		rsp->cid = rdma_req->req.cmd->cid;
		rsp->cdw1 = req->out_real_length;
		temp_rdma_req = STAILQ_NEXT(rdma_req, state_link);
		STAILQ_REMOVE_HEAD(&req->wait_rpc_handle_queue, state_link);
		SPDK_DEBUGLOG(rdma, "111 rdma_req=%p stqe_next=%p temp_rdma_req=%p out_real_length=%d\n", rdma_req, rdma_req->state_link.stqe_next, temp_rdma_req, req->out_real_length);
		STAILQ_INSERT_TAIL(&rconn->pending_complete_queue, rdma_req, state_link);
		assert(rdma_req->recv != NULL);
		rdma_req = temp_rdma_req;
	}

	req->state = PENDING_READ;
	SPDK_DEBUGLOG(rdma, "spdk_srv_rpc_request_handle_complete_cb finish\n");
}

void spdk_srv_rpc_request_handle_complete_iovs_cb(void *cb_arg, int status, struct iovec *iovs, int iov_cnt, int len, spdk_srv_rpc_service_complete_cb service_cb, void *service_cb_arg)
{
	int ret = 0;
	struct spdk_srv_rdma_request *rdma_req, *temp_rdma_req;
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_req_cpl *rsp;
	struct spdk_md5ctx md5ctx;

	/* If the number of buffers is too large, then we know the I/O is larger than allowed.
	 *  Fail it.
	 */

	struct spdk_srv_rpc_request *req = cb_arg;
	SPDK_DEBUGLOG(rdma, "spdk_srv_rpc_request_handle_complete_iovs_cb req addr:%p, index:%d, state:%d\n", (uintptr_t)req, req->rpc_index, req->state);
	rconn = req->rconn;
	if (req->rconn == NULL)
	{
		SPDK_ERRLOG("Fatal error req addr:%p, index:%d, state:%d\n", (uintptr_t)req, req->rpc_index, req->state);
	}
	uint32_t max_io_size = req->rconn->conn.transport->opts.max_io_size;

	// 提前计算好client要切分的子请求个数，也就是要响应的次数

	assert(req->submit_type == SPDK_CLIENT_SUBMIT_IOVES);
	req->out_rdma_send_left = SPDK_CEIL_DIV(len, max_io_size);
	req->out_real_length = len;
	req->out_iovs = iovs;
	req->out_iov_cnt = iov_cnt;
	req->out_status = status;
	req->service_cb = service_cb;
	req->service_cb_arg = service_cb_arg;

	SPDK_DEBUGLOG(rdma, "spdk_srv_rpc_request_handle_complete_iovs_cb %d %p %p\n", len, service_cb, service_cb_arg);

	if (req->check_md5)
	{
		md5init(&md5ctx);
		for (int i = 0; i < iov_cnt; i++)
		{
			md5update(&md5ctx, iovs[i].iov_base, iovs[i].iov_len);
		}
		md5final(req->md5sum, &md5ctx);
	}

	// TODO: 把链表上rdma request放到pending_complete_queue上
	rdma_req = STAILQ_FIRST(&req->wait_rpc_handle_queue);
	assert(rdma_req->recv != NULL);
	SPDK_DEBUGLOG(rdma, "spdk_srv_rpc_request_handle_complete_iovs_cb rconn=%p\n", rconn);
	SPDK_DEBUGLOG(rdma, "spdk_srv_rpc_request_handle_complete_iovs_cb queue_head=%p\n", &rconn->pending_complete_queue);
	while (rdma_req)
	{
		SPDK_DEBUGLOG(rdma, "000 rdma_req=%p\n", rdma_req);
		// 提前处理rsp的一些字段
		rsp = rdma_req->req.rsp;
		rsp->sqid = 0;
		rsp->status.p = 0;
		rsp->cdw0 = status; // 这个其实没什么用，因为在rpc_read的时候,会把这个status再带回去
		rsp->cid = rdma_req->req.cmd->cid;
		rsp->cdw1 = req->out_real_length;
		temp_rdma_req = STAILQ_NEXT(rdma_req, state_link);
		STAILQ_REMOVE_HEAD(&req->wait_rpc_handle_queue, state_link);
		SPDK_DEBUGLOG(rdma, "111 rdma_req=%p stqe_next=%p temp_rdma_req=%p out_real_length=%d\n", rdma_req, rdma_req->state_link.stqe_next, temp_rdma_req, req->out_real_length);
		STAILQ_INSERT_TAIL(&rconn->pending_complete_queue, rdma_req, state_link);
		assert(rdma_req->recv != NULL);
		rdma_req = temp_rdma_req;
	}
	req->state = PENDING_READ;
	SPDK_DEBUGLOG(rdma, "spdk_srv_rpc_request_handle_complete_cb finish\n");
}

struct spdk_srv_rdma_poller_stat
{
	uint64_t completions;
	uint64_t polls;
	uint64_t idle_polls;
	uint64_t requests;
	uint64_t request_latency;
	uint64_t pending_free_request;
	uint64_t pending_rdma_read;
	uint64_t pending_rdma_write;
	struct spdk_rdma_qp_stats qp_stats;
};

struct spdk_srv_rdma_poller
{
	struct spdk_srv_rdma_device *device;
	struct spdk_srv_rdma_poll_group *group;

	int num_cqe;
	int required_num_wr;
	struct ibv_cq *cq;

	/* The maximum number of I/O outstanding on the shared receive queue at one time */
	uint16_t max_srq_depth;

	/* Shared receive queue */
	struct spdk_rdma_srq *srq;

	struct spdk_srv_rdma_resources *resources;
	struct spdk_srv_rdma_poller_stat stat;

	TAILQ_HEAD(, spdk_srv_rdma_conn)
	conns;

	STAILQ_HEAD(, spdk_srv_rdma_conn)
	conns_pending_recv;

	STAILQ_HEAD(, spdk_srv_rdma_conn)
	conns_pending_send;

	TAILQ_ENTRY(spdk_srv_rdma_poller)
	link;
};

struct spdk_srv_rdma_poll_group_stat
{
	uint64_t pending_data_buffer;
};

struct spdk_srv_rdma_poll_group
{
	struct spdk_srv_transport_poll_group group;
	struct spdk_srv_rdma_poll_group_stat stat;
	TAILQ_HEAD(, spdk_srv_rdma_poller)
	pollers;
	TAILQ_ENTRY(spdk_srv_rdma_poll_group)
	link;
};

struct spdk_srv_rdma_conn_sched
{
	struct spdk_srv_rdma_poll_group *next_io_pg;
};

/* Assuming rdma_cm uses just one protection domain per ibv_context. */
struct spdk_srv_rdma_device
{
	struct ibv_device_attr attr;
	struct ibv_context *context;

	struct spdk_rdma_mem_map *map;
	struct ibv_pd *pd;

	int num_srq;

	TAILQ_ENTRY(spdk_srv_rdma_device)
	link;
};

struct spdk_srv_rdma_port
{
	const struct spdk_srv_transport_id *trid;
	struct rdma_cm_id *id;
	struct spdk_srv_rdma_device *device;
	TAILQ_ENTRY(spdk_srv_rdma_port)
	link;
};

struct rdma_transport_opts
{
	int num_cqe;
	uint32_t max_srq_depth;
	bool no_srq;
	bool no_wr_batching;
	int acceptor_backlog;
};

struct spdk_srv_rdma_transport
{
	struct spdk_srv_transport transport;
	struct rdma_transport_opts rdma_opts;

	struct spdk_srv_rdma_conn_sched conn_sched;

	struct rdma_event_channel *event_channel;

	struct spdk_mempool *data_wr_pool;

	struct spdk_poller *accept_poller;
	pthread_mutex_t lock;

	/* fields used to poll RDMA/IB events */
	nfds_t npoll_fds;
	struct pollfd *poll_fds;

	TAILQ_HEAD(, spdk_srv_rdma_device)
	devices;
	TAILQ_HEAD(, spdk_srv_rdma_port)
	ports;
	TAILQ_HEAD(, spdk_srv_rdma_poll_group)
	poll_groups;
};

static const struct spdk_json_object_decoder rdma_transport_opts_decoder[] = {
	{"num_cqe", offsetof(struct rdma_transport_opts, num_cqe),
	 spdk_json_decode_int32, true},
	{"max_srq_depth", offsetof(struct rdma_transport_opts, max_srq_depth),
	 spdk_json_decode_uint32, true},
	{"no_srq", offsetof(struct rdma_transport_opts, no_srq),
	 spdk_json_decode_bool, true},
	{"no_wr_batching", offsetof(struct rdma_transport_opts, no_wr_batching),
	 spdk_json_decode_bool, true},
	{"acceptor_backlog", offsetof(struct rdma_transport_opts, acceptor_backlog),
	 spdk_json_decode_int32, true},
};

static bool
srv_rdma_request_process(struct spdk_srv_rdma_transport *rtransport,
						 struct spdk_srv_rdma_request *rdma_req);

static void
_poller_submit_sends(struct spdk_srv_rdma_transport *rtransport,
					 struct spdk_srv_rdma_poller *rpoller);

static void
_poller_submit_recvs(struct spdk_srv_rdma_transport *rtransport,
					 struct spdk_srv_rdma_poller *rpoller);

static inline int
srv_rdma_check_ibv_state(enum ibv_qp_state state)
{
	switch (state)
	{
	case IBV_QPS_RESET:
	case IBV_QPS_INIT:
	case IBV_QPS_RTR:
	case IBV_QPS_RTS:
	case IBV_QPS_SQD:
	case IBV_QPS_SQE:
	case IBV_QPS_ERR:
		return 0;
	default:
		return -1;
	}
}

static enum ibv_qp_state
srv_rdma_update_ibv_state(struct spdk_srv_rdma_conn *rconn)
{
	enum ibv_qp_state old_state, new_state;
	struct ibv_qp_attr qp_attr;
	struct ibv_qp_init_attr init_attr;
	int rc;

	old_state = rconn->ibv_state;
	rc = ibv_query_qp(rconn->rdma_qp->qp, &qp_attr,
					  g_spdk_srv_ibv_query_mask, &init_attr);

	if (rc)
	{
		SPDK_ERRLOG("Failed to get updated RDMA queue pair state!\n");
		return IBV_QPS_ERR + 1;
	}

	new_state = qp_attr.qp_state;
	rconn->ibv_state = new_state;
	qp_attr.ah_attr.port_num = qp_attr.port_num;

	rc = srv_rdma_check_ibv_state(new_state);
	if (rc)
	{
		SPDK_ERRLOG("QP#%d: bad state updated: %u, maybe hardware issue\n", rconn->conn.qid, new_state);
		/*
		 * IBV_QPS_UNKNOWN undefined if lib version smaller than libibverbs-1.1.8
		 * IBV_QPS_UNKNOWN is the enum element after IBV_QPS_ERR
		 */
		return IBV_QPS_ERR + 1;
	}

	if (old_state != new_state)
	{
		spdk_trace_record(TRACE_RDMA_QP_STATE_CHANGE, 0, 0, (uintptr_t)rconn, new_state);
	}
	return new_state;
}

static void
srv_rdma_request_free_data(struct spdk_srv_rdma_request *rdma_req,
						   struct spdk_srv_rdma_transport *rtransport)
{
	struct spdk_srv_rdma_request_data *data_wr;
	struct ibv_send_wr *next_send_wr;
	uint64_t req_wrid;

	rdma_req->num_outstanding_data_wr = 0;
	data_wr = &rdma_req->data;
	req_wrid = data_wr->wr.wr_id;
	while (data_wr && data_wr->wr.wr_id == req_wrid)
	{
		memset(data_wr->sgl, 0, sizeof(data_wr->wr.sg_list[0]) * data_wr->wr.num_sge);
		data_wr->wr.num_sge = 0;
		next_send_wr = data_wr->wr.next;
		if (data_wr != &rdma_req->data)
		{
			spdk_mempool_put(rtransport->data_wr_pool, data_wr);
		}
		data_wr = (!next_send_wr || next_send_wr == &rdma_req->rsp.wr) ? NULL : SPDK_CONTAINEROF(next_send_wr, struct spdk_srv_rdma_request_data, wr);
	}
}

static void
srv_rdma_dump_request(struct spdk_srv_rdma_request *req)
{
	SPDK_ERRLOG("\t\tRequest Data From Pool: %d\n", req->req.data_from_pool);
	if (req->req.cmd)
	{
		SPDK_ERRLOG("\t\tRequest opcode: %d\n", req->req.cmd->opc);
	}
	if (req->recv)
	{
		SPDK_ERRLOG("\t\tRequest recv wr_id%lu\n", req->recv->wr.wr_id);
	}
}

static void
srv_rdma_dump_conn_contents(struct spdk_srv_rdma_conn *rconn)
{
	int i;

	SPDK_ERRLOG("Dumping contents of queue pair (QID %d)\n", rconn->conn.qid);
	for (i = 0; i < rconn->max_queue_depth; i++)
	{
		if (rconn->resources->reqs[i].state != RDMA_REQUEST_STATE_FREE)
		{
			srv_rdma_dump_request(&rconn->resources->reqs[i]);
		}
	}
}

static void
srv_rdma_resources_destroy(struct spdk_srv_rdma_resources *resources)
{
	if (resources->cmds_mr)
	{
		ibv_dereg_mr(resources->cmds_mr);
	}

	if (resources->cpls_mr)
	{
		ibv_dereg_mr(resources->cpls_mr);
	}

	if (resources->bufs_mr)
	{
		ibv_dereg_mr(resources->bufs_mr);
	}

	spdk_free(resources->cmds);
	spdk_free(resources->cpls);
	spdk_free(resources->bufs);
	free(resources->rpc_reqs);
	free(resources->reqs);
	free(resources->recvs);
	free(resources);
}

static struct spdk_srv_rdma_resources *
srv_rdma_resources_create(struct spdk_srv_rdma_resource_opts *opts)
{
	struct spdk_srv_rdma_resources *resources;
	struct spdk_srv_rdma_request *rdma_req;
	struct spdk_srv_rdma_recv *rdma_recv;
	struct spdk_rdma_qp *qp = NULL;
	struct spdk_rdma_srq *srq = NULL;
	struct ibv_recv_wr *bad_wr = NULL;
	struct spdk_srv_rpc_request *rpc_req;
	uint32_t i;
	int rc = 0;

	resources = calloc(1, sizeof(struct spdk_srv_rdma_resources));
	if (!resources)
	{
		SPDK_ERRLOG("Unable to allocate resources for receive queue.\n");
		return NULL;
	}

	resources->reqs = calloc(opts->max_queue_depth, sizeof(*resources->reqs));
	resources->recvs = calloc(opts->max_queue_depth, sizeof(*resources->recvs));
	resources->cmds = spdk_zmalloc(opts->max_queue_depth * sizeof(*resources->cmds),
								   0x1000, NULL, SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);
	resources->cpls = spdk_zmalloc(opts->max_queue_depth * sizeof(*resources->cpls),
								   0x1000, NULL, SPDK_ENV_LCORE_ID_ANY, SPDK_MALLOC_DMA);

	resources->rpc_reqs = calloc(MAX_RPC_REQ_QUEUE_DEPTH, sizeof(*resources->rpc_reqs));

	if (opts->in_capsule_data_size > 0)
	{
		resources->bufs = spdk_zmalloc(opts->max_queue_depth * opts->in_capsule_data_size,
									   0x1000, NULL, SPDK_ENV_LCORE_ID_ANY,
									   SPDK_MALLOC_DMA);
	}

	if (!resources->reqs || !resources->recvs || !resources->cmds ||
		!resources->cpls || (opts->in_capsule_data_size && !resources->bufs))
	{
		SPDK_ERRLOG("Unable to allocate sufficient memory for RDMA queue.\n");
		goto cleanup;
	}

	resources->cmds_mr = ibv_reg_mr(opts->pd, resources->cmds,
									opts->max_queue_depth * sizeof(*resources->cmds),
									IBV_ACCESS_LOCAL_WRITE);
	resources->cpls_mr = ibv_reg_mr(opts->pd, resources->cpls,
									opts->max_queue_depth * sizeof(*resources->cpls),
									0);

	if (opts->in_capsule_data_size)
	{
		resources->bufs_mr = ibv_reg_mr(opts->pd, resources->bufs,
										opts->max_queue_depth *
											opts->in_capsule_data_size,
										IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
	}

	if (!resources->cmds_mr || !resources->cpls_mr ||
		(opts->in_capsule_data_size &&
		 !resources->bufs_mr))
	{
		goto cleanup;
	}
	SPDK_DEBUGLOG(rdma, "Command Array: %p Length: %lx LKey: %x\n",
				  resources->cmds, opts->max_queue_depth * sizeof(*resources->cmds),
				  resources->cmds_mr->lkey);
	SPDK_DEBUGLOG(rdma, "Completion Array: %p Length: %lx LKey: %x\n",
				  resources->cpls, opts->max_queue_depth * sizeof(*resources->cpls),
				  resources->cpls_mr->lkey);
	if (resources->bufs && resources->bufs_mr)
	{
		SPDK_DEBUGLOG(rdma, "In Capsule Data Array: %p Length: %x LKey: %x\n",
					  resources->bufs, opts->max_queue_depth * opts->in_capsule_data_size, resources->bufs_mr->lkey);
	}

	/* Initialize queues */
	STAILQ_INIT(&resources->incoming_queue);
	STAILQ_INIT(&resources->free_queue);

	if (opts->shared)
	{
		srq = (struct spdk_rdma_srq *)opts->qp;
	}
	else
	{
		qp = (struct spdk_rdma_qp *)opts->qp;
	}

	for (i = 0; i < opts->max_queue_depth; i++)
	{
		rdma_recv = &resources->recvs[i];
		rdma_recv->conn = opts->conn;

		/* Set up memory to receive commands */
		if (resources->bufs)
		{
			rdma_recv->buf = (void *)((uintptr_t)resources->bufs + (i *
																	opts->in_capsule_data_size));
		}

		rdma_recv->rdma_wr.type = RDMA_WR_TYPE_RECV;

		rdma_recv->sgl[0].addr = (uintptr_t)&resources->cmds[i];
		rdma_recv->sgl[0].length = sizeof(resources->cmds[i]);
		rdma_recv->sgl[0].lkey = resources->cmds_mr->lkey;
		rdma_recv->wr.num_sge = 1;

		if (rdma_recv->buf && resources->bufs_mr)
		{
			rdma_recv->sgl[1].addr = (uintptr_t)rdma_recv->buf;
			rdma_recv->sgl[1].length = opts->in_capsule_data_size;
			rdma_recv->sgl[1].lkey = resources->bufs_mr->lkey;
			rdma_recv->wr.num_sge++;
		}

		rdma_recv->wr.wr_id = (uintptr_t)&rdma_recv->rdma_wr;
		rdma_recv->wr.sg_list = rdma_recv->sgl;
		if (srq)
		{
			spdk_rdma_srq_queue_recv_wrs(srq, &rdma_recv->wr);
		}
		else
		{
			spdk_rdma_qp_queue_recv_wrs(qp, &rdma_recv->wr);
		}
	}

	for (i = 0; i < opts->max_queue_depth; i++)
	{
		rdma_req = &resources->reqs[i];

		if (opts->conn != NULL)
		{
			rdma_req->req.conn = &opts->conn->conn;
		}
		else
		{
			rdma_req->req.conn = NULL;
		}
		rdma_req->req.cmd = NULL;

		/* Set up memory to send responses */
		rdma_req->req.rsp = &resources->cpls[i];

		rdma_req->rsp.sgl[0].addr = (uintptr_t)&resources->cpls[i];
		rdma_req->rsp.sgl[0].length = sizeof(resources->cpls[i]);
		rdma_req->rsp.sgl[0].lkey = resources->cpls_mr->lkey;

		rdma_req->rsp.rdma_wr.type = RDMA_WR_TYPE_SEND;
		rdma_req->rsp.wr.wr_id = (uintptr_t)&rdma_req->rsp.rdma_wr;
		rdma_req->rsp.wr.next = NULL;
		rdma_req->rsp.wr.opcode = IBV_WR_SEND;
		rdma_req->rsp.wr.send_flags = IBV_SEND_SIGNALED;
		rdma_req->rsp.wr.sg_list = rdma_req->rsp.sgl;
		rdma_req->rsp.wr.num_sge = SPDK_COUNTOF(rdma_req->rsp.sgl);

		/* Set up memory for data buffers */
		rdma_req->data.rdma_wr.type = RDMA_WR_TYPE_DATA;
		rdma_req->data.wr.wr_id = (uintptr_t)&rdma_req->data.rdma_wr;
		rdma_req->data.wr.next = NULL;
		rdma_req->data.wr.send_flags = IBV_SEND_SIGNALED;
		rdma_req->data.wr.sg_list = rdma_req->data.sgl;
		rdma_req->data.wr.num_sge = SPDK_COUNTOF(rdma_req->data.sgl);

		/* Initialize request state to FREE */
		rdma_req->state = RDMA_REQUEST_STATE_FREE;
		STAILQ_INSERT_TAIL(&resources->free_queue, rdma_req, state_link);
	}

	for (i = 0; i < MAX_RPC_REQ_QUEUE_DEPTH; i++)
	{
		rpc_req = &resources->rpc_reqs[i];
		memset(rpc_req, 0, sizeof(*rpc_req));
		rpc_req->state = FREE;
		STAILQ_INIT(&rpc_req->wait_rpc_handle_queue);
	}

	if (srq)
	{
		rc = spdk_rdma_srq_flush_recv_wrs(srq, &bad_wr);
	}
	else
	{
		rc = spdk_rdma_qp_flush_recv_wrs(qp, &bad_wr);
	}

	if (rc)
	{
		goto cleanup;
	}

	return resources;

cleanup:
	srv_rdma_resources_destroy(resources);
	return NULL;
}

static void
srv_rdma_conn_clean_ibv_events(struct spdk_srv_rdma_conn *rconn)
{
	struct spdk_srv_rdma_ibv_event_ctx *ctx, *tctx;
	STAILQ_FOREACH_SAFE(ctx, &rconn->ibv_events, link, tctx)
	{
		ctx->rconn = NULL;
		/* Memory allocated for ctx is freed in srv_rdma_conn_process_ibv_event */
		STAILQ_REMOVE(&rconn->ibv_events, ctx, spdk_srv_rdma_ibv_event_ctx, link);
	}
}

static void
srv_rdma_conn_destroy(struct spdk_srv_rdma_conn *rconn)
{
	struct spdk_srv_rdma_recv *rdma_recv, *recv_tmp;
	struct ibv_recv_wr *bad_recv_wr = NULL;
	int rc;

	spdk_trace_record(TRACE_RDMA_QP_DESTROY, 0, 0, (uintptr_t)rconn);

	if (rconn->qd != 0)
	{
		struct spdk_srv_conn *conn = &rconn->conn;
		struct spdk_srv_rdma_transport *rtransport = SPDK_CONTAINEROF(conn->transport,
																	  struct spdk_srv_rdma_transport, transport);
		struct spdk_srv_rdma_request *req;
		uint32_t i, max_req_count = 0;

		SPDK_WARNLOG("Destroying conn when queue depth is %d\n", rconn->qd);

		if (rconn->srq == NULL)
		{
			srv_rdma_dump_conn_contents(rconn);
			max_req_count = rconn->max_queue_depth;
		}
		else if (rconn->poller && rconn->resources)
		{
			max_req_count = rconn->poller->max_srq_depth;
		}

		SPDK_DEBUGLOG(rdma, "Release incomplete requests\n");
		for (i = 0; i < max_req_count; i++)
		{
			req = &rconn->resources->reqs[i];
			if (req->req.conn == conn && req->state != RDMA_REQUEST_STATE_FREE)
			{
				/* srv_rdma_request_process checks conn ibv and internal state
				 * and completes a request */
				srv_rdma_request_process(rtransport, req);
			}
		}
		assert(rconn->qd == 0);
	}

	if (rconn->poller)
	{
		TAILQ_REMOVE(&rconn->poller->conns, rconn, link);

		if (rconn->srq != NULL && rconn->resources != NULL)
		{
			/* Drop all received but unprocessed commands for this queue and return them to SRQ */
			STAILQ_FOREACH_SAFE(rdma_recv, &rconn->resources->incoming_queue, link, recv_tmp)
			{
				if (rconn == rdma_recv->conn)
				{
					STAILQ_REMOVE(&rconn->resources->incoming_queue, rdma_recv, spdk_srv_rdma_recv, link);
					spdk_rdma_srq_queue_recv_wrs(rconn->srq, &rdma_recv->wr);
					rc = spdk_rdma_srq_flush_recv_wrs(rconn->srq, &bad_recv_wr);
					if (rc)
					{
						SPDK_ERRLOG("Unable to re-post rx descriptor\n");
					}
				}
			}
		}
	}

	if (rconn->cm_id)
	{
		if (rconn->rdma_qp != NULL)
		{
			spdk_rdma_qp_destroy(rconn->rdma_qp);
			rconn->rdma_qp = NULL;
		}
		rdma_destroy_id(rconn->cm_id);

		if (rconn->poller != NULL && rconn->srq == NULL)
		{
			rconn->poller->required_num_wr -= MAX_WR_PER_QP(rconn->max_queue_depth);
		}
	}

	if (rconn->srq == NULL && rconn->resources != NULL)
	{
		srv_rdma_resources_destroy(rconn->resources);
	}

	srv_rdma_conn_clean_ibv_events(rconn);

	if (rconn->destruct_channel)
	{
		spdk_put_io_channel(rconn->destruct_channel);
		rconn->destruct_channel = NULL;
	}

	free(rconn);
}

static int
srv_rdma_resize_cq(struct spdk_srv_rdma_conn *rconn, struct spdk_srv_rdma_device *device)
{
	struct spdk_srv_rdma_poller *rpoller;
	int rc, num_cqe, required_num_wr;

	/* Enlarge CQ size dynamically */
	rpoller = rconn->poller;
	required_num_wr = rpoller->required_num_wr + MAX_WR_PER_QP(rconn->max_queue_depth);
	num_cqe = rpoller->num_cqe;
	if (num_cqe < required_num_wr)
	{
		num_cqe = spdk_max(num_cqe * 2, required_num_wr);
		num_cqe = spdk_min(num_cqe, device->attr.max_cqe);
	}

	if (rpoller->num_cqe != num_cqe)
	{
		if (device->context->device->transport_type == IBV_TRANSPORT_IWARP)
		{
			SPDK_ERRLOG("iWARP doesn't support CQ resize. Current capacity %u, required %u\n"
						"Using CQ of insufficient size may lead to CQ overrun\n",
						rpoller->num_cqe, num_cqe);
			return -1;
		}
		if (required_num_wr > device->attr.max_cqe)
		{
			SPDK_ERRLOG("RDMA CQE requirement (%d) exceeds device max_cqe limitation (%d)\n",
						required_num_wr, device->attr.max_cqe);
			return -1;
		}

		SPDK_DEBUGLOG(rdma, "Resize RDMA CQ from %d to %d\n", rpoller->num_cqe, num_cqe);
		rc = ibv_resize_cq(rpoller->cq, num_cqe);
		if (rc)
		{
			SPDK_ERRLOG("RDMA CQ resize failed: errno %d: %s\n", errno, spdk_strerror(errno));
			return -1;
		}

		rpoller->num_cqe = num_cqe;
	}

	rpoller->required_num_wr = required_num_wr;
	return 0;
}

static int
srv_rdma_conn_initialize(struct spdk_srv_conn *conn)
{
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_srv_rdma_transport *rtransport;
	struct spdk_srv_transport *transport;
	struct spdk_srv_rdma_resource_opts opts;
	struct spdk_srv_rdma_device *device;
	struct spdk_rdma_qp_init_attr qp_init_attr = {};

	rconn = SPDK_CONTAINEROF(conn, struct spdk_srv_rdma_conn, conn);
	device = rconn->device;

	qp_init_attr.qp_context = rconn;
	qp_init_attr.pd = device->pd;
	qp_init_attr.send_cq = rconn->poller->cq;
	qp_init_attr.recv_cq = rconn->poller->cq;

	if (rconn->srq)
	{
		qp_init_attr.srq = rconn->srq->srq;
	}
	else
	{
		qp_init_attr.cap.max_recv_wr = rconn->max_queue_depth;
	}

	/* SEND, READ, and WRITE operations */
	qp_init_attr.cap.max_send_wr = (uint32_t)rconn->max_queue_depth * 2;
	qp_init_attr.cap.max_send_sge = spdk_min((uint32_t)device->attr.max_sge, SRV_DEFAULT_TX_SGE);
	qp_init_attr.cap.max_recv_sge = spdk_min((uint32_t)device->attr.max_sge, SRV_DEFAULT_RX_SGE);
	qp_init_attr.stats = &rconn->poller->stat.qp_stats;

	if (rconn->srq == NULL && srv_rdma_resize_cq(rconn, device) < 0)
	{
		SPDK_ERRLOG("Failed to resize the completion queue. Cannot initialize conn.\n");
		goto error;
	}

	rconn->rdma_qp = spdk_rdma_qp_create(rconn->cm_id, &qp_init_attr);
	if (!rconn->rdma_qp)
	{
		goto error;
	}

	rconn->max_send_depth = spdk_min((uint32_t)(rconn->max_queue_depth * 2),
									 qp_init_attr.cap.max_send_wr);
	rconn->max_send_sge = spdk_min(SRV_DEFAULT_TX_SGE, qp_init_attr.cap.max_send_sge);
	rconn->max_recv_sge = spdk_min(SRV_DEFAULT_RX_SGE, qp_init_attr.cap.max_recv_sge);
	spdk_trace_record(TRACE_RDMA_QP_CREATE, 0, 0, (uintptr_t)rconn);
	SPDK_DEBUGLOG(rdma, "New RDMA Connection: %p\n", conn);

	if (rconn->poller->srq == NULL)
	{
		rtransport = SPDK_CONTAINEROF(conn->transport, struct spdk_srv_rdma_transport, transport);
		transport = &rtransport->transport;

		opts.qp = rconn->rdma_qp;
		opts.pd = rconn->cm_id->pd;
		opts.conn = rconn;
		opts.shared = false;
		opts.max_queue_depth = rconn->max_queue_depth;
		opts.in_capsule_data_size = transport->opts.in_capsule_data_size;

		rconn->resources = srv_rdma_resources_create(&opts);

		if (!rconn->resources)
		{
			SPDK_ERRLOG("Unable to allocate resources for receive queue.\n");
			rdma_destroy_qp(rconn->cm_id);
			goto error;
		}
	}
	else
	{
		rconn->resources = rconn->poller->resources;
	}

	rconn->current_recv_depth = 0;
	STAILQ_INIT(&rconn->pending_rdma_read_queue);
	STAILQ_INIT(&rconn->pending_rdma_write_queue);
	STAILQ_INIT(&rconn->pending_complete_queue);

	return 0;

error:
	rdma_destroy_id(rconn->cm_id);
	rconn->cm_id = NULL;
	return -1;
}

/* Append the given recv wr structure to the resource structs outstanding recvs list. */
/* This function accepts either a single wr or the first wr in a linked list. */
static void
srv_rdma_conn_queue_recv_wrs(struct spdk_srv_rdma_conn *rconn, struct ibv_recv_wr *first)
{
	struct spdk_srv_rdma_transport *rtransport = SPDK_CONTAINEROF(rconn->conn.transport,
																  struct spdk_srv_rdma_transport, transport);

	if (rconn->srq != NULL)
	{
		spdk_rdma_srq_queue_recv_wrs(rconn->srq, first);
	}
	else
	{
		if (spdk_rdma_qp_queue_recv_wrs(rconn->rdma_qp, first))
		{
			STAILQ_INSERT_TAIL(&rconn->poller->conns_pending_recv, rconn, recv_link);
		}
	}

	if (rtransport->rdma_opts.no_wr_batching)
	{
		_poller_submit_recvs(rtransport, rconn->poller);
	}
}

static int
request_transfer_in(struct spdk_srv_request *req)
{
	struct spdk_srv_rdma_request *rdma_req;
	struct spdk_srv_conn *conn;
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_srv_rdma_transport *rtransport;

	conn = req->conn;
	rdma_req = SPDK_CONTAINEROF(req, struct spdk_srv_rdma_request, req);
	rconn = SPDK_CONTAINEROF(conn, struct spdk_srv_rdma_conn, conn);
	rtransport = SPDK_CONTAINEROF(rconn->conn.transport,
								  struct spdk_srv_rdma_transport, transport);

	assert(req->xfer == SPDK_SRV_DATA_HOST_TO_CONTROLLER);
	assert(rdma_req != NULL);

	if (spdk_rdma_qp_queue_send_wrs(rconn->rdma_qp, &rdma_req->data.wr))
	{
		STAILQ_INSERT_TAIL(&rconn->poller->conns_pending_send, rconn, send_link);
	}
	if (rtransport->rdma_opts.no_wr_batching)
	{
		_poller_submit_sends(rtransport, rconn->poller);
	}

	rconn->current_read_depth += rdma_req->num_outstanding_data_wr;
	rconn->current_send_depth += rdma_req->num_outstanding_data_wr;
	return 0;
}

static int
request_transfer_out(struct spdk_srv_request *req, int *data_posted)
{
	int num_outstanding_data_wr = 0;
	struct spdk_srv_rdma_request *rdma_req;
	struct spdk_srv_conn *conn;
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_req_cpl *rsp;
	struct ibv_send_wr *first = NULL;
	struct spdk_srv_rdma_transport *rtransport;

	*data_posted = 0;
	conn = req->conn;
	rsp = req->rsp;
	rdma_req = SPDK_CONTAINEROF(req, struct spdk_srv_rdma_request, req);
	rconn = SPDK_CONTAINEROF(conn, struct spdk_srv_rdma_conn, conn);
	rtransport = SPDK_CONTAINEROF(rconn->conn.transport,
								  struct spdk_srv_rdma_transport, transport);

	/* Advance our sq_head pointer */
	if (conn->sq_head == conn->sq_head_max)
	{
		conn->sq_head = 0;
	}
	else
	{
		conn->sq_head++;
	}
	rsp->sqhd = conn->sq_head;

	/* queue the capsule for the recv buffer */
	assert(rdma_req->recv != NULL);

	srv_rdma_conn_queue_recv_wrs(rconn, &rdma_req->recv->wr);

	rdma_req->recv = NULL;
	assert(rconn->current_recv_depth > 0);
	rconn->current_recv_depth--;

	/* Build the response which consists of optional
	 * RDMA WRITEs to transfer data, plus an RDMA SEND
	 * containing the response.
	 */
	first = &rdma_req->rsp.wr;

	if (rsp->status.sc != SPDK_SRV_SC_SUCCESS)
	{
		/* On failure, data was not read from the controller. So clear the
		 * number of outstanding data WRs to zero.
		 */
		rdma_req->num_outstanding_data_wr = 0;
	}
	else if (req->xfer == SPDK_SRV_DATA_CONTROLLER_TO_HOST)
	{
		first = &rdma_req->data.wr;
		*data_posted = 1;
		num_outstanding_data_wr = rdma_req->num_outstanding_data_wr;
	}
	if (spdk_rdma_qp_queue_send_wrs(rconn->rdma_qp, first))
	{
		STAILQ_INSERT_TAIL(&rconn->poller->conns_pending_send, rconn, send_link);
	}
	SPDK_DEBUGLOG(rdma, "no_wr_batching=%d\n", rtransport->rdma_opts.no_wr_batching);
	if (rtransport->rdma_opts.no_wr_batching)
	{
		_poller_submit_sends(rtransport, rconn->poller);
	}

	/* +1 for the rsp wr */
	rconn->current_send_depth += num_outstanding_data_wr + 1;

	return 0;
}

static int
srv_rdma_event_accept(struct rdma_cm_id *id, struct spdk_srv_rdma_conn *rconn)
{
	struct spdk_srv_rdma_accept_private_data accept_data;
	struct rdma_conn_param ctrlr_event_data = {};
	int rc;

	accept_data.recfmt = 0;
	accept_data.crqsize = rconn->max_queue_depth;

	ctrlr_event_data.private_data = &accept_data;
	ctrlr_event_data.private_data_len = sizeof(accept_data);
	if (id->ps == RDMA_PS_TCP)
	{
		ctrlr_event_data.responder_resources = 0; /* We accept 0 reads from the host */
		ctrlr_event_data.initiator_depth = rconn->max_read_depth;
	}

	/* Configure infinite retries for the initiator side conn.
	 * When using a shared receive queue on the target side,
	 * we need to pass this value to the initiator to prevent the
	 * initiator side NIC from completing SEND requests back to the
	 * initiator with status rnr_retry_count_exceeded. */
	if (rconn->srq != NULL)
	{
		ctrlr_event_data.rnr_retry_count = 0x7;
	}

	/* When conn is created without use of rdma cm API, an additional
	 * information must be provided to initiator in the connection response:
	 * whether conn is using SRQ and its qp_num
	 * Fields below are ignored by rdma cm if conn has been
	 * created using rdma cm API. */
	ctrlr_event_data.srq = rconn->srq ? 1 : 0;
	ctrlr_event_data.qp_num = rconn->rdma_qp->qp->qp_num;

	rc = spdk_rdma_qp_accept(rconn->rdma_qp, &ctrlr_event_data);
	if (rc)
	{
		SPDK_ERRLOG("Error %d on spdk_rdma_qp_accept\n", errno);
	}
	else
	{
		SPDK_DEBUGLOG(rdma, "Sent back the accept\n");
	}

	return rc;
}

static void
srv_rdma_event_reject(struct rdma_cm_id *id, enum spdk_srv_rdma_transport_error error)
{
	struct spdk_srv_rdma_reject_private_data rej_data;

	rej_data.recfmt = 0;
	rej_data.sts = error;

	rdma_reject(id, &rej_data, sizeof(rej_data));
}

static int
srv_rdma_connect(struct spdk_srv_transport *transport, struct rdma_cm_event *event)
{
	struct spdk_srv_rdma_transport *rtransport;
	struct spdk_srv_rdma_conn *rconn = NULL;
	struct spdk_srv_rdma_port *port;
	struct rdma_conn_param *rdma_param = NULL;
	const struct spdk_srv_rdma_request_private_data *private_data = NULL;
	uint16_t max_queue_depth;
	uint16_t max_read_depth;

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_srv_rdma_transport, transport);

	assert(event->id != NULL);		  /* Impossible. Can't even reject the connection. */
	assert(event->id->verbs != NULL); /* Impossible. No way to handle this. */

	rdma_param = &event->param.conn;
	if (rdma_param->private_data == NULL ||
		rdma_param->private_data_len < sizeof(struct spdk_srv_rdma_request_private_data))
	{
		SPDK_ERRLOG("connect request: no private data provided\n");
		srv_rdma_event_reject(event->id, SPDK_SRV_RDMA_ERROR_INVALID_PRIVATE_DATA_LENGTH);
		return -1;
	}

	private_data = rdma_param->private_data;
	if (private_data->recfmt != 0)
	{
		SPDK_ERRLOG("Received RDMA private data with RECFMT != 0\n");
		srv_rdma_event_reject(event->id, SPDK_SRV_RDMA_ERROR_INVALID_RECFMT);
		return -1;
	}

	SPDK_DEBUGLOG(rdma, "Connect Recv on fabric intf name %s, dev_name %s\n",
				  event->id->verbs->device->name, event->id->verbs->device->dev_name);

	port = event->listen_id->context;
	SPDK_DEBUGLOG(rdma, "Listen Id was %p with verbs %p. ListenAddr: %p\n",
				  event->listen_id, event->listen_id->verbs, port);

	/* Figure out the supported queue depth. This is a multi-step process
	 * that takes into account hardware maximums, host provided values,
	 * and our target's internal memory limits */

	SPDK_DEBUGLOG(rdma, "Calculating Queue Depth\n");

	/* Start with the maximum queue depth allowed by the target */
	max_queue_depth = rtransport->transport.opts.max_queue_depth;
	max_read_depth = rtransport->transport.opts.max_queue_depth;
	SPDK_DEBUGLOG(rdma, "Target Max Queue Depth: %d\n",
				  rtransport->transport.opts.max_queue_depth);

	/* Next check the local NIC's hardware limitations */
	SPDK_DEBUGLOG(rdma,
				  "Local NIC Max Send/Recv Queue Depth: %d Max Read/Write Queue Depth: %d\n",
				  port->device->attr.max_qp_wr, port->device->attr.max_qp_rd_atom);
	max_queue_depth = spdk_min(max_queue_depth, port->device->attr.max_qp_wr);
	max_read_depth = spdk_min(max_read_depth, port->device->attr.max_qp_init_rd_atom);

	/* Next check the remote NIC's hardware limitations */
	SPDK_DEBUGLOG(rdma,
				  "Host (Initiator) NIC Max Incoming RDMA R/W operations: %d Max Outgoing RDMA R/W operations: %d\n",
				  rdma_param->initiator_depth, rdma_param->responder_resources);
	if (rdma_param->initiator_depth > 0)
	{
		max_read_depth = spdk_min(max_read_depth, rdma_param->initiator_depth);
	}

	/* Finally check for the host software requested values, which are
	 * optional. */
	if (rdma_param->private_data != NULL &&
		rdma_param->private_data_len >= sizeof(struct spdk_srv_rdma_request_private_data))
	{
		SPDK_DEBUGLOG(rdma, "Host Receive Queue Size: %d\n", private_data->hrqsize);
		SPDK_DEBUGLOG(rdma, "Host Send Queue Size: %d\n", private_data->hsqsize);
		max_queue_depth = spdk_min(max_queue_depth, private_data->hrqsize);
		max_queue_depth = spdk_min(max_queue_depth, private_data->hsqsize + 1);
	}

	SPDK_DEBUGLOG(rdma, "Final Negotiated Queue Depth: %d R/W Depth: %d\n",
				  max_queue_depth, max_read_depth);

	rconn = calloc(1, sizeof(struct spdk_srv_rdma_conn));
	if (rconn == NULL)
	{
		SPDK_ERRLOG("Could not allocate new connection.\n");
		srv_rdma_event_reject(event->id, SPDK_SRV_RDMA_ERROR_NO_RESOURCES);
		return -1;
	}

	rconn->device = port->device;
	rconn->max_queue_depth = max_queue_depth;
	rconn->max_read_depth = max_read_depth;
	rconn->cm_id = event->id;
	rconn->listen_id = event->listen_id;
	rconn->conn.transport = transport;
	STAILQ_INIT(&rconn->ibv_events);
	/* use qid from the private data to determine the conn type
	   qid will be set to the appropriate value when the controller is created */
	rconn->conn.qid = private_data->qid;

	event->id->context = &rconn->conn;

	spdk_srv_tgt_new_conn(transport->tgt, &rconn->conn);

	return 0;
}

static inline void
srv_rdma_setup_wr(struct ibv_send_wr *wr, struct ibv_send_wr *next,
				  enum spdk_srv_data_transfer xfer)
{
	if (xfer == SPDK_SRV_DATA_CONTROLLER_TO_HOST)
	{
		wr->opcode = IBV_WR_RDMA_WRITE;
		wr->send_flags = 0;
		wr->next = next;
	}
	else if (xfer == SPDK_SRV_DATA_HOST_TO_CONTROLLER)
	{
		wr->opcode = IBV_WR_RDMA_READ;
		wr->send_flags = IBV_SEND_SIGNALED;
		wr->next = NULL;
	}
	else
	{
		assert(0);
	}
}

static int
srv_request_alloc_wrs(struct spdk_srv_rdma_transport *rtransport,
					  struct spdk_srv_rdma_request *rdma_req,
					  uint32_t num_sgl_descriptors)
{
	struct spdk_srv_rdma_request_data *work_requests[SPDK_SRV_MAX_SGL_ENTRIES];
	struct spdk_srv_rdma_request_data *current_data_wr;
	uint32_t i;

	if (num_sgl_descriptors > SPDK_SRV_MAX_SGL_ENTRIES)
	{
		SPDK_ERRLOG("Requested too much entries (%u), the limit is %u\n",
					num_sgl_descriptors, SPDK_SRV_MAX_SGL_ENTRIES);
		return -EINVAL;
	}

	if (spdk_mempool_get_bulk(rtransport->data_wr_pool, (void **)work_requests, num_sgl_descriptors))
	{
		return -ENOMEM;
	}

	current_data_wr = &rdma_req->data;

	for (i = 0; i < num_sgl_descriptors; i++)
	{
		srv_rdma_setup_wr(&current_data_wr->wr, &work_requests[i]->wr, rdma_req->req.xfer);
		current_data_wr->wr.next = &work_requests[i]->wr;
		current_data_wr = work_requests[i];
		current_data_wr->wr.sg_list = current_data_wr->sgl;
		current_data_wr->wr.wr_id = rdma_req->data.wr.wr_id;
	}

	srv_rdma_setup_wr(&current_data_wr->wr, &rdma_req->rsp.wr, rdma_req->req.xfer);

	return 0;
}

static inline void
srv_rdma_setup_request(struct spdk_srv_rdma_request *rdma_req)
{
	struct ibv_send_wr *wr = &rdma_req->data.wr;
	struct spdk_req_sgl_descriptor *sgl = &rdma_req->req.cmd->dptr.sgl1;

	wr->wr.rdma.rkey = sgl->keyed.key;
	wr->wr.rdma.remote_addr = sgl->address;
	srv_rdma_setup_wr(wr, &rdma_req->rsp.wr, rdma_req->req.xfer);
}

static inline void
srv_rdma_update_remote_addr(struct spdk_srv_rdma_request *rdma_req, uint32_t num_wrs)
{
	struct ibv_send_wr *wr = &rdma_req->data.wr;
	struct spdk_req_sgl_descriptor *sgl = &rdma_req->req.cmd->dptr.sgl1;
	uint32_t i;
	int j;
	uint64_t remote_addr_offset = 0;

	for (i = 0; i < num_wrs; ++i)
	{
		wr->wr.rdma.rkey = sgl->keyed.key;
		wr->wr.rdma.remote_addr = sgl->address + remote_addr_offset;
		for (j = 0; j < wr->num_sge; ++j)
		{
			remote_addr_offset += wr->sg_list[j].length;
		}
		wr = wr->next;
	}
}

static int
srv_rdma_fill_wr_sgl(struct spdk_srv_rdma_poll_group *rgroup,
					 struct spdk_srv_rdma_device *device,
					 struct spdk_srv_rdma_request *rdma_req,
					 struct ibv_send_wr *wr,
					 uint32_t total_length,
					 uint32_t num_extra_wrs)
{
	struct spdk_rdma_memory_translation mem_translation;
	struct ibv_sge *sg_ele;
	struct iovec *iov;
	uint32_t remaining_data_block = 0;
	uint32_t lkey, remaining;
	int rc;

	wr->num_sge = 0;

	while (total_length && (num_extra_wrs || wr->num_sge < SPDK_SRV_MAX_SGL_ENTRIES))
	{
		iov = &rdma_req->req.iov[rdma_req->iovpos];
		rc = spdk_rdma_get_translation(device->map, iov->iov_base, iov->iov_len, &mem_translation);
		if (spdk_unlikely(rc))
		{
			return false;
		}

		lkey = spdk_rdma_memory_translation_get_lkey(&mem_translation);
		sg_ele = &wr->sg_list[wr->num_sge];
		remaining = spdk_min((uint32_t)iov->iov_len - rdma_req->offset, total_length);

		sg_ele->lkey = lkey;
		sg_ele->addr = (uintptr_t)iov->iov_base + rdma_req->offset;
		sg_ele->length = remaining;
		SPDK_DEBUGLOG(rdma, "sge[%d] %p addr 0x%" PRIx64 ", len %u\n", wr->num_sge, sg_ele, sg_ele->addr,
					  sg_ele->length);
		rdma_req->offset += sg_ele->length;
		total_length -= sg_ele->length;
		wr->num_sge++;

		if (rdma_req->offset == iov->iov_len)
		{
			rdma_req->offset = 0;
			rdma_req->iovpos++;
		}
	}

	if (total_length)
	{
		SPDK_ERRLOG("Not enough SG entries to hold data buffer\n");
		return -EINVAL;
	}

	return 0;
}

static inline uint32_t
srv_rdma_calc_num_wrs(uint32_t length, uint32_t io_unit_size, uint32_t block_size)
{
	/* estimate the number of SG entries and WRs needed to process the request */
	uint32_t num_sge = 0;
	uint32_t i;
	uint32_t num_buffers = SPDK_CEIL_DIV(length, io_unit_size);

	for (i = 0; i < num_buffers && length > 0; i++)
	{
		uint32_t buffer_len = spdk_min(length, io_unit_size);
		uint32_t num_sge_in_block = SPDK_CEIL_DIV(buffer_len, block_size);

		if (num_sge_in_block * block_size > buffer_len)
		{
			++num_sge_in_block;
		}
		num_sge += num_sge_in_block;
		length -= buffer_len;
	}
	return SPDK_CEIL_DIV(num_sge, SPDK_SRV_MAX_SGL_ENTRIES);
}

static int
srv_rdma_request_fill_iovs(struct spdk_srv_rdma_transport *rtransport,
						   struct spdk_srv_rdma_device *device,
						   struct spdk_srv_rdma_request *rdma_req,
						   uint32_t length)
{
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_srv_rdma_poll_group *rgroup;
	struct spdk_srv_request *req = &rdma_req->req;
	struct ibv_send_wr *wr = &rdma_req->data.wr;
	int rc;
	uint32_t num_wrs = 1;

	rconn = SPDK_CONTAINEROF(req->conn, struct spdk_srv_rdma_conn, conn);
	rgroup = rconn->poller->group;

	/* rdma wr specifics */
	srv_rdma_setup_request(rdma_req);

	rc = spdk_srv_request_get_buffers(req, &rgroup->group, &rtransport->transport,
									  length);
	if (rc != 0)
	{
		return rc;
	}

	assert(req->iovcnt <= rconn->max_send_sge);

	rdma_req->iovpos = 0;

	rc = srv_rdma_fill_wr_sgl(rgroup, device, rdma_req, wr, length, num_wrs - 1);
	if (spdk_unlikely(rc != 0))
	{
		goto err_exit;
	}

	if (spdk_unlikely(num_wrs > 1))
	{
		srv_rdma_update_remote_addr(rdma_req, num_wrs);
	}

	/* set the number of outstanding data WRs for this request. */
	rdma_req->num_outstanding_data_wr = num_wrs;

	return rc;

err_exit:
	spdk_srv_request_free_buffers(req, &rgroup->group, &rtransport->transport);
	srv_rdma_request_free_data(rdma_req, rtransport);
	req->iovcnt = 0;
	return rc;
}

static int
srv_rdma_request_fill_iovs_multi_sgl(struct spdk_srv_rdma_transport *rtransport,
									 struct spdk_srv_rdma_device *device,
									 struct spdk_srv_rdma_request *rdma_req)
{
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_srv_rdma_poll_group *rgroup;
	struct ibv_send_wr *current_wr;
	struct spdk_srv_request *req = &rdma_req->req;
	struct spdk_req_sgl_descriptor *inline_segment, *desc;
	uint32_t num_sgl_descriptors;
	uint32_t lengths[SPDK_SRV_MAX_SGL_ENTRIES], total_length = 0;
	uint32_t i;
	int rc;

	rconn = SPDK_CONTAINEROF(rdma_req->req.conn, struct spdk_srv_rdma_conn, conn);
	rgroup = rconn->poller->group;

	inline_segment = &req->cmd->dptr.sgl1;
	assert(inline_segment->generic.type == SPDK_SRV_SGL_TYPE_LAST_SEGMENT);
	assert(inline_segment->unkeyed.subtype == SPDK_SRV_SGL_SUBTYPE_OFFSET);

	num_sgl_descriptors = inline_segment->unkeyed.length / sizeof(struct spdk_req_sgl_descriptor);
	assert(num_sgl_descriptors <= SPDK_SRV_MAX_SGL_ENTRIES);

	desc = (struct spdk_req_sgl_descriptor *)rdma_req->recv->buf + inline_segment->address;
	for (i = 0; i < num_sgl_descriptors; i++)
	{
		if (spdk_likely(!req->dif_enabled))
		{
			lengths[i] = desc->keyed.length;
		}

		total_length += lengths[i];
		desc++;
	}

	if (total_length > rtransport->transport.opts.max_io_size)
	{
		SPDK_ERRLOG("Multi SGL length 0x%x exceeds max io size 0x%x\n",
					total_length, rtransport->transport.opts.max_io_size);
		req->rsp->status.sc = SPDK_SRV_SC_DATA_SGL_LENGTH_INVALID;
		return -EINVAL;
	}

	if (srv_request_alloc_wrs(rtransport, rdma_req, num_sgl_descriptors - 1) != 0)
	{
		return -ENOMEM;
	}

	rc = spdk_srv_request_get_buffers(req, &rgroup->group, &rtransport->transport, total_length);
	if (rc != 0)
	{
		srv_rdma_request_free_data(rdma_req, rtransport);
		return rc;
	}

	/* The first WR must always be the embedded data WR. This is how we unwind them later. */
	current_wr = &rdma_req->data.wr;
	assert(current_wr != NULL);

	req->length = 0;
	rdma_req->iovpos = 0;
	desc = (struct spdk_req_sgl_descriptor *)rdma_req->recv->buf + inline_segment->address;
	for (i = 0; i < num_sgl_descriptors; i++)
	{
		/* The descriptors must be keyed data block descriptors with an address, not an offset. */
		if (spdk_unlikely(desc->generic.type != SPDK_SRV_SGL_TYPE_KEYED_DATA_BLOCK ||
						  desc->keyed.subtype != SPDK_SRV_SGL_SUBTYPE_ADDRESS))
		{
			rc = -EINVAL;
			goto err_exit;
		}

		rc = srv_rdma_fill_wr_sgl(rgroup, device, rdma_req, current_wr, lengths[i], 0);
		if (rc != 0)
		{
			rc = -ENOMEM;
			goto err_exit;
		}

		req->length += desc->keyed.length;
		current_wr->wr.rdma.rkey = desc->keyed.key;
		current_wr->wr.rdma.remote_addr = desc->address;
		current_wr = current_wr->next;
		desc++;
	}

#ifdef SPDK_CONFIG_RDMA_SEND_WITH_INVAL
	/* Go back to the last descriptor in the list. */
	desc--;
	if ((device->attr.device_cap_flags & IBV_DEVICE_MEM_MGT_EXTENSIONS) != 0)
	{
		if (desc->keyed.subtype == SPDK_SRV_SGL_SUBTYPE_INVALIDATE_KEY)
		{
			rdma_req->rsp.wr.opcode = IBV_WR_SEND_WITH_INV;
			rdma_req->rsp.wr.imm_data = desc->keyed.key;
		}
	}
#endif

	rdma_req->num_outstanding_data_wr = num_sgl_descriptors;

	return 0;

err_exit:
	spdk_srv_request_free_buffers(req, &rgroup->group, &rtransport->transport);
	srv_rdma_request_free_data(rdma_req, rtransport);
	return rc;
}

static int
srv_rdma_request_parse_sgl(struct spdk_srv_rdma_transport *rtransport,
						   struct spdk_srv_rdma_device *device,
						   struct spdk_srv_rdma_request *rdma_req)
{
	struct spdk_srv_request *req = &rdma_req->req;
	struct spdk_req_cpl *rsp;
	struct spdk_req_sgl_descriptor *sgl;
	int rc;
	uint32_t length;

	rsp = req->rsp;
	sgl = &req->cmd->dptr.sgl1;

	if (sgl->generic.type == SPDK_SRV_SGL_TYPE_KEYED_DATA_BLOCK &&
		(sgl->keyed.subtype == SPDK_SRV_SGL_SUBTYPE_ADDRESS ||
		 sgl->keyed.subtype == SPDK_SRV_SGL_SUBTYPE_INVALIDATE_KEY))
	{

		length = sgl->keyed.length;
		if (length > rtransport->transport.opts.max_io_size)
		{
			SPDK_ERRLOG("SGL length 0x%x exceeds max io size 0x%x\n",
						length, rtransport->transport.opts.max_io_size);
			rsp->status.sc = SPDK_SRV_SC_DATA_SGL_LENGTH_INVALID;
			return -1;
		}
#ifdef SPDK_CONFIG_RDMA_SEND_WITH_INVAL
		if ((device->attr.device_cap_flags & IBV_DEVICE_MEM_MGT_EXTENSIONS) != 0)
		{
			if (sgl->keyed.subtype == SPDK_SRV_SGL_SUBTYPE_INVALIDATE_KEY)
			{
				rdma_req->rsp.wr.opcode = IBV_WR_SEND_WITH_INV;
				rdma_req->rsp.wr.imm_data = sgl->keyed.key;
			}
		}
#endif

		/* fill request length and populate iovs */
		req->length = length;

		rc = srv_rdma_request_fill_iovs(rtransport, device, rdma_req, length);
		if (spdk_unlikely(rc < 0))
		{
			if (rc == -EINVAL)
			{
				SPDK_ERRLOG("SGL length exceeds the max I/O size\n");
				rsp->status.sc = SPDK_SRV_SC_DATA_SGL_LENGTH_INVALID;
				return -1;
			}
			/* No available buffers. Queue this request up. */
			SPDK_DEBUGLOG(rdma, "No available large data buffers. Queueing request %p\n", rdma_req);
			return 0;
		}

		/* backward compatible */
		req->data = req->iov[0].iov_base;

		SPDK_DEBUGLOG(rdma, "Request %p took %d buffer/s from central pool\n", rdma_req,
					  req->iovcnt);

		return 0;
	}
	else if (sgl->generic.type == SPDK_SRV_SGL_TYPE_DATA_BLOCK &&
			 sgl->unkeyed.subtype == SPDK_SRV_SGL_SUBTYPE_OFFSET)
	{
		uint64_t offset = sgl->address;
		uint32_t max_len = rtransport->transport.opts.in_capsule_data_size;

		SPDK_DEBUGLOG(rdma, "In-capsule data: offset 0x%" PRIx64 ", length 0x%x\n",
					  offset, sgl->unkeyed.length);

		if (offset > max_len)
		{
			SPDK_ERRLOG("In-capsule offset 0x%" PRIx64 " exceeds capsule length 0x%x\n",
						offset, max_len);
			rsp->status.sc = SPDK_SRV_SC_INVALID_SGL_OFFSET;
			return -1;
		}
		max_len -= (uint32_t)offset;

		if (sgl->unkeyed.length > max_len)
		{
			SPDK_ERRLOG("In-capsule data length 0x%x exceeds capsule length 0x%x\n",
						sgl->unkeyed.length, max_len);
			rsp->status.sc = SPDK_SRV_SC_DATA_SGL_LENGTH_INVALID;
			return -1;
		}

		rdma_req->num_outstanding_data_wr = 0;
		req->data = rdma_req->recv->buf + offset;
		req->data_from_pool = false;
		req->length = sgl->unkeyed.length;

		req->iov[0].iov_base = req->data;
		req->iov[0].iov_len = req->length;
		req->iovcnt = 1;
		SPDK_DEBUGLOG(rdma, "In-capsule data: iov_base %p, iov_length %p\n",
					  req->iov[0].iov_base, req->iov[0].iov_len);

		return 0;
	}
	else if (sgl->generic.type == SPDK_SRV_SGL_TYPE_LAST_SEGMENT &&
			 sgl->unkeyed.subtype == SPDK_SRV_SGL_SUBTYPE_OFFSET)
	{

		rc = srv_rdma_request_fill_iovs_multi_sgl(rtransport, device, rdma_req);
		if (rc == -ENOMEM)
		{
			SPDK_DEBUGLOG(rdma, "No available large data buffers. Queueing request %p\n", rdma_req);
			return 0;
		}
		else if (rc == -EINVAL)
		{
			SPDK_ERRLOG("Multi SGL element request length exceeds the max I/O size\n");
			rsp->status.sc = SPDK_SRV_SC_DATA_SGL_LENGTH_INVALID;
			return -1;
		}

		/* backward compatible */
		req->data = req->iov[0].iov_base;

		SPDK_DEBUGLOG(rdma, "Request %p took %d buffer/s from central pool\n", rdma_req,
					  req->iovcnt);

		return 0;
	}

	SPDK_ERRLOG("Invalid Srv I/O Command SGL:  Type 0x%x, Subtype 0x%x\n",
				sgl->generic.type, sgl->generic.subtype);
	rsp->status.sc = SPDK_SRV_SC_SGL_DESCRIPTOR_TYPE_INVALID;
	return -1;
}

static void
_srv_rdma_request_free(struct spdk_srv_rdma_request *rdma_req,
					   struct spdk_srv_rdma_transport *rtransport)
{
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_srv_rdma_poll_group *rgroup;

	rconn = SPDK_CONTAINEROF(rdma_req->req.conn, struct spdk_srv_rdma_conn, conn);
	if (rdma_req->req.data_from_pool)
	{
		rgroup = rconn->poller->group;

		spdk_srv_request_free_buffers(&rdma_req->req, &rgroup->group, &rtransport->transport);
	}
	srv_rdma_request_free_data(rdma_req, rtransport);
	rdma_req->req.length = 0;
	rdma_req->req.iovcnt = 0;
	rdma_req->req.data = NULL;
	rdma_req->rsp.wr.next = NULL;
	rdma_req->data.wr.next = NULL;
	rdma_req->offset = 0;
	rconn->qd--;

	STAILQ_INSERT_HEAD(&rconn->resources->free_queue, rdma_req, state_link);
	rdma_req->state = RDMA_REQUEST_STATE_FREE;
}

static void srv_rpc_write_request_exec(struct spdk_srv_rdma_request *rdma_req)
{
	uint32_t rpc_index;
	uint32_t data_length;
	uint32_t rpc_opc;
	uint32_t submit_type;
	uint32_t lba_start, subrequest_id;
	int iov_offset;
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_srv_rpc_request *rpc_req;
	uint8_t md5sum[SPDK_MD5DIGEST_LEN];
	rpc_index = rdma_req->req.cmd->rsvd2;
	data_length = rdma_req->req.cmd->rsvd3;
	rpc_opc = rdma_req->req.cmd->rpc_opc;
	submit_type = rdma_req->req.cmd->cdw13;
	uint32_t check_md5 = rdma_req->req.cmd->cdw14;
	rconn = SPDK_CONTAINEROF(rdma_req->req.conn, struct spdk_srv_rdma_conn, conn);
	rpc_req = &rconn->resources->rpc_reqs[rpc_index];
	uint32_t io_unit_size = rconn->conn.transport->opts.io_unit_size;
	uint32_t max_io_size = rconn->conn.transport->opts.max_io_size;
	struct spdk_md5ctx md5ctx;
	int out_data_offset = 0;
	int out_remain_len = 0;
	int copy_len = 0;
	int md5_batch_len = 0;
	int md5_total_len = 0;
	struct iovec *iovec;
	assert(rdma_req->recv != NULL);
	SPDK_DEBUGLOG(rdma, "start srv_rpc_write_request_exec rdma_req:%p, rpc_req:%p, rpc_index:%d, state:%d opc:%d rpc_opc:%d\n", (uintptr_t)rdma_req, (uintptr_t)rpc_req, rpc_index, rpc_req->state, rdma_req->req.cmd->opc, rdma_req->req.cmd->rpc_opc);

	if (rpc_req->state == FREE)
	{
		rpc_req->in_real_length = data_length;
		rpc_req->in_iov_cnt_total = SPDK_CEIL_DIV(data_length, io_unit_size);
		rpc_req->in_iov_cnt_left = rpc_req->in_iov_cnt_total;
		rpc_req->rpc_index = rpc_index;
		rpc_req->rconn = rconn;
		rpc_req->rpc_opc = rpc_opc;
		rpc_req->submit_type = submit_type;
		SPDK_DEBUGLOG(rdma, "in_iov_cnt_total :%d\n", rpc_req->in_iov_cnt_total);
		if (rpc_req->in_iov_cnt_total > SPDK_SRV_MAX_SGL_ENTRIES)
		{
			// 说明rpc会被分裂为多个子请求，这里需要分配一个iovec *的数组,用于存储全部子请求的iovec的指针
			// 需在在上层应用处理完rpc请求，调用传递的callback函数时，释放
			rpc_req->in_iovs = calloc(rpc_req->in_iov_cnt_total, sizeof(struct iovec));
			if (rpc_req->in_iovs == NULL)
			{
				exit(-1);
			}
			// 检查一下LBA起始的数值，按理说应该是256的整数倍,因为sector_size 是512字节，一次最大传输单元是128K
			lba_start = rdma_req->req.cmd->cdw10;
			subrequest_id = lba_start / (max_io_size / 512);
			iov_offset = subrequest_id * SPDK_SRV_MAX_SGL_ENTRIES;
			for (int i = 0; i < rdma_req->req.iovcnt; i++)
			{
				rpc_req->in_iovs[iov_offset + i].iov_base = rdma_req->req.iov[i].iov_base;
				rpc_req->in_iovs[iov_offset + i].iov_len = rdma_req->req.iov[i].iov_len;
				rpc_req->in_iov_cnt_left--;
			}
			rpc_req->state = WAIT_OTHER_SUBREQUEST;
		}
		else
		{
			// 没有子请求，不必再分数组了，直接指向rdma_req->req里面的定长数组
			rpc_req->in_iovs = (struct iovec **)rdma_req->req.iov;
			rpc_req->in_iov_cnt_left = 0;
			rpc_req->state = PROCESS_DATA;
			SPDK_DEBUGLOG(rdma, " 2222222 srv_rpc_write_request_exec state:%d addr:%ld len:%d\n", rpc_req->state, rdma_req->req.iov[0], rdma_req->req.iovcnt);
		}
		// rdma_req请求挂到spdk_srv_rpc_request里的队列上
		STAILQ_INSERT_TAIL(&rpc_req->wait_rpc_handle_queue, rdma_req, state_link);
	}
	else if (rpc_req->state == WAIT_OTHER_SUBREQUEST)
	{
		lba_start = rdma_req->req.cmd->cdw10;
		subrequest_id = lba_start / (max_io_size / 512);
		iov_offset = subrequest_id * SPDK_SRV_MAX_SGL_ENTRIES;
		for (int i = 0; i < rdma_req->req.iovcnt; i++)
		{
			rpc_req->in_iovs[iov_offset + i].iov_base = rdma_req->req.iov[i].iov_base;
			rpc_req->in_iovs[iov_offset + i].iov_len = rdma_req->req.iov[i].iov_len;
			rpc_req->in_iov_cnt_left--;
		}
		if (rpc_req->in_iov_cnt_left == 0)
		{
			rpc_req->state = PROCESS_DATA;
		}
		// rdma_req请求挂到spdk_srv_rpc_request里的队列上
		STAILQ_INSERT_TAIL(&rpc_req->wait_rpc_handle_queue, rdma_req, state_link);
	}
	else
	{
		SPDK_ERRLOG("srv_rpc_write_request_exec assert error request:%p, state:%d, rpc_index\n", rdma_req, rpc_req->state, rpc_req->rpc_index);
		exit(-1);
	}
	SPDK_DEBUGLOG(rdma, "11111111 srv_rpc_write_request_exec rpc_req:%p, index:%d, state:%d\n", (uintptr_t)rpc_req, rpc_req->rpc_index, rpc_req->state);
	if (rpc_req->state == PROCESS_DATA)
	{
		assert(g_rpc_dispatcher != NULL);
		assert(rdma_req->recv != NULL);
		// check md5sum
		if (check_md5 == 1)
		{
			rpc_req->check_md5 = true;
			SPDK_DEBUGLOG(rdma, "check md5sum start iov_cnt:%d, real_length:%d\n", rpc_req->in_iov_cnt_total, rpc_req->in_real_length);
			md5_total_len = rpc_req->in_real_length;
			md5_batch_len = 0;
			md5init(&md5ctx);
			for (int i = 0; i < rpc_req->in_iov_cnt_total; i++)
			{
				md5_batch_len = spdk_min(rpc_req->in_iovs[i].iov_len, md5_total_len);
				md5update(&md5ctx, rpc_req->in_iovs[i].iov_base, md5_batch_len);
				md5_total_len -= md5_batch_len;
				SPDK_DEBUGLOG(rdma, "checking md5sum iov_len:%d, md5_total_len:%d\n", rpc_req->in_iovs[i].iov_len, md5_total_len);
			}
			assert(md5_total_len == 0);
			md5final(md5sum, &md5ctx);
			for (int i = 0; i < SPDK_MD5DIGEST_LEN; i++)
			{
				assert(md5sum[i] == rdma_req->req.cmd->md5sum[i]);
				SPDK_DEBUGLOG(rdma, "check md5sum compare caled:%d, receved:%d\n", md5sum[i], rdma_req->req.cmd->md5sum[i]);
			}
			SPDK_DEBUGLOG(rdma, "check md5sum success\n");
		}
		if (rpc_req->submit_type == SPDK_CLIENT_SUBMIT_CONTING)
		{
			(*(spdk_srv_rpc_dispatcher)g_rpc_dispatcher[rpc_req->submit_type])(rpc_req->rpc_opc, rpc_req->in_iovs, rpc_req->in_iov_cnt_total, rpc_req->in_real_length, spdk_srv_rpc_request_handle_complete_cb, rpc_req);
		}
		else if (rpc_req->submit_type == SPDK_CLIENT_SUBMIT_IOVES)
		{
			(*(spdk_srv_rpc_dispatcher_iovs)g_rpc_dispatcher[rpc_req->submit_type])(rpc_req->rpc_opc, rpc_req->in_iovs, rpc_req->in_iov_cnt_total, rpc_req->in_real_length, spdk_srv_rpc_request_handle_complete_iovs_cb, rpc_req);
		}
	}
	return;
}

static void srv_rpc_read_request_exec(struct spdk_srv_rdma_request *rdma_req)
{
	uint32_t rpc_index;
	uint32_t data_length;
	uint32_t lba_start, subrequest_id;
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_srv_rpc_request *rpc_req;
	rpc_index = rdma_req->req.cmd->rsvd2;
	data_length = rdma_req->req.cmd->rsvd3;
	rconn = SPDK_CONTAINEROF(rdma_req->req.conn, struct spdk_srv_rdma_conn, conn);
	rpc_req = &rconn->resources->rpc_reqs[rpc_index];
	uint32_t io_unit_size = rconn->conn.transport->opts.io_unit_size;
	uint32_t max_io_size = rconn->conn.transport->opts.max_io_size;
	struct spdk_req_cpl *rsp;
	int out_data_offset = 0;
	int out_remain_len = 0;
	int copy_len = 0;

	// 理论上只需要第一次拷贝数据之前需要seek到某个pos和offset，seeked用于在循环中标识是否执行过seek操作
	bool seeked = false;
	int seeked_offset = 0;
	int last_seeked_offset = 0;

	int iovpos_dst = 0;
	int iovpos_src = 0;
	int offset_dst = 0;
	int offset_src = 0;
	int iov_remain_length_dst = 0;
	int iov_remain_length_src = 0;
	struct iovec *iov_src;
	struct iovec *iov_dst;

	assert(rdma_req->recv != NULL);
	SPDK_DEBUGLOG(rdma, "start srv_rpc_read_request_exec rdma_req:%p, rpc_req:%p, rpc_index:%d, state:%d opc:%d rpc_opc:%d\n", (uintptr_t)rdma_req, (uintptr_t)rpc_req, rpc_index, rpc_req->state, rdma_req->req.cmd->opc, rdma_req->req.cmd->rpc_opc);

	if (rpc_req->state == PENDING_READ)
	{
		lba_start = rdma_req->req.cmd->cdw10;
		out_data_offset = lba_start * 512;
		out_remain_len = rpc_req->out_real_length - out_data_offset;
		out_remain_len = spdk_min(out_remain_len, max_io_size);
		iovpos_dst = 0;
		SPDK_DEBUGLOG(rdma, "lba_start:%d out_data_offset:%d out_remain_len:%d\n", lba_start, out_data_offset, out_remain_len);
		while (out_remain_len > 0)
		{
			if (rpc_req->submit_type == SPDK_CLIENT_SUBMIT_CONTING)
			{
				iov_dst = &rdma_req->req.iov[iovpos_dst];
				copy_len = spdk_min(iov_dst->iov_len, out_remain_len);
				memcpy(iov_dst->iov_base, rpc_req->out_data + out_data_offset, copy_len);
				out_data_offset += copy_len;
				out_remain_len -= copy_len;
				iovpos_dst++;
			}
			else if (rpc_req->submit_type == SPDK_CLIENT_SUBMIT_IOVES)
			{
				if (!seeked)
				{
					for (int i = 0; i < rpc_req->out_iov_cnt; i++)
					{
						last_seeked_offset = seeked_offset;
						seeked_offset += rpc_req->out_iovs[i].iov_len;
						if (seeked_offset > out_data_offset)
						{
							offset_src = out_data_offset - last_seeked_offset;
							break;
						}
						else if (seeked_offset == out_data_offset)
						{
							iovpos_src++;
							offset_src = 0;
							break;
						}
						else
						{
							iovpos_src++;
						}
					}
					seeked = true;
				}
				iov_dst = &rdma_req->req.iov[iovpos_dst];

				iov_remain_length_dst = iov_dst->iov_len - offset_dst;
				while (iov_remain_length_dst > 0)
				{
					iov_src = &rpc_req->out_iovs[iovpos_src];
					iov_remain_length_src = iov_src->iov_len - offset_src;
					copy_len = spdk_min(iov_remain_length_dst, iov_remain_length_src);
					memcpy(iov_dst->iov_base + offset_dst, iov_src->iov_base + offset_src, copy_len);
					offset_dst = offset_dst + copy_len;
					offset_src = offset_src + copy_len;
					iov_remain_length_dst = iov_remain_length_dst - copy_len;
					iov_remain_length_src = iov_remain_length_src - copy_len;
					out_remain_len = out_remain_len - copy_len;
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
						SPDK_ERRLOG("srv_rpc_read_request_exec HIT CRITIAL ERROR\n");
					}
				}
			}
			else
			{
				assert(rpc_req->submit_type < SPDK_CLIENT_SUBMIT_TYPES_TOTAL);
				SPDK_ERRLOG("not supported submit_type %d\n", rpc_req->submit_type);
			}
		};
		assert(out_remain_len == 0);
		SPDK_DEBUGLOG(rdma, "iovpos_dst:%d req.iovcnt:%d\n", iovpos_dst, rdma_req->req.iovcnt);
		assert(iovpos_dst == rdma_req->req.iovcnt);

		// 如果需要计算md5，提前把md5值放到rsp里面的md5sum字段里面
		//  提前处理rsp的一些字段
		rsp = rdma_req->req.rsp;
		rsp->cdw0 = rpc_req->out_status;
		if (rpc_req->check_md5)
		{
			memcpy(rsp->md5sum, rpc_req->md5sum, SPDK_MD5DIGEST_LEN);
		}
	}
	else
	{
		SPDK_ERRLOG("srv_rpc_read_request_exec assert error request:%p, state:%d, rpc_index:%d\n", rdma_req, rpc_req->state, rpc_req->rpc_index);
		assert(-1);
	}
	rpc_req->out_rdma_send_left--;
	if (rpc_req->out_rdma_send_left == 0)
	{
		rpc_req->state = FINISH;
		(*rpc_req->service_cb)(rpc_req->service_cb_arg, 0);
		srv_rpc_request_free(rpc_req);
	}
	SPDK_DEBUGLOG(rdma, "11111111 srv_rpc_read_request_exec rpc_req:%p, state:%d\n", (uintptr_t)rpc_req, rpc_req->state);
	return;
}

void srv_rpc_request_free(struct spdk_srv_rpc_request *rpc_req)
{
	memset(rpc_req, 0, offsetof(struct spdk_srv_rpc_request, wait_rpc_handle_queue));
	rpc_req->state = FREE;
}

bool srv_rdma_request_process(struct spdk_srv_rdma_transport *rtransport,
							  struct spdk_srv_rdma_request *rdma_req)
{
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_srv_rdma_device *device;
	struct spdk_srv_rdma_poll_group *rgroup;
	struct spdk_req_cpl *rsp = rdma_req->req.rsp;
	int rc;
	struct spdk_srv_rdma_recv *rdma_recv;
	enum spdk_srv_rdma_request_state prev_state;
	bool progress = false;
	int data_posted;
	uint32_t num_blocks;
	struct spdk_srv_rpc_request *rpc_req;
	uint32_t rpc_index;

	rconn = SPDK_CONTAINEROF(rdma_req->req.conn, struct spdk_srv_rdma_conn, conn);
	device = rconn->device;
	rgroup = rconn->poller->group;

	assert(rdma_req->state != RDMA_REQUEST_STATE_FREE);

	/* If the queue pair is in an error state, force the request to the completed state
	 * to release resources. */
	if (rconn->ibv_state == IBV_QPS_ERR || rconn->conn.state != SPDK_SRV_CONN_ACTIVE)
	{
		if (rdma_req->state == RDMA_REQUEST_STATE_NEED_BUFFER)
		{
			STAILQ_REMOVE(&rgroup->group.pending_buf_queue, &rdma_req->req, spdk_srv_request, buf_link);
		}
		else if (rdma_req->state == RDMA_REQUEST_STATE_DATA_TRANSFER_TO_CONTROLLER_PENDING)
		{
			STAILQ_REMOVE(&rconn->pending_rdma_read_queue, rdma_req, spdk_srv_rdma_request, state_link);
		}
		else if (rdma_req->state == RDMA_REQUEST_STATE_DATA_TRANSFER_TO_HOST_PENDING)
		{
			STAILQ_REMOVE(&rconn->pending_rdma_write_queue, rdma_req, spdk_srv_rdma_request, state_link);
		}
		rdma_req->state = RDMA_REQUEST_STATE_COMPLETED;
	}

	/* The loop here is to allow for several back-to-back state changes. */
	do
	{
		prev_state = rdma_req->state;

		SPDK_DEBUGLOG(rdma, "Request %p entering state %d\n", rdma_req, prev_state);

		switch (rdma_req->state)
		{
		case RDMA_REQUEST_STATE_FREE:
			/* Some external code must kick a request into RDMA_REQUEST_STATE_NEW
			 * to escape this state. */
			break;
		case RDMA_REQUEST_STATE_NEW:
			spdk_trace_record(TRACE_RDMA_REQUEST_STATE_NEW, 0, 0,
							  (uintptr_t)rdma_req, (uintptr_t)rconn);
			rdma_recv = rdma_req->recv;

			/* The first element of the SGL is the Srv command */
			rdma_req->req.cmd = (struct spdk_req_cmd *)rdma_recv->sgl[0].addr;
			memset(rdma_req->req.rsp, 0, sizeof(*rdma_req->req.rsp));

			if (rconn->ibv_state == IBV_QPS_ERR || rconn->conn.state != SPDK_SRV_CONN_ACTIVE)
			{
				rdma_req->state = RDMA_REQUEST_STATE_COMPLETED;
				break;
			}
			SPDK_DEBUGLOG(rdma, "enter RDMA_REQUEST_STATE_NEW\n");

#ifdef SPDK_CONFIG_RDMA_SEND_WITH_INVAL
			rdma_req->rsp.wr.opcode = IBV_WR_SEND;
			rdma_req->rsp.wr.imm_data = 0;
#endif

			/* The next state transition depends on the data transfer needs of this request. */
			rdma_req->req.xfer = spdk_srv_req_get_xfer(&rdma_req->req);

			/* If no data to transfer, ready to execute. */
			if (rdma_req->req.xfer == SPDK_SRV_DATA_NONE)
			{
				rdma_req->state = RDMA_REQUEST_STATE_READY_TO_EXECUTE;
				break;
			}

			rdma_req->state = RDMA_REQUEST_STATE_NEED_BUFFER;
			STAILQ_INSERT_TAIL(&rgroup->group.pending_buf_queue, &rdma_req->req, buf_link);
			break;
		case RDMA_REQUEST_STATE_NEED_BUFFER:
			SPDK_DEBUGLOG(rdma, "enter RDMA_REQUEST_STATE_NEED_BUFFER\n");
			spdk_trace_record(TRACE_RDMA_REQUEST_STATE_NEED_BUFFER, 0, 0,
							  (uintptr_t)rdma_req, (uintptr_t)rconn);

			assert(rdma_req->req.xfer != SPDK_SRV_DATA_NONE);

			if (&rdma_req->req != STAILQ_FIRST(&rgroup->group.pending_buf_queue))
			{
				/* This request needs to wait in line to obtain a buffer */
				break;
			}

			/* Try to get a data buffer */
			rc = srv_rdma_request_parse_sgl(rtransport, device, rdma_req);
			if (rc < 0)
			{
				STAILQ_REMOVE_HEAD(&rgroup->group.pending_buf_queue, buf_link);
				rdma_req->state = RDMA_REQUEST_STATE_READY_TO_COMPLETE;
				break;
			}

			if (!rdma_req->req.data)
			{
				/* No buffers available. */
				rgroup->stat.pending_data_buffer++;
				break;
			}

			STAILQ_REMOVE_HEAD(&rgroup->group.pending_buf_queue, buf_link);

			/* If data is transferring from host to controller and the data didn't
			 * arrive using in capsule data, we need to do a transfer from the host.
			 */
			if (rdma_req->req.xfer == SPDK_SRV_DATA_HOST_TO_CONTROLLER &&
				rdma_req->req.data_from_pool)
			{
				STAILQ_INSERT_TAIL(&rconn->pending_rdma_read_queue, rdma_req, state_link);
				rdma_req->state = RDMA_REQUEST_STATE_DATA_TRANSFER_TO_CONTROLLER_PENDING;
				break;
			}

			rdma_req->state = RDMA_REQUEST_STATE_READY_TO_EXECUTE;
			break;
		case RDMA_REQUEST_STATE_DATA_TRANSFER_TO_CONTROLLER_PENDING:
			SPDK_DEBUGLOG(rdma, "enter RDMA_REQUEST_STATE_DATA_TRANSFER_TO_CONTROLLER_PENDING\n");
			spdk_trace_record(TRACE_RDMA_REQUEST_STATE_DATA_TRANSFER_TO_CONTROLLER_PENDING, 0, 0,
							  (uintptr_t)rdma_req, (uintptr_t)rconn);

			if (rdma_req != STAILQ_FIRST(&rconn->pending_rdma_read_queue))
			{
				/* This request needs to wait in line to perform RDMA */
				break;
			}
			if (rconn->current_send_depth + rdma_req->num_outstanding_data_wr > rconn->max_send_depth || rconn->current_read_depth + rdma_req->num_outstanding_data_wr > rconn->max_read_depth)
			{
				/* We can only have so many WRs outstanding. we have to wait until some finish. */
				rconn->poller->stat.pending_rdma_read++;
				break;
			}

			/* We have already verified that this request is the head of the queue. */
			STAILQ_REMOVE_HEAD(&rconn->pending_rdma_read_queue, state_link);

			rc = request_transfer_in(&rdma_req->req);
			if (!rc)
			{
				rdma_req->state = RDMA_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER;
			}
			else
			{
				rsp->status.sc = SPDK_SRV_SC_INTERNAL_DEVICE_ERROR;
				rdma_req->state = RDMA_REQUEST_STATE_READY_TO_COMPLETE;
			}
			break;
		case RDMA_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER:
			SPDK_DEBUGLOG(rdma, "enter RDMA_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER\n");
			spdk_trace_record(TRACE_RDMA_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER, 0, 0,
							  (uintptr_t)rdma_req, (uintptr_t)rconn);
			/* Some external code must kick a request into RDMA_REQUEST_STATE_READY_TO_EXECUTE
			 * to escape this state. */
			break;
		case RDMA_REQUEST_STATE_READY_TO_EXECUTE:
			spdk_trace_record(TRACE_RDMA_REQUEST_STATE_READY_TO_EXECUTE, 0, 0,
							  (uintptr_t)rdma_req, (uintptr_t)rconn);

			SPDK_DEBUGLOG(rdma, "enter RDMA_REQUEST_STATE_READY_TO_EXECUTE\n");
			rdma_req->state = RDMA_REQUEST_STATE_EXECUTING;
			if (rdma_req->req.cmd->opc == SPDK_CLIENT_OPC_RPC_WRITE)
			{
				srv_rpc_write_request_exec(rdma_req);
			}
			else if (rdma_req->req.cmd->opc == SPDK_CLIENT_OPC_RPC_READ)
			{
				srv_rpc_read_request_exec(rdma_req);
			}
			else
			{
				spdk_srv_request_exec(&rdma_req->req);
			}
			break;
		case RDMA_REQUEST_STATE_EXECUTING:
			spdk_trace_record(TRACE_RDMA_REQUEST_STATE_EXECUTING, 0, 0,
							  (uintptr_t)rdma_req, (uintptr_t)rconn);
			/* Some external code must kick a request into RDMA_REQUEST_STATE_EXECUTED
			 * to escape this state. */
			SPDK_DEBUGLOG(rdma, "enter RDMA_REQUEST_STATE_EXECUTING\n");

			if (rdma_req->req.cmd->opc == SPDK_CLIENT_OPC_RPC_READ)
			{
				spdk_srv_request_exec(&rdma_req->req);
			}
			break;
		case RDMA_REQUEST_STATE_EXECUTED:
			SPDK_DEBUGLOG(rdma, "enter RDMA_REQUEST_STATE_EXECUTED\n");
			spdk_trace_record(TRACE_RDMA_REQUEST_STATE_EXECUTED, 0, 0,
							  (uintptr_t)rdma_req, (uintptr_t)rconn);

			if (rdma_req->req.cmd->opc == SPDK_CLIENT_OPC_RPC_WRITE)
			{
				if (rdma_req != STAILQ_FIRST(&rconn->pending_complete_queue))
				{
					/* This request needs to wait in line to perform RDMA */
					break;
				}
				STAILQ_REMOVE_HEAD(&rconn->pending_complete_queue, state_link);
			}

			if (rsp->status.sc == SPDK_SRV_SC_SUCCESS &&
				rdma_req->req.xfer == SPDK_SRV_DATA_CONTROLLER_TO_HOST)
			{
				STAILQ_INSERT_TAIL(&rconn->pending_rdma_write_queue, rdma_req, state_link);
				rdma_req->state = RDMA_REQUEST_STATE_DATA_TRANSFER_TO_HOST_PENDING;
			}
			else
			{
				rdma_req->state = RDMA_REQUEST_STATE_READY_TO_COMPLETE;
			}

			break;
		case RDMA_REQUEST_STATE_DATA_TRANSFER_TO_HOST_PENDING:
			SPDK_DEBUGLOG(rdma, "enter RDMA_REQUEST_STATE_DATA_TRANSFER_TO_HOST_PENDING\n");
			spdk_trace_record(TRACE_RDMA_REQUEST_STATE_DATA_TRANSFER_TO_HOST_PENDING, 0, 0,
							  (uintptr_t)rdma_req, (uintptr_t)rconn);

			if (rdma_req != STAILQ_FIRST(&rconn->pending_rdma_write_queue))
			{
				/* This request needs to wait in line to perform RDMA */
				break;
			}
			if ((rconn->current_send_depth + rdma_req->num_outstanding_data_wr + 1) >
				rconn->max_send_depth)
			{
				/* We can only have so many WRs outstanding. we have to wait until some finish.
				 * +1 since each request has an additional wr in the resp. */
				rconn->poller->stat.pending_rdma_write++;
				break;
			}

			/* We have already verified that this request is the head of the queue. */
			STAILQ_REMOVE_HEAD(&rconn->pending_rdma_write_queue, state_link);

			/* The data transfer will be kicked off from
			 * RDMA_REQUEST_STATE_READY_TO_COMPLETE state.
			 */
			rdma_req->state = RDMA_REQUEST_STATE_READY_TO_COMPLETE;
			break;
		case RDMA_REQUEST_STATE_READY_TO_COMPLETE:
			SPDK_DEBUGLOG(rdma, "enter RDMA_REQUEST_STATE_READY_TO_COMPLETE\n");
			spdk_trace_record(TRACE_RDMA_REQUEST_STATE_READY_TO_COMPLETE, 0, 0,
							  (uintptr_t)rdma_req, (uintptr_t)rconn);
			rc = request_transfer_out(&rdma_req->req, &data_posted);
			assert(rc == 0); /* No good way to handle this currently */
			if (rc)
			{
				rdma_req->state = RDMA_REQUEST_STATE_COMPLETED;
			}
			else
			{
				rdma_req->state = data_posted ? RDMA_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST : RDMA_REQUEST_STATE_COMPLETING;
			}
			break;
		case RDMA_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST:
			spdk_trace_record(TRACE_RDMA_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST, 0, 0,
							  (uintptr_t)rdma_req, (uintptr_t)rconn);
			/* Some external code must kick a request into RDMA_REQUEST_STATE_COMPLETED
			 * to escape this state. */
			break;
		case RDMA_REQUEST_STATE_COMPLETING:
			SPDK_DEBUGLOG(rdma, "enter RDMA_REQUEST_STATE_COMPLETING\n");
			spdk_trace_record(TRACE_RDMA_REQUEST_STATE_COMPLETING, 0, 0,
							  (uintptr_t)rdma_req, (uintptr_t)rconn);
			/* Some external code must kick a request into RDMA_REQUEST_STATE_COMPLETED
			 * to escape this state. */
			break;
		case RDMA_REQUEST_STATE_COMPLETED:
			SPDK_DEBUGLOG(rdma, "enter RDMA_REQUEST_STATE_COMPLETED\n");
			spdk_trace_record(TRACE_RDMA_REQUEST_STATE_COMPLETED, 0, 0,
							  (uintptr_t)rdma_req, (uintptr_t)rconn);

			rconn->poller->stat.request_latency += spdk_get_ticks() - rdma_req->receive_tsc;
			_srv_rdma_request_free(rdma_req, rtransport);
			break;
		case RDMA_REQUEST_NUM_STATES:
		default:
			assert(0);
			break;
		}

		if (rdma_req->state != prev_state)
		{
			progress = true;
		}
	} while (rdma_req->state != prev_state);

	return progress;
}

/* Public API callbacks begin here */

#define SPDK_SRV_RDMA_DEFAULT_MAX_QUEUE_DEPTH 4096
#define SPDK_SRV_RDMA_DEFAULT_AQ_DEPTH 4096
#define SPDK_SRV_RDMA_DEFAULT_SRQ_DEPTH 4096
#define SPDK_SRV_RDMA_DEFAULT_MAX_CONNS_PER_TGT 65535
#define SPDK_SRV_RDMA_DEFAULT_IN_CAPSULE_DATA_SIZE 8192
#define SPDK_SRV_RDMA_DEFAULT_MAX_IO_SIZE 131072
#define SPDK_SRV_RDMA_MIN_IO_BUFFER_SIZE (SPDK_SRV_RDMA_DEFAULT_MAX_IO_SIZE / SPDK_SRV_MAX_SGL_ENTRIES)
#define SPDK_SRV_RDMA_DEFAULT_NUM_SHARED_BUFFERS 4095
#define SPDK_SRV_RDMA_DEFAULT_BUFFER_CACHE_SIZE 32
#define SPDK_SRV_RDMA_DEFAULT_NO_SRQ false
#define SPDK_SRV_RDMA_DIF_INSERT_OR_STRIP false
#define SPDK_SRV_RDMA_ACCEPTOR_BACKLOG 100
#define SPDK_SRV_RDMA_DEFAULT_ABORT_TIMEOUT_SEC 1
#define SPDK_SRV_RDMA_DEFAULT_NO_WR_BATCHING true // try set this

static void
srv_rdma_opts_init(struct spdk_srv_transport_opts *opts)
{
	opts->max_queue_depth = SPDK_SRV_RDMA_DEFAULT_MAX_QUEUE_DEPTH;
	opts->max_conns_per_tgt = SPDK_SRV_RDMA_DEFAULT_MAX_CONNS_PER_TGT;
	opts->in_capsule_data_size = SPDK_SRV_RDMA_DEFAULT_IN_CAPSULE_DATA_SIZE;
	opts->max_io_size = SPDK_SRV_RDMA_DEFAULT_MAX_IO_SIZE;
	opts->io_unit_size = SPDK_SRV_RDMA_MIN_IO_BUFFER_SIZE;
	opts->max_aq_depth = SPDK_SRV_RDMA_DEFAULT_AQ_DEPTH;
	opts->num_shared_buffers = SPDK_SRV_RDMA_DEFAULT_NUM_SHARED_BUFFERS;
	opts->buf_cache_size = SPDK_SRV_RDMA_DEFAULT_BUFFER_CACHE_SIZE;
	opts->dif_insert_or_strip = SPDK_SRV_RDMA_DIF_INSERT_OR_STRIP;
	opts->abort_timeout_sec = SPDK_SRV_RDMA_DEFAULT_ABORT_TIMEOUT_SEC;
	opts->transport_specific = NULL;
}

static int srv_rdma_destroy(struct spdk_srv_transport *transport,
							spdk_srv_transport_destroy_done_cb cb_fn, void *cb_arg);

static inline bool
srv_rdma_is_rxe_device(struct spdk_srv_rdma_device *device)
{
	return device->attr.vendor_id == SPDK_RDMA_RXE_VENDOR_ID_OLD ||
		   device->attr.vendor_id == SPDK_RDMA_RXE_VENDOR_ID_NEW;
}

static int
srv_rdma_accept(void *ctx);

static struct spdk_srv_transport *
srv_rdma_create(struct spdk_srv_transport_opts *opts)
{
	int rc;
	struct spdk_srv_rdma_transport *rtransport;
	struct spdk_srv_rdma_device *device, *tmp;
	struct ibv_context **contexts;
	uint32_t i;
	int flag;
	uint32_t sge_count;
	uint32_t min_shared_buffers;
	uint32_t min_in_capsule_data_size;
	int max_device_sge = SPDK_SRV_MAX_SGL_ENTRIES;
	pthread_mutexattr_t attr;

	rtransport = calloc(1, sizeof(*rtransport));
	if (!rtransport)
	{
		return NULL;
	}

	if (pthread_mutexattr_init(&attr))
	{
		SPDK_ERRLOG("pthread_mutexattr_init() failed\n");
		free(rtransport);
		return NULL;
	}

	if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE))
	{
		SPDK_ERRLOG("pthread_mutexattr_settype() failed\n");
		pthread_mutexattr_destroy(&attr);
		free(rtransport);
		return NULL;
	}

	if (pthread_mutex_init(&rtransport->lock, &attr))
	{
		SPDK_ERRLOG("pthread_mutex_init() failed\n");
		pthread_mutexattr_destroy(&attr);
		free(rtransport);
		return NULL;
	}

	pthread_mutexattr_destroy(&attr);

	TAILQ_INIT(&rtransport->devices);
	TAILQ_INIT(&rtransport->ports);
	TAILQ_INIT(&rtransport->poll_groups);

	rtransport->transport.ops = &spdk_srv_transport_rdma;
	rtransport->rdma_opts.num_cqe = DEFAULT_SRV_RDMA_CQ_SIZE;
	rtransport->rdma_opts.max_srq_depth = SPDK_SRV_RDMA_DEFAULT_SRQ_DEPTH;
	rtransport->rdma_opts.no_srq = SPDK_SRV_RDMA_DEFAULT_NO_SRQ;
	rtransport->rdma_opts.acceptor_backlog = SPDK_SRV_RDMA_ACCEPTOR_BACKLOG;
	rtransport->rdma_opts.no_wr_batching = SPDK_SRV_RDMA_DEFAULT_NO_WR_BATCHING;
	if (opts->transport_specific != NULL &&
		spdk_json_decode_object_relaxed(opts->transport_specific, rdma_transport_opts_decoder,
										SPDK_COUNTOF(rdma_transport_opts_decoder),
										&rtransport->rdma_opts))
	{
		SPDK_ERRLOG("spdk_json_decode_object_relaxed failed\n");
		srv_rdma_destroy(&rtransport->transport, NULL, NULL);
		return NULL;
	}

	SPDK_INFOLOG(rdma, "*** RDMA Transport Init ***\n"
					   "  Transport opts:  max_ioq_depth=%d, max_io_size=%d,\n"
					   "  max_io_conns_per_ctrlr=%d, io_unit_size=%d,\n"
					   "  in_capsule_data_size=%d, max_aq_depth=%d,\n"
					   "  num_shared_buffers=%d, num_cqe=%d, max_srq_depth=%d, no_srq=%d,"
					   "  acceptor_backlog=%d, no_wr_batching=%d abort_timeout_sec=%d\n",
				 opts->max_queue_depth,
				 opts->max_io_size,
				 opts->max_conns_per_tgt - 1,
				 opts->io_unit_size,
				 opts->in_capsule_data_size,
				 opts->max_aq_depth,
				 opts->num_shared_buffers,
				 rtransport->rdma_opts.num_cqe,
				 rtransport->rdma_opts.max_srq_depth,
				 rtransport->rdma_opts.no_srq,
				 rtransport->rdma_opts.acceptor_backlog,
				 rtransport->rdma_opts.no_wr_batching,
				 opts->abort_timeout_sec);

	/* I/O unit size cannot be larger than max I/O size */
	if (opts->io_unit_size > opts->max_io_size)
	{
		opts->io_unit_size = opts->max_io_size;
	}

	if (rtransport->rdma_opts.acceptor_backlog <= 0)
	{
		SPDK_ERRLOG("The acceptor backlog cannot be less than 1, setting to the default value of (%d).\n",
					SPDK_SRV_RDMA_ACCEPTOR_BACKLOG);
		rtransport->rdma_opts.acceptor_backlog = SPDK_SRV_RDMA_ACCEPTOR_BACKLOG;
	}

	if (opts->num_shared_buffers < (SPDK_SRV_MAX_SGL_ENTRIES * 2))
	{
		SPDK_ERRLOG("The number of shared data buffers (%d) is less than"
					"the minimum number required to guarantee that forward progress can be made (%d)\n",
					opts->num_shared_buffers, (SPDK_SRV_MAX_SGL_ENTRIES * 2));
		srv_rdma_destroy(&rtransport->transport, NULL, NULL);
		return NULL;
	}

	min_shared_buffers = spdk_env_get_core_count() * opts->buf_cache_size;
	if (min_shared_buffers > opts->num_shared_buffers)
	{
		SPDK_ERRLOG("There are not enough buffers to satisfy"
					"per-poll group caches for each thread. (%" PRIu32 ")"
					"supplied. (%" PRIu32 ") required\n",
					opts->num_shared_buffers, min_shared_buffers);
		SPDK_ERRLOG("Please specify a larger number of shared buffers\n");
		srv_rdma_destroy(&rtransport->transport, NULL, NULL);
		return NULL;
	}

	sge_count = opts->max_io_size / opts->io_unit_size;
	if (sge_count > SRV_DEFAULT_TX_SGE)
	{
		SPDK_ERRLOG("Unsupported IO Unit size specified, %d bytes\n", opts->io_unit_size);
		srv_rdma_destroy(&rtransport->transport, NULL, NULL);
		return NULL;
	}

	min_in_capsule_data_size = sizeof(struct spdk_req_sgl_descriptor) * SPDK_SRV_MAX_SGL_ENTRIES;
	if (opts->in_capsule_data_size < min_in_capsule_data_size)
	{
		SPDK_WARNLOG("In capsule data size is set to %u, this is minimum size required to support msdbd=16\n",
					 min_in_capsule_data_size);
		opts->in_capsule_data_size = min_in_capsule_data_size;
	}

	rtransport->event_channel = rdma_create_event_channel();
	if (rtransport->event_channel == NULL)
	{
		SPDK_ERRLOG("rdma_create_event_channel() failed, %s\n", spdk_strerror(errno));
		srv_rdma_destroy(&rtransport->transport, NULL, NULL);
		return NULL;
	}

	flag = fcntl(rtransport->event_channel->fd, F_GETFL);
	if (fcntl(rtransport->event_channel->fd, F_SETFL, flag | O_NONBLOCK) < 0)
	{
		SPDK_ERRLOG("fcntl can't set nonblocking mode for socket, fd: %d (%s)\n",
					rtransport->event_channel->fd, spdk_strerror(errno));
		srv_rdma_destroy(&rtransport->transport, NULL, NULL);
		return NULL;
	}

	rtransport->data_wr_pool = spdk_mempool_create("spdk_srv_rdma_wr_data",
												   opts->max_queue_depth * SPDK_SRV_MAX_SGL_ENTRIES,
												   sizeof(struct spdk_srv_rdma_request_data),
												   SPDK_MEMPOOL_DEFAULT_CACHE_SIZE,
												   SPDK_ENV_SOCKET_ID_ANY);
	if (!rtransport->data_wr_pool)
	{
		SPDK_ERRLOG("Unable to allocate work request pool for poll group\n");
		srv_rdma_destroy(&rtransport->transport, NULL, NULL);
		return NULL;
	}

	contexts = rdma_get_devices(NULL);
	if (contexts == NULL)
	{
		SPDK_ERRLOG("rdma_get_devices() failed: %s (%d)\n", spdk_strerror(errno), errno);
		srv_rdma_destroy(&rtransport->transport, NULL, NULL);
		return NULL;
	}

	i = 0;
	rc = 0;
	while (contexts[i] != NULL)
	{
		device = calloc(1, sizeof(*device));
		if (!device)
		{
			SPDK_ERRLOG("Unable to allocate memory for RDMA devices.\n");
			rc = -ENOMEM;
			break;
		}
		device->context = contexts[i];
		rc = ibv_query_device(device->context, &device->attr);
		if (rc < 0)
		{
			SPDK_ERRLOG("Failed to query RDMA device attributes.\n");
			free(device);
			break;
		}

		max_device_sge = spdk_min(max_device_sge, device->attr.max_sge);

#ifdef SPDK_CONFIG_RDMA_SEND_WITH_INVAL
		if ((device->attr.device_cap_flags & IBV_DEVICE_MEM_MGT_EXTENSIONS) == 0)
		{
			SPDK_WARNLOG("The libibverbs on this system supports SEND_WITH_INVALIDATE,");
			SPDK_WARNLOG("but the device with vendor ID %u does not.\n", device->attr.vendor_id);
		}

		/**
		 * The vendor ID is assigned by the IEEE and an ID of 0 implies Soft-RoCE.
		 * The Soft-RoCE RXE driver does not currently support send with invalidate,
		 * but incorrectly reports that it does. There are changes making their way
		 * through the kernel now that will enable this feature. When they are merged,
		 * we can conditionally enable this feature.
		 *
		 * TODO: enable this for versions of the kernel rxe driver that support it.
		 */
		if (srv_rdma_is_rxe_device(device))
		{
			device->attr.device_cap_flags &= ~(IBV_DEVICE_MEM_MGT_EXTENSIONS);
		}
#endif

		/* set up device context async ev fd as NON_BLOCKING */
		flag = fcntl(device->context->async_fd, F_GETFL);
		rc = fcntl(device->context->async_fd, F_SETFL, flag | O_NONBLOCK);
		if (rc < 0)
		{
			SPDK_ERRLOG("Failed to set context async fd to NONBLOCK.\n");
			free(device);
			break;
		}

		TAILQ_INSERT_TAIL(&rtransport->devices, device, link);
		i++;

		device->pd = ibv_alloc_pd(device->context);

		if (!device->pd)
		{
			SPDK_ERRLOG("Unable to allocate protection domain.\n");
			rc = -ENOMEM;
			break;
		}

		assert(device->map == NULL);

		device->map = spdk_rdma_create_mem_map(device->pd, 0, SPDK_RDMA_MEMORY_MAP_ROLE_TARGET);
		if (!device->map)
		{
			SPDK_ERRLOG("Unable to allocate memory map for listen address\n");
			rc = -ENOMEM;
			break;
		}

		assert(device->map != NULL);
		assert(device->pd != NULL);
	}
	rdma_free_devices(contexts);

	if (opts->io_unit_size * max_device_sge < opts->max_io_size)
	{
		/* divide and round up. */
		opts->io_unit_size = (opts->max_io_size + max_device_sge - 1) / max_device_sge;

		/* round up to the nearest 4k. */
		opts->io_unit_size = (opts->io_unit_size + SRV_DATA_BUFFER_ALIGNMENT - 1) & ~SRV_DATA_BUFFER_MASK;

		opts->io_unit_size = spdk_max(opts->io_unit_size, SPDK_SRV_RDMA_MIN_IO_BUFFER_SIZE);
		SPDK_NOTICELOG("Adjusting the io unit size to fit the device's maximum I/O size. New I/O unit size %u\n",
					   opts->io_unit_size);
	}

	if (rc < 0)
	{
		srv_rdma_destroy(&rtransport->transport, NULL, NULL);
		return NULL;
	}

	/* Set up poll descriptor array to monitor events from RDMA and IB
	 * in a single poll syscall
	 */
	rtransport->npoll_fds = i + 1;
	i = 0;
	rtransport->poll_fds = calloc(rtransport->npoll_fds, sizeof(struct pollfd));
	if (rtransport->poll_fds == NULL)
	{
		SPDK_ERRLOG("poll_fds allocation failed\n");
		srv_rdma_destroy(&rtransport->transport, NULL, NULL);
		return NULL;
	}

	rtransport->poll_fds[i].fd = rtransport->event_channel->fd;
	rtransport->poll_fds[i++].events = POLLIN;

	TAILQ_FOREACH_SAFE(device, &rtransport->devices, link, tmp)
	{
		rtransport->poll_fds[i].fd = device->context->async_fd;
		rtransport->poll_fds[i++].events = POLLIN;
	}

	rtransport->accept_poller = SPDK_POLLER_REGISTER(srv_rdma_accept, &rtransport->transport,
													 opts->acceptor_poll_rate);
	if (!rtransport->accept_poller)
	{
		srv_rdma_destroy(&rtransport->transport, NULL, NULL);
		return NULL;
	}

	return &rtransport->transport;
}

static void
srv_rdma_dump_opts(struct spdk_srv_transport *transport, struct spdk_json_write_ctx *w)
{
	struct spdk_srv_rdma_transport *rtransport;
	assert(w != NULL);

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_srv_rdma_transport, transport);
	spdk_json_write_named_uint32(w, "max_srq_depth", rtransport->rdma_opts.max_srq_depth);
	spdk_json_write_named_bool(w, "no_srq", rtransport->rdma_opts.no_srq);
	if (rtransport->rdma_opts.no_srq == true)
	{
		spdk_json_write_named_int32(w, "num_cqe", rtransport->rdma_opts.num_cqe);
	}
	spdk_json_write_named_int32(w, "acceptor_backlog", rtransport->rdma_opts.acceptor_backlog);
	spdk_json_write_named_bool(w, "no_wr_batching", rtransport->rdma_opts.no_wr_batching);
}

static int
srv_rdma_destroy(struct spdk_srv_transport *transport,
				 spdk_srv_transport_destroy_done_cb cb_fn, void *cb_arg)
{
	struct spdk_srv_rdma_transport *rtransport;
	struct spdk_srv_rdma_port *port, *port_tmp;
	struct spdk_srv_rdma_device *device, *device_tmp;

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_srv_rdma_transport, transport);

	TAILQ_FOREACH_SAFE(port, &rtransport->ports, link, port_tmp)
	{
		TAILQ_REMOVE(&rtransport->ports, port, link);
		rdma_destroy_id(port->id);
		free(port);
	}

	if (rtransport->poll_fds != NULL)
	{
		free(rtransport->poll_fds);
	}

	if (rtransport->event_channel != NULL)
	{
		rdma_destroy_event_channel(rtransport->event_channel);
	}

	TAILQ_FOREACH_SAFE(device, &rtransport->devices, link, device_tmp)
	{
		TAILQ_REMOVE(&rtransport->devices, device, link);
		spdk_rdma_free_mem_map(&device->map);
		if (device->pd)
		{
			ibv_dealloc_pd(device->pd);
		}
		free(device);
	}

	if (rtransport->data_wr_pool != NULL)
	{
		if (spdk_mempool_count(rtransport->data_wr_pool) !=
			(transport->opts.max_queue_depth * SPDK_SRV_MAX_SGL_ENTRIES))
		{
			SPDK_ERRLOG("transport wr pool count is %zu but should be %u\n",
						spdk_mempool_count(rtransport->data_wr_pool),
						transport->opts.max_queue_depth * SPDK_SRV_MAX_SGL_ENTRIES);
		}
	}

	spdk_mempool_free(rtransport->data_wr_pool);

	spdk_poller_unregister(&rtransport->accept_poller);
	pthread_mutex_destroy(&rtransport->lock);
	free(rtransport);

	if (cb_fn)
	{
		cb_fn(cb_arg);
	}
	return 0;
}

static int
srv_rdma_trid_from_cm_id(struct rdma_cm_id *id,
						 struct spdk_srv_transport_id *trid,
						 bool peer);

static int
srv_rdma_listen(struct spdk_srv_transport *transport, const struct spdk_srv_transport_id *trid,
				struct spdk_srv_listen_opts *listen_opts)
{
	struct spdk_srv_rdma_transport *rtransport;
	struct spdk_srv_rdma_device *device;
	struct spdk_srv_rdma_port *port;
	struct addrinfo *res;
	struct addrinfo hints;
	int family;
	int rc;

	if (!strlen(trid->trsvcid))
	{
		SPDK_ERRLOG("Service id is required\n");
		return -EINVAL;
	}

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_srv_rdma_transport, transport);
	assert(rtransport->event_channel != NULL);

	pthread_mutex_lock(&rtransport->lock);
	port = calloc(1, sizeof(*port));
	if (!port)
	{
		SPDK_ERRLOG("Port allocation failed\n");
		pthread_mutex_unlock(&rtransport->lock);
		return -ENOMEM;
	}

	port->trid = trid;

	switch (trid->adrfam)
	{
	case SPDK_SRV_ADRFAM_IPV4:
		family = AF_INET;
		break;
	case SPDK_SRV_ADRFAM_IPV6:
		family = AF_INET6;
		break;
	default:
		SPDK_ERRLOG("Unhandled ADRFAM %d\n", trid->adrfam);
		free(port);
		pthread_mutex_unlock(&rtransport->lock);
		return -EINVAL;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;

	rc = getaddrinfo(trid->traddr, trid->trsvcid, &hints, &res);
	if (rc)
	{
		SPDK_ERRLOG("getaddrinfo failed: %s (%d)\n", gai_strerror(rc), rc);
		free(port);
		pthread_mutex_unlock(&rtransport->lock);
		return -EINVAL;
	}

	rc = rdma_create_id(rtransport->event_channel, &port->id, port, RDMA_PS_TCP);
	if (rc < 0)
	{
		SPDK_ERRLOG("rdma_create_id() failed\n");
		freeaddrinfo(res);
		free(port);
		pthread_mutex_unlock(&rtransport->lock);
		return rc;
	}

	rc = rdma_bind_addr(port->id, res->ai_addr);
	freeaddrinfo(res);

	if (rc < 0)
	{
		SPDK_ERRLOG("rdma_bind_addr() failed\n");
		rdma_destroy_id(port->id);
		free(port);
		pthread_mutex_unlock(&rtransport->lock);
		return rc;
	}

	if (!port->id->verbs)
	{
		SPDK_ERRLOG("ibv_context is null\n");
		rdma_destroy_id(port->id);
		free(port);
		pthread_mutex_unlock(&rtransport->lock);
		return -1;
	}

	rc = rdma_listen(port->id, rtransport->rdma_opts.acceptor_backlog);
	if (rc < 0)
	{
		SPDK_ERRLOG("rdma_listen() failed\n");
		rdma_destroy_id(port->id);
		free(port);
		pthread_mutex_unlock(&rtransport->lock);
		return rc;
	}

	TAILQ_FOREACH(device, &rtransport->devices, link)
	{
		if (device->context == port->id->verbs)
		{
			port->device = device;
			break;
		}
	}
	if (!port->device)
	{
		SPDK_ERRLOG("Accepted a connection with verbs %p, but unable to find a corresponding device.\n",
					port->id->verbs);
		rdma_destroy_id(port->id);
		free(port);
		pthread_mutex_unlock(&rtransport->lock);
		return -EINVAL;
	}

	SPDK_NOTICELOG("*** Srv/RDMA Target Listening on %s port %s ***\n",
				   trid->traddr, trid->trsvcid);

	TAILQ_INSERT_TAIL(&rtransport->ports, port, link);
	pthread_mutex_unlock(&rtransport->lock);
	return 0;
}

static void
srv_rdma_stop_listen(struct spdk_srv_transport *transport,
					 const struct spdk_srv_transport_id *trid)
{
	struct spdk_srv_rdma_transport *rtransport;
	struct spdk_srv_rdma_port *port, *tmp;

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_srv_rdma_transport, transport);

	pthread_mutex_lock(&rtransport->lock);
	TAILQ_FOREACH_SAFE(port, &rtransport->ports, link, tmp)
	{
		if (spdk_srv_transport_id_compare(port->trid, trid) == 0)
		{
			TAILQ_REMOVE(&rtransport->ports, port, link);
			rdma_destroy_id(port->id);
			free(port);
			break;
		}
	}

	pthread_mutex_unlock(&rtransport->lock);
}

static void
srv_rdma_conn_process_pending(struct spdk_srv_rdma_transport *rtransport,
							  struct spdk_srv_rdma_conn *rconn, bool drain)
{
	struct spdk_srv_request *req, *tmp;
	struct spdk_srv_rdma_request *rdma_req, *req_tmp;
	struct spdk_srv_rdma_resources *resources;
	struct spdk_req_cpl *rsp;

	/* We process I/O in the data transfer pending queue at the highest priority. RDMA reads first */
	STAILQ_FOREACH_SAFE(rdma_req, &rconn->pending_rdma_read_queue, state_link, req_tmp)
	{
		if (srv_rdma_request_process(rtransport, rdma_req) == false && drain == false)
		{
			break;
		}
	}

	/* Then RDMA writes since reads have stronger restrictions than writes */
	STAILQ_FOREACH_SAFE(rdma_req, &rconn->pending_rdma_write_queue, state_link, req_tmp)
	{
		if (srv_rdma_request_process(rtransport, rdma_req) == false && drain == false)
		{
			break;
		}
	}

	/* Then we handle request waiting on memory buffers. */
	STAILQ_FOREACH_SAFE(req, &rconn->poller->group->group.pending_buf_queue, buf_link, tmp)
	{
		rdma_req = SPDK_CONTAINEROF(req, struct spdk_srv_rdma_request, req);
		if (srv_rdma_request_process(rtransport, rdma_req) == false && drain == false)
		{
			break;
		}
	}

	resources = rconn->resources;
	while (!STAILQ_EMPTY(&resources->free_queue) && !STAILQ_EMPTY(&resources->incoming_queue))
	{
		rdma_req = STAILQ_FIRST(&resources->free_queue);
		STAILQ_REMOVE_HEAD(&resources->free_queue, state_link);
		rdma_req->recv = STAILQ_FIRST(&resources->incoming_queue);
		STAILQ_REMOVE_HEAD(&resources->incoming_queue, link);

		if (rconn->srq != NULL)
		{
			rdma_req->req.conn = &rdma_req->recv->conn->conn;
			rdma_req->recv->conn->qd++;
		}
		else
		{
			rconn->qd++;
		}

		rdma_req->receive_tsc = rdma_req->recv->receive_tsc;
		rdma_req->state = RDMA_REQUEST_STATE_NEW;
		if (srv_rdma_request_process(rtransport, rdma_req) == false)
		{
			break;
		}
	}
	if (!STAILQ_EMPTY(&resources->incoming_queue) && STAILQ_EMPTY(&resources->free_queue))
	{
		rconn->poller->stat.pending_free_request++;
	}
}

static inline bool
srv_rdma_can_ignore_last_wqe_reached(struct spdk_srv_rdma_device *device)
{
	/* iWARP transport and SoftRoCE driver don't support LAST_WQE_REACHED ibv async event */
	return srv_rdma_is_rxe_device(device) ||
		   device->context->device->transport_type == IBV_TRANSPORT_IWARP;
}

static void
srv_rdma_destroy_drained_conn(struct spdk_srv_rdma_conn *rconn)
{
	struct spdk_srv_rdma_transport *rtransport = SPDK_CONTAINEROF(rconn->conn.transport,
																  struct spdk_srv_rdma_transport, transport);

	srv_rdma_conn_process_pending(rtransport, rconn, true);

	/* nvmr_rdma_close_conn is not called */
	if (!rconn->to_close)
	{
		return;
	}

	/* In non SRQ path, we will reach rconn->max_queue_depth. In SRQ path, we will get the last_wqe event. */
	if (rconn->current_send_depth != 0)
	{
		return;
	}

	if (rconn->srq == NULL && rconn->current_recv_depth != rconn->max_queue_depth)
	{
		return;
	}

	if (rconn->srq != NULL && rconn->last_wqe_reached == false &&
		!srv_rdma_can_ignore_last_wqe_reached(rconn->device))
	{
		return;
	}

	assert(rconn->conn.state == SPDK_SRV_CONN_ERROR);

	srv_rdma_conn_destroy(rconn);
}

static int
srv_rdma_disconnect(struct rdma_cm_event *evt)
{
	struct spdk_srv_conn *conn;
	struct spdk_srv_rdma_conn *rconn;

	if (evt->id == NULL)
	{
		SPDK_ERRLOG("disconnect request: missing cm_id\n");
		return -1;
	}

	conn = evt->id->context;
	if (conn == NULL)
	{
		SPDK_ERRLOG("disconnect request: no active connection\n");
		return -1;
	}

	rconn = SPDK_CONTAINEROF(conn, struct spdk_srv_rdma_conn, conn);

	spdk_trace_record(TRACE_RDMA_QP_DISCONNECT, 0, 0, (uintptr_t)rconn);

	spdk_srv_conn_disconnect(&rconn->conn, NULL, NULL);

	return 0;
}

#ifdef DEBUG
static const char *CM_EVENT_STR[] = {
	"RDMA_CM_EVENT_ADDR_RESOLVED",
	"RDMA_CM_EVENT_ADDR_ERROR",
	"RDMA_CM_EVENT_ROUTE_RESOLVED",
	"RDMA_CM_EVENT_ROUTE_ERROR",
	"RDMA_CM_EVENT_CONNECT_REQUEST",
	"RDMA_CM_EVENT_CONNECT_RESPONSE",
	"RDMA_CM_EVENT_CONNECT_ERROR",
	"RDMA_CM_EVENT_UNREACHABLE",
	"RDMA_CM_EVENT_REJECTED",
	"RDMA_CM_EVENT_ESTABLISHED",
	"RDMA_CM_EVENT_DISCONNECTED",
	"RDMA_CM_EVENT_DEVICE_REMOVAL",
	"RDMA_CM_EVENT_MULTICAST_JOIN",
	"RDMA_CM_EVENT_MULTICAST_ERROR",
	"RDMA_CM_EVENT_ADDR_CHANGE",
	"RDMA_CM_EVENT_TIMEWAIT_EXIT"};
#endif /* DEBUG */

static void
srv_rdma_disconnect_conns_on_port(struct spdk_srv_rdma_transport *rtransport,
								  struct spdk_srv_rdma_port *port)
{
	struct spdk_srv_rdma_poll_group *rgroup;
	struct spdk_srv_rdma_poller *rpoller;
	struct spdk_srv_rdma_conn *rconn;

	TAILQ_FOREACH(rgroup, &rtransport->poll_groups, link)
	{
		TAILQ_FOREACH(rpoller, &rgroup->pollers, link)
		{
			TAILQ_FOREACH(rconn, &rpoller->conns, link)
			{
				if (rconn->listen_id == port->id)
				{
					spdk_srv_conn_disconnect(&rconn->conn, NULL, NULL);
				}
			}
		}
	}
}

static bool
srv_rdma_handle_cm_event_addr_change(struct spdk_srv_transport *transport,
									 struct rdma_cm_event *event)
{
	const struct spdk_srv_transport_id *trid;
	struct spdk_srv_rdma_port *port;
	struct spdk_srv_rdma_transport *rtransport;
	bool event_acked = false;

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_srv_rdma_transport, transport);
	TAILQ_FOREACH(port, &rtransport->ports, link)
	{
		if (port->id == event->id)
		{
			SPDK_ERRLOG("ADDR_CHANGE: IP %s:%s migrated\n", port->trid->traddr, port->trid->trsvcid);
			rdma_ack_cm_event(event);
			event_acked = true;
			trid = port->trid;
			break;
		}
	}

	if (event_acked)
	{
		srv_rdma_disconnect_conns_on_port(rtransport, port);

		srv_rdma_stop_listen(transport, trid);
		srv_rdma_listen(transport, trid, NULL);
	}

	return event_acked;
}

static void
srv_rdma_handle_cm_event_port_removal(struct spdk_srv_transport *transport,
									  struct rdma_cm_event *event)
{
	struct spdk_srv_rdma_port *port;
	struct spdk_srv_rdma_transport *rtransport;

	port = event->id->context;
	rtransport = SPDK_CONTAINEROF(transport, struct spdk_srv_rdma_transport, transport);

	SPDK_NOTICELOG("Port %s:%s is being removed\n", port->trid->traddr, port->trid->trsvcid);

	srv_rdma_disconnect_conns_on_port(rtransport, port);

	rdma_ack_cm_event(event);

	while (spdk_srv_transport_stop_listen(transport, port->trid) == 0)
	{
		;
	}
}

static void
srv_process_cm_event(struct spdk_srv_transport *transport)
{
	struct spdk_srv_rdma_transport *rtransport;
	struct rdma_cm_event *event;
	int rc;
	bool event_acked;

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_srv_rdma_transport, transport);

	if (rtransport->event_channel == NULL)
	{
		return;
	}

	while (1)
	{
		event_acked = false;
		rc = rdma_get_cm_event(rtransport->event_channel, &event);
		if (rc)
		{
			if (errno != EAGAIN && errno != EWOULDBLOCK)
			{
				SPDK_ERRLOG("Acceptor Event Error: %s\n", spdk_strerror(errno));
			}
			break;
		}

		SPDK_DEBUGLOG(rdma, "Acceptor Event: %s\n", CM_EVENT_STR[event->event]);

		spdk_trace_record(TRACE_RDMA_CM_ASYNC_EVENT, 0, 0, 0, event->event);

		switch (event->event)
		{
		case RDMA_CM_EVENT_ADDR_RESOLVED:
		case RDMA_CM_EVENT_ADDR_ERROR:
		case RDMA_CM_EVENT_ROUTE_RESOLVED:
		case RDMA_CM_EVENT_ROUTE_ERROR:
			/* No action required. The target never attempts to resolve routes. */
			break;
		case RDMA_CM_EVENT_CONNECT_REQUEST:
			rc = srv_rdma_connect(transport, event);
			if (rc < 0)
			{
				SPDK_ERRLOG("Unable to process connect event. rc: %d\n", rc);
				break;
			}
			break;
		case RDMA_CM_EVENT_CONNECT_RESPONSE:
			/* The target never initiates a new connection. So this will not occur. */
			break;
		case RDMA_CM_EVENT_CONNECT_ERROR:
			/* Can this happen? The docs say it can, but not sure what causes it. */
			break;
		case RDMA_CM_EVENT_UNREACHABLE:
		case RDMA_CM_EVENT_REJECTED:
			/* These only occur on the client side. */
			break;
		case RDMA_CM_EVENT_ESTABLISHED:
			/* TODO: Should we be waiting for this event anywhere? */
			break;
		case RDMA_CM_EVENT_DISCONNECTED:
			rc = srv_rdma_disconnect(event);
			if (rc < 0)
			{
				SPDK_ERRLOG("Unable to process disconnect event. rc: %d\n", rc);
				break;
			}
			break;
		case RDMA_CM_EVENT_DEVICE_REMOVAL:
			/* In case of device removal, kernel IB part triggers IBV_EVENT_DEVICE_FATAL
			 * which triggers RDMA_CM_EVENT_DEVICE_REMOVAL on all cma_id’s.
			 * Once these events are sent to SPDK, we should release all IB resources and
			 * don't make attempts to call any ibv_query/modify/create functions. We can only call
			 * ibv_destroy* functions to release user space memory allocated by IB. All kernel
			 * resources are already cleaned. */
			if (event->id->qp)
			{
				/* If rdma_cm event has a valid `qp` pointer then the event refers to the
				 * corresponding conn. Otherwise the event refers to a listening device */
				rc = srv_rdma_disconnect(event);
				if (rc < 0)
				{
					SPDK_ERRLOG("Unable to process disconnect event. rc: %d\n", rc);
					break;
				}
			}
			else
			{
				srv_rdma_handle_cm_event_port_removal(transport, event);
				event_acked = true;
			}
			break;
		case RDMA_CM_EVENT_MULTICAST_JOIN:
		case RDMA_CM_EVENT_MULTICAST_ERROR:
			/* Multicast is not used */
			break;
		case RDMA_CM_EVENT_ADDR_CHANGE:
			event_acked = srv_rdma_handle_cm_event_addr_change(transport, event);
			break;
		case RDMA_CM_EVENT_TIMEWAIT_EXIT:
			/* For now, do nothing. The target never re-uses queue pairs. */
			break;
		default:
			SPDK_ERRLOG("Unexpected Acceptor Event [%d]\n", event->event);
			break;
		}
		if (!event_acked)
		{
			rdma_ack_cm_event(event);
		}
	}
}

static void
srv_rdma_handle_last_wqe_reached(struct spdk_srv_rdma_conn *rconn)
{
	rconn->last_wqe_reached = true;
	srv_rdma_destroy_drained_conn(rconn);
}

static void
srv_rdma_conn_process_ibv_event(void *ctx)
{
	struct spdk_srv_rdma_ibv_event_ctx *event_ctx = ctx;

	if (event_ctx->rconn)
	{
		STAILQ_REMOVE(&event_ctx->rconn->ibv_events, event_ctx, spdk_srv_rdma_ibv_event_ctx, link);
		if (event_ctx->cb_fn)
		{
			event_ctx->cb_fn(event_ctx->rconn);
		}
	}
	free(event_ctx);
}

static int
srv_rdma_send_conn_async_event(struct spdk_srv_rdma_conn *rconn,
							   spdk_srv_rdma_conn_ibv_event fn)
{
	struct spdk_srv_rdma_ibv_event_ctx *ctx;
	struct spdk_thread *thr = NULL;
	int rc;

	if (rconn->conn.group)
	{
		thr = rconn->conn.group->thread;
	}
	else if (rconn->destruct_channel)
	{
		thr = spdk_io_channel_get_thread(rconn->destruct_channel);
	}

	if (!thr)
	{
		SPDK_DEBUGLOG(rdma, "rconn %p has no thread\n", rconn);
		return -EINVAL;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
	{
		return -ENOMEM;
	}

	ctx->rconn = rconn;
	ctx->cb_fn = fn;
	STAILQ_INSERT_TAIL(&rconn->ibv_events, ctx, link);

	rc = spdk_thread_send_msg(thr, srv_rdma_conn_process_ibv_event, ctx);
	if (rc)
	{
		STAILQ_REMOVE(&rconn->ibv_events, ctx, spdk_srv_rdma_ibv_event_ctx, link);
		free(ctx);
	}

	return rc;
}

static int
srv_process_ib_event(struct spdk_srv_rdma_device *device)
{
	int rc;
	struct spdk_srv_rdma_conn *rconn = NULL;
	struct ibv_async_event event;

	rc = ibv_get_async_event(device->context, &event);

	if (rc)
	{
		/* In non-blocking mode -1 means there are no events available */
		return rc;
	}

	switch (event.event_type)
	{
	case IBV_EVENT_QP_FATAL:
		rconn = event.element.qp->qp_context;
		SPDK_ERRLOG("Fatal event received for rconn %p\n", rconn);
		spdk_trace_record(TRACE_RDMA_IBV_ASYNC_EVENT, 0, 0,
						  (uintptr_t)rconn, event.event_type);
		srv_rdma_update_ibv_state(rconn);
		spdk_srv_conn_disconnect(&rconn->conn, NULL, NULL);
		break;
	case IBV_EVENT_QP_LAST_WQE_REACHED:
		/* This event only occurs for shared receive queues. */
		rconn = event.element.qp->qp_context;
		SPDK_DEBUGLOG(rdma, "Last WQE reached event received for rconn %p\n", rconn);
		rc = srv_rdma_send_conn_async_event(rconn, srv_rdma_handle_last_wqe_reached);
		if (rc)
		{
			SPDK_WARNLOG("Failed to send LAST_WQE_REACHED event. rconn %p, err %d\n", rconn, rc);
			rconn->last_wqe_reached = true;
		}
		break;
	case IBV_EVENT_SQ_DRAINED:
		/* This event occurs frequently in both error and non-error states.
		 * Check if the conn is in an error state before sending a message. */
		rconn = event.element.qp->qp_context;
		SPDK_DEBUGLOG(rdma, "Last sq drained event received for rconn %p\n", rconn);
		spdk_trace_record(TRACE_RDMA_IBV_ASYNC_EVENT, 0, 0,
						  (uintptr_t)rconn, event.event_type);
		if (srv_rdma_update_ibv_state(rconn) == IBV_QPS_ERR)
		{
			spdk_srv_conn_disconnect(&rconn->conn, NULL, NULL);
		}
		break;
	case IBV_EVENT_QP_REQ_ERR:
	case IBV_EVENT_QP_ACCESS_ERR:
	case IBV_EVENT_COMM_EST:
	case IBV_EVENT_PATH_MIG:
	case IBV_EVENT_PATH_MIG_ERR:
		SPDK_NOTICELOG("Async event: %s\n",
					   ibv_event_type_str(event.event_type));
		rconn = event.element.qp->qp_context;
		spdk_trace_record(TRACE_RDMA_IBV_ASYNC_EVENT, 0, 0,
						  (uintptr_t)rconn, event.event_type);
		srv_rdma_update_ibv_state(rconn);
		break;
	case IBV_EVENT_CQ_ERR:
	case IBV_EVENT_DEVICE_FATAL:
	case IBV_EVENT_PORT_ACTIVE:
	case IBV_EVENT_PORT_ERR:
	case IBV_EVENT_LID_CHANGE:
	case IBV_EVENT_PKEY_CHANGE:
	case IBV_EVENT_SM_CHANGE:
	case IBV_EVENT_SRQ_ERR:
	case IBV_EVENT_SRQ_LIMIT_REACHED:
	case IBV_EVENT_CLIENT_REREGISTER:
	case IBV_EVENT_GID_CHANGE:
	default:
		SPDK_NOTICELOG("Async event: %s\n",
					   ibv_event_type_str(event.event_type));
		spdk_trace_record(TRACE_RDMA_IBV_ASYNC_EVENT, 0, 0, 0, event.event_type);
		break;
	}
	ibv_ack_async_event(&event);

	return 0;
}

static void
srv_process_ib_events(struct spdk_srv_rdma_device *device, uint32_t max_events)
{
	int rc = 0;
	uint32_t i = 0;

	for (i = 0; i < max_events; i++)
	{
		rc = srv_process_ib_event(device);
		if (rc)
		{
			break;
		}
	}

	SPDK_DEBUGLOG(rdma, "Device %s: %u events processed\n", device->context->device->name, i);
}

static int
srv_rdma_accept(void *ctx)
{
	int nfds, i = 0;
	struct spdk_srv_transport *transport = ctx;
	struct spdk_srv_rdma_transport *rtransport;
	struct spdk_srv_rdma_device *device, *tmp;
	uint32_t count;

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_srv_rdma_transport, transport);
	count = nfds = poll(rtransport->poll_fds, rtransport->npoll_fds, 0);

	if (nfds <= 0)
	{
		return SPDK_POLLER_IDLE;
	}

	/* The first poll descriptor is RDMA CM event */
	if (rtransport->poll_fds[i++].revents & POLLIN)
	{
		srv_process_cm_event(transport);
		nfds--;
	}

	if (nfds == 0)
	{
		return SPDK_POLLER_BUSY;
	}

	/* Second and subsequent poll descriptors are IB async events */
	TAILQ_FOREACH_SAFE(device, &rtransport->devices, link, tmp)
	{
		if (rtransport->poll_fds[i++].revents & POLLIN)
		{
			srv_process_ib_events(device, 32);
			nfds--;
		}
	}
	/* check all flagged fd's have been served */
	assert(nfds == 0);

	return count > 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}

static void
srv_rdma_poll_group_destroy(struct spdk_srv_transport_poll_group *group);

static struct spdk_srv_transport_poll_group *
srv_rdma_poll_group_create(struct spdk_srv_transport *transport)
{
	struct spdk_srv_rdma_transport *rtransport;
	struct spdk_srv_rdma_poll_group *rgroup;
	struct spdk_srv_rdma_poller *poller;
	struct spdk_srv_rdma_device *device;
	struct spdk_rdma_srq_init_attr srq_init_attr;
	struct spdk_srv_rdma_resource_opts opts;
	int num_cqe;

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_srv_rdma_transport, transport);

	rgroup = calloc(1, sizeof(*rgroup));
	if (!rgroup)
	{
		return NULL;
	}

	TAILQ_INIT(&rgroup->pollers);

	pthread_mutex_lock(&rtransport->lock);
	TAILQ_FOREACH(device, &rtransport->devices, link)
	{
		poller = calloc(1, sizeof(*poller));
		if (!poller)
		{
			SPDK_ERRLOG("Unable to allocate memory for new RDMA poller\n");
			srv_rdma_poll_group_destroy(&rgroup->group);
			pthread_mutex_unlock(&rtransport->lock);
			return NULL;
		}

		poller->device = device;
		poller->group = rgroup;

		TAILQ_INIT(&poller->conns);
		STAILQ_INIT(&poller->conns_pending_send);
		STAILQ_INIT(&poller->conns_pending_recv);

		TAILQ_INSERT_TAIL(&rgroup->pollers, poller, link);

		/*
		 * When using an srq, we can limit the completion queue at startup.
		 * The following formula represents the calculation:
		 * num_cqe = num_recv + num_data_wr + num_send_wr.
		 * where num_recv=num_data_wr=and num_send_wr=poller->max_srq_depth
		 */
		if (poller->srq)
		{
			num_cqe = poller->max_srq_depth * 3;
		}
		else
		{
			num_cqe = rtransport->rdma_opts.num_cqe;
		}

		poller->cq = ibv_create_cq(device->context, num_cqe, poller, NULL, 0);
		if (!poller->cq)
		{
			SPDK_ERRLOG("Unable to create completion queue\n");
			srv_rdma_poll_group_destroy(&rgroup->group);
			pthread_mutex_unlock(&rtransport->lock);
			return NULL;
		}
		poller->num_cqe = num_cqe;
	}

	TAILQ_INSERT_TAIL(&rtransport->poll_groups, rgroup, link);
	if (rtransport->conn_sched.next_io_pg == NULL)
	{
		rtransport->conn_sched.next_io_pg = rgroup;
	}

	pthread_mutex_unlock(&rtransport->lock);
	return &rgroup->group;
}

static struct spdk_srv_transport_poll_group *
srv_rdma_get_optimal_poll_group(struct spdk_srv_conn *conn)
{
	struct spdk_srv_rdma_transport *rtransport;
	struct spdk_srv_rdma_poll_group **pg;
	struct spdk_srv_transport_poll_group *result;

	rtransport = SPDK_CONTAINEROF(conn->transport, struct spdk_srv_rdma_transport, transport);

	pthread_mutex_lock(&rtransport->lock);

	if (TAILQ_EMPTY(&rtransport->poll_groups))
	{
		pthread_mutex_unlock(&rtransport->lock);
		return NULL;
	}

	pg = &rtransport->conn_sched.next_io_pg;

	assert(*pg != NULL);

	result = &(*pg)->group;

	*pg = TAILQ_NEXT(*pg, link);
	if (*pg == NULL)
	{
		*pg = TAILQ_FIRST(&rtransport->poll_groups);
	}

	pthread_mutex_unlock(&rtransport->lock);

	return result;
}

static void
srv_rdma_poll_group_destroy(struct spdk_srv_transport_poll_group *group)
{
	struct spdk_srv_rdma_poll_group *rgroup, *next_rgroup;
	struct spdk_srv_rdma_poller *poller, *tmp;
	struct spdk_srv_rdma_conn *conn, *tmp_conn;
	struct spdk_srv_rdma_transport *rtransport;

	rgroup = SPDK_CONTAINEROF(group, struct spdk_srv_rdma_poll_group, group);
	if (!rgroup)
	{
		return;
	}

	TAILQ_FOREACH_SAFE(poller, &rgroup->pollers, link, tmp)
	{
		TAILQ_REMOVE(&rgroup->pollers, poller, link);

		TAILQ_FOREACH_SAFE(conn, &poller->conns, link, tmp_conn)
		{
			srv_rdma_conn_destroy(conn);
		}

		if (poller->srq)
		{
			if (poller->resources)
			{
				srv_rdma_resources_destroy(poller->resources);
			}
			spdk_rdma_srq_destroy(poller->srq);
			SPDK_DEBUGLOG(rdma, "Destroyed RDMA shared queue %p\n", poller->srq);
		}

		if (poller->cq)
		{
			ibv_destroy_cq(poller->cq);
		}

		free(poller);
	}

	if (rgroup->group.transport == NULL)
	{
		/* Transport can be NULL when srv_rdma_poll_group_create()
		 * calls this function directly in a failure path. */
		free(rgroup);
		return;
	}

	rtransport = SPDK_CONTAINEROF(rgroup->group.transport, struct spdk_srv_rdma_transport, transport);

	pthread_mutex_lock(&rtransport->lock);
	next_rgroup = TAILQ_NEXT(rgroup, link);
	TAILQ_REMOVE(&rtransport->poll_groups, rgroup, link);
	if (next_rgroup == NULL)
	{
		next_rgroup = TAILQ_FIRST(&rtransport->poll_groups);
	}
	if (rtransport->conn_sched.next_io_pg == rgroup)
	{
		rtransport->conn_sched.next_io_pg = next_rgroup;
	}
	pthread_mutex_unlock(&rtransport->lock);

	free(rgroup);
}

static void
srv_rdma_conn_reject_connection(struct spdk_srv_rdma_conn *rconn)
{
	if (rconn->cm_id != NULL)
	{
		srv_rdma_event_reject(rconn->cm_id, SPDK_SRV_RDMA_ERROR_NO_RESOURCES);
	}
}

static int
srv_rdma_poll_group_add(struct spdk_srv_transport_poll_group *group,
						struct spdk_srv_conn *conn)
{
	struct spdk_srv_rdma_poll_group *rgroup;
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_srv_rdma_device *device;
	struct spdk_srv_rdma_poller *poller;
	int rc;

	rgroup = SPDK_CONTAINEROF(group, struct spdk_srv_rdma_poll_group, group);
	rconn = SPDK_CONTAINEROF(conn, struct spdk_srv_rdma_conn, conn);

	device = rconn->device;

	TAILQ_FOREACH(poller, &rgroup->pollers, link)
	{
		if (poller->device == device)
		{
			break;
		}
	}

	if (!poller)
	{
		SPDK_ERRLOG("No poller found for device.\n");
		return -1;
	}

	TAILQ_INSERT_TAIL(&poller->conns, rconn, link);
	rconn->poller = poller;
	rconn->srq = rconn->poller->srq;

	rc = srv_rdma_conn_initialize(conn);
	if (rc < 0)
	{
		SPDK_ERRLOG("Failed to initialize srv_rdma_conn with conn=%p\n", conn);
		return -1;
	}

	rc = srv_rdma_event_accept(rconn->cm_id, rconn);
	if (rc)
	{
		/* Try to reject, but we probably can't */
		srv_rdma_conn_reject_connection(rconn);
		return -1;
	}

	srv_rdma_update_ibv_state(rconn);

	return 0;
}

// FIXME:
static int
srv_rdma_poll_group_remove(struct spdk_srv_transport_poll_group *group,
						   struct spdk_srv_conn *conn)
{
	return 0;
}

static int
srv_rdma_request_free(struct spdk_srv_request *req)
{
	struct spdk_srv_rdma_request *rdma_req = SPDK_CONTAINEROF(req, struct spdk_srv_rdma_request, req);
	struct spdk_srv_rdma_transport *rtransport = SPDK_CONTAINEROF(req->conn->transport,
																  struct spdk_srv_rdma_transport, transport);
	struct spdk_srv_rdma_conn *rconn = SPDK_CONTAINEROF(rdma_req->req.conn,
														struct spdk_srv_rdma_conn, conn);

	/*
	 * AER requests are freed when a conn is destroyed. The recv corresponding to that request
	 * needs to be returned to the shared receive queue or the poll group will eventually be
	 * starved of RECV structures.
	 */
	if (rconn->srq && rdma_req->recv)
	{
		int rc;
		struct ibv_recv_wr *bad_recv_wr;

		spdk_rdma_srq_queue_recv_wrs(rconn->srq, &rdma_req->recv->wr);
		rc = spdk_rdma_srq_flush_recv_wrs(rconn->srq, &bad_recv_wr);
		if (rc)
		{
			SPDK_ERRLOG("Unable to re-post rx descriptor\n");
		}
	}

	_srv_rdma_request_free(rdma_req, rtransport);
	return 0;
}

static int
srv_rdma_request_complete(struct spdk_srv_request *req)
{
	struct spdk_srv_rdma_transport *rtransport = SPDK_CONTAINEROF(req->conn->transport,
																  struct spdk_srv_rdma_transport, transport);
	struct spdk_srv_rdma_request *rdma_req = SPDK_CONTAINEROF(req,
															  struct spdk_srv_rdma_request, req);
	struct spdk_srv_rdma_conn *rconn = SPDK_CONTAINEROF(rdma_req->req.conn,
														struct spdk_srv_rdma_conn, conn);

	if (rconn->ibv_state != IBV_QPS_ERR)
	{
		/* The connection is alive, so process the request as normal */
		rdma_req->state = RDMA_REQUEST_STATE_EXECUTED;
	}
	else
	{
		/* The connection is dead. Move the request directly to the completed state. */
		rdma_req->state = RDMA_REQUEST_STATE_COMPLETED;
	}

	srv_rdma_request_process(rtransport, rdma_req);

	return 0;
}

static void
srv_rdma_close_conn(struct spdk_srv_conn *conn,
					spdk_srv_transport_conn_fini_cb cb_fn, void *cb_arg)
{
	struct spdk_srv_rdma_conn *rconn = SPDK_CONTAINEROF(conn, struct spdk_srv_rdma_conn, conn);

	rconn->to_close = true;

	/* This happens only when the conn is disconnected before
	 * it is added to the poll group. Since there is no poll group,
	 * the RDMA qp has not been initialized yet and the RDMA CM
	 * event has not yet been acknowledged, so we need to reject it.
	 */
	if (rconn->conn.state == SPDK_SRV_CONN_UNINITIALIZED)
	{
		srv_rdma_conn_reject_connection(rconn);
		srv_rdma_conn_destroy(rconn);
		return;
	}

	if (rconn->rdma_qp)
	{
		spdk_rdma_qp_disconnect(rconn->rdma_qp);
	}

	srv_rdma_destroy_drained_conn(rconn);

	if (cb_fn)
	{
		cb_fn(cb_arg);
	}
}

static struct spdk_srv_rdma_conn *
get_rdma_conn_from_wc(struct spdk_srv_rdma_poller *rpoller, struct ibv_wc *wc)
{
	struct spdk_srv_rdma_conn *rconn;
	/* @todo: improve QP search */
	TAILQ_FOREACH(rconn, &rpoller->conns, link)
	{
		if (wc->qp_num == rconn->rdma_qp->qp->qp_num)
		{
			return rconn;
		}
	}
	SPDK_ERRLOG("Didn't find QP with qp_num %u\n", wc->qp_num);
	return NULL;
}

#ifdef DEBUG
static int
srv_rdma_req_is_completing(struct spdk_srv_rdma_request *rdma_req)
{
	return rdma_req->state == RDMA_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST ||
		   rdma_req->state == RDMA_REQUEST_STATE_COMPLETING;
}
#endif

static void
_poller_reset_failed_recvs(struct spdk_srv_rdma_poller *rpoller, struct ibv_recv_wr *bad_recv_wr,
						   int rc)
{
	struct spdk_srv_rdma_recv *rdma_recv;
	struct spdk_srv_rdma_wr *bad_rdma_wr;

	SPDK_ERRLOG("Failed to post a recv for the poller %p with errno %d\n", rpoller, -rc);
	while (bad_recv_wr != NULL)
	{
		bad_rdma_wr = (struct spdk_srv_rdma_wr *)bad_recv_wr->wr_id;
		rdma_recv = SPDK_CONTAINEROF(bad_rdma_wr, struct spdk_srv_rdma_recv, rdma_wr);

		rdma_recv->conn->current_recv_depth++;
		bad_recv_wr = bad_recv_wr->next;
		SPDK_ERRLOG("Failed to post a recv for the conn %p with errno %d\n", rdma_recv->conn, -rc);
		spdk_srv_conn_disconnect(&rdma_recv->conn->conn, NULL, NULL);
	}
}

static void
_qp_reset_failed_recvs(struct spdk_srv_rdma_conn *rconn, struct ibv_recv_wr *bad_recv_wr, int rc)
{
	SPDK_ERRLOG("Failed to post a recv for the conn %p with errno %d\n", rconn, -rc);
	while (bad_recv_wr != NULL)
	{
		bad_recv_wr = bad_recv_wr->next;
		rconn->current_recv_depth++;
	}
	spdk_srv_conn_disconnect(&rconn->conn, NULL, NULL);
}

static void
_poller_submit_recvs(struct spdk_srv_rdma_transport *rtransport,
					 struct spdk_srv_rdma_poller *rpoller)
{
	struct spdk_srv_rdma_conn *rconn;
	struct ibv_recv_wr *bad_recv_wr;
	int rc;

	if (rpoller->srq)
	{
		rc = spdk_rdma_srq_flush_recv_wrs(rpoller->srq, &bad_recv_wr);
		if (rc)
		{
			_poller_reset_failed_recvs(rpoller, bad_recv_wr, rc);
		}
	}
	else
	{
		while (!STAILQ_EMPTY(&rpoller->conns_pending_recv))
		{
			rconn = STAILQ_FIRST(&rpoller->conns_pending_recv);
			rc = spdk_rdma_qp_flush_recv_wrs(rconn->rdma_qp, &bad_recv_wr);
			if (rc)
			{
				_qp_reset_failed_recvs(rconn, bad_recv_wr, rc);
			}
			STAILQ_REMOVE_HEAD(&rpoller->conns_pending_recv, recv_link);
		}
	}
}

static void
_poller_comsume_pending_rpc_rdma_request(struct spdk_srv_rdma_transport *rtransport,
										 struct spdk_srv_rdma_poller *rpoller)
{
	struct spdk_srv_rdma_conn *rconn, *rconn_tmp;
	struct spdk_srv_rdma_request *rdma_req, *req_tmp;
	struct ibv_recv_wr *bad_recv_wr;
	int rc;
	SPDK_DEBUGLOG(rdma, "enter _poller_comsume_pending_rpc_rdma_request\n");
	TAILQ_FOREACH_SAFE(rconn, &rpoller->conns, link, rconn_tmp)
	{
		STAILQ_FOREACH_SAFE(rdma_req, &rconn->pending_complete_queue, state_link, req_tmp)
		{
			if (rconn->ibv_state != IBV_QPS_ERR)
			{
				/* The connection is alive, so process the request as normal */
				rdma_req->state = RDMA_REQUEST_STATE_EXECUTED;
			}
			else
			{
				/* The connection is dead. Move the request directly to the completed state. */
				rdma_req->state = RDMA_REQUEST_STATE_COMPLETED;
			}
			SPDK_DEBUGLOG(rdma, "rdma_req addr: %p\n", rdma_req);
			assert(rdma_req->recv != NULL);
			if (srv_rdma_request_process(rtransport, rdma_req) == false)
			{
				break;
			}
		}
	}
}

static void
_qp_reset_failed_sends(struct spdk_srv_rdma_transport *rtransport,
					   struct spdk_srv_rdma_conn *rconn, struct ibv_send_wr *bad_wr, int rc)
{
	struct spdk_srv_rdma_wr *bad_rdma_wr;
	struct spdk_srv_rdma_request *prev_rdma_req = NULL, *cur_rdma_req = NULL;

	SPDK_ERRLOG("Failed to post a send for the conn %p with errno %d\n", rconn, -rc);
	for (; bad_wr != NULL; bad_wr = bad_wr->next)
	{
		bad_rdma_wr = (struct spdk_srv_rdma_wr *)bad_wr->wr_id;
		assert(rconn->current_send_depth > 0);
		rconn->current_send_depth--;
		switch (bad_rdma_wr->type)
		{
		case RDMA_WR_TYPE_DATA:
			cur_rdma_req = SPDK_CONTAINEROF(bad_rdma_wr, struct spdk_srv_rdma_request, data.rdma_wr);
			if (bad_wr->opcode == IBV_WR_RDMA_READ)
			{
				assert(rconn->current_read_depth > 0);
				rconn->current_read_depth--;
			}
			break;
		case RDMA_WR_TYPE_SEND:
			cur_rdma_req = SPDK_CONTAINEROF(bad_rdma_wr, struct spdk_srv_rdma_request, rsp.rdma_wr);
			break;
		default:
			SPDK_ERRLOG("Found a RECV in the list of pending SEND requests for conn %p\n", rconn);
			prev_rdma_req = cur_rdma_req;
			continue;
		}

		if (prev_rdma_req == cur_rdma_req)
		{
			/* this request was handled by an earlier wr. i.e. we were performing an srv read. */
			/* We only have to check against prev_wr since each requests wrs are contiguous in this list. */
			continue;
		}

		switch (cur_rdma_req->state)
		{
		case RDMA_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER:
			cur_rdma_req->req.rsp->status.sc = SPDK_SRV_SC_INTERNAL_DEVICE_ERROR;
			cur_rdma_req->state = RDMA_REQUEST_STATE_READY_TO_COMPLETE;
			break;
		case RDMA_REQUEST_STATE_TRANSFERRING_CONTROLLER_TO_HOST:
		case RDMA_REQUEST_STATE_COMPLETING:
			cur_rdma_req->state = RDMA_REQUEST_STATE_COMPLETED;
			break;
		default:
			SPDK_ERRLOG("Found a request in a bad state %d when draining pending SEND requests for conn %p\n",
						cur_rdma_req->state, rconn);
			continue;
		}

		srv_rdma_request_process(rtransport, cur_rdma_req);
		prev_rdma_req = cur_rdma_req;
	}

	if (rconn->conn.state == SPDK_SRV_CONN_ACTIVE)
	{
		/* Disconnect the connection. */
		spdk_srv_conn_disconnect(&rconn->conn, NULL, NULL);
	}
}

static void
_poller_submit_sends(struct spdk_srv_rdma_transport *rtransport,
					 struct spdk_srv_rdma_poller *rpoller)
{
	struct spdk_srv_rdma_conn *rconn;
	struct ibv_send_wr *bad_wr = NULL;
	int rc;
	SPDK_DEBUGLOG(rdma, "enter _poller_submit_sends \n");
	while (!STAILQ_EMPTY(&rpoller->conns_pending_send))
	{
		rconn = STAILQ_FIRST(&rpoller->conns_pending_send);
		rc = spdk_rdma_qp_flush_send_wrs(rconn->rdma_qp, &bad_wr);

		/* bad wr always points to the first wr that failed. */
		if (rc)
		{
			_qp_reset_failed_sends(rtransport, rconn, bad_wr, rc);
		}
		STAILQ_REMOVE_HEAD(&rpoller->conns_pending_send, send_link);
	}
}

static const char *
srv_rdma_wr_type_str(enum spdk_srv_rdma_wr_type wr_type)
{
	switch (wr_type)
	{
	case RDMA_WR_TYPE_RECV:
		return "RECV";
	case RDMA_WR_TYPE_SEND:
		return "SEND";
	case RDMA_WR_TYPE_DATA:
		return "DATA";
	default:
		SPDK_ERRLOG("Unknown WR type %d\n", wr_type);
		SPDK_UNREACHABLE();
	}
}

static inline void
srv_rdma_log_wc_status(struct spdk_srv_rdma_conn *rconn, struct ibv_wc *wc)
{
	enum spdk_srv_rdma_wr_type wr_type = ((struct spdk_srv_rdma_wr *)wc->wr_id)->type;

	if (wc->status == IBV_WC_WR_FLUSH_ERR)
	{
		/* If conn is in ERR state, we will receive completions for all posted and not completed
		 * Work Requests with IBV_WC_WR_FLUSH_ERR status. Don't log an error in that case */
		SPDK_DEBUGLOG(rdma,
					  "Error on CQ %p, (qp state %d ibv_state %d) request 0x%lu, type %s, status: (%d): %s\n",
					  rconn->poller->cq, rconn->conn.state, rconn->ibv_state, wc->wr_id,
					  srv_rdma_wr_type_str(wr_type), wc->status, ibv_wc_status_str(wc->status));
	}
	else
	{
		SPDK_ERRLOG("Error on CQ %p, (qp state %d ibv_state %d) request 0x%lu, type %s, status: (%d): %s\n",
					rconn->poller->cq, rconn->conn.state, rconn->ibv_state, wc->wr_id,
					srv_rdma_wr_type_str(wr_type), wc->status, ibv_wc_status_str(wc->status));
	}
}

static int
srv_rdma_poller_poll(struct spdk_srv_rdma_transport *rtransport,
					 struct spdk_srv_rdma_poller *rpoller)
{
	struct ibv_wc wc[32];
	struct spdk_srv_rdma_wr *rdma_wr;
	struct spdk_srv_rdma_request *rdma_req, *req_tmp;
	struct spdk_srv_rdma_recv *rdma_recv;
	struct spdk_srv_rdma_conn *rconn;
	int reaped, i;
	int count = 0;
	bool error = false;
	uint64_t poll_tsc = spdk_get_ticks();

	/* Poll for completing operations. */
	reaped = ibv_poll_cq(rpoller->cq, 32, wc);
	if (reaped < 0)
	{
		SPDK_ERRLOG("Error polling CQ! (%d): %s\n",
					errno, spdk_strerror(errno));
		return -1;
	}
	else if (reaped == 0)
	{
		rpoller->stat.idle_polls++;
	}

	rpoller->stat.polls++;
	rpoller->stat.completions += reaped;

	for (i = 0; i < reaped; i++)
	{

		rdma_wr = (struct spdk_srv_rdma_wr *)wc[i].wr_id;
		SPDK_DEBUGLOG(rdma, "enter srv_rdma_poller_poll reaped %d current %d\n", reaped, i);
		switch (rdma_wr->type)
		{
		case RDMA_WR_TYPE_SEND:
			rdma_req = SPDK_CONTAINEROF(rdma_wr, struct spdk_srv_rdma_request, rsp.rdma_wr);
			rconn = SPDK_CONTAINEROF(rdma_req->req.conn, struct spdk_srv_rdma_conn, conn);

			if (!wc[i].status)
			{
				count++;
				assert(wc[i].opcode == IBV_WC_SEND);
				assert(srv_rdma_req_is_completing(rdma_req));
			}

			rdma_req->state = RDMA_REQUEST_STATE_COMPLETED;
			/* RDMA_WRITE operation completed. +1 since it was chained with rsp WR */
			rconn->current_send_depth -= rdma_req->num_outstanding_data_wr + 1;
			rdma_req->num_outstanding_data_wr = 0;

			srv_rdma_request_process(rtransport, rdma_req);
			break;
		case RDMA_WR_TYPE_RECV:
			/* rdma_recv->conn will be invalid if using an SRQ.  In that case we have to get the conn from the wc. */
			rdma_recv = SPDK_CONTAINEROF(rdma_wr, struct spdk_srv_rdma_recv, rdma_wr);
			if (rpoller->srq != NULL)
			{
				rdma_recv->conn = get_rdma_conn_from_wc(rpoller, &wc[i]);
				/* It is possible that there are still some completions for destroyed QP
				 * associated with SRQ. We just ignore these late completions and re-post
				 * receive WRs back to SRQ.
				 */
				if (spdk_unlikely(NULL == rdma_recv->conn))
				{
					struct ibv_recv_wr *bad_wr;
					int rc;

					rdma_recv->wr.next = NULL;
					spdk_rdma_srq_queue_recv_wrs(rpoller->srq, &rdma_recv->wr);
					rc = spdk_rdma_srq_flush_recv_wrs(rpoller->srq, &bad_wr);
					if (rc)
					{
						SPDK_ERRLOG("Failed to re-post recv WR to SRQ, err %d\n", rc);
					}
					continue;
				}
			}
			rconn = rdma_recv->conn;

			assert(rconn != NULL);
			if (!wc[i].status)
			{
				assert(wc[i].opcode == IBV_WC_RECV);
				if (rconn->current_recv_depth >= rconn->max_queue_depth)
				{
					spdk_srv_conn_disconnect(&rconn->conn, NULL, NULL);
					break;
				}
			}

			rdma_recv->wr.next = NULL;
			rconn->current_recv_depth++;
			rdma_recv->receive_tsc = poll_tsc;
			rpoller->stat.requests++;
			STAILQ_INSERT_HEAD(&rconn->resources->incoming_queue, rdma_recv, link);
			break;
		case RDMA_WR_TYPE_DATA:
			rdma_req = SPDK_CONTAINEROF(rdma_wr, struct spdk_srv_rdma_request, data.rdma_wr);
			rconn = SPDK_CONTAINEROF(rdma_req->req.conn, struct spdk_srv_rdma_conn, conn);

			assert(rdma_req->num_outstanding_data_wr > 0);

			rconn->current_send_depth--;
			rdma_req->num_outstanding_data_wr--;
			if (!wc[i].status)
			{
				assert(wc[i].opcode == IBV_WC_RDMA_READ);
				rconn->current_read_depth--;
				/* wait for all outstanding reads associated with the same rdma_req to complete before proceeding. */
				if (rdma_req->num_outstanding_data_wr == 0)
				{
					rdma_req->state = RDMA_REQUEST_STATE_READY_TO_EXECUTE;
					srv_rdma_request_process(rtransport, rdma_req);
				}
			}
			else
			{
				/* If the data transfer fails still force the queue into the error state,
				 * if we were performing an RDMA_READ, we need to force the request into a
				 * completed state since it wasn't linked to a send. However, in the RDMA_WRITE
				 * case, we should wait for the SEND to complete. */
				if (rdma_req->data.wr.opcode == IBV_WR_RDMA_READ)
				{
					rconn->current_read_depth--;
					if (rdma_req->num_outstanding_data_wr == 0)
					{
						rdma_req->state = RDMA_REQUEST_STATE_COMPLETED;
					}
				}
			}
			break;
		default:
			SPDK_ERRLOG("Received an unknown opcode on the CQ: %d\n", wc[i].opcode);
			continue;
		}

		/* Handle error conditions */
		if (wc[i].status)
		{
			srv_rdma_update_ibv_state(rconn);
			srv_rdma_log_wc_status(rconn, &wc[i]);

			error = true;

			if (rconn->conn.state == SPDK_SRV_CONN_ACTIVE)
			{
				/* Disconnect the connection. */
				spdk_srv_conn_disconnect(&rconn->conn, NULL, NULL);
			}
			else
			{
				srv_rdma_destroy_drained_conn(rconn);
			}
			continue;
		}

		srv_rdma_conn_process_pending(rtransport, rconn, false);

		if (rconn->conn.state != SPDK_SRV_CONN_ACTIVE)
		{
			srv_rdma_destroy_drained_conn(rconn);
		}
	}

	if (error == true)
	{
		return -1;
	}

	/* submit outstanding work requests. */
	_poller_submit_recvs(rtransport, rpoller);
	_poller_submit_sends(rtransport, rpoller);
	_poller_comsume_pending_rpc_rdma_request(rtransport, rpoller);

	return count;
}

static int
srv_rdma_poll_group_poll(struct spdk_srv_transport_poll_group *group)
{
	struct spdk_srv_rdma_transport *rtransport;
	struct spdk_srv_rdma_poll_group *rgroup;
	struct spdk_srv_rdma_poller *rpoller;
	int count, rc;

	rtransport = SPDK_CONTAINEROF(group->transport, struct spdk_srv_rdma_transport, transport);
	rgroup = SPDK_CONTAINEROF(group, struct spdk_srv_rdma_poll_group, group);

	count = 0;
	TAILQ_FOREACH(rpoller, &rgroup->pollers, link)
	{
		rc = srv_rdma_poller_poll(rtransport, rpoller);
		if (rc < 0)
		{
			return rc;
		}
		count += rc;
	}

	return count;
}

static int
srv_rdma_trid_from_cm_id(struct rdma_cm_id *id,
						 struct spdk_srv_transport_id *trid,
						 bool peer)
{
	struct sockaddr *saddr;
	uint16_t port;

	spdk_srv_trid_populate_transport(trid, SPDK_SRV_TRANSPORT_RDMA);

	if (peer)
	{
		saddr = rdma_get_peer_addr(id);
	}
	else
	{
		saddr = rdma_get_local_addr(id);
	}
	switch (saddr->sa_family)
	{
	case AF_INET:
	{
		struct sockaddr_in *saddr_in = (struct sockaddr_in *)saddr;

		trid->adrfam = SPDK_SRV_ADRFAM_IPV4;
		inet_ntop(AF_INET, &saddr_in->sin_addr,
				  trid->traddr, sizeof(trid->traddr));
		if (peer)
		{
			port = ntohs(rdma_get_dst_port(id));
		}
		else
		{
			port = ntohs(rdma_get_src_port(id));
		}
		snprintf(trid->trsvcid, sizeof(trid->trsvcid), "%u", port);
		break;
	}
	case AF_INET6:
	{
		struct sockaddr_in6 *saddr_in = (struct sockaddr_in6 *)saddr;
		trid->adrfam = SPDK_SRV_ADRFAM_IPV6;
		inet_ntop(AF_INET6, &saddr_in->sin6_addr,
				  trid->traddr, sizeof(trid->traddr));
		if (peer)
		{
			port = ntohs(rdma_get_dst_port(id));
		}
		else
		{
			port = ntohs(rdma_get_src_port(id));
		}
		snprintf(trid->trsvcid, sizeof(trid->trsvcid), "%u", port);
		break;
	}
	default:
		return -1;
	}

	return 0;
}

static int
srv_rdma_conn_get_peer_trid(struct spdk_srv_conn *conn,
							struct spdk_srv_transport_id *trid)
{
	struct spdk_srv_rdma_conn *rconn;

	rconn = SPDK_CONTAINEROF(conn, struct spdk_srv_rdma_conn, conn);

	return srv_rdma_trid_from_cm_id(rconn->cm_id, trid, true);
}

static int
srv_rdma_conn_get_local_trid(struct spdk_srv_conn *conn,
							 struct spdk_srv_transport_id *trid)
{
	struct spdk_srv_rdma_conn *rconn;

	rconn = SPDK_CONTAINEROF(conn, struct spdk_srv_rdma_conn, conn);

	return srv_rdma_trid_from_cm_id(rconn->cm_id, trid, false);
}

static int
srv_rdma_conn_get_listen_trid(struct spdk_srv_conn *conn,
							  struct spdk_srv_transport_id *trid)
{
	struct spdk_srv_rdma_conn *rconn;

	rconn = SPDK_CONTAINEROF(conn, struct spdk_srv_rdma_conn, conn);

	return srv_rdma_trid_from_cm_id(rconn->listen_id, trid, false);
}

static void
srv_rdma_request_set_abort_status(struct spdk_srv_request *req,
								  struct spdk_srv_rdma_request *rdma_req_to_abort)
{
	rdma_req_to_abort->req.rsp->status.sc = SPDK_SRV_SC_ABORTED_BY_REQUEST;

	rdma_req_to_abort->state = RDMA_REQUEST_STATE_READY_TO_COMPLETE;

	req->rsp->cdw0 &= ~1U; /* Command was successfully aborted. */
}

static int
_srv_rdma_conn_abort_request(void *ctx)
{
	struct spdk_srv_request *req = ctx;
	struct spdk_srv_rdma_request *rdma_req_to_abort = SPDK_CONTAINEROF(
		req->req_to_abort, struct spdk_srv_rdma_request, req);
	struct spdk_srv_rdma_conn *rconn = SPDK_CONTAINEROF(req->req_to_abort->conn,
														struct spdk_srv_rdma_conn, conn);
	int rc;

	spdk_poller_unregister(&req->poller);

	switch (rdma_req_to_abort->state)
	{
	case RDMA_REQUEST_STATE_EXECUTING:

		break;

	case RDMA_REQUEST_STATE_NEED_BUFFER:
		STAILQ_REMOVE(&rconn->poller->group->group.pending_buf_queue,
					  &rdma_req_to_abort->req, spdk_srv_request, buf_link);

		srv_rdma_request_set_abort_status(req, rdma_req_to_abort);
		break;

	case RDMA_REQUEST_STATE_DATA_TRANSFER_TO_CONTROLLER_PENDING:
		STAILQ_REMOVE(&rconn->pending_rdma_read_queue, rdma_req_to_abort,
					  spdk_srv_rdma_request, state_link);

		srv_rdma_request_set_abort_status(req, rdma_req_to_abort);
		break;

	case RDMA_REQUEST_STATE_DATA_TRANSFER_TO_HOST_PENDING:
		STAILQ_REMOVE(&rconn->pending_rdma_write_queue, rdma_req_to_abort,
					  spdk_srv_rdma_request, state_link);

		srv_rdma_request_set_abort_status(req, rdma_req_to_abort);
		break;

	case RDMA_REQUEST_STATE_TRANSFERRING_HOST_TO_CONTROLLER:
		if (spdk_get_ticks() < req->timeout_tsc)
		{
			req->poller = SPDK_POLLER_REGISTER(_srv_rdma_conn_abort_request, req, 0);
			return SPDK_POLLER_BUSY;
		}
		break;

	default:
		break;
	}

	spdk_srv_request_complete(req);
	return SPDK_POLLER_BUSY;
}

static void
srv_rdma_conn_abort_request(struct spdk_srv_conn *conn,
							struct spdk_srv_request *req)
{
	struct spdk_srv_rdma_conn *rconn;
	struct spdk_srv_rdma_transport *rtransport;
	struct spdk_srv_transport *transport;
	uint16_t cid;
	uint32_t i, max_req_count;
	struct spdk_srv_rdma_request *rdma_req_to_abort = NULL, *rdma_req;

	rconn = SPDK_CONTAINEROF(conn, struct spdk_srv_rdma_conn, conn);
	rtransport = SPDK_CONTAINEROF(conn->transport, struct spdk_srv_rdma_transport, transport);
	transport = &rtransport->transport;
	cid = req->cmd->cid;
	max_req_count = rconn->srq == NULL ? rconn->max_queue_depth : rconn->poller->max_srq_depth;

	for (i = 0; i < max_req_count; i++)
	{
		rdma_req = &rconn->resources->reqs[i];
		/* When SRQ == NULL, rconn has its own requests and req.conn pointer always points to the conn
		 * When SRQ != NULL all rconns share common requests and conn pointer is assigned when we start to
		 * process a request. So in both cases all requests which are not in FREE state have valid conn ptr */
		if (rdma_req->state != RDMA_REQUEST_STATE_FREE && rdma_req->req.cmd->cid == cid &&
			rdma_req->req.conn == conn)
		{
			rdma_req_to_abort = rdma_req;
			break;
		}
	}

	if (rdma_req_to_abort == NULL)
	{
		spdk_srv_request_complete(req);
		return;
	}

	req->req_to_abort = &rdma_req_to_abort->req;
	req->timeout_tsc = spdk_get_ticks() +
					   transport->opts.abort_timeout_sec * spdk_get_ticks_hz();
	req->poller = NULL;

	_srv_rdma_conn_abort_request(req);
}

static void
srv_rdma_poll_group_dump_stat(struct spdk_srv_transport_poll_group *group,
							  struct spdk_json_write_ctx *w)
{
	struct spdk_srv_rdma_poll_group *rgroup;
	struct spdk_srv_rdma_poller *rpoller;

	assert(w != NULL);

	rgroup = SPDK_CONTAINEROF(group, struct spdk_srv_rdma_poll_group, group);

	spdk_json_write_named_uint64(w, "pending_data_buffer", rgroup->stat.pending_data_buffer);

	spdk_json_write_named_array_begin(w, "devices");

	TAILQ_FOREACH(rpoller, &rgroup->pollers, link)
	{
		spdk_json_write_object_begin(w);
		spdk_json_write_named_string(w, "name",
									 ibv_get_device_name(rpoller->device->context->device));
		spdk_json_write_named_uint64(w, "polls",
									 rpoller->stat.polls);
		spdk_json_write_named_uint64(w, "idle_polls",
									 rpoller->stat.idle_polls);
		spdk_json_write_named_uint64(w, "completions",
									 rpoller->stat.completions);
		spdk_json_write_named_uint64(w, "requests",
									 rpoller->stat.requests);
		spdk_json_write_named_uint64(w, "request_latency",
									 rpoller->stat.request_latency);
		spdk_json_write_named_uint64(w, "pending_free_request",
									 rpoller->stat.pending_free_request);
		spdk_json_write_named_uint64(w, "pending_rdma_read",
									 rpoller->stat.pending_rdma_read);
		spdk_json_write_named_uint64(w, "pending_rdma_write",
									 rpoller->stat.pending_rdma_write);
		spdk_json_write_named_uint64(w, "total_send_wrs",
									 rpoller->stat.qp_stats.send.num_submitted_wrs);
		spdk_json_write_named_uint64(w, "send_doorbell_updates",
									 rpoller->stat.qp_stats.send.doorbell_updates);
		spdk_json_write_named_uint64(w, "total_recv_wrs",
									 rpoller->stat.qp_stats.recv.num_submitted_wrs);
		spdk_json_write_named_uint64(w, "recv_doorbell_updates",
									 rpoller->stat.qp_stats.recv.doorbell_updates);
		spdk_json_write_object_end(w);
	}

	spdk_json_write_array_end(w);
}

const struct spdk_srv_transport_ops spdk_srv_transport_rdma = {
	.name = "RDMA",
	.type = SPDK_SRV_TRANSPORT_RDMA,
	.opts_init = srv_rdma_opts_init,
	.create = srv_rdma_create,
	.dump_opts = srv_rdma_dump_opts,
	.destroy = srv_rdma_destroy,

	.listen = srv_rdma_listen,
	.stop_listen = srv_rdma_stop_listen,

	.poll_group_create = srv_rdma_poll_group_create,
	.get_optimal_poll_group = srv_rdma_get_optimal_poll_group,
	.poll_group_destroy = srv_rdma_poll_group_destroy,
	.poll_group_add = srv_rdma_poll_group_add,
	.poll_group_remove = srv_rdma_poll_group_remove,
	.poll_group_poll = srv_rdma_poll_group_poll,

	.req_free = srv_rdma_request_free,
	.req_complete = srv_rdma_request_complete,

	.conn_fini = srv_rdma_close_conn,
	.conn_get_peer_trid = srv_rdma_conn_get_peer_trid,
	.conn_get_local_trid = srv_rdma_conn_get_local_trid,
	.conn_get_listen_trid = srv_rdma_conn_get_listen_trid,
	.conn_abort_request = srv_rdma_conn_abort_request,

	.poll_group_dump_stat = srv_rdma_poll_group_dump_stat,
};

SPDK_SRV_TRANSPORT_REGISTER(rdma, &spdk_srv_transport_rdma);
SPDK_LOG_REGISTER_COMPONENT(rdma)
