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

/*
 * Client over RDMA transport
 */

#include "spdk/stdinc.h"

#include "spdk/assert.h"
#include "spdk/dma.h"
#include "spdk/log.h"
#include "spdk/trace.h"
#include "spdk/queue.h"
#include "spdk/string.h"
#include "spdk/endian.h"
#include "spdk/likely.h"
#include "spdk/config.h"

#include "spdk/rdma_client.h"
#include "spdk_internal/rdma_client.h"
#include "spdk_internal/rdma.h"

#define CLIENT_RDMA_TIME_OUT_IN_MS 2000
#define CLIENT_RDMA_RW_BUFFER_SIZE 131072

/*
 * CLIENT RDMA qpair Resource Defaults
 */
#define CLIENT_RDMA_DEFAULT_TX_SGE 2
#define CLIENT_RDMA_DEFAULT_RX_SGE 1

/* Max number of Client-oF SGL descriptors supported by the host */
#define CLIENT_RDMA_MAX_SGL_DESCRIPTORS 16

/* number of STAILQ entries for holding pending RDMA CM events. */
#define CLIENT_RDMA_NUM_CM_EVENTS 256

/* CM event processing timeout */
#define CLIENT_RDMA_QPAIR_CM_EVENT_TIMEOUT_US 1000000

/* The default size for a shared rdma completion queue. */
#define DEFAULT_CLIENT_RDMA_CQ_SIZE 4096

/*
 * In the special case of a stale connection we don't expose a mechanism
 * for the user to retry the connection so we need to handle it internally.
 */
#define CLIENT_RDMA_STALE_CONN_RETRY_MAX 5
#define CLIENT_RDMA_STALE_CONN_RETRY_DELAY_US 10000

/*
 * Maximum value of transport_retry_count used by RDMA controller
 */
#define CLIENT_RDMA_CTRLR_MAX_TRANSPORT_RETRY_COUNT 7

/*
 * Maximum value of transport_ack_timeout used by RDMA controller
 */
#define CLIENT_RDMA_CTRLR_MAX_TRANSPORT_ACK_TIMEOUT 31

/*
 * Number of microseconds to keep a pointer to destroyed qpairs
 * in the poll group.
 */
#define CLIENT_RDMA_DESTROYED_QPAIR_EXPIRATION_TIMEOUT_US 1000000ull

/*
 * Number of microseconds to wait until the lingering qpair becomes quiet.
 */
#define CLIENT_RDMA_DISCONNECTED_QPAIR_TIMEOUT_US 1000000ull

/*
 * The max length of keyed SGL data block (3 bytes)
 */
#define CLIENT_RDMA_MAX_KEYED_SGL_LENGTH ((1u << 24u) - 1)

#define WC_PER_QPAIR(queue_depth) (queue_depth * 2)

#define CLIENT_RDMA_POLL_GROUP_CHECK_QPN(_rqpair, qpn) \
	((_rqpair)->rdma_qp && (_rqpair)->rdma_qp->qp->qp_num == (qpn))

struct client_rdma_memory_domain
{
	TAILQ_ENTRY(client_rdma_memory_domain)
	link;
	uint32_t ref;
	struct ibv_pd *pd;
	struct spdk_memory_domain *domain;
	struct spdk_memory_domain_rdma_ctx rdma_ctx;
};

enum client_rdma_wr_type
{
	RDMA_WR_TYPE_RECV,
	RDMA_WR_TYPE_SEND,
};

struct client_rdma_wr
{
	/* Using this instead of the enum allows this struct to only occupy one byte. */
	uint8_t type;
};

struct spdk_client_cmd
{
	struct spdk_req_cmd cmd;
	struct spdk_req_sgl_descriptor sgl[CLIENT_RDMA_MAX_SGL_DESCRIPTORS];
};

struct spdk_client_rdma_hooks g_client_hooks = {};

/* STAILQ wrapper for cm events. */
struct client_rdma_cm_event_entry
{
	struct rdma_cm_event *evt;
	STAILQ_ENTRY(client_rdma_cm_event_entry)
	link;
};

/* Client RDMA transport extensions for spdk_client_ctrlr */
struct client_rdma_ctrlr
{
	struct spdk_client_ctrlr ctrlr;

	struct ibv_pd *pd;

	uint16_t max_sge;

	struct rdma_event_channel *cm_channel;

	STAILQ_HEAD(, client_rdma_cm_event_entry)
	pending_cm_events;

	STAILQ_HEAD(, client_rdma_cm_event_entry)
	free_cm_events;

	struct client_rdma_cm_event_entry *cm_events;
};

struct client_rdma_destroyed_qpair
{
	struct client_rdma_qpair *destroyed_qpair_tracker;
	uint64_t timeout_ticks;
	STAILQ_ENTRY(client_rdma_destroyed_qpair)
	link;
};

struct client_rdma_poller_stats
{
	uint64_t polls;
	uint64_t idle_polls;
	uint64_t queued_requests;
	uint64_t completions;
	struct spdk_rdma_qp_stats rdma_stats;
};

struct client_rdma_poller
{
	struct ibv_context *device;
	struct ibv_cq *cq;
	int required_num_wc;
	int current_num_wc;
	struct client_rdma_poller_stats stats;
	STAILQ_ENTRY(client_rdma_poller)
	link;
};

typedef int (*client_rdma_cm_event_cb)(struct client_rdma_qpair *rqpair, int ret);

struct client_rdma_poll_group
{
	struct spdk_client_transport_poll_group group;
	STAILQ_HEAD(, client_rdma_poller)
	pollers;
	uint32_t num_pollers;
	STAILQ_HEAD(, client_rdma_destroyed_qpair)
	destroyed_qpairs;
};

/* Memory regions */
union client_rdma_mr
{
	struct ibv_mr *mr;
	uint64_t key;
};

enum client_rdma_qpair_state
{
	CLIENT_RDMA_QPAIR_STATE_INVALID = 0,
	CLIENT_RDMA_QPAIR_STATE_STALE_CONN,
	CLIENT_RDMA_QPAIR_STATE_INITIALIZING,
	CLIENT_RDMA_QPAIR_STATE_RUNNING,
	CLIENT_RDMA_QPAIR_STATE_EXITING,
	CLIENT_RDMA_QPAIR_STATE_LINGERING,
	CLIENT_RDMA_QPAIR_STATE_EXITED,
};

/* Client RDMA qpair extensions for spdk_client_qpair */
struct client_rdma_qpair
{
	struct spdk_client_qpair qpair;

	struct spdk_rdma_qp *rdma_qp;
	struct rdma_cm_id *cm_id;
	struct ibv_cq *cq;

	struct spdk_client_rdma_req *rdma_reqs;

	uint32_t max_send_sge;

	uint32_t max_recv_sge;

	uint16_t num_entries;

	bool delay_cmd_submit;

	uint32_t num_completions;

	/* Parallel arrays of response buffers + response SGLs of size num_entries */
	struct ibv_sge *rsp_sgls;
	struct spdk_client_rdma_rsp *rsps;

	struct ibv_recv_wr *rsp_recv_wrs;

	/* Memory region describing all rsps for this qpair */
	union client_rdma_mr rsp_mr;

	/*
	 * Array of num_entries Client commands registered as RDMA message buffers.
	 * Indexed by rdma_req->id.
	 */
	struct spdk_client_cmd *cmds;

	/* Memory region describing all cmds for this qpair */
	union client_rdma_mr cmd_mr;

	struct spdk_rdma_mem_map *mr_map;

	TAILQ_HEAD(, spdk_client_rdma_req)
	free_reqs;
	TAILQ_HEAD(, spdk_client_rdma_req)
	outstanding_reqs;

	struct client_rdma_memory_domain *memory_domain;

	/* Counts of outstanding send and recv objects */
	uint16_t current_num_recvs;
	uint16_t current_num_sends;

	/* Placed at the end of the struct since it is not used frequently */
	struct rdma_cm_event *evt;
	struct client_rdma_poller *poller;

	enum client_rdma_qpair_state state;

	bool in_connect_poll;

	uint64_t evt_timeout_ticks;
	client_rdma_cm_event_cb evt_cb;
	enum rdma_cm_event_type expected_evt_type;

	uint8_t stale_conn_retry_count;
	/* Used by poll group to keep the qpair around until it is ready to remove it. */
	bool defer_deletion_to_pg;
};

enum CLIENT_RDMA_COMPLETION_FLAGS
{
	CLIENT_RDMA_SEND_COMPLETED = 1u << 0,
	CLIENT_RDMA_RECV_COMPLETED = 1u << 1,
};

struct spdk_client_rdma_req
{
	uint16_t id;
	uint16_t completion_flags : 2;
	uint16_t reserved : 14;
	/* if completion of RDMA_RECV received before RDMA_SEND, we will complete client request
	 * during processing of RDMA_SEND. To complete the request we must know the index
	 * of client_cpl received in RDMA_RECV, so store it in this field */
	uint16_t rsp_idx;

	struct client_rdma_wr rdma_wr;

	struct ibv_send_wr send_wr;

	struct client_request *req;

	struct ibv_sge send_sgl[CLIENT_RDMA_DEFAULT_TX_SGE];

	TAILQ_ENTRY(spdk_client_rdma_req)
	link;
};

struct spdk_client_rdma_rsp
{
	struct spdk_req_cpl cpl;
	struct client_rdma_qpair *rqpair;
	uint16_t idx;
	struct client_rdma_wr rdma_wr;
};

struct client_rdma_memory_translation_ctx
{
	void *addr;
	size_t length;
	uint32_t lkey;
	uint32_t rkey;
};

static const char *rdma_cm_event_str[] = {
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

struct client_rdma_qpair *client_rdma_poll_group_get_qpair_by_id(struct client_rdma_poll_group *group,
																 uint32_t qp_num);

static TAILQ_HEAD(, client_rdma_memory_domain) g_memory_domains = TAILQ_HEAD_INITIALIZER(
	g_memory_domains);
static pthread_mutex_t g_memory_domains_lock = PTHREAD_MUTEX_INITIALIZER;

static struct client_rdma_memory_domain *
client_rdma_get_memory_domain(struct ibv_pd *pd)
{
	struct client_rdma_memory_domain *domain = NULL;
	struct spdk_memory_domain_ctx ctx;
	int rc;

	pthread_mutex_lock(&g_memory_domains_lock);

	TAILQ_FOREACH(domain, &g_memory_domains, link)
	{
		if (domain->pd == pd)
		{
			domain->ref++;
			pthread_mutex_unlock(&g_memory_domains_lock);
			return domain;
		}
	}

	domain = calloc(1, sizeof(*domain));
	if (!domain)
	{
		SPDK_ERRLOG("Memory allocation failed\n");
		pthread_mutex_unlock(&g_memory_domains_lock);
		return NULL;
	}

	domain->rdma_ctx.size = sizeof(domain->rdma_ctx);
	domain->rdma_ctx.ibv_pd = pd;
	ctx.size = sizeof(ctx);
	ctx.user_ctx = &domain->rdma_ctx;

	rc = spdk_memory_domain_create(&domain->domain, SPDK_DMA_DEVICE_TYPE_RDMA, &ctx,
								   SPDK_RDMA_DMA_DEVICE);
	if (rc)
	{
		SPDK_ERRLOG("Failed to create memory domain\n");
		free(domain);
		pthread_mutex_unlock(&g_memory_domains_lock);
		return NULL;
	}

	domain->pd = pd;
	domain->ref = 1;
	TAILQ_INSERT_TAIL(&g_memory_domains, domain, link);

	pthread_mutex_unlock(&g_memory_domains_lock);

	return domain;
}

static void
client_rdma_put_memory_domain(struct client_rdma_memory_domain *device)
{
	if (!device)
	{
		return;
	}

	pthread_mutex_lock(&g_memory_domains_lock);

	assert(device->ref > 0);

	device->ref--;

	if (device->ref == 0)
	{
		spdk_memory_domain_destroy(device->domain);
		TAILQ_REMOVE(&g_memory_domains, device, link);
		free(device);
	}

	pthread_mutex_unlock(&g_memory_domains_lock);
}

static inline void *
client_rdma_calloc(size_t nmemb, size_t size)
{
	if (!nmemb || !size)
	{
		return NULL;
	}

	if (!g_client_hooks.get_rkey)
	{
		return calloc(nmemb, size);
	}
	else
	{
		return spdk_zmalloc(nmemb * size, 0, NULL, SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
	}
}

static inline void
client_rdma_free(void *buf)
{
	if (!g_client_hooks.get_rkey)
	{
		free(buf);
	}
	else
	{
		spdk_free(buf);
	}
}

static int client_rdma_ctrlr_delete_io_qpair(struct spdk_client_ctrlr *ctrlr,
											 struct spdk_client_qpair *qpair);

static inline struct client_rdma_qpair *
client_rdma_qpair(struct spdk_client_qpair *qpair)
{
	assert(qpair->trtype == SPDK_CLIENT_TRANSPORT_RDMA);
	return SPDK_CONTAINEROF(qpair, struct client_rdma_qpair, qpair);
}

static inline struct client_rdma_poll_group *
client_rdma_poll_group(struct spdk_client_transport_poll_group *group)
{
	return (SPDK_CONTAINEROF(group, struct client_rdma_poll_group, group));
}

static inline struct client_rdma_ctrlr *
client_rdma_ctrlr(struct spdk_client_ctrlr *ctrlr)
{
	return SPDK_CONTAINEROF(ctrlr, struct client_rdma_ctrlr, ctrlr);
}

static struct spdk_client_rdma_req *
client_rdma_req_get(struct client_rdma_qpair *rqpair)
{
	struct spdk_client_rdma_req *rdma_req;

	rdma_req = TAILQ_FIRST(&rqpair->free_reqs);
	if (rdma_req)
	{
		TAILQ_REMOVE(&rqpair->free_reqs, rdma_req, link);
		TAILQ_INSERT_TAIL(&rqpair->outstanding_reqs, rdma_req, link);
	}

	return rdma_req;
}

static void
client_rdma_req_put(struct client_rdma_qpair *rqpair, struct spdk_client_rdma_req *rdma_req)
{
	rdma_req->completion_flags = 0;
	rdma_req->req = NULL;
	TAILQ_INSERT_HEAD(&rqpair->free_reqs, rdma_req, link);
}

static void
client_rdma_req_complete(struct spdk_client_rdma_req *rdma_req,
						 struct spdk_req_cpl *rsp)
{
	struct client_request *req = rdma_req->req;
	struct client_rdma_qpair *rqpair;

	assert(req != NULL);

	rqpair = client_rdma_qpair(req->qpair);
	TAILQ_REMOVE(&rqpair->outstanding_reqs, rdma_req, link);

	client_complete_request(req->cb_fn, req->cb_arg, req->qpair, req, rsp);
	client_free_request(req);
}

static const char *
client_rdma_cm_event_str_get(uint32_t event)
{
	if (event < SPDK_COUNTOF(rdma_cm_event_str))
	{
		return rdma_cm_event_str[event];
	}
	else
	{
		return "Undefined";
	}
}

void client_transport_ctrlr_disconnect_qpair_done(struct spdk_client_qpair *qpair)
{
	client_qpair_abort_all_queued_reqs(qpair, 0);
	client_transport_qpair_abort_reqs(qpair, 0);
	client_qpair_set_state(qpair, CLIENT_QPAIR_DISCONNECTED);
}

static int
client_rdma_qpair_process_cm_event(struct client_rdma_qpair *rqpair)
{
	struct rdma_cm_event *event = rqpair->evt;
	struct spdk_srv_rdma_accept_private_data *accept_data;
	int rc = 0;

	if (event)
	{
		switch (event->event)
		{
		case RDMA_CM_EVENT_ADDR_RESOLVED:
		case RDMA_CM_EVENT_ADDR_ERROR:
		case RDMA_CM_EVENT_ROUTE_RESOLVED:
		case RDMA_CM_EVENT_ROUTE_ERROR:
			break;
		case RDMA_CM_EVENT_CONNECT_REQUEST:
			break;
		case RDMA_CM_EVENT_CONNECT_ERROR:
			break;
		case RDMA_CM_EVENT_UNREACHABLE:
		case RDMA_CM_EVENT_REJECTED:
			break;
		case RDMA_CM_EVENT_CONNECT_RESPONSE:
			rc = spdk_rdma_qp_complete_connect(rqpair->rdma_qp);
		/* fall through */
		case RDMA_CM_EVENT_ESTABLISHED:
			accept_data = (struct spdk_srv_rdma_accept_private_data *)event->param.conn.private_data;
			if (accept_data == NULL)
			{
				rc = -1;
			}
			else
			{
				SPDK_NOTICELOG("client_rdma_qpair_process_cm_event num_entries before: %d\n", rqpair->num_entries);
				SPDK_DEBUGLOG(client, "Requested queue depth %d. Actually got queue depth %d.\n",
							  rqpair->num_entries, accept_data->crqsize);
				rqpair->num_entries = spdk_min(rqpair->num_entries, accept_data->crqsize);
				SPDK_NOTICELOG("client_rdma_qpair_process_cm_event num_entries: %d %d\n", rqpair->num_entries, accept_data->crqsize);
			}
			break;
		case RDMA_CM_EVENT_DISCONNECTED:
			rqpair->qpair.transport_failure_reason = SPDK_CLIENT_QPAIR_FAILURE_REMOTE;
			break;
		case RDMA_CM_EVENT_DEVICE_REMOVAL:
			rqpair->qpair.transport_failure_reason = SPDK_CLIENT_QPAIR_FAILURE_LOCAL;
			break;
		case RDMA_CM_EVENT_MULTICAST_JOIN:
		case RDMA_CM_EVENT_MULTICAST_ERROR:
			break;
		case RDMA_CM_EVENT_ADDR_CHANGE:
			rqpair->qpair.transport_failure_reason = SPDK_CLIENT_QPAIR_FAILURE_LOCAL;
			break;
		case RDMA_CM_EVENT_TIMEWAIT_EXIT:
			break;
		default:
			SPDK_ERRLOG("Unexpected Acceptor Event [%d]\n", event->event);
			break;
		}
		rqpair->evt = NULL;
		rdma_ack_cm_event(event);
	}

	return rc;
}

/*
 * This function must be called under the client controller's lock
 * because it touches global controller variables. The lock is taken
 * by the generic transport code before invoking a few of the functions
 * in this file: client_rdma_ctrlr_connect_qpair, client_rdma_ctrlr_delete_io_qpair,
 * and conditionally client_rdma_qpair_process_completions when it is calling
 * completions on the admin qpair. When adding a new call to this function, please
 * verify that it is in a situation where it falls under the lock.
 */
static int
client_rdma_poll_events(struct client_rdma_ctrlr *rctrlr)
{
	struct client_rdma_cm_event_entry *entry, *tmp;
	struct client_rdma_qpair *event_qpair;
	struct rdma_cm_event *event;
	struct rdma_event_channel *channel = rctrlr->cm_channel;

	STAILQ_FOREACH_SAFE(entry, &rctrlr->pending_cm_events, link, tmp)
	{
		event_qpair = entry->evt->id->context;
		if (event_qpair->evt == NULL)
		{
			event_qpair->evt = entry->evt;
			STAILQ_REMOVE(&rctrlr->pending_cm_events, entry, client_rdma_cm_event_entry, link);
			STAILQ_INSERT_HEAD(&rctrlr->free_cm_events, entry, link);
		}
	}

	while (rdma_get_cm_event(channel, &event) == 0)
	{
		event_qpair = event->id->context;
		if (event_qpair->evt == NULL)
		{
			event_qpair->evt = event;
		}
		else
		{
			assert(rctrlr == client_rdma_ctrlr(event_qpair->qpair.ctrlr));
			entry = STAILQ_FIRST(&rctrlr->free_cm_events);
			if (entry == NULL)
			{
				rdma_ack_cm_event(event);
				return -ENOMEM;
			}
			STAILQ_REMOVE(&rctrlr->free_cm_events, entry, client_rdma_cm_event_entry, link);
			entry->evt = event;
			STAILQ_INSERT_TAIL(&rctrlr->pending_cm_events, entry, link);
		}
	}

	/* rdma_get_cm_event() returns -1 on error. If an error occurs, errno
	 * will be set to indicate the failure reason. So return negated errno here.
	 */
	return -errno;
}

static int
client_rdma_validate_cm_event(enum rdma_cm_event_type expected_evt_type,
							  struct rdma_cm_event *reaped_evt)
{
	int rc = -EBADMSG;

	if (expected_evt_type == reaped_evt->event)
	{
		return 0;
	}

	switch (expected_evt_type)
	{
	case RDMA_CM_EVENT_ESTABLISHED:
		/*
		 * There is an enum ib_cm_rej_reason in the kernel headers that sets 10 as
		 * IB_CM_REJ_STALE_CONN. I can't find the corresponding userspace but we get
		 * the same values here.
		 */
		if (reaped_evt->event == RDMA_CM_EVENT_REJECTED && reaped_evt->status == 10)
		{
			rc = -ESTALE;
		}
		else if (reaped_evt->event == RDMA_CM_EVENT_CONNECT_RESPONSE)
		{
			/*
			 *  If we are using a qpair which is not created using rdma cm API
			 *  then we will receive RDMA_CM_EVENT_CONNECT_RESPONSE instead of
			 *  RDMA_CM_EVENT_ESTABLISHED.
			 */
			return 0;
		}
		break;
	default:
		break;
	}

	SPDK_ERRLOG("Expected %s but received %s (%d) from CM event channel (status = %d)\n",
				client_rdma_cm_event_str_get(expected_evt_type),
				client_rdma_cm_event_str_get(reaped_evt->event), reaped_evt->event,
				reaped_evt->status);
	return rc;
}
static int
client_rdma_process_event_start(struct client_rdma_qpair *rqpair,
								enum rdma_cm_event_type evt,
								client_rdma_cm_event_cb evt_cb)
{
	int rc;

	assert(evt_cb != NULL);

	if (rqpair->evt != NULL)
	{
		rc = client_rdma_qpair_process_cm_event(rqpair);
		if (rc)
		{
			return rc;
		}
	}

	rqpair->expected_evt_type = evt;
	rqpair->evt_cb = evt_cb;
	rqpair->evt_timeout_ticks = (CLIENT_RDMA_QPAIR_CM_EVENT_TIMEOUT_US * spdk_get_ticks_hz()) /
									SPDK_SEC_TO_USEC +
								spdk_get_ticks();

	return 0;
}

static int
client_rdma_process_event_poll(struct client_rdma_qpair *rqpair)
{
	struct client_rdma_ctrlr *rctrlr;
	int rc = 0, rc2;

	rctrlr = client_rdma_ctrlr(rqpair->qpair.ctrlr);
	assert(rctrlr != NULL);

	if (!rqpair->evt && spdk_get_ticks() < rqpair->evt_timeout_ticks)
	{
		rc = client_rdma_poll_events(rctrlr);
		if (rc == -EAGAIN || rc == -EWOULDBLOCK)
		{
			return rc;
		}
	}

	if (rqpair->evt == NULL)
	{
		rc = -EADDRNOTAVAIL;
		goto exit;
	}

	rc = client_rdma_validate_cm_event(rqpair->expected_evt_type, rqpair->evt);

	rc2 = client_rdma_qpair_process_cm_event(rqpair);
	/* bad message takes precedence over the other error codes from processing the event. */
	rc = rc == 0 ? rc2 : rc;

exit:
	assert(rqpair->evt_cb != NULL);
	return rqpair->evt_cb(rqpair, rc);
}

static int
client_rdma_resize_cq(struct client_rdma_qpair *rqpair, struct client_rdma_poller *poller)
{
	int current_num_wc, required_num_wc;

	required_num_wc = poller->required_num_wc + WC_PER_QPAIR(rqpair->num_entries);
	current_num_wc = poller->current_num_wc;
	if (current_num_wc < required_num_wc)
	{
		current_num_wc = spdk_max(current_num_wc * 2, required_num_wc);
	}

	if (poller->current_num_wc != current_num_wc)
	{
		SPDK_DEBUGLOG(client, "Resize RDMA CQ from %d to %d\n", poller->current_num_wc,
					  current_num_wc);
		if (ibv_resize_cq(poller->cq, current_num_wc))
		{
			SPDK_ERRLOG("RDMA CQ resize failed: errno %d: %s\n", errno, spdk_strerror(errno));
			return -1;
		}

		poller->current_num_wc = current_num_wc;
	}

	poller->required_num_wc = required_num_wc;
	return 0;
}

static int
client_rdma_poll_group_set_cq(struct spdk_client_qpair *qpair)
{
	struct client_rdma_qpair *rqpair = client_rdma_qpair(qpair);
	struct client_rdma_poll_group *group = client_rdma_poll_group(qpair->poll_group);
	struct client_rdma_poller *poller;

	assert(rqpair->cq == NULL);

	STAILQ_FOREACH(poller, &group->pollers, link)
	{
		if (poller->device == rqpair->cm_id->verbs)
		{
			if (client_rdma_resize_cq(rqpair, poller))
			{
				return -EPROTO;
			}
			rqpair->cq = poller->cq;
			rqpair->poller = poller;
			break;
		}
	}

	if (rqpair->cq == NULL)
	{
		SPDK_ERRLOG("Unable to find a cq for qpair %p on poll group %p\n", qpair, qpair->poll_group);
		return -EINVAL;
	}

	return 0;
}

static int
client_rdma_qpair_init(struct client_rdma_qpair *rqpair)
{
	int rc;
	struct spdk_rdma_qp_init_attr attr = {};
	struct ibv_device_attr dev_attr;
	struct client_rdma_ctrlr *rctrlr;

	rc = ibv_query_device(rqpair->cm_id->verbs, &dev_attr);
	if (rc != 0)
	{
		SPDK_ERRLOG("Failed to query RDMA device attributes.\n");
		return -1;
	}

	if (rqpair->qpair.poll_group)
	{
		assert(!rqpair->cq);
		rc = client_rdma_poll_group_set_cq(&rqpair->qpair);
		if (rc)
		{
			SPDK_ERRLOG("Unable to activate the rdmaqpair.\n");
			return -1;
		}
		assert(rqpair->cq);
	}
	else
	{
		rqpair->cq = ibv_create_cq(rqpair->cm_id->verbs, rqpair->num_entries * 2, rqpair, NULL, 0);
		if (!rqpair->cq)
		{
			SPDK_ERRLOG("Unable to create completion queue: errno %d: %s\n", errno, spdk_strerror(errno));
			return -1;
		}
	}

	rctrlr = client_rdma_ctrlr(rqpair->qpair.ctrlr);
	if (g_client_hooks.get_ibv_pd)
	{
		rctrlr->pd = g_client_hooks.get_ibv_pd(rqpair->qpair.trid, rqpair->cm_id->verbs);
	}
	else
	{
		rctrlr->pd = NULL;
	}

	attr.pd = rctrlr->pd;
	attr.stats = rqpair->poller ? &rqpair->poller->stats.rdma_stats : NULL;
	attr.send_cq = rqpair->cq;
	attr.recv_cq = rqpair->cq;
	attr.cap.max_send_wr = rqpair->num_entries; /* SEND operations */
	attr.cap.max_recv_wr = rqpair->num_entries; /* RECV operations */
	attr.cap.max_send_sge = spdk_min(CLIENT_RDMA_DEFAULT_TX_SGE, dev_attr.max_sge);
	attr.cap.max_recv_sge = spdk_min(CLIENT_RDMA_DEFAULT_RX_SGE, dev_attr.max_sge);

	rqpair->rdma_qp = spdk_rdma_qp_create(rqpair->cm_id, &attr);

	if (!rqpair->rdma_qp)
	{
		return -1;
	}

	rqpair->memory_domain = client_rdma_get_memory_domain(rqpair->rdma_qp->qp->pd);
	if (!rqpair->memory_domain)
	{
		SPDK_ERRLOG("Failed to get memory domain\n");
		return -1;
	}

	/* ibv_create_qp will change the values in attr.cap. Make sure we store the proper value. */
	rqpair->max_send_sge = spdk_min(CLIENT_RDMA_DEFAULT_TX_SGE, attr.cap.max_send_sge);
	rqpair->max_recv_sge = spdk_min(CLIENT_RDMA_DEFAULT_RX_SGE, attr.cap.max_recv_sge);
	rqpair->current_num_recvs = 0;
	rqpair->current_num_sends = 0;

	rctrlr->pd = rqpair->rdma_qp->qp->pd;

	rqpair->cm_id->context = rqpair;

	return 0;
}

static inline int
client_rdma_qpair_submit_sends(struct client_rdma_qpair *rqpair)
{
	struct ibv_send_wr *bad_send_wr = NULL;
	int rc;

	rc = spdk_rdma_qp_flush_send_wrs(rqpair->rdma_qp, &bad_send_wr);

	if (spdk_unlikely(rc))
	{
		SPDK_ERRLOG("Failed to post WRs on send queue, errno %d (%s), bad_wr %p\n",
					rc, spdk_strerror(rc), bad_send_wr);
		while (bad_send_wr != NULL)
		{
			assert(rqpair->current_num_sends > 0);
			rqpair->current_num_sends--;
			bad_send_wr = bad_send_wr->next;
		}
		return rc;
	}

	return 0;
}

static inline int
client_rdma_qpair_submit_recvs(struct client_rdma_qpair *rqpair)
{
	struct ibv_recv_wr *bad_recv_wr;
	int rc = 0;

	rc = spdk_rdma_qp_flush_recv_wrs(rqpair->rdma_qp, &bad_recv_wr);
	if (spdk_unlikely(rc))
	{
		SPDK_ERRLOG("Failed to post WRs on receive queue, errno %d (%s), bad_wr %p\n",
					rc, spdk_strerror(rc), bad_recv_wr);
		while (bad_recv_wr != NULL)
		{
			assert(rqpair->current_num_sends > 0);
			rqpair->current_num_recvs--;
			bad_recv_wr = bad_recv_wr->next;
		}
	}

	return rc;
}

/* Append the given send wr structure to the qpair's outstanding sends list. */
/* This function accepts only a single wr. */
static inline int
client_rdma_qpair_queue_send_wr(struct client_rdma_qpair *rqpair, struct ibv_send_wr *wr)
{
	assert(wr->next == NULL);

	assert(rqpair->current_num_sends < rqpair->num_entries);

	rqpair->current_num_sends++;
	spdk_rdma_qp_queue_send_wrs(rqpair->rdma_qp, wr);

	if (!rqpair->delay_cmd_submit)
	{
		return client_rdma_qpair_submit_sends(rqpair);
	}

	return 0;
}

/* Append the given recv wr structure to the qpair's outstanding recvs list. */
/* This function accepts only a single wr. */
static inline int
client_rdma_qpair_queue_recv_wr(struct client_rdma_qpair *rqpair, struct ibv_recv_wr *wr)
{

	assert(wr->next == NULL);
	assert(rqpair->current_num_recvs < rqpair->num_entries);

	rqpair->current_num_recvs++;
	spdk_rdma_qp_queue_recv_wrs(rqpair->rdma_qp, wr);

	if (!rqpair->delay_cmd_submit)
	{
		return client_rdma_qpair_submit_recvs(rqpair);
	}

	return 0;
}

#define client_rdma_trace_ibv_sge(sg_list)                                          \
	if (sg_list)                                                                    \
	{                                                                               \
		SPDK_DEBUGLOG(client, "local addr %p length 0x%x lkey 0x%x\n",              \
					  (void *)(sg_list)->addr, (sg_list)->length, (sg_list)->lkey); \
	}

static int
client_rdma_post_recv(struct client_rdma_qpair *rqpair, uint16_t rsp_idx)
{
	struct ibv_recv_wr *wr;

	wr = &rqpair->rsp_recv_wrs[rsp_idx];
	wr->next = NULL;
	client_rdma_trace_ibv_sge(wr->sg_list);
	return client_rdma_qpair_queue_recv_wr(rqpair, wr);
}

static int
client_rdma_reg_mr(struct rdma_cm_id *cm_id, union client_rdma_mr *mr, void *mem, size_t length)
{
	if (!g_client_hooks.get_rkey)
	{
		mr->mr = rdma_reg_msgs(cm_id, mem, length);
		if (mr->mr == NULL)
		{
			SPDK_ERRLOG("Unable to register mr: %s (%d)\n",
						spdk_strerror(errno), errno);
			return -1;
		}
	}
	else
	{
		mr->key = g_client_hooks.get_rkey(cm_id->pd, mem, length);
	}

	return 0;
}

static void
client_rdma_dereg_mr(union client_rdma_mr *mr)
{
	if (!g_client_hooks.get_rkey)
	{
		if (mr->mr && rdma_dereg_mr(mr->mr))
		{
			SPDK_ERRLOG("Unable to de-register mr\n");
		}
	}
	else
	{
		if (mr->key)
		{
			g_client_hooks.put_rkey(mr->key);
		}
	}
	memset(mr, 0, sizeof(*mr));
}

static uint32_t
client_rdma_mr_get_lkey(union client_rdma_mr *mr)
{
	uint32_t lkey;

	if (!g_client_hooks.get_rkey)
	{
		lkey = mr->mr->lkey;
	}
	else
	{
		lkey = *((uint64_t *)mr->key);
	}

	return lkey;
}

static void
client_rdma_unregister_rsps(struct client_rdma_qpair *rqpair)
{
	client_rdma_dereg_mr(&rqpair->rsp_mr);
}

static void
client_rdma_free_rsps(struct client_rdma_qpair *rqpair)
{
	client_rdma_free(rqpair->rsps);
	rqpair->rsps = NULL;
	client_rdma_free(rqpair->rsp_sgls);
	rqpair->rsp_sgls = NULL;
	client_rdma_free(rqpair->rsp_recv_wrs);
	rqpair->rsp_recv_wrs = NULL;
}

static int
client_rdma_alloc_rsps(struct client_rdma_qpair *rqpair)
{
	rqpair->rsps = NULL;
	rqpair->rsp_recv_wrs = NULL;

	rqpair->rsp_sgls = client_rdma_calloc(rqpair->num_entries, sizeof(*rqpair->rsp_sgls));
	if (!rqpair->rsp_sgls)
	{
		SPDK_ERRLOG("Failed to allocate rsp_sgls\n");
		goto fail;
	}

	rqpair->rsp_recv_wrs = client_rdma_calloc(rqpair->num_entries, sizeof(*rqpair->rsp_recv_wrs));
	if (!rqpair->rsp_recv_wrs)
	{
		SPDK_ERRLOG("Failed to allocate rsp_recv_wrs\n");
		goto fail;
	}

	rqpair->rsps = client_rdma_calloc(rqpair->num_entries, sizeof(*rqpair->rsps));
	if (!rqpair->rsps)
	{
		SPDK_ERRLOG("can not allocate rdma rsps\n");
		goto fail;
	}

	return 0;
fail:
	client_rdma_free_rsps(rqpair);
	return -ENOMEM;
}

static int
client_rdma_register_rsps(struct client_rdma_qpair *rqpair)
{
	uint16_t i;
	int rc;
	uint32_t lkey;

	rc = client_rdma_reg_mr(rqpair->cm_id, &rqpair->rsp_mr,
							rqpair->rsps, rqpair->num_entries * sizeof(*rqpair->rsps));

	if (rc < 0)
	{
		goto fail;
	}

	lkey = client_rdma_mr_get_lkey(&rqpair->rsp_mr);

	for (i = 0; i < rqpair->num_entries; i++)
	{
		struct ibv_sge *rsp_sgl = &rqpair->rsp_sgls[i];
		struct spdk_client_rdma_rsp *rsp = &rqpair->rsps[i];

		rsp->rqpair = rqpair;
		rsp->rdma_wr.type = RDMA_WR_TYPE_RECV;
		rsp->idx = i;
		rsp_sgl->addr = (uint64_t)&rqpair->rsps[i];
		rsp_sgl->length = sizeof(struct spdk_req_cpl);
		rsp_sgl->lkey = lkey;

		rqpair->rsp_recv_wrs[i].wr_id = (uint64_t)&rsp->rdma_wr;
		rqpair->rsp_recv_wrs[i].next = NULL;
		rqpair->rsp_recv_wrs[i].sg_list = rsp_sgl;
		rqpair->rsp_recv_wrs[i].num_sge = 1;

		rc = client_rdma_post_recv(rqpair, i);
		if (rc)
		{
			goto fail;
		}
	}

	rc = client_rdma_qpair_submit_recvs(rqpair);
	if (rc)
	{
		goto fail;
	}

	return 0;

fail:
	client_rdma_unregister_rsps(rqpair);
	return rc;
}

static void
client_rdma_unregister_reqs(struct client_rdma_qpair *rqpair)
{
	client_rdma_dereg_mr(&rqpair->cmd_mr);
}

static void
client_rdma_free_reqs(struct client_rdma_qpair *rqpair)
{
	if (!rqpair->rdma_reqs)
	{
		return;
	}

	client_rdma_free(rqpair->cmds);
	rqpair->cmds = NULL;

	client_rdma_free(rqpair->rdma_reqs);
	rqpair->rdma_reqs = NULL;
}

static int
client_rdma_alloc_reqs(struct client_rdma_qpair *rqpair)
{
	uint16_t i;

	rqpair->rdma_reqs = client_rdma_calloc(rqpair->num_entries, sizeof(struct spdk_client_rdma_req));
	if (rqpair->rdma_reqs == NULL)
	{
		SPDK_ERRLOG("Failed to allocate rdma_reqs\n");
		goto fail;
	}

	rqpair->cmds = client_rdma_calloc(rqpair->num_entries, sizeof(*rqpair->cmds));
	if (!rqpair->cmds)
	{
		SPDK_ERRLOG("Failed to allocate RDMA cmds\n");
		goto fail;
	}

	TAILQ_INIT(&rqpair->free_reqs);
	TAILQ_INIT(&rqpair->outstanding_reqs);
	for (i = 0; i < rqpair->num_entries; i++)
	{
		struct spdk_client_rdma_req *rdma_req;
		struct spdk_client_cmd *cmd;

		rdma_req = &rqpair->rdma_reqs[i];
		rdma_req->rdma_wr.type = RDMA_WR_TYPE_SEND;
		cmd = &rqpair->cmds[i];

		rdma_req->id = i;

		/* The first RDMA sgl element will always point
		 * at this data structure. Depending on whether
		 * an Client-oF SGL is required, the length of
		 * this element may change. */
		rdma_req->send_sgl[0].addr = (uint64_t)cmd;
		rdma_req->send_wr.wr_id = (uint64_t)&rdma_req->rdma_wr;
		rdma_req->send_wr.next = NULL;
		rdma_req->send_wr.opcode = IBV_WR_SEND;
		rdma_req->send_wr.send_flags = IBV_SEND_SIGNALED;
		rdma_req->send_wr.sg_list = rdma_req->send_sgl;
		rdma_req->send_wr.imm_data = 0;

		TAILQ_INSERT_TAIL(&rqpair->free_reqs, rdma_req, link);
	}

	return 0;
fail:
	client_rdma_free_reqs(rqpair);
	return -ENOMEM;
}

static int
client_rdma_register_reqs(struct client_rdma_qpair *rqpair)
{
	int i;
	int rc;
	uint32_t lkey;
	SPDK_NOTICELOG("client_rdma_register_reqs: %d\n", rqpair->num_entries);
	rc = client_rdma_reg_mr(rqpair->cm_id, &rqpair->cmd_mr,
							rqpair->cmds, rqpair->num_entries * sizeof(*rqpair->cmds));

	if (rc < 0)
	{
		goto fail;
	}

	lkey = client_rdma_mr_get_lkey(&rqpair->cmd_mr);

	for (i = 0; i < rqpair->num_entries; i++)
	{
		rqpair->rdma_reqs[i].send_sgl[0].lkey = lkey;
	}

	return 0;

fail:
	client_rdma_unregister_reqs(rqpair);
	return -ENOMEM;
}

static int client_rdma_connect(struct client_rdma_qpair *rqpair);

static int
client_rdma_route_resolved(struct client_rdma_qpair *rqpair, int ret)
{
	if (ret)
	{
		SPDK_ERRLOG("RDMA route resolution error\n");
		return -1;
	}

	ret = client_rdma_qpair_init(rqpair);
	if (ret < 0)
	{
		SPDK_ERRLOG("client_rdma_qpair_init() failed\n");
		return -1;
	}

	return client_rdma_connect(rqpair);
}

static int
client_rdma_addr_resolved(struct client_rdma_qpair *rqpair, int ret)
{
	if (ret)
	{
		SPDK_ERRLOG("RDMA address resolution error\n");
		return -1;
	}

	if (rqpair->qpair.ctrlr->opts.transport_ack_timeout != SPDK_CLIENT_TRANSPORT_ACK_TIMEOUT_DISABLED)
	{
#ifdef SPDK_CONFIG_RDMA_SET_ACK_TIMEOUT
		uint8_t timeout = rqpair->qpair.ctrlr->opts.transport_ack_timeout;
		ret = rdma_set_option(rqpair->cm_id, RDMA_OPTION_ID,
							  RDMA_OPTION_ID_ACK_TIMEOUT,
							  &timeout, sizeof(timeout));
		if (ret)
		{
			SPDK_NOTICELOG("Can't apply RDMA_OPTION_ID_ACK_TIMEOUT %d, ret %d\n", timeout, ret);
		}
#else
		SPDK_DEBUGLOG(client, "transport_ack_timeout is not supported\n");
#endif
	}

	ret = rdma_resolve_route(rqpair->cm_id, CLIENT_RDMA_TIME_OUT_IN_MS);
	if (ret)
	{
		SPDK_ERRLOG("rdma_resolve_route\n");
		return ret;
	}

	return client_rdma_process_event_start(rqpair, RDMA_CM_EVENT_ROUTE_RESOLVED,
										   client_rdma_route_resolved);
}

static int
client_rdma_resolve_addr(struct client_rdma_qpair *rqpair,
						 struct sockaddr *src_addr,
						 struct sockaddr *dst_addr)

{
	int ret;

	ret = rdma_resolve_addr(rqpair->cm_id, src_addr, dst_addr,
							CLIENT_RDMA_TIME_OUT_IN_MS);
	if (ret)
	{
		SPDK_ERRLOG("rdma_resolve_addr, %d\n", errno);
		return ret;
	}

	return client_rdma_process_event_start(rqpair, RDMA_CM_EVENT_ADDR_RESOLVED,
										   client_rdma_addr_resolved);
}

static int client_rdma_stale_conn_retry(struct client_rdma_qpair *rqpair);

static int
client_rdma_connect_established(struct client_rdma_qpair *rqpair, int ret)
{
	if (ret == -ESTALE)
	{
		return client_rdma_stale_conn_retry(rqpair);
	}
	else if (ret)
	{
		SPDK_ERRLOG("RDMA connect error %d\n", ret);
		return ret;
	}

	ret = client_rdma_register_reqs(rqpair);
	SPDK_DEBUGLOG(client, "rc =%d\n", ret);
	if (ret)
	{
		SPDK_ERRLOG("Unable to register rqpair RDMA requests\n");
		return -1;
	}
	SPDK_DEBUGLOG(client, "RDMA requests registered\n");

	ret = client_rdma_register_rsps(rqpair);
	SPDK_DEBUGLOG(client, "rc =%d\n", ret);
	if (ret < 0)
	{
		SPDK_ERRLOG("Unable to register rqpair RDMA responses\n");
		return -1;
	}
	SPDK_DEBUGLOG(client, "RDMA responses registered\n");

	rqpair->mr_map = spdk_rdma_create_mem_map(rqpair->rdma_qp->qp->pd, &g_client_hooks,
											  SPDK_RDMA_MEMORY_MAP_ROLE_INITIATOR);
	if (!rqpair->mr_map)
	{
		SPDK_ERRLOG("Unable to register RDMA memory translation map\n");
		return -1;
	}

	rqpair->state = CLIENT_RDMA_QPAIR_STATE_RUNNING;

	return 0;
}

static int
client_rdma_connect(struct client_rdma_qpair *rqpair)
{
	struct rdma_conn_param param = {};
	struct spdk_srv_rdma_request_private_data request_data = {};
	struct ibv_device_attr attr;
	int ret;
	struct spdk_client_ctrlr *ctrlr;
	struct client_rdma_ctrlr *rctrlr;

	ret = ibv_query_device(rqpair->cm_id->verbs, &attr);
	if (ret != 0)
	{
		SPDK_ERRLOG("Failed to query RDMA device attributes.\n");
		return ret;
	}

	param.responder_resources = spdk_min(rqpair->num_entries, attr.max_qp_rd_atom);

	ctrlr = rqpair->qpair.ctrlr;
	if (!ctrlr)
	{
		return -1;
	}
	rctrlr = client_rdma_ctrlr(ctrlr);
	assert(rctrlr != NULL);

	request_data.qid = rqpair->qpair.id;
	request_data.hrqsize = rqpair->num_entries;
	request_data.hsqsize = rqpair->num_entries - 1;
	request_data.cntlid = ctrlr->cntlid;

	param.private_data = &request_data;
	param.private_data_len = sizeof(request_data);
	param.retry_count = ctrlr->opts.transport_retry_count;
	param.rnr_retry_count = 7;

	/* Fields below are ignored by rdma cm if qpair has been
	 * created using rdma cm API. */
	param.srq = 0;
	param.qp_num = rqpair->rdma_qp->qp->qp_num;

	ret = rdma_connect(rqpair->cm_id, &param);
	if (ret)
	{
		SPDK_ERRLOG("client rdma connect error\n");
		return ret;
	}

	return client_rdma_process_event_start(rqpair, RDMA_CM_EVENT_ESTABLISHED,
										   client_rdma_connect_established);
}

static int
client_rdma_parse_addr(struct sockaddr_storage *sa, int family, const char *addr, const char *service)
{
	struct addrinfo *res;
	struct addrinfo hints;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;

	ret = getaddrinfo(addr, service, &hints, &res);
	if (ret)
	{
		SPDK_ERRLOG("getaddrinfo failed: %s (%d)\n", gai_strerror(ret), ret);
		return ret;
	}

	if (res->ai_addrlen > sizeof(*sa))
	{
		SPDK_ERRLOG("getaddrinfo() ai_addrlen %zu too large\n", (size_t)res->ai_addrlen);
		ret = EINVAL;
	}
	else
	{
		memcpy(sa, res->ai_addr, res->ai_addrlen);
	}

	freeaddrinfo(res);
	return ret;
}

static int
client_rdma_ctrlr_connect_qpair(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair)
{
	struct sockaddr_storage dst_addr;
	struct sockaddr_storage src_addr;
	bool src_addr_specified;
	int rc;
	struct client_rdma_ctrlr *rctrlr;
	struct client_rdma_qpair *rqpair;
	int family;

	rqpair = client_rdma_qpair(qpair);
	rctrlr = client_rdma_ctrlr(ctrlr);
	assert(rctrlr != NULL);

	switch (qpair->trid->adrfam)
	{
	case SPDK_SRV_ADRFAM_IPV4:
		family = AF_INET;
		break;
	case SPDK_SRV_ADRFAM_IPV6:
		family = AF_INET6;
		break;
	default:
		SPDK_ERRLOG("Unhandled ADRFAM %d\n", qpair->trid->adrfam);
		return -1;
	}

	SPDK_DEBUGLOG(client, "adrfam %d ai_family %d\n", qpair->trid->adrfam, family);

	memset(&dst_addr, 0, sizeof(dst_addr));

	SPDK_DEBUGLOG(client, "trsvcid is %s\n", qpair->trid->trsvcid);
	rc = client_rdma_parse_addr(&dst_addr, family, qpair->trid->traddr, qpair->trid->trsvcid);
	if (rc != 0)
	{
		SPDK_ERRLOG("dst_addr client_rdma_parse_addr() failed\n");
		return -1;
	}

	if (ctrlr->opts.src_addr[0] || ctrlr->opts.src_svcid[0])
	{
		memset(&src_addr, 0, sizeof(src_addr));
		rc = client_rdma_parse_addr(&src_addr, family, ctrlr->opts.src_addr, ctrlr->opts.src_svcid);
		if (rc != 0)
		{
			SPDK_ERRLOG("src_addr client_rdma_parse_addr() failed\n");
			return -1;
		}
		src_addr_specified = true;
	}
	else
	{
		src_addr_specified = false;
	}

	rc = rdma_create_id(rctrlr->cm_channel, &rqpair->cm_id, rqpair, RDMA_PS_TCP);
	if (rc < 0)
	{
		SPDK_ERRLOG("rdma_create_id() failed\n");
		return -1;
	}

	rc = client_rdma_resolve_addr(rqpair,
								  src_addr_specified ? (struct sockaddr *)&src_addr : NULL,
								  (struct sockaddr *)&dst_addr);
	if (rc < 0)
	{
		SPDK_ERRLOG("client_rdma_resolve_addr() failed\n");
		return -1;
	}

	rqpair->state = CLIENT_RDMA_QPAIR_STATE_INITIALIZING;
	return 0;
}

static int
client_rdma_stale_conn_reconnect(struct client_rdma_qpair *rqpair)
{
	struct spdk_client_qpair *qpair = &rqpair->qpair;

	if (spdk_get_ticks() < rqpair->evt_timeout_ticks)
	{
		return -EAGAIN;
	}

	return client_rdma_ctrlr_connect_qpair(qpair->ctrlr, qpair);
}

static int
client_rdma_ctrlr_connect_qpair_poll(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair)
{
	struct client_rdma_qpair *rqpair = client_rdma_qpair(qpair);
	int rc;

	if (rqpair->in_connect_poll)
	{
		return -EAGAIN;
	}

	rqpair->in_connect_poll = true;

	switch (rqpair->state)
	{
	case CLIENT_RDMA_QPAIR_STATE_INVALID:
		rc = -EAGAIN;
		break;

	case CLIENT_RDMA_QPAIR_STATE_INITIALIZING:
	case CLIENT_RDMA_QPAIR_STATE_EXITING:

		client_robust_mutex_lock(&ctrlr->ctrlr_lock);

		rc = client_rdma_process_event_poll(rqpair);

		client_robust_mutex_unlock(&ctrlr->ctrlr_lock);

		if (rc == 0)
		{
			rc = -EAGAIN;
		}
		rqpair->in_connect_poll = false;

		return rc;

	case CLIENT_RDMA_QPAIR_STATE_STALE_CONN:
		rc = client_rdma_stale_conn_reconnect(rqpair);
		if (rc == 0)
		{
			rc = -EAGAIN;
		}
		break;
	case CLIENT_RDMA_QPAIR_STATE_RUNNING:
		client_qpair_set_state(qpair, CLIENT_QPAIR_CONNECTED);
		qpair->cb(qpair->cb_args, 0);
		rc = 0;
		break;
	default:
		assert(false);
		rc = -EINVAL;
		break;
	}

	rqpair->in_connect_poll = false;

	return rc;
}

static inline int
client_rdma_get_memory_translation(struct client_request *req, struct client_rdma_qpair *rqpair,
								   struct client_rdma_memory_translation_ctx *_ctx)
{
	struct spdk_memory_domain_translation_ctx ctx;
	struct spdk_memory_domain_translation_result dma_translation = {.iov_count = 0};
	struct spdk_rdma_memory_translation rdma_translation;
	int rc;

	assert(req);
	assert(rqpair);
	assert(_ctx);

	rc = spdk_rdma_get_translation(rqpair->mr_map, _ctx->addr, _ctx->length, &rdma_translation);
	if (spdk_unlikely(rc))
	{
		SPDK_ERRLOG("RDMA memory translation failed, rc %d\n", rc);
		return rc;
	}
	if (rdma_translation.translation_type == SPDK_RDMA_TRANSLATION_MR)
	{
		_ctx->lkey = rdma_translation.mr_or_key.mr->lkey;
		_ctx->rkey = rdma_translation.mr_or_key.mr->rkey;
	}
	else
	{
		_ctx->lkey = _ctx->rkey = (uint32_t)rdma_translation.mr_or_key.key;
	}
	return 0;
}

/*
 * Build SGL describing empty payload.
 */
static int
client_rdma_build_null_request(struct spdk_client_rdma_req *rdma_req)
{
	struct client_request *req = rdma_req->req;

	req->cmd.psdt = SPDK_CLIENT_PSDT_SGL_MPTR_CONTIG;

	/* The first element of this SGL is pointing at an
	 * spdk_client_cmd object. For this particular command,
	 * we only need the first 64 bytes corresponding to
	 * the Client command. */
	rdma_req->send_sgl[0].length = sizeof(struct spdk_req_cmd);

	/* The RDMA SGL needs one element describing the Client command. */
	rdma_req->send_wr.num_sge = 1;

	req->cmd.dptr.sgl1.keyed.type = SPDK_CLIENT_SGL_TYPE_KEYED_DATA_BLOCK;
	req->cmd.dptr.sgl1.keyed.subtype = SPDK_CLIENT_SGL_SUBTYPE_ADDRESS;
	req->cmd.dptr.sgl1.keyed.length = 0;
	req->cmd.dptr.sgl1.keyed.key = 0;
	req->cmd.dptr.sgl1.address = 0;

	return 0;
}

/*
 * Build inline SGL describing contiguous payload buffer.
 */
static int
client_rdma_build_contig_inline_request(struct client_rdma_qpair *rqpair,
										struct spdk_client_rdma_req *rdma_req)
{
	struct client_request *req = rdma_req->req;
	struct client_rdma_memory_translation_ctx ctx = {
		.addr = req->payload.contig_or_cb_arg + req->payload_offset,
		.length = req->payload_size};
	int rc;

	assert(ctx.length != 0);
	assert(client_payload_type(&req->payload) == CLIENT_PAYLOAD_TYPE_CONTIG);

	rc = client_rdma_get_memory_translation(req, rqpair, &ctx);
	if (spdk_unlikely(rc))
	{
		return -1;
	}

	rdma_req->send_sgl[1].lkey = ctx.lkey;

	/* The first element of this SGL is pointing at an
	 * spdk_client_cmd object. For this particular command,
	 * we only need the first 64 bytes corresponding to
	 * the Client command. */
	rdma_req->send_sgl[0].length = sizeof(struct spdk_req_cmd);

	rdma_req->send_sgl[1].addr = (uint64_t)ctx.addr;
	rdma_req->send_sgl[1].length = (uint32_t)ctx.length;

	/* The RDMA SGL contains two elements. The first describes
	 * the Client command and the second describes the data
	 * payload. */
	rdma_req->send_wr.num_sge = 2;

	req->cmd.psdt = SPDK_CLIENT_PSDT_SGL_MPTR_CONTIG;
	req->cmd.dptr.sgl1.unkeyed.type = SPDK_CLIENT_SGL_TYPE_DATA_BLOCK;
	req->cmd.dptr.sgl1.unkeyed.subtype = SPDK_CLIENT_SGL_SUBTYPE_OFFSET;
	req->cmd.dptr.sgl1.unkeyed.length = (uint32_t)ctx.length;
	/* Inline only supported for icdoff == 0 currently.  This function will
	 * not get called for controllers with other values. */
	req->cmd.dptr.sgl1.address = (uint64_t)0;

	return 0;
}

/*
 * Build SGL describing contiguous payload buffer.
 */
static int
client_rdma_build_contig_request(struct client_rdma_qpair *rqpair,
								 struct spdk_client_rdma_req *rdma_req)
{
	struct client_request *req = rdma_req->req;
	struct client_rdma_memory_translation_ctx ctx = {
		.addr = req->payload.contig_or_cb_arg + req->payload_offset,
		.length = req->payload_size};
	int rc;

	assert(req->payload_size != 0);
	assert(client_payload_type(&req->payload) == CLIENT_PAYLOAD_TYPE_CONTIG);

	if (spdk_unlikely(req->payload_size > CLIENT_RDMA_MAX_KEYED_SGL_LENGTH))
	{
		SPDK_ERRLOG("SGL length %u exceeds max keyed SGL block size %u\n",
					req->payload_size, CLIENT_RDMA_MAX_KEYED_SGL_LENGTH);
		return -1;
	}

	rc = client_rdma_get_memory_translation(req, rqpair, &ctx);
	if (spdk_unlikely(rc))
	{
		return -1;
	}

	req->cmd.dptr.sgl1.keyed.key = ctx.rkey;

	/* The first element of this SGL is pointing at an
	 * spdk_client_cmd object. For this particular command,
	 * we only need the first 64 bytes corresponding to
	 * the Client command. */
	rdma_req->send_sgl[0].length = sizeof(struct spdk_req_cmd);

	/* The RDMA SGL needs one element describing the Client command. */
	rdma_req->send_wr.num_sge = 1;

	req->cmd.psdt = SPDK_CLIENT_PSDT_SGL_MPTR_CONTIG;
	req->cmd.dptr.sgl1.keyed.type = SPDK_CLIENT_SGL_TYPE_KEYED_DATA_BLOCK;
	req->cmd.dptr.sgl1.keyed.subtype = SPDK_CLIENT_SGL_SUBTYPE_ADDRESS;
	req->cmd.dptr.sgl1.keyed.length = (uint32_t)ctx.length;
	req->cmd.dptr.sgl1.address = (uint64_t)ctx.addr;

	return 0;
}

/*
 * Build SGL describing scattered payload buffer.
 */
static int
client_rdma_build_sgl_request(struct client_rdma_qpair *rqpair,
							  struct spdk_client_rdma_req *rdma_req)
{
	struct client_request *req = rdma_req->req;
	struct spdk_client_cmd *cmd = &rqpair->cmds[rdma_req->id];
	struct client_rdma_memory_translation_ctx ctx;
	uint32_t remaining_size;
	uint32_t sge_length;
	int rc, max_num_sgl, num_sgl_desc;

	assert(req->payload_size != 0);
	assert(client_payload_type(&req->payload) == CLIENT_PAYLOAD_TYPE_SGL);
	assert(req->payload.reset_sgl_fn != NULL);
	assert(req->payload.next_sge_fn != NULL);
	req->payload.reset_sgl_fn(req->payload.contig_or_cb_arg, req->payload_offset);

	max_num_sgl = req->qpair->ctrlr->max_sges;

	remaining_size = req->payload_size;
	num_sgl_desc = 0;
	do
	{
		rc = req->payload.next_sge_fn(req->payload.contig_or_cb_arg, &ctx.addr, &sge_length);
		if (rc)
		{
			return -1;
		}

		sge_length = spdk_min(remaining_size, sge_length);

		if (spdk_unlikely(sge_length > CLIENT_RDMA_MAX_KEYED_SGL_LENGTH))
		{
			SPDK_ERRLOG("SGL length %u exceeds max keyed SGL block size %u\n",
						sge_length, CLIENT_RDMA_MAX_KEYED_SGL_LENGTH);
			return -1;
		}
		ctx.length = sge_length;
		rc = client_rdma_get_memory_translation(req, rqpair, &ctx);
		if (spdk_unlikely(rc))
		{
			return -1;
		}

		cmd->sgl[num_sgl_desc].keyed.key = ctx.rkey;
		cmd->sgl[num_sgl_desc].keyed.type = SPDK_CLIENT_SGL_TYPE_KEYED_DATA_BLOCK;
		cmd->sgl[num_sgl_desc].keyed.subtype = SPDK_CLIENT_SGL_SUBTYPE_ADDRESS;
		cmd->sgl[num_sgl_desc].keyed.length = (uint32_t)ctx.length;
		cmd->sgl[num_sgl_desc].address = (uint64_t)ctx.addr;

		remaining_size -= ctx.length;
		num_sgl_desc++;
	} while (remaining_size > 0 && num_sgl_desc < max_num_sgl);

	/* Should be impossible if we did our sgl checks properly up the stack, but do a sanity check here. */
	if (remaining_size > 0)
	{
		return -1;
	}

	req->cmd.psdt = SPDK_CLIENT_PSDT_SGL_MPTR_CONTIG;

	/* The RDMA SGL needs one element describing some portion
	 * of the spdk_client_cmd structure. */
	rdma_req->send_wr.num_sge = 1;

	/*
	 * If only one SGL descriptor is required, it can be embedded directly in the command
	 * as a data block descriptor.
	 */
	if (num_sgl_desc == 1)
	{
		/* The first element of this SGL is pointing at an
		 * spdk_client_cmd object. For this particular command,
		 * we only need the first 64 bytes corresponding to
		 * the Client command. */
		rdma_req->send_sgl[0].length = sizeof(struct spdk_req_cmd);

		req->cmd.dptr.sgl1.keyed.type = cmd->sgl[0].keyed.type;
		req->cmd.dptr.sgl1.keyed.subtype = cmd->sgl[0].keyed.subtype;
		req->cmd.dptr.sgl1.keyed.length = cmd->sgl[0].keyed.length;
		req->cmd.dptr.sgl1.keyed.key = cmd->sgl[0].keyed.key;
		req->cmd.dptr.sgl1.address = cmd->sgl[0].address;
	}
	else
	{
		/*
		 * Otherwise, The SGL descriptor embedded in the command must point to the list of
		 * SGL descriptors used to describe the operation. In that case it is a last segment descriptor.
		 */
		uint32_t descriptors_size = sizeof(struct spdk_req_sgl_descriptor) * num_sgl_desc;

		if (spdk_unlikely(descriptors_size > rqpair->qpair.ctrlr->ioccsz_bytes))
		{
			SPDK_ERRLOG("Size of SGL descriptors (%u) exceeds ICD (%u)\n",
						descriptors_size, rqpair->qpair.ctrlr->ioccsz_bytes);
			return -1;
		}
		rdma_req->send_sgl[0].length = sizeof(struct spdk_req_cmd) + descriptors_size;

		req->cmd.dptr.sgl1.unkeyed.type = SPDK_CLIENT_SGL_TYPE_LAST_SEGMENT;
		req->cmd.dptr.sgl1.unkeyed.subtype = SPDK_CLIENT_SGL_SUBTYPE_OFFSET;
		req->cmd.dptr.sgl1.unkeyed.length = descriptors_size;
		req->cmd.dptr.sgl1.address = (uint64_t)0;
	}

	return 0;
}

/*
 * Build inline SGL describing sgl payload buffer.
 */
static int
client_rdma_build_sgl_inline_request(struct client_rdma_qpair *rqpair,
									 struct spdk_client_rdma_req *rdma_req)
{
	struct client_request *req = rdma_req->req;
	struct client_rdma_memory_translation_ctx ctx;
	uint32_t length;
	int rc;

	assert(req->payload_size != 0);
	assert(client_payload_type(&req->payload) == CLIENT_PAYLOAD_TYPE_SGL);
	assert(req->payload.reset_sgl_fn != NULL);
	assert(req->payload.next_sge_fn != NULL);
	req->payload.reset_sgl_fn(req->payload.contig_or_cb_arg, req->payload_offset);

	rc = req->payload.next_sge_fn(req->payload.contig_or_cb_arg, &ctx.addr, &length);
	if (rc)
	{
		return -1;
	}

	if (length < req->payload_size)
	{
		SPDK_DEBUGLOG(client, "Inline SGL request split so sending separately.\n");
		return client_rdma_build_sgl_request(rqpair, rdma_req);
	}

	if (length > req->payload_size)
	{
		length = req->payload_size;
	}

	ctx.length = length;
	rc = client_rdma_get_memory_translation(req, rqpair, &ctx);
	if (spdk_unlikely(rc))
	{
		return -1;
	}

	rdma_req->send_sgl[1].addr = (uint64_t)ctx.addr;
	rdma_req->send_sgl[1].length = (uint32_t)ctx.length;
	rdma_req->send_sgl[1].lkey = ctx.lkey;
	SPDK_DEBUGLOG(rdma, "client_rdma_build_sgl_inline_request length=%d\n", (uint32_t)ctx.length);
	rdma_req->send_wr.num_sge = 2;

	/* The first element of this SGL is pointing at an
	 * spdk_client_cmd object. For this particular command,
	 * we only need the first 64 bytes corresponding to
	 * the Client command. */
	rdma_req->send_sgl[0].length = sizeof(struct spdk_req_cmd);

	req->cmd.psdt = SPDK_CLIENT_PSDT_SGL_MPTR_CONTIG;
	req->cmd.dptr.sgl1.unkeyed.type = SPDK_CLIENT_SGL_TYPE_DATA_BLOCK;
	req->cmd.dptr.sgl1.unkeyed.subtype = SPDK_CLIENT_SGL_SUBTYPE_OFFSET;
	req->cmd.dptr.sgl1.unkeyed.length = (uint32_t)ctx.length;
	/* Inline only supported for icdoff == 0 currently.  This function will
	 * not get called for controllers with other values. */
	req->cmd.dptr.sgl1.address = (uint64_t)0;

	return 0;
}

static int
client_rdma_req_init(struct client_rdma_qpair *rqpair, struct client_request *req,
					 struct spdk_client_rdma_req *rdma_req)
{
	struct spdk_client_ctrlr *ctrlr = rqpair->qpair.ctrlr;
	enum client_payload_type payload_type;
	bool icd_supported;
	int rc;

	assert(rdma_req->req == NULL);
	rdma_req->req = req;
	req->cmd.cid = rdma_req->id;
	payload_type = client_payload_type(&req->payload);
	/*
	 * Check if icdoff is non zero, to avoid interop conflicts with
	 * targets with non-zero icdoff.  Both SPDK and the Linux kernel
	 * targets use icdoff = 0.  For targets with non-zero icdoff, we
	 * will currently just not use inline data for now.
	 */
	icd_supported = spdk_client_opc_get_data_transfer(req->cmd.opc) == SPDK_CLIENT_DATA_HOST_TO_CONTROLLER && req->payload_size <= ctrlr->ioccsz_bytes && ctrlr->icdoff == 0;
	SPDK_DEBUGLOG(rdma, "debug client_rdma_req_init payload_size=%d, payload_type=%d, icd_supported=%d\n", req->payload_size, payload_type, icd_supported);
	if (req->payload_size == 0)
	{
		rc = client_rdma_build_null_request(rdma_req);
	}
	else if (payload_type == CLIENT_PAYLOAD_TYPE_CONTIG)
	{
		if (icd_supported)
		{
			rc = client_rdma_build_contig_inline_request(rqpair, rdma_req);
		}
		else
		{
			rc = client_rdma_build_contig_request(rqpair, rdma_req);
		}
	}
	else if (payload_type == CLIENT_PAYLOAD_TYPE_SGL)
	{

		if (icd_supported)
		{
			rc = client_rdma_build_sgl_inline_request(rqpair, rdma_req);
		}
		else
		{
			rc = client_rdma_build_sgl_request(rqpair, rdma_req);
		}
	}
	else
	{
		rc = -1;
	}

	if (rc)
	{
		rdma_req->req = NULL;
		return rc;
	}

	memcpy(&rqpair->cmds[rdma_req->id], &req->cmd, sizeof(req->cmd));
	return 0;
}

static struct spdk_client_qpair *
client_rdma_ctrlr_create_qpair(struct spdk_client_ctrlr *ctrlr,
							   uint16_t qid, uint32_t qsize,
							   enum spdk_client_qprio qprio,
							   uint32_t num_requests,
							   bool delay_cmd_submit)
{
	struct client_rdma_qpair *rqpair;
	struct spdk_client_qpair *qpair;
	int rc;

	rqpair = client_rdma_calloc(1, sizeof(struct client_rdma_qpair));
	if (!rqpair)
	{
		SPDK_ERRLOG("failed to get create rqpair\n");
		return NULL;
	}

	rqpair->num_entries = qsize;
	rqpair->delay_cmd_submit = delay_cmd_submit;
	rqpair->state = CLIENT_RDMA_QPAIR_STATE_INVALID;
	qpair = &rqpair->qpair;
	rc = client_qpair_init(qpair, qid, ctrlr, qprio, num_requests, false);
	if (rc != 0)
	{
		client_rdma_free(rqpair);
		return NULL;
	}

	rc = client_rdma_alloc_reqs(rqpair);
	SPDK_DEBUGLOG(client, "rc =%d\n", rc);
	if (rc)
	{
		SPDK_ERRLOG("Unable to allocate rqpair RDMA requests\n");
		client_rdma_free(rqpair);
		return NULL;
	}
	SPDK_DEBUGLOG(client, "RDMA requests allocated\n");

	rc = client_rdma_alloc_rsps(rqpair);
	SPDK_DEBUGLOG(client, "rc =%d\n", rc);
	if (rc < 0)
	{
		SPDK_ERRLOG("Unable to allocate rqpair RDMA responses\n");
		client_rdma_free_reqs(rqpair);
		client_rdma_free(rqpair);
		return NULL;
	}
	SPDK_DEBUGLOG(client, "RDMA responses allocated\n");
	SPDK_NOTICELOG("client_rdma_ctrlr_create_qpair num_entries: %d\n", rqpair->num_entries);
	return qpair;
}

static void
client_rdma_qpair_destroy(struct client_rdma_qpair *rqpair)
{
	struct spdk_client_qpair *qpair = &rqpair->qpair;
	struct client_rdma_ctrlr *rctrlr;
	struct client_rdma_cm_event_entry *entry, *tmp;

	spdk_rdma_free_mem_map(&rqpair->mr_map);
	client_rdma_unregister_reqs(rqpair);
	client_rdma_unregister_rsps(rqpair);

	if (rqpair->evt)
	{
		rdma_ack_cm_event(rqpair->evt);
		rqpair->evt = NULL;
	}

	/*
	 * This works because we have the controller lock both in
	 * this function and in the function where we add new events.
	 */
	if (qpair->ctrlr != NULL)
	{
		rctrlr = client_rdma_ctrlr(qpair->ctrlr);
		STAILQ_FOREACH_SAFE(entry, &rctrlr->pending_cm_events, link, tmp)
		{
			if (entry->evt->id->context == rqpair)
			{
				STAILQ_REMOVE(&rctrlr->pending_cm_events, entry, client_rdma_cm_event_entry, link);
				rdma_ack_cm_event(entry->evt);
				STAILQ_INSERT_HEAD(&rctrlr->free_cm_events, entry, link);
			}
		}
	}

	if (rqpair->cm_id)
	{
		if (rqpair->rdma_qp)
		{
			spdk_rdma_qp_destroy(rqpair->rdma_qp);
			rqpair->rdma_qp = NULL;
		}

		rdma_destroy_id(rqpair->cm_id);
		rqpair->cm_id = NULL;
	}

	if (rqpair->cq)
	{
		ibv_destroy_cq(rqpair->cq);
		rqpair->cq = NULL;
	}
}

static void client_rdma_qpair_abort_reqs(struct spdk_client_qpair *qpair, uint32_t dnr);

static int
client_rdma_qpair_disconnected(struct client_rdma_qpair *rqpair, int ret)
{
	struct spdk_client_qpair *qpair = &rqpair->qpair;

	client_rdma_qpair_destroy(rqpair);

	client_rdma_qpair_abort_reqs(&rqpair->qpair, 0);

	if (ret)
	{
		SPDK_DEBUGLOG(client, "Target did not respond to qpair disconnect.\n");
		goto quiet;
	}

	if (qpair->poll_group == NULL)
	{
		/* If poll group is not used, cq is already destroyed. So complete
		 * disconnecting qpair immediately.
		 */
		goto quiet;
	}

	if (rqpair->current_num_sends != 0 || rqpair->current_num_recvs != 0)
	{
		rqpair->state = CLIENT_RDMA_QPAIR_STATE_LINGERING;
		rqpair->evt_timeout_ticks = (CLIENT_RDMA_DISCONNECTED_QPAIR_TIMEOUT_US * spdk_get_ticks_hz()) /
										SPDK_SEC_TO_USEC +
									spdk_get_ticks();

		return -EAGAIN;
	}

quiet:
	rqpair->state = CLIENT_RDMA_QPAIR_STATE_EXITED;

	client_transport_ctrlr_disconnect_qpair_done(&rqpair->qpair);

	return 0;
}

static void
_client_rdma_ctrlr_disconnect_qpair(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair,
									client_rdma_cm_event_cb disconnected_qpair_cb)
{
	struct client_rdma_qpair *rqpair = client_rdma_qpair(qpair);
	int rc;

	assert(disconnected_qpair_cb != NULL);

	rqpair->state = CLIENT_RDMA_QPAIR_STATE_EXITING;

	if (rqpair->cm_id)
	{
		if (rqpair->rdma_qp)
		{
			rc = spdk_rdma_qp_disconnect(rqpair->rdma_qp);
			if ((qpair->ctrlr != NULL) && (rc == 0))
			{
				rc = client_rdma_process_event_start(rqpair, RDMA_CM_EVENT_DISCONNECTED,
													 disconnected_qpair_cb);
				if (rc == 0)
				{
					return;
				}
			}
		}
	}

	disconnected_qpair_cb(rqpair, 0);
}

static int
client_rdma_qpair_wait_until_quiet(struct client_rdma_qpair *rqpair)
{
	if (spdk_get_ticks() < rqpair->evt_timeout_ticks &&
		(rqpair->current_num_sends != 0 || rqpair->current_num_recvs != 0))
	{
		return -EAGAIN;
	}

	rqpair->state = CLIENT_RDMA_QPAIR_STATE_EXITED;

	client_transport_ctrlr_disconnect_qpair_done(&rqpair->qpair);

	return 0;
}

static int client_rdma_ctrlr_disconnect_qpair_poll(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair);
static void
client_rdma_ctrlr_disconnect_qpair(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair)
{
	int rc;

	_client_rdma_ctrlr_disconnect_qpair(ctrlr, qpair, client_rdma_qpair_disconnected);

	/* If the qpair is in a poll group, disconnected_qpair_cb has to be called
	 * asynchronously after the qpair is actually disconnected. Hence let
	 * poll_group_process_completions() poll the qpair until then.
	 *
	 * If the qpair is not in a poll group, poll the qpair until it is actually
	 * disconnected here.
	 */
	if (qpair->async || qpair->poll_group != NULL)
	{
		return;
	}

	while (1)
	{
		rc = client_rdma_ctrlr_disconnect_qpair_poll(ctrlr, qpair);
		if (rc != -EAGAIN)
		{
			break;
		}
	}
}

static int
client_rdma_stale_conn_disconnected(struct client_rdma_qpair *rqpair, int ret)
{
	struct spdk_client_qpair *qpair = &rqpair->qpair;

	if (ret)
	{
		SPDK_DEBUGLOG(client, "Target did not respond to qpair disconnect.\n");
	}

	client_rdma_qpair_destroy(rqpair);

	qpair->last_transport_failure_reason = qpair->transport_failure_reason;
	qpair->transport_failure_reason = SPDK_CLIENT_QPAIR_FAILURE_NONE;

	rqpair->state = CLIENT_RDMA_QPAIR_STATE_STALE_CONN;
	rqpair->evt_timeout_ticks = (CLIENT_RDMA_STALE_CONN_RETRY_DELAY_US * spdk_get_ticks_hz()) /
									SPDK_SEC_TO_USEC +
								spdk_get_ticks();

	return 0;
}

static int
client_rdma_stale_conn_retry(struct client_rdma_qpair *rqpair)
{
	struct spdk_client_qpair *qpair = &rqpair->qpair;

	if (rqpair->stale_conn_retry_count >= CLIENT_RDMA_STALE_CONN_RETRY_MAX)
	{
		SPDK_ERRLOG("Retry failed %d times, give up stale connection to qpair (cntlid:%u, qid:%u).\n",
					CLIENT_RDMA_STALE_CONN_RETRY_MAX, qpair->ctrlr->cntlid, qpair->id);
		return -ESTALE;
	}

	rqpair->stale_conn_retry_count++;

	SPDK_NOTICELOG("%d times, retry stale connnection to qpair (cntlid:%u, qid:%u).\n",
				   rqpair->stale_conn_retry_count, qpair->ctrlr->cntlid, qpair->id);

	if (qpair->poll_group)
	{
		rqpair->cq = NULL;
	}

	_client_rdma_ctrlr_disconnect_qpair(qpair->ctrlr, qpair, client_rdma_stale_conn_disconnected);

	return 0;
}

static int
client_rdma_ctrlr_delete_io_qpair(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair)
{
	struct client_rdma_qpair *rqpair;

	assert(qpair != NULL);
	rqpair = client_rdma_qpair(qpair);

	if (rqpair->defer_deletion_to_pg)
	{
		client_qpair_set_state(qpair, CLIENT_QPAIR_DESTROYING);
		return 0;
	}

	client_rdma_qpair_abort_reqs(qpair, 0);
	client_qpair_deinit(qpair);

	client_rdma_put_memory_domain(rqpair->memory_domain);

	client_rdma_free_reqs(rqpair);
	client_rdma_free_rsps(rqpair);
	client_rdma_free(rqpair);

	return 0;
}

static struct spdk_client_qpair *
client_rdma_ctrlr_create_io_qpair(struct spdk_client_ctrlr *ctrlr, uint16_t qid,
								  const struct spdk_client_io_qpair_opts *opts)
{
	SPDK_NOTICELOG("client_rdma_ctrlr_create_io_qpair io_queue_size: %d io_queue_requests: %d\n", opts->io_queue_size, opts->io_queue_requests);
	return client_rdma_ctrlr_create_qpair(ctrlr, qid, opts->io_queue_size, opts->qprio,
										  opts->io_queue_requests,
										  opts->delay_cmd_submit);
}

static int client_rdma_ctrlr_destruct(struct spdk_client_ctrlr *ctrlr);

static struct spdk_client_ctrlr *client_rdma_ctrlr_construct(
	const struct spdk_client_ctrlr_opts *opts,
	void *devhandle)
{
	struct client_rdma_ctrlr *rctrlr;
	struct ibv_context **contexts;
	struct ibv_device_attr dev_attr;
	int i, flag, rc;

	rctrlr = client_rdma_calloc(1, sizeof(struct client_rdma_ctrlr));
	if (rctrlr == NULL)
	{
		SPDK_ERRLOG("could not allocate ctrlr\n");
		return NULL;
	}

	rctrlr->ctrlr.opts = *opts;

	if (opts->transport_retry_count > CLIENT_RDMA_CTRLR_MAX_TRANSPORT_RETRY_COUNT)
	{
		SPDK_NOTICELOG("transport_retry_count exceeds max value %d, use max value\n",
					   CLIENT_RDMA_CTRLR_MAX_TRANSPORT_RETRY_COUNT);
		rctrlr->ctrlr.opts.transport_retry_count = CLIENT_RDMA_CTRLR_MAX_TRANSPORT_RETRY_COUNT;
	}

	if (opts->transport_ack_timeout > CLIENT_RDMA_CTRLR_MAX_TRANSPORT_ACK_TIMEOUT)
	{
		SPDK_NOTICELOG("transport_ack_timeout exceeds max value %d, use max value\n",
					   CLIENT_RDMA_CTRLR_MAX_TRANSPORT_ACK_TIMEOUT);
		rctrlr->ctrlr.opts.transport_ack_timeout = CLIENT_RDMA_CTRLR_MAX_TRANSPORT_ACK_TIMEOUT;
	}

	contexts = rdma_get_devices(NULL);
	if (contexts == NULL)
	{
		SPDK_ERRLOG("rdma_get_devices() failed: %s (%d)\n", spdk_strerror(errno), errno);
		client_rdma_free(rctrlr);
		return NULL;
	}

	i = 0;
	rctrlr->max_sge = CLIENT_RDMA_MAX_SGL_DESCRIPTORS;

	while (contexts[i] != NULL)
	{
		rc = ibv_query_device(contexts[i], &dev_attr);
		if (rc < 0)
		{
			SPDK_ERRLOG("Failed to query RDMA device attributes.\n");
			rdma_free_devices(contexts);
			client_rdma_free(rctrlr);
			return NULL;
		}
		rctrlr->max_sge = spdk_min(rctrlr->max_sge, (uint16_t)dev_attr.max_sge);
		i++;
	}

	rdma_free_devices(contexts);

	rc = client_ctrlr_construct(&rctrlr->ctrlr);
	if (rc != 0)
	{
		client_rdma_free(rctrlr);
		return NULL;
	}

	STAILQ_INIT(&rctrlr->pending_cm_events);
	STAILQ_INIT(&rctrlr->free_cm_events);
	rctrlr->cm_events = client_rdma_calloc(CLIENT_RDMA_NUM_CM_EVENTS, sizeof(*rctrlr->cm_events));
	if (rctrlr->cm_events == NULL)
	{
		SPDK_ERRLOG("unable to allocate buffers to hold CM events.\n");
		goto destruct_ctrlr;
	}

	for (i = 0; i < CLIENT_RDMA_NUM_CM_EVENTS; i++)
	{
		STAILQ_INSERT_TAIL(&rctrlr->free_cm_events, &rctrlr->cm_events[i], link);
	}

	rctrlr->cm_channel = rdma_create_event_channel();
	if (rctrlr->cm_channel == NULL)
	{
		SPDK_ERRLOG("rdma_create_event_channel() failed\n");
		goto destruct_ctrlr;
	}

	flag = fcntl(rctrlr->cm_channel->fd, F_GETFL);
	if (fcntl(rctrlr->cm_channel->fd, F_SETFL, flag | O_NONBLOCK) < 0)
	{
		SPDK_ERRLOG("Cannot set event channel to non blocking\n");
		goto destruct_ctrlr;
	}

	if (client_ctrlr_add_process(&rctrlr->ctrlr, 0) != 0)
	{
		SPDK_ERRLOG("client_ctrlr_add_process() failed\n");
		goto destruct_ctrlr;
	}

	SPDK_DEBUGLOG(client, "successfully initialized the srv ctrlr\n");
	return &rctrlr->ctrlr;

destruct_ctrlr:
	client_ctrlr_destruct(&rctrlr->ctrlr);
	return NULL;
}

static int
client_rdma_ctrlr_destruct(struct spdk_client_ctrlr *ctrlr)
{
	struct client_rdma_ctrlr *rctrlr = client_rdma_ctrlr(ctrlr);
	struct client_rdma_cm_event_entry *entry;

	STAILQ_FOREACH(entry, &rctrlr->pending_cm_events, link)
	{
		rdma_ack_cm_event(entry->evt);
	}

	STAILQ_INIT(&rctrlr->free_cm_events);
	STAILQ_INIT(&rctrlr->pending_cm_events);
	client_rdma_free(rctrlr->cm_events);

	if (rctrlr->cm_channel)
	{
		rdma_destroy_event_channel(rctrlr->cm_channel);
		rctrlr->cm_channel = NULL;
	}

	client_ctrlr_destruct_finish(ctrlr);

	client_rdma_free(rctrlr);

	return 0;
}

static int
client_rdma_qpair_submit_request(struct spdk_client_qpair *qpair,
								 struct client_request *req)
{
	struct client_rdma_qpair *rqpair;
	struct spdk_client_rdma_req *rdma_req;
	struct ibv_send_wr *wr;

	rqpair = client_rdma_qpair(qpair);
	assert(rqpair != NULL);
	assert(req != NULL);

	rdma_req = client_rdma_req_get(rqpair);
	if (spdk_unlikely(!rdma_req))
	{
		if (rqpair->poller)
		{
			rqpair->poller->stats.queued_requests++;
		}
		/* Inform the upper layer to try again later. */
		return -EAGAIN;
	}

	if (client_rdma_req_init(rqpair, req, rdma_req))
	{
		SPDK_ERRLOG("client_rdma_req_init() failed\n");
		TAILQ_REMOVE(&rqpair->outstanding_reqs, rdma_req, link);
		client_rdma_req_put(rqpair, rdma_req);
		return -1;
	}

	wr = &rdma_req->send_wr;
	wr->next = NULL;
	client_rdma_trace_ibv_sge(wr->sg_list);
	return client_rdma_qpair_queue_send_wr(rqpair, wr);
}

static int
client_rdma_qpair_reset(struct spdk_client_qpair *qpair)
{
	/* Currently, doing nothing here */
	return 0;
}

static void
client_rdma_qpair_abort_reqs(struct spdk_client_qpair *qpair, uint32_t dnr)
{
	struct spdk_client_rdma_req *rdma_req, *tmp;
	struct spdk_req_cpl cpl;
	struct client_rdma_qpair *rqpair = client_rdma_qpair(qpair);

	//(fixme wuxingyi)
	cpl.status.sc = SPDK_CLIENT_SC_QUEUE_ABORTED;
	cpl.status.sct = SPDK_CLIENT_SCT_GENERIC;
	cpl.status.dnr = dnr;

	/*
	 * We cannot abort requests at the RDMA layer without
	 * unregistering them. If we do, we can still get error
	 * free completions on the shared completion queue.
	 */
	if (client_qpair_get_state(qpair) > CLIENT_QPAIR_DISCONNECTING &&
		client_qpair_get_state(qpair) != CLIENT_QPAIR_DESTROYING)
	{
		client_ctrlr_disconnect_qpair(qpair);
	}

	TAILQ_FOREACH_SAFE(rdma_req, &rqpair->outstanding_reqs, link, tmp)
	{
		client_rdma_req_complete(rdma_req, &cpl);
		client_rdma_req_put(rqpair, rdma_req);
	}
}

static void
client_rdma_qpair_check_timeout(struct spdk_client_qpair *qpair)
{
	uint64_t t02;
	struct spdk_client_rdma_req *rdma_req, *tmp;
	struct client_rdma_qpair *rqpair = client_rdma_qpair(qpair);
	struct spdk_client_ctrlr *ctrlr = qpair->ctrlr;
	struct spdk_client_ctrlr_process *active_proc;

	active_proc = qpair->active_proc;

	/* Only check timeouts if the current process has a timeout callback. */
	if (active_proc == NULL || active_proc->timeout_cb_fn == NULL)
	{
		return;
	}

	t02 = spdk_get_ticks();
	TAILQ_FOREACH_SAFE(rdma_req, &rqpair->outstanding_reqs, link, tmp)
	{
		assert(rdma_req->req != NULL);

		if (client_request_check_timeout(rdma_req->req, rdma_req->id, active_proc, t02))
		{
			/*
			 * The requests are in order, so as soon as one has not timed out,
			 * stop iterating.
			 */
			break;
		}
	}
}

static inline int
client_rdma_request_ready(struct client_rdma_qpair *rqpair, struct spdk_client_rdma_req *rdma_req)
{
	client_rdma_req_complete(rdma_req, &rqpair->rsps[rdma_req->rsp_idx].cpl);
	client_rdma_req_put(rqpair, rdma_req);
	return client_rdma_post_recv(rqpair, rdma_req->rsp_idx);
}

#define MAX_COMPLETIONS_PER_POLL 128

static void
client_rdma_fail_qpair(struct spdk_client_qpair *qpair, int failure_reason)
{
	if (failure_reason == IBV_WC_RETRY_EXC_ERR)
	{
		qpair->transport_failure_reason = SPDK_CLIENT_QPAIR_FAILURE_REMOTE;
	}
	else if (qpair->transport_failure_reason == SPDK_CLIENT_QPAIR_FAILURE_NONE)
	{
		qpair->transport_failure_reason = SPDK_CLIENT_QPAIR_FAILURE_UNKNOWN;
	}

	client_ctrlr_disconnect_qpair(qpair);
}

static void
client_rdma_conditional_fail_qpair(struct client_rdma_qpair *rqpair, struct client_rdma_poll_group *group)
{
	struct client_rdma_destroyed_qpair *qpair_tracker;

	assert(rqpair);
	if (group)
	{
		STAILQ_FOREACH(qpair_tracker, &group->destroyed_qpairs, link)
		{
			if (qpair_tracker->destroyed_qpair_tracker == rqpair)
			{
				return;
			}
		}
	}
	client_rdma_fail_qpair(&rqpair->qpair, 0);
}

static inline void
client_rdma_log_wc_status(struct client_rdma_qpair *rqpair, struct ibv_wc *wc)
{
	struct client_rdma_wr *rdma_wr = (struct client_rdma_wr *)wc->wr_id;

	if (wc->status == IBV_WC_WR_FLUSH_ERR)
	{
		/* If qpair is in ERR state, we will receive completions for all posted and not completed
		 * Work Requests with IBV_WC_WR_FLUSH_ERR status. Don't log an error in that case */
		SPDK_DEBUGLOG(client, "WC error, qid %u, qp state %d, request 0x%lu type %d, status: (%d): %s\n",
					  rqpair->qpair.id, rqpair->qpair.state, wc->wr_id, rdma_wr->type, wc->status,
					  ibv_wc_status_str(wc->status));
	}
	else
	{
		SPDK_ERRLOG("WC error, qid %u, qp state %d, request 0x%lu type %d, status: (%d): %s\n",
					rqpair->qpair.id, rqpair->qpair.state, wc->wr_id, rdma_wr->type, wc->status,
					ibv_wc_status_str(wc->status));
	}
}

static inline bool
client_rdma_is_rxe_device(struct ibv_device_attr *dev_attr)
{
	return dev_attr->vendor_id == SPDK_RDMA_RXE_VENDOR_ID_OLD ||
		   dev_attr->vendor_id == SPDK_RDMA_RXE_VENDOR_ID_NEW;
}

static int
client_rdma_cq_process_completions(struct ibv_cq *cq, uint32_t batch_size,
								   struct client_rdma_poll_group *group,
								   struct client_rdma_qpair *rdma_qpair,
								   uint64_t *rdma_completions)
{
	struct ibv_wc wc[MAX_COMPLETIONS_PER_POLL];
	struct client_rdma_qpair *rqpair;
	struct spdk_client_rdma_req *rdma_req;
	struct spdk_client_rdma_rsp *rdma_rsp;
	struct client_rdma_wr *rdma_wr;
	uint32_t reaped = 0;
	int completion_rc = 0;
	int rc, i;

	rc = ibv_poll_cq(cq, batch_size, wc);
	if (rc < 0)
	{
		SPDK_ERRLOG("Error polling CQ! (%d): %s\n",
					errno, spdk_strerror(errno));
		return -ECANCELED;
	}
	else if (rc == 0)
	{
		return 0;
	}

	for (i = 0; i < rc; i++)
	{
		rdma_wr = (struct client_rdma_wr *)wc[i].wr_id;
		switch (rdma_wr->type)
		{
		case RDMA_WR_TYPE_RECV:
			rdma_rsp = SPDK_CONTAINEROF(rdma_wr, struct spdk_client_rdma_rsp, rdma_wr);
			rqpair = rdma_rsp->rqpair;
			assert(rqpair->current_num_recvs > 0);
			rqpair->current_num_recvs--;

			if (wc[i].status)
			{
				client_rdma_log_wc_status(rqpair, &wc[i]);
				client_rdma_conditional_fail_qpair(rqpair, group);
				completion_rc = -ENXIO;
				continue;
			}

			SPDK_DEBUGLOG(client, "CQ recv completion\n");

			if (wc[i].byte_len < sizeof(struct spdk_req_cpl))
			{
				SPDK_ERRLOG("recv length %u less than expected response size\n", wc[i].byte_len);
				client_rdma_conditional_fail_qpair(rqpair, group);
				completion_rc = -ENXIO;
				continue;
			}
			rdma_req = &rqpair->rdma_reqs[rdma_rsp->cpl.cid];
			rdma_req->completion_flags |= CLIENT_RDMA_RECV_COMPLETED;
			rdma_req->rsp_idx = rdma_rsp->idx;

			if ((rdma_req->completion_flags & CLIENT_RDMA_SEND_COMPLETED) != 0)
			{
				if (spdk_unlikely(client_rdma_request_ready(rqpair, rdma_req)))
				{
					SPDK_ERRLOG("Unable to re-post rx descriptor\n");
					client_rdma_conditional_fail_qpair(rqpair, group);
					completion_rc = -ENXIO;
					continue;
				}
				reaped++;
				rqpair->num_completions++;
			}
			break;

		case RDMA_WR_TYPE_SEND:
			rdma_req = SPDK_CONTAINEROF(rdma_wr, struct spdk_client_rdma_req, rdma_wr);

			/* If we are flushing I/O */
			if (wc[i].status)
			{
				rqpair = rdma_req->req ? client_rdma_qpair(rdma_req->req->qpair) : NULL;
				if (!rqpair)
				{
					rqpair = rdma_qpair != NULL ? rdma_qpair : client_rdma_poll_group_get_qpair_by_id(group, wc[i].qp_num);
				}
				if (!rqpair)
				{
					/* When poll_group is used, several qpairs share the same CQ and it is possible to
					 * receive a completion with error (e.g. IBV_WC_WR_FLUSH_ERR) for already disconnected qpair
					 * That happens due to qpair is destroyed while there are submitted but not completed send/receive
					 * Work Requests
					 * TODO: ibv qpair must be destroyed only when all submitted Work Requests are completed */
					assert(group);
					continue;
				}
				SPDK_NOTICELOG("******************cid %d %d\n", rdma_req->req->cmd.cid, rdma_req->id);
				SPDK_NOTICELOG("******************num_entries %d\n", rqpair->num_entries);
				SPDK_NOTICELOG("******************cmd address %v\n", &rqpair->cmds[rdma_req->req->cmd.cid]);
				assert(rqpair->current_num_sends > 0);
				rqpair->current_num_sends--;
				client_rdma_log_wc_status(rqpair, &wc[i]);
				client_rdma_conditional_fail_qpair(rqpair, group);
				completion_rc = -ENXIO;
				continue;
			}

			if (spdk_unlikely(rdma_req->req == NULL))
			{
				struct ibv_device_attr dev_attr;
				int query_status;

				/* Bug in Soft Roce - we may receive a completion without error status when qpair is disconnected/destroyed.
				 * As sanity check - log an error if we use a real HW (it should never happen) */
				query_status = ibv_query_device(cq->context, &dev_attr);
				if (query_status == 0)
				{
					if (!client_rdma_is_rxe_device(&dev_attr))
					{
						SPDK_ERRLOG("Received malformed completion: request 0x%" PRIx64 " type %d\n", wc->wr_id,
									rdma_wr->type);
						assert(0);
					}
				}
				else
				{
					SPDK_ERRLOG("Failed to query ib device\n");
					assert(0);
				}
				continue;
			}

			rqpair = client_rdma_qpair(rdma_req->req->qpair);
			rdma_req->completion_flags |= CLIENT_RDMA_SEND_COMPLETED;
			rqpair->current_num_sends--;

			if ((rdma_req->completion_flags & CLIENT_RDMA_RECV_COMPLETED) != 0)
			{
				if (spdk_unlikely(client_rdma_request_ready(rqpair, rdma_req)))
				{
					SPDK_ERRLOG("Unable to re-post rx descriptor\n");
					client_rdma_conditional_fail_qpair(rqpair, group);
					completion_rc = -ENXIO;
					continue;
				}
				reaped++;
				rqpair->num_completions++;
			}
			break;

		default:
			SPDK_ERRLOG("Received an unexpected opcode on the CQ: %d\n", rdma_wr->type);
			return -ECANCELED;
		}
	}

	*rdma_completions += rc;

	if (completion_rc)
	{
		return completion_rc;
	}
	return reaped;
}

static void
dummy_disconnected_qpair_cb(struct spdk_client_qpair *qpair, void *poll_group_ctx)
{
}

static int
client_rdma_qpair_process_completions(struct spdk_client_qpair *qpair,
									  uint32_t max_completions)
{
	struct client_rdma_qpair *rqpair = client_rdma_qpair(qpair);
	int rc = 0, batch_size;
	struct ibv_cq *cq;
	struct client_rdma_ctrlr *rctrlr = client_rdma_ctrlr(qpair->ctrlr);
	uint64_t rdma_completions = 0;

	/*
	 * This is used during the connection phase. It's possible that we are still reaping error completions
	 * from other qpairs so we need to call the poll group function. Also, it's more correct since the cq
	 * is shared.
	 */
	if (qpair->poll_group != NULL)
	{
		return spdk_client_poll_group_process_completions(qpair->poll_group->group, max_completions,
														  dummy_disconnected_qpair_cb);
	}

	if (max_completions == 0)
	{
		max_completions = rqpair->num_entries;
	}
	else
	{
		max_completions = spdk_min(max_completions, rqpair->num_entries);
	}

	switch (client_qpair_get_state(qpair))
	{
	case CLIENT_QPAIR_CONNECTING:
		rc = client_rdma_ctrlr_connect_qpair_poll(qpair->ctrlr, qpair);
		if (rc == 0)
		{
			/* Once the connection is completed, we can submit queued requests */
			client_qpair_resubmit_requests(qpair, rqpair->num_entries);
		}
		else if (rc != -EAGAIN)
		{
			SPDK_ERRLOG("Failed to connect rqpair=%p\n", rqpair);
			goto failed;
		}
		else if (rqpair->state <= CLIENT_RDMA_QPAIR_STATE_INITIALIZING)
		{
			return 0;
		}
		break;

	case CLIENT_QPAIR_DISCONNECTING:
		client_rdma_ctrlr_disconnect_qpair_poll(qpair->ctrlr, qpair);
		return -ENXIO;

	default:
		client_rdma_qpair_process_cm_event(rqpair);
		break;
	}

	if (spdk_unlikely(qpair->transport_failure_reason != SPDK_CLIENT_QPAIR_FAILURE_NONE))
	{
		goto failed;
	}

	cq = rqpair->cq;

	rqpair->num_completions = 0;
	do
	{
		batch_size = spdk_min((max_completions - rqpair->num_completions), MAX_COMPLETIONS_PER_POLL);
		rc = client_rdma_cq_process_completions(cq, batch_size, NULL, rqpair, &rdma_completions);

		if (rc == 0)
		{
			break;
			/* Handle the case where we fail to poll the cq. */
		}
		else if (rc == -ECANCELED)
		{
			goto failed;
		}
		else if (rc == -ENXIO)
		{
			return rc;
		}
	} while (rqpair->num_completions < max_completions);

	if (spdk_unlikely(client_rdma_qpair_submit_sends(rqpair) ||
					  client_rdma_qpair_submit_recvs(rqpair)))
	{
		goto failed;
	}

	if (spdk_unlikely(rqpair->qpair.ctrlr->timeout_enabled))
	{
		client_rdma_qpair_check_timeout(qpair);
	}

	return rqpair->num_completions;
failed:
	client_rdma_fail_qpair(qpair, 0);
	return -ENXIO;
}

static uint16_t
client_rdma_ctrlr_get_max_sges(struct spdk_client_ctrlr *ctrlr)
{
	struct client_rdma_ctrlr *rctrlr = client_rdma_ctrlr(ctrlr);

	return rctrlr->max_sge;
}

static int
client_rdma_qpair_iterate_requests(struct spdk_client_qpair *qpair,
								   int (*iter_fn)(struct client_request *req, void *arg),
								   void *arg)
{
	struct client_rdma_qpair *rqpair = client_rdma_qpair(qpair);
	struct spdk_client_rdma_req *rdma_req, *tmp;
	int rc;

	assert(iter_fn != NULL);

	TAILQ_FOREACH_SAFE(rdma_req, &rqpair->outstanding_reqs, link, tmp)
	{
		assert(rdma_req->req != NULL);

		rc = iter_fn(rdma_req->req, arg);
		if (rc != 0)
		{
			return rc;
		}
	}

	return 0;
}

static int
client_rdma_poller_create(struct client_rdma_poll_group *group, struct ibv_context *ctx)
{
	struct client_rdma_poller *poller;

	poller = calloc(1, sizeof(*poller));
	if (poller == NULL)
	{
		SPDK_ERRLOG("Unable to allocate poller.\n");
		return -ENOMEM;
	}

	poller->device = ctx;
	poller->cq = ibv_create_cq(poller->device, DEFAULT_CLIENT_RDMA_CQ_SIZE, group, NULL, 0);

	if (poller->cq == NULL)
	{
		free(poller);
		return -EINVAL;
	}

	STAILQ_INSERT_HEAD(&group->pollers, poller, link);
	group->num_pollers++;
	poller->current_num_wc = DEFAULT_CLIENT_RDMA_CQ_SIZE;
	poller->required_num_wc = 0;
	return 0;
}

static void
client_rdma_poll_group_free_pollers(struct client_rdma_poll_group *group)
{
	struct client_rdma_poller *poller, *tmp_poller;

	STAILQ_FOREACH_SAFE(poller, &group->pollers, link, tmp_poller)
	{
		if (poller->cq)
		{
			ibv_destroy_cq(poller->cq);
		}
		STAILQ_REMOVE(&group->pollers, poller, client_rdma_poller, link);
		free(poller);
	}
}

static struct spdk_client_transport_poll_group *
client_rdma_poll_group_create(void)
{
	struct client_rdma_poll_group *group;
	struct ibv_context **contexts;
	int i = 0;

	group = calloc(1, sizeof(*group));
	if (group == NULL)
	{
		SPDK_ERRLOG("Unable to allocate poll group.\n");
		return NULL;
	}

	STAILQ_INIT(&group->pollers);

	contexts = rdma_get_devices(NULL);
	if (contexts == NULL)
	{
		SPDK_ERRLOG("rdma_get_devices() failed: %s (%d)\n", spdk_strerror(errno), errno);
		free(group);
		return NULL;
	}

	while (contexts[i] != NULL)
	{
		if (client_rdma_poller_create(group, contexts[i]))
		{
			client_rdma_poll_group_free_pollers(group);
			free(group);
			rdma_free_devices(contexts);
			return NULL;
		}
		i++;
	}

	rdma_free_devices(contexts);
	STAILQ_INIT(&group->destroyed_qpairs);
	return &group->group;
}

struct client_rdma_qpair *
client_rdma_poll_group_get_qpair_by_id(struct client_rdma_poll_group *group, uint32_t qp_num)
{
	struct spdk_client_qpair *qpair;
	struct client_rdma_destroyed_qpair *rqpair_tracker;
	struct client_rdma_qpair *rqpair;

	STAILQ_FOREACH(qpair, &group->group.disconnected_qpairs, poll_group_stailq)
	{
		rqpair = client_rdma_qpair(qpair);
		if (CLIENT_RDMA_POLL_GROUP_CHECK_QPN(rqpair, qp_num))
		{
			return rqpair;
		}
	}

	STAILQ_FOREACH(qpair, &group->group.connected_qpairs, poll_group_stailq)
	{
		rqpair = client_rdma_qpair(qpair);
		if (CLIENT_RDMA_POLL_GROUP_CHECK_QPN(rqpair, qp_num))
		{
			return rqpair;
		}
	}

	STAILQ_FOREACH(rqpair_tracker, &group->destroyed_qpairs, link)
	{
		if (CLIENT_RDMA_POLL_GROUP_CHECK_QPN(rqpair_tracker->destroyed_qpair_tracker, qp_num))
		{
			return rqpair_tracker->destroyed_qpair_tracker;
		}
	}

	return NULL;
}

/* static int
client_rdma_resize_cq(struct client_rdma_qpair *rqpair, struct client_rdma_poller *poller)
{
	int current_num_wc, required_num_wc;

	required_num_wc = poller->required_num_wc + WC_PER_QPAIR(rqpair->num_entries);
	current_num_wc = poller->current_num_wc;
	if (current_num_wc < required_num_wc)
	{
		current_num_wc = spdk_max(current_num_wc * 2, required_num_wc);
	}

	if (poller->current_num_wc != current_num_wc)
	{
		SPDK_DEBUGLOG(client, "Resize RDMA CQ from %d to %d\n", poller->current_num_wc,
					  current_num_wc);
		if (ibv_resize_cq(poller->cq, current_num_wc))
		{
			SPDK_ERRLOG("RDMA CQ resize failed: errno %d: %s\n", errno, spdk_strerror(errno));
			return -1;
		}

		poller->current_num_wc = current_num_wc;
	}

	poller->required_num_wc = required_num_wc;
	return 0;
}
 */
static int
client_rdma_poll_group_connect_qpair(struct spdk_client_qpair *qpair)
{
	/* 	struct client_rdma_qpair *rqpair = client_rdma_qpair(qpair);
		struct client_rdma_poll_group *group = client_rdma_poll_group(qpair->poll_group);
		struct client_rdma_poller *poller;

		assert(rqpair->cq == NULL);

		STAILQ_FOREACH(poller, &group->pollers, link)
		{
			if (poller->device == rqpair->cm_id->verbs)
			{
				if (client_rdma_resize_cq(rqpair, poller))
				{
					return -EPROTO;
				}
				rqpair->cq = poller->cq;
				rqpair->poller = poller;
				break;
			}
		}

		if (rqpair->cq == NULL)
		{
			SPDK_ERRLOG("Unable to find a cq for qpair %p on poll group %p\n", qpair, qpair->poll_group);
			return -EINVAL;
		}
	 */
	return 0;
}

static int
client_rdma_poll_group_disconnect_qpair(struct spdk_client_qpair *qpair)
{
	struct client_rdma_qpair *rqpair = client_rdma_qpair(qpair);
	struct client_rdma_poll_group *group;
	struct client_rdma_destroyed_qpair *destroyed_qpair;

	group = client_rdma_poll_group(qpair->poll_group);

	rqpair->cq = NULL;

	/*
	 * If this fails, the system is in serious trouble,
	 * just let the qpair get cleaned up immediately.
	 */
	destroyed_qpair = calloc(1, sizeof(*destroyed_qpair));
	if (destroyed_qpair == NULL)
	{
		return 0;
	}

	destroyed_qpair->destroyed_qpair_tracker = rqpair;
	destroyed_qpair->timeout_ticks = spdk_get_ticks() +
									 (CLIENT_RDMA_DESTROYED_QPAIR_EXPIRATION_TIMEOUT_US *
									  spdk_get_ticks_hz()) /
										 SPDK_SEC_TO_USEC;
	STAILQ_INSERT_TAIL(&group->destroyed_qpairs, destroyed_qpair, link);

	rqpair->defer_deletion_to_pg = true;

	return 0;
}

static int
client_rdma_poll_group_add(struct spdk_client_transport_poll_group *tgroup,
						   struct spdk_client_qpair *qpair)
{
	return 0;
}

static int
client_rdma_poll_group_remove(struct spdk_client_transport_poll_group *tgroup,
							  struct spdk_client_qpair *qpair)
{
	assert(qpair->poll_group_tailq_head == &tgroup->disconnected_qpairs);

	return 0;
}

static void
client_rdma_poll_group_delete_qpair(struct client_rdma_poll_group *group,
									struct client_rdma_destroyed_qpair *qpair_tracker)
{
	struct client_rdma_qpair *rqpair = qpair_tracker->destroyed_qpair_tracker;

	rqpair->defer_deletion_to_pg = false;
	if (client_qpair_get_state(&rqpair->qpair) == CLIENT_QPAIR_DESTROYING)
	{
		client_rdma_ctrlr_delete_io_qpair(rqpair->qpair.ctrlr, &rqpair->qpair);
	}
	STAILQ_REMOVE(&group->destroyed_qpairs, qpair_tracker, client_rdma_destroyed_qpair, link);
	free(qpair_tracker);
}

static int
client_rdma_ctrlr_disconnect_qpair_poll(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair)
{
	struct client_rdma_qpair *rqpair = client_rdma_qpair(qpair);
	int rc;

	switch (rqpair->state)
	{
	case CLIENT_RDMA_QPAIR_STATE_EXITING:

		client_robust_mutex_lock(&ctrlr->ctrlr_lock);
		rc = client_rdma_process_event_poll(rqpair);
		client_robust_mutex_unlock(&ctrlr->ctrlr_lock);
		break;

	case CLIENT_RDMA_QPAIR_STATE_LINGERING:
		rc = client_rdma_qpair_wait_until_quiet(rqpair);
		break;
	case CLIENT_RDMA_QPAIR_STATE_EXITED:
		rc = 0;
		break;

	default:
		assert(false);
		rc = -EAGAIN;
		break;
	}

	return rc;
}

static int64_t
client_rdma_poll_group_process_completions(struct spdk_client_transport_poll_group *tgroup,
										   uint32_t completions_per_qpair, spdk_client_disconnected_qpair_cb disconnected_qpair_cb)
{
	struct spdk_client_qpair *qpair, *tmp_qpair;
	struct client_rdma_destroyed_qpair *qpair_tracker, *tmp_qpair_tracker;
	struct client_rdma_qpair *rqpair;
	struct client_rdma_poll_group *group;
	struct client_rdma_poller *poller;
	int num_qpairs = 0, batch_size, rc;
	int64_t total_completions = 0;
	uint64_t completions_allowed = 0;
	uint64_t completions_per_poller = 0;
	uint64_t poller_completions = 0;
	uint64_t rdma_completions;

	if (completions_per_qpair == 0)
	{
		completions_per_qpair = MAX_COMPLETIONS_PER_POLL;
	}

	group = client_rdma_poll_group(tgroup);
	STAILQ_FOREACH_SAFE(qpair, &tgroup->disconnected_qpairs, poll_group_stailq, tmp_qpair)
	{
		rc = client_rdma_ctrlr_disconnect_qpair_poll(qpair->ctrlr, qpair);
		if (rc == 0)
		{
			disconnected_qpair_cb(qpair, tgroup->group->ctx);
		}
	}

	STAILQ_FOREACH_SAFE(qpair, &tgroup->connected_qpairs, poll_group_stailq, tmp_qpair)
	{
		rqpair = client_rdma_qpair(qpair);
		rqpair->num_completions = 0;

		if (spdk_unlikely(client_qpair_get_state(qpair) == CLIENT_QPAIR_CONNECTING))
		{
			rc = client_rdma_ctrlr_connect_qpair_poll(qpair->ctrlr, qpair);
			if (rc == 0)
			{
				/* Once the connection is completed, we can submit queued requests */
				client_qpair_resubmit_requests(qpair, rqpair->num_entries);
			}
			else if (rc != -EAGAIN)
			{
				SPDK_ERRLOG("Failed to connect rqpair=%p\n", rqpair);
				client_rdma_fail_qpair(qpair, 0);
				continue;
			}
		}
		else
		{
			client_rdma_qpair_process_cm_event(rqpair);
		}

		if (spdk_unlikely(qpair->transport_failure_reason != SPDK_CLIENT_QPAIR_FAILURE_NONE))
		{
			client_rdma_fail_qpair(qpair, 0);
			disconnected_qpair_cb(qpair, tgroup->group->ctx);
			continue;
		}
		num_qpairs++;
	}

	completions_allowed = completions_per_qpair * num_qpairs;
	completions_per_poller = spdk_max(completions_allowed / group->num_pollers, 1);

	STAILQ_FOREACH(poller, &group->pollers, link)
	{
		poller_completions = 0;
		rdma_completions = 0;
		do
		{
			poller->stats.polls++;
			batch_size = spdk_min((completions_per_poller - poller_completions), MAX_COMPLETIONS_PER_POLL);
			rc = client_rdma_cq_process_completions(poller->cq, batch_size, group, NULL, &rdma_completions);
			if (rc <= 0)
			{
				if (rc == -ECANCELED)
				{
					return -EIO;
				}
				else if (rc == 0)
				{
					poller->stats.idle_polls++;
				}
				break;
			}

			poller_completions += rc;
		} while (poller_completions < completions_per_poller);
		total_completions += poller_completions;
		poller->stats.completions += rdma_completions;
	}

	STAILQ_FOREACH_SAFE(qpair, &tgroup->connected_qpairs, poll_group_stailq, tmp_qpair)
	{
		rqpair = client_rdma_qpair(qpair);

		if (spdk_unlikely(rqpair->state <= CLIENT_RDMA_QPAIR_STATE_INITIALIZING))
		{
			continue;
		}
		if (spdk_unlikely(qpair->ctrlr->timeout_enabled))
		{
			client_rdma_qpair_check_timeout(qpair);
		}

		client_rdma_qpair_submit_sends(rqpair);
		client_rdma_qpair_submit_recvs(rqpair);
		if (rqpair->num_completions > 0)
		{
			client_qpair_resubmit_requests(&rqpair->qpair, rqpair->num_completions);
		}
	}

	return total_completions;
}

static int
client_rdma_poll_group_destroy(struct spdk_client_transport_poll_group *tgroup)
{
	struct client_rdma_poll_group *group = client_rdma_poll_group(tgroup);
	struct client_rdma_destroyed_qpair *qpair_tracker, *tmp_qpair_tracker;
	struct client_rdma_qpair *rqpair;

	if (!STAILQ_EMPTY(&tgroup->connected_qpairs) || !STAILQ_EMPTY(&tgroup->disconnected_qpairs))
	{
		return -EBUSY;
	}

	STAILQ_FOREACH_SAFE(qpair_tracker, &group->destroyed_qpairs, link, tmp_qpair_tracker)
	{
		rqpair = qpair_tracker->destroyed_qpair_tracker;
		if (client_qpair_get_state(&rqpair->qpair) == CLIENT_QPAIR_DESTROYING)
		{
			rqpair->defer_deletion_to_pg = false;
			client_rdma_ctrlr_delete_io_qpair(rqpair->qpair.ctrlr, &rqpair->qpair);
		}

		STAILQ_REMOVE(&group->destroyed_qpairs, qpair_tracker, client_rdma_destroyed_qpair, link);
		free(qpair_tracker);
	}

	client_rdma_poll_group_free_pollers(group);
	free(group);

	return 0;
}

static int
client_rdma_poll_group_get_stats(struct spdk_client_transport_poll_group *tgroup,
								 struct spdk_client_transport_poll_group_stat **_stats)
{
	struct client_rdma_poll_group *group;
	struct spdk_client_transport_poll_group_stat *stats;
	struct spdk_client_rdma_device_stat *device_stat;
	struct client_rdma_poller *poller;
	uint32_t i = 0;

	if (tgroup == NULL || _stats == NULL)
	{
		SPDK_ERRLOG("Invalid stats or group pointer\n");
		return -EINVAL;
	}

	group = client_rdma_poll_group(tgroup);
	stats = calloc(1, sizeof(*stats));
	if (!stats)
	{
		SPDK_ERRLOG("Can't allocate memory for RDMA stats\n");
		return -ENOMEM;
	}
	stats->trtype = SPDK_CLIENT_TRANSPORT_RDMA;
	stats->rdma.num_devices = group->num_pollers;
	stats->rdma.device_stats = calloc(stats->rdma.num_devices, sizeof(*stats->rdma.device_stats));
	if (!stats->rdma.device_stats)
	{
		SPDK_ERRLOG("Can't allocate memory for RDMA device stats\n");
		free(stats);
		return -ENOMEM;
	}

	STAILQ_FOREACH(poller, &group->pollers, link)
	{
		device_stat = &stats->rdma.device_stats[i];
		device_stat->name = poller->device->device->name;
		device_stat->polls = poller->stats.polls;
		device_stat->idle_polls = poller->stats.idle_polls;
		device_stat->completions = poller->stats.completions;
		device_stat->queued_requests = poller->stats.queued_requests;
		device_stat->total_send_wrs = poller->stats.rdma_stats.send.num_submitted_wrs;
		device_stat->send_doorbell_updates = poller->stats.rdma_stats.send.doorbell_updates;
		device_stat->total_recv_wrs = poller->stats.rdma_stats.recv.num_submitted_wrs;
		device_stat->recv_doorbell_updates = poller->stats.rdma_stats.recv.doorbell_updates;
		i++;
	}

	*_stats = stats;

	return 0;
}

static void
client_rdma_poll_group_free_stats(struct spdk_client_transport_poll_group *tgroup,
								  struct spdk_client_transport_poll_group_stat *stats)
{
	if (stats)
	{
		free(stats->rdma.device_stats);
	}
	free(stats);
}

void spdk_client_rdma_init_hooks(struct spdk_client_rdma_hooks *hooks)
{
	g_client_hooks = *hooks;
}

const struct spdk_client_transport_ops rdma_trans_ops = {
	.name = "RDMA",
	.type = SPDK_CLIENT_TRANSPORT_RDMA,
	.ctrlr_construct = client_rdma_ctrlr_construct,
	.ctrlr_destruct = client_rdma_ctrlr_destruct,

	.ctrlr_get_max_sges = client_rdma_ctrlr_get_max_sges,

	.ctrlr_create_io_qpair = client_rdma_ctrlr_create_io_qpair,
	.ctrlr_delete_io_qpair = client_rdma_ctrlr_delete_io_qpair,
	.ctrlr_connect_qpair = client_rdma_ctrlr_connect_qpair,
	.ctrlr_disconnect_qpair = client_rdma_ctrlr_disconnect_qpair,

	.qpair_abort_reqs = client_rdma_qpair_abort_reqs,
	.qpair_reset = client_rdma_qpair_reset,
	.qpair_submit_request = client_rdma_qpair_submit_request,
	.qpair_process_completions = client_rdma_qpair_process_completions,
	.qpair_iterate_requests = client_rdma_qpair_iterate_requests,

	.poll_group_create = client_rdma_poll_group_create,
	.poll_group_connect_qpair = client_rdma_poll_group_connect_qpair,
	.poll_group_disconnect_qpair = client_rdma_poll_group_disconnect_qpair,
	.poll_group_add = client_rdma_poll_group_add,
	.poll_group_remove = client_rdma_poll_group_remove,
	.poll_group_process_completions = client_rdma_poll_group_process_completions,
	.poll_group_destroy = client_rdma_poll_group_destroy,
	.poll_group_get_stats = client_rdma_poll_group_get_stats,
	.poll_group_free_stats = client_rdma_poll_group_free_stats,
};

SPDK_CLIENT_TRANSPORT_REGISTER(rdma, &rdma_trans_ops);