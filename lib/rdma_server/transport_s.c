#include "spdk/stdinc.h"
#include "spdk/config.h"
#include "spdk/log.h"
#include "spdk/queue.h"
#include "spdk/util.h"
#include "spdk/thread.h"
#include "spdk_internal/usdt.h"
#include "spdk_internal/rdma_server.h"

#define MAX_MEMPOOL_NAME_LENGTH 40
struct srv_transport_ops_list_element
{
	struct spdk_srv_transport_ops ops;
	TAILQ_ENTRY(srv_transport_ops_list_element)
	link;
};

TAILQ_HEAD(srv_transport_ops_list, srv_transport_ops_list_element)
g_spdk_srv_transport_ops = TAILQ_HEAD_INITIALIZER(g_spdk_srv_transport_ops);

static inline const struct spdk_srv_transport_ops *
srv_get_transport_ops(const char *transport_name)
{
	struct srv_transport_ops_list_element *ops;
	TAILQ_FOREACH(ops, &g_spdk_srv_transport_ops, link)
	{
		if (strcasecmp(transport_name, ops->ops.name) == 0)
		{
			return &ops->ops;
		}
	}
	return NULL;
}

void spdk_srv_transport_register(const struct spdk_srv_transport_ops *ops)
{
	struct srv_transport_ops_list_element *new_ops;

	if (srv_get_transport_ops(ops->name) != NULL)
	{
		SPDK_ERRLOG("Double registering srv transport type %s.\n", ops->name);
		assert(false);
		return;
	}

	new_ops = calloc(1, sizeof(*new_ops));
	if (new_ops == NULL)
	{
		SPDK_ERRLOG("Unable to allocate memory to register new transport type %s.\n", ops->name);
		assert(false);
		return;
	}

	new_ops->ops = *ops;

	TAILQ_INSERT_TAIL(&g_spdk_srv_transport_ops, new_ops, link);
}

const struct spdk_srv_transport_opts *
spdk_srv_get_transport_opts(struct spdk_srv_transport *transport)
{
	return &transport->opts;
}

spdk_srv_transport_type_t spdk_srv_get_transport_type(struct spdk_srv_transport *transport)
{
	return transport->ops->type;
}

const char *
spdk_srv_get_transport_name(struct spdk_srv_transport *transport)
{
	return transport->ops->name;
}

static void srv_transport_opts_copy(struct spdk_srv_transport_opts *opts,
									struct spdk_srv_transport_opts *opts_src,
									size_t opts_size)
{
	assert(opts);
	assert(opts_src);

	opts->opts_size = opts_size;

#define SET_FIELD(field)                                                                    \
	if (offsetof(struct spdk_srv_transport_opts, field) + sizeof(opts->field) <= opts_size) \
	{                                                                                       \
		opts->field = opts_src->field;                                                      \
	}

	SET_FIELD(max_queue_depth);
	SET_FIELD(in_capsule_data_size);
	SET_FIELD(max_io_size);
	SET_FIELD(io_unit_size);
	SET_FIELD(max_aq_depth);
	SET_FIELD(buf_cache_size);
	SET_FIELD(num_shared_buffers);
	SET_FIELD(dif_insert_or_strip);
	SET_FIELD(abort_timeout_sec);
	SET_FIELD(association_timeout);
	SET_FIELD(transport_specific);
	SET_FIELD(acceptor_poll_rate);
	SET_FIELD(zcopy);

	/* Do not remove this statement, you should always update this statement when you adding a new field,
	 * and do not forget to add the SET_FIELD statement for your added field. */
	SPDK_STATIC_ASSERT(sizeof(struct spdk_srv_transport_opts) == 64, "Incorrect size");

#undef SET_FIELD
#undef FILED_CHECK
}

struct spdk_srv_transport *
spdk_srv_transport_create(const char *transport_name, struct spdk_srv_transport_opts *opts)
{
	const struct spdk_srv_transport_ops *ops = NULL;
	struct spdk_srv_transport *transport;
	char spdk_mempool_name[MAX_MEMPOOL_NAME_LENGTH];
	int chars_written;
	struct spdk_srv_transport_opts opts_local = {};

	if (!opts)
	{
		SPDK_ERRLOG("opts should not be NULL\n");
		return NULL;
	}

	if (!opts->opts_size)
	{
		SPDK_ERRLOG("The opts_size in opts structure should not be zero\n");
		return NULL;
	}

	ops = srv_get_transport_ops(transport_name);
	if (!ops)
	{
		SPDK_ERRLOG("Transport type '%s' unavailable.\n", transport_name);
		return NULL;
	}
	srv_transport_opts_copy(&opts_local, opts, opts->opts_size);

	if (opts_local.max_io_size != 0 && (!spdk_u32_is_pow2(opts_local.max_io_size) ||
										opts_local.max_io_size < 8192))
	{
		SPDK_ERRLOG("max_io_size %u must be a power of 2 and be greater than or equal 8KB\n",
					opts_local.max_io_size);
		return NULL;
	}

	transport = ops->create(&opts_local);
	if (!transport)
	{
		SPDK_ERRLOG("Unable to create new transport of type %s\n", transport_name);
		return NULL;
	}

	TAILQ_INIT(&transport->listeners);

	transport->ops = ops;
	transport->opts = opts_local;

	chars_written = snprintf(spdk_mempool_name, MAX_MEMPOOL_NAME_LENGTH, "%s_%s_%s", "spdk_srv",
							 transport_name, "data");
	if (chars_written < 0)
	{
		SPDK_ERRLOG("Unable to generate transport data buffer pool name.\n");
		ops->destroy(transport, NULL, NULL);
		return NULL;
	}

	if (opts_local.num_shared_buffers)
	{
		transport->data_buf_pool = spdk_mempool_create(spdk_mempool_name,
													   opts_local.num_shared_buffers,
													   opts_local.io_unit_size + SRV_DATA_BUFFER_ALIGNMENT,
													   SPDK_MEMPOOL_DEFAULT_CACHE_SIZE,
													   SPDK_ENV_SOCKET_ID_ANY);

		if (!transport->data_buf_pool)
		{
			SPDK_ERRLOG("Unable to allocate buffer pool for poll group\n");
			ops->destroy(transport, NULL, NULL);
			return NULL;
		}
	}

	return transport;
}

struct spdk_srv_transport *
spdk_srv_transport_get_next(struct spdk_srv_transport *transport)
{
	return TAILQ_NEXT(transport, link);
}

int spdk_srv_transport_destroy(struct spdk_srv_transport *transport,
							   spdk_srv_transport_destroy_done_cb cb_fn, void *cb_arg)
{
	struct spdk_srv_listener *listener, *listener_tmp;

	if (transport->data_buf_pool != NULL)
	{
		if (spdk_mempool_count(transport->data_buf_pool) !=
			transport->opts.num_shared_buffers)
		{
			SPDK_ERRLOG("transport buffer pool count is %zu but should be %u\n",
						spdk_mempool_count(transport->data_buf_pool),
						transport->opts.num_shared_buffers);
		}
		spdk_mempool_free(transport->data_buf_pool);
	}

	TAILQ_FOREACH_SAFE(listener, &transport->listeners, link, listener_tmp)
	{
		TAILQ_REMOVE(&transport->listeners, listener, link);
		transport->ops->stop_listen(transport, &listener->trid);
		free(listener);
	}

	return transport->ops->destroy(transport, cb_fn, cb_arg);
}

struct spdk_srv_listener *
srv_transport_find_listener(struct spdk_srv_transport *transport,
							const struct spdk_srv_transport_id *trid)
{
	struct spdk_srv_listener *listener;

	TAILQ_FOREACH(listener, &transport->listeners, link)
	{
		if (spdk_srv_transport_id_compare(&listener->trid, trid) == 0)
		{
			return listener;
		}
	}

	return NULL;
}

int spdk_srv_transport_listen(struct spdk_srv_transport *transport,
							  const struct spdk_srv_transport_id *trid, struct spdk_srv_listen_opts *opts)

{
	struct spdk_srv_listener *listener;
	int rc;

	listener = srv_transport_find_listener(transport, trid);
	if (!listener)
	{
		listener = calloc(1, sizeof(*listener));
		if (!listener)
		{
			return -ENOMEM;
		}

		listener->ref = 1;
		listener->trid = *trid;
		TAILQ_INSERT_TAIL(&transport->listeners, listener, link);
		rc = transport->ops->listen(transport, &listener->trid, opts);
		if (rc != 0)
		{
			TAILQ_REMOVE(&transport->listeners, listener, link);
			free(listener);
		}
		return rc;
	}

	++listener->ref;

	return 0;
}

int spdk_srv_transport_stop_listen(struct spdk_srv_transport *transport,
								   const struct spdk_srv_transport_id *trid)
{
	struct spdk_srv_listener *listener;

	listener = srv_transport_find_listener(transport, trid);
	if (!listener)
	{
		return -ENOENT;
	}

	if (--listener->ref == 0)
	{
		TAILQ_REMOVE(&transport->listeners, listener, link);
		transport->ops->stop_listen(transport, trid);
		free(listener);
	}

	return 0;
}

struct spdk_srv_transport_poll_group *
srv_transport_poll_group_create(struct spdk_srv_transport *transport)
{
	struct spdk_srv_transport_poll_group *group;
	struct spdk_srv_transport_pg_cache_buf **bufs;
	uint32_t i;

	group = transport->ops->poll_group_create(transport);
	if (!group)
	{
		return NULL;
	}
	group->transport = transport;

	STAILQ_INIT(&group->pending_buf_queue);
	STAILQ_INIT(&group->buf_cache);

	if (transport->opts.buf_cache_size)
	{
		group->buf_cache_size = transport->opts.buf_cache_size;
		bufs = calloc(group->buf_cache_size, sizeof(struct spdk_srv_transport_pg_cache_buf *));

		if (!bufs)
		{
			SPDK_ERRLOG("Memory allocation failed, can't reserve buffers for the pg buffer cache\n");
			return group;
		}

		if (spdk_mempool_get_bulk(transport->data_buf_pool, (void **)bufs, group->buf_cache_size))
		{
			group->buf_cache_size = (uint32_t)spdk_mempool_count(transport->data_buf_pool);
			SPDK_NOTICELOG("Unable to reserve the full number of buffers for the pg buffer cache. "
						   "Decrease the number of cached buffers from %u to %u\n",
						   transport->opts.buf_cache_size, group->buf_cache_size);
			/* Sanity check */
			assert(group->buf_cache_size <= transport->opts.buf_cache_size);
			/* Try again with less number of buffers */
			if (spdk_mempool_get_bulk(transport->data_buf_pool, (void **)bufs, group->buf_cache_size))
			{
				SPDK_NOTICELOG("Failed to reserve %u buffers\n", group->buf_cache_size);
				group->buf_cache_size = 0;
			}
		}

		for (i = 0; i < group->buf_cache_size; i++)
		{
			STAILQ_INSERT_HEAD(&group->buf_cache, bufs[i], link);
		}
		group->buf_cache_count = group->buf_cache_size;

		free(bufs);
	}

	return group;
}

struct spdk_srv_transport_poll_group *
srv_transport_get_optimal_poll_group(struct spdk_srv_transport *transport,
									 struct spdk_srv_conn *conn)
{
	if (transport->ops->get_optimal_poll_group)
	{
		return transport->ops->get_optimal_poll_group(conn);
	}
	else
	{
		return NULL;
	}
}

void srv_transport_poll_group_destroy(struct spdk_srv_transport_poll_group *group)
{
	struct spdk_srv_transport_pg_cache_buf *buf, *tmp;

	if (!STAILQ_EMPTY(&group->pending_buf_queue))
	{
		SPDK_ERRLOG("Pending I/O list wasn't empty on poll group destruction\n");
	}

	STAILQ_FOREACH_SAFE(buf, &group->buf_cache, link, tmp)
	{
		STAILQ_REMOVE(&group->buf_cache, buf, spdk_srv_transport_pg_cache_buf, link);
		spdk_mempool_put(group->transport->data_buf_pool, buf);
	}
	group->transport->ops->poll_group_destroy(group);
}

int srv_transport_poll_group_add(struct spdk_srv_transport_poll_group *group,
								 struct spdk_srv_conn *conn)
{
	if (conn->transport)
	{
		assert(conn->transport == group->transport);
		if (conn->transport != group->transport)
		{
			return -1;
		}
	}
	else
	{
		conn->transport = group->transport;
	}

	SPDK_DTRACE_PROBE3(srv_transport_poll_group_add, conn, conn->qid,
					   spdk_thread_get_id(group->group->thread));

	return group->transport->ops->poll_group_add(group, conn);
}

int srv_transport_poll_group_remove(struct spdk_srv_transport_poll_group *group,
									struct spdk_srv_conn *conn)
{
	int rc = ENOTSUP;

	SPDK_DTRACE_PROBE3(srv_transport_poll_group_remove, conn, conn->qid,
					   spdk_thread_get_id(group->group->thread));

	assert(conn->transport == group->transport);
	if (group->transport->ops->poll_group_remove)
	{
		rc = group->transport->ops->poll_group_remove(group, conn);
	}

	return rc;
}

int srv_transport_poll_group_poll(struct spdk_srv_transport_poll_group *group)
{
	return group->transport->ops->poll_group_poll(group);
}

static int
srv_transport_req_free(struct spdk_srv_request *req)
{
	return req->conn->transport->ops->req_free(req);
}

static int
srv_transport_req_complete(struct spdk_srv_request *req)
{
	return req->conn->transport->ops->req_complete(req);
}

static void
srv_transport_conn_fini(struct spdk_srv_conn *conn,
						spdk_srv_transport_conn_fini_cb cb_fn,
						void *cb_arg)
{
	SPDK_DTRACE_PROBE1(srv_transport_conn_fini, conn);

	conn->transport->ops->conn_fini(conn, cb_fn, cb_arg);
}

int srv_transport_conn_get_peer_trid(struct spdk_srv_conn *conn,
									 struct spdk_srv_transport_id *trid)
{
	return conn->transport->ops->conn_get_peer_trid(conn, trid);
}

int srv_transport_conn_get_local_trid(struct spdk_srv_conn *conn,
									  struct spdk_srv_transport_id *trid)
{
	return conn->transport->ops->conn_get_local_trid(conn, trid);
}

int srv_transport_conn_get_listen_trid(struct spdk_srv_conn *conn,
									   struct spdk_srv_transport_id *trid)
{
	return conn->transport->ops->conn_get_listen_trid(conn, trid);
}

static void
srv_transport_conn_abort_request(struct spdk_srv_conn *conn,
								 struct spdk_srv_request *req)
{
	if (conn->transport->ops->conn_abort_request)
	{
		conn->transport->ops->conn_abort_request(conn, req);
	}
}

bool spdk_srv_transport_opts_init(const char *transport_name,
								  struct spdk_srv_transport_opts *opts, size_t opts_size)
{
	const struct spdk_srv_transport_ops *ops;
	struct spdk_srv_transport_opts opts_local = {};

	ops = srv_get_transport_ops(transport_name);
	if (!ops)
	{
		SPDK_ERRLOG("Transport type %s unavailable.\n", transport_name);
		return false;
	}

	if (!opts)
	{
		SPDK_ERRLOG("opts should not be NULL\n");
		return false;
	}

	if (!opts_size)
	{
		SPDK_ERRLOG("opts_size inside opts should not be zero value\n");
		return false;
	}

	opts_local.association_timeout = SRV_TRANSPORT_DEFAULT_ASSOCIATION_TIMEOUT_IN_MS;
	opts_local.acceptor_poll_rate = SPDK_SRV_DEFAULT_ACCEPT_POLL_RATE_US;
	ops->opts_init(&opts_local);

	srv_transport_opts_copy(opts, &opts_local, opts_size);

	return true;
}

static int
cmp_int(int a, int b)
{
	return a - b;
}

int spdk_srv_transport_id_compare(const struct spdk_srv_transport_id *trid1,
								  const struct spdk_srv_transport_id *trid2)
{
	int cmp;

	if (trid1->trtype == SPDK_SRV_TRANSPORT_CUSTOM)
	{
		cmp = strcasecmp(trid1->trstring, trid2->trstring);
	}
	else
	{
		cmp = cmp_int(trid1->trtype, trid2->trtype);
	}

	if (cmp)
	{
		return cmp;
	}

	cmp = strcasecmp(trid1->traddr, trid2->traddr);
	if (cmp)
	{
		return cmp;
	}

	cmp = cmp_int(trid1->adrfam, trid2->adrfam);
	if (cmp)
	{
		return cmp;
	}

	cmp = strcasecmp(trid1->trsvcid, trid2->trsvcid);
	if (cmp)
	{
		return cmp;
	}

	return 0;
}

void spdk_srv_request_free_buffers(struct spdk_srv_request *req,
								   struct spdk_srv_transport_poll_group *group,
								   struct spdk_srv_transport *transport)
{
	uint32_t i;

	for (i = 0; i < req->iovcnt; i++)
	{
		if (group->buf_cache_count < group->buf_cache_size)
		{
			STAILQ_INSERT_HEAD(&group->buf_cache,
							   (struct spdk_srv_transport_pg_cache_buf *)req->buffers[i],
							   link);
			group->buf_cache_count++;
		}
		else
		{
			spdk_mempool_put(transport->data_buf_pool, req->buffers[i]);
		}
		req->iov[i].iov_base = NULL;
		req->buffers[i] = NULL;
		req->iov[i].iov_len = 0;
	}
	req->data_from_pool = false;
}

static inline int
srv_request_set_buffer(struct spdk_srv_request *req, void *buf, uint32_t length,
					   uint32_t io_unit_size)
{
	req->buffers[req->iovcnt] = buf;
	req->iov[req->iovcnt].iov_base = (void *)((uintptr_t)(buf + SRV_DATA_BUFFER_MASK) &
											  ~SRV_DATA_BUFFER_MASK);
	req->iov[req->iovcnt].iov_len = spdk_min(length, io_unit_size);
	length -= req->iov[req->iovcnt].iov_len;
	req->iovcnt++;

	return length;
}

static int
srv_request_get_buffers(struct spdk_srv_request *req,
						struct spdk_srv_transport_poll_group *group,
						struct spdk_srv_transport *transport,
						uint32_t length)
{
	uint32_t io_unit_size = transport->opts.io_unit_size;
	uint32_t num_buffers;
	uint32_t i = 0, j;
	void *buffer, *buffers[SRV_REQ_MAX_BUFFERS];

	/* If the number of buffers is too large, then we know the I/O is larger than allowed.
	 *  Fail it.
	 */
	num_buffers = SPDK_CEIL_DIV(length, io_unit_size);
	if (num_buffers > SRV_REQ_MAX_BUFFERS)
	{
		return -EINVAL;
	}

	while (i < num_buffers)
	{
		if (!(STAILQ_EMPTY(&group->buf_cache)))
		{
			group->buf_cache_count--;
			buffer = STAILQ_FIRST(&group->buf_cache);
			STAILQ_REMOVE_HEAD(&group->buf_cache, link);
			assert(buffer != NULL);

			length = srv_request_set_buffer(req, buffer, length, io_unit_size);
			i++;
		}
		else
		{
			if (spdk_mempool_get_bulk(transport->data_buf_pool, buffers,
									  num_buffers - i))
			{
				return -ENOMEM;
			}
			for (j = 0; j < num_buffers - i; j++)
			{
				length = srv_request_set_buffer(req, buffers[j], length, io_unit_size);
			}
			i += num_buffers - i;
		}
	}

	assert(length == 0);

	req->data_from_pool = true;
	return 0;
}

int spdk_srv_request_get_buffers(struct spdk_srv_request *req,
								 struct spdk_srv_transport_poll_group *group,
								 struct spdk_srv_transport *transport,
								 uint32_t length)
{
	int rc;

	req->iovcnt = 0;

	rc = srv_request_get_buffers(req, group, transport, length);
	if (rc == -ENOMEM)
	{
		spdk_srv_request_free_buffers(req, group, transport);
	}

	return rc;
}

static void
srv_conn_request_cleanup(struct spdk_srv_conn *conn)
{
	if (conn->state == SPDK_SRV_CONN_DEACTIVATING)
	{
		assert(conn->state_cb != NULL);

		if (TAILQ_EMPTY(&conn->outstanding))
		{
			conn->state_cb(conn->state_cb_arg, 0);
		}
	}
}

static void
_srv_request_complete(void *ctx)
{
	struct spdk_srv_request *req = ctx;
	struct spdk_req_cpl *rsp = req->rsp;
	struct spdk_srv_conn *conn;
	struct spdk_srv_subsystem_poll_group *sgroup = NULL;
	bool is_aer = false;
	uint32_t nsid;
	bool paused;
	uint8_t opcode;

	rsp->sqid = 0;
	rsp->status.p = 0;
	rsp->cid = req->cmd->cid;
	opcode = req->cmd->opc;

	conn = req->conn;

	if (srv_transport_req_complete(req))
	{
		SPDK_ERRLOG("Transport request completion error!\n");
	}

	srv_conn_request_cleanup(conn);
}

void spdk_srv_request_exec(struct spdk_srv_request *req)
{
	struct spdk_srv_conn *conn = req->conn;
	struct spdk_srv_transport *transport = conn->transport;
	enum spdk_srv_request_exec_status status;

	// TODO: handle req
	status = SPDK_SRV_REQUEST_EXEC_STATUS_COMPLETE;
	SPDK_DEBUGLOG(srv, "handle a request complete\n");

	if (status == SPDK_SRV_REQUEST_EXEC_STATUS_COMPLETE)
	{
		_srv_request_complete(req);
	}
}

int spdk_srv_request_complete(struct spdk_srv_request *req)
{
	struct spdk_srv_conn *conn = req->conn;

	if (spdk_likely(conn->group->thread == spdk_get_thread()))
	{
		_srv_request_complete(req);
	}
	else
	{
		spdk_thread_send_msg(conn->group->thread,
							 _srv_request_complete, req);
	}

	return 0;
}

void spdk_srv_trid_populate_transport(struct spdk_srv_transport_id *trid,
									  enum spdk_srv_transport_type trtype)
{
	const char *trstring = "";

	trid->trtype = trtype;
	switch (trtype)
	{
	case SPDK_SRV_TRANSPORT_RDMA:
		trstring = SPDK_SRV_TRANSPORT_NAME_RDMA;
		break;
	default:
		SPDK_ERRLOG("no available transports\n");
		assert(0);
		return;
	}
	snprintf(trid->trstring, SPDK_SRV_TRSTRING_MAX_LEN, "%s", trstring);
}

/* supplied to a single call to srv_conn_disconnect */
struct srv_conn_disconnect_ctx
{
	struct spdk_srv_conn *conn;
	srv_conn_disconnect_cb cb_fn;
	struct spdk_thread *thread;
	void *ctx;
	uint16_t qid;
};

static void
_srv_transport_conn_fini_complete(void *cb_ctx)
{
	struct srv_conn_disconnect_ctx *conn_ctx = cb_ctx;
	/* Store cb args since cb_ctx can be freed in _srv_ctrlr_free_from_conn */
	srv_conn_disconnect_cb cb_fn = conn_ctx->cb_fn;
	void *cb_arg = conn_ctx->ctx;
	struct spdk_thread *cb_thread = conn_ctx->thread;

	SPDK_DEBUGLOG(srv, "Finish destroying qid %u\n", conn_ctx->qid);

	free(conn_ctx);

	if (cb_fn)
	{
		spdk_thread_send_msg(cb_thread, cb_fn, cb_arg);
	}
}

static void
_srv_conn_destroy(void *ctx, int status)
{
	struct srv_conn_disconnect_ctx *conn_ctx = ctx;
	struct spdk_srv_conn *conn = conn_ctx->conn;
	struct spdk_srv_request *req, *tmp;
	struct spdk_srv_subsystem_poll_group *sgroup;

	assert(conn->state == SPDK_SRV_CONN_DEACTIVATING);
	conn_ctx->qid = conn->qid;

	spdk_srv_poll_group_remove(conn);
	srv_transport_conn_fini(conn, _srv_transport_conn_fini_complete, conn_ctx);
}

static void
_srv_conn_disconnect_msg(void *ctx)
{
	struct srv_conn_disconnect_ctx *conn_ctx = ctx;

	spdk_srv_conn_disconnect(conn_ctx->conn, conn_ctx->cb_fn, conn_ctx->ctx);
	free(ctx);
}

void srv_conn_set_state(struct spdk_srv_conn *conn,
						enum spdk_srv_conn_state state)
{
	assert(conn != NULL);
	assert(conn->group->thread == spdk_get_thread());

	conn->state = state;
}

int spdk_srv_conn_disconnect(struct spdk_srv_conn *conn, srv_conn_disconnect_cb cb_fn, void *ctx)
{
	struct spdk_srv_poll_group *group = conn->group;
	struct srv_conn_disconnect_ctx *conn_ctx;

	if (__atomic_test_and_set(&conn->disconnect_started, __ATOMIC_RELAXED))
	{
		if (cb_fn)
		{
			cb_fn(ctx);
		}
		return 0;
	}

	/* If we get a conn in the uninitialized state, we can just destroy it immediately */
	if (conn->state == SPDK_SRV_CONN_UNINITIALIZED)
	{
		srv_transport_conn_fini(conn, NULL, NULL);
		if (cb_fn)
		{
			cb_fn(ctx);
		}
		return 0;
	}

	assert(group != NULL);
	if (spdk_get_thread() != group->thread)
	{
		/* clear the atomic so we can set it on the next call on the proper thread. */
		__atomic_clear(&conn->disconnect_started, __ATOMIC_RELAXED);
		conn_ctx = calloc(1, sizeof(struct srv_conn_disconnect_ctx));
		if (!conn_ctx)
		{
			SPDK_ERRLOG("Unable to allocate context for srv_conn_disconnect\n");
			return -ENOMEM;
		}
		conn_ctx->conn = conn;
		conn_ctx->cb_fn = cb_fn;
		conn_ctx->thread = group->thread;
		conn_ctx->ctx = ctx;
		spdk_thread_send_msg(group->thread, _srv_conn_disconnect_msg, conn_ctx);
		return 0;
	}

	SPDK_DTRACE_PROBE2(srv_conn_disconnect, conn, spdk_thread_get_id(group->thread));
	assert(conn->state == SPDK_SRV_CONN_ACTIVE);
	srv_conn_set_state(conn, SPDK_SRV_CONN_DEACTIVATING);

	conn_ctx = calloc(1, sizeof(struct srv_conn_disconnect_ctx));
	if (!conn_ctx)
	{
		SPDK_ERRLOG("Unable to allocate context for srv_conn_disconnect\n");
		return -ENOMEM;
	}

	conn_ctx->conn = conn;
	conn_ctx->cb_fn = cb_fn;
	conn_ctx->thread = group->thread;
	conn_ctx->ctx = ctx;

	/* Check for outstanding I/O */
	if (!TAILQ_EMPTY(&conn->outstanding))
	{
		SPDK_DTRACE_PROBE2(srv_poll_group_drain_conn, conn, spdk_thread_get_id(group->thread));
		conn->state_cb = _srv_conn_destroy;
		conn->state_cb_arg = conn_ctx;
		return 0;
	}

	_srv_conn_destroy(conn_ctx, 0);

	return 0;
}