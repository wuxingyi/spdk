#include "spdk/stdinc.h"

#include "spdk/bdev.h"
#include "spdk/bit_array.h"
#include "spdk/thread.h"
#include "spdk/endian.h"
#include "spdk/string.h"
#include "spdk/util.h"
#include "spdk/log.h"
#include "spdk_internal/usdt.h"
#include "spdk_internal/rdma_server.h"

SPDK_LOG_REGISTER_COMPONENT(srv)

static TAILQ_HEAD(, spdk_srv_tgt) g_srv_tgts = TAILQ_HEAD_INITIALIZER(g_srv_tgts);
static struct spdk_thread *g_init_thread = NULL;
static struct spdk_srv_tgt *g_srv_tgt = NULL;
typedef void (*srv_conn_disconnect_cpl)(void *ctx, int status);
static void srv_tgt_destroy_poll_group(void *io_device, void *ctx_buf);
int srv_poll_group_add_transport(struct spdk_srv_poll_group *group,
								 struct spdk_srv_transport *transport);

/*
 * There are several times when we need to iterate through the list of all conns and selectively delete them.
 * In order to do this sequentially without overlap, we must provide a context to recover the next conn from
 * to enable calling srv_conn_disconnect on the next desired conn.
 */
struct srv_conn_disconnect_many_ctx
{
	struct spdk_srv_subsystem *subsystem;
	struct spdk_srv_poll_group *group;
	spdk_srv_poll_group_mod_done cpl_fn;
	void *cpl_ctx;
	uint32_t count;
};

struct spdk_srv_tgt_add_transport_ctx
{
	struct spdk_srv_tgt *tgt;
	struct spdk_srv_transport *transport;
	spdk_srv_tgt_add_transport_done_fn cb_fn;
	void *cb_arg;
	int status;
};

struct spdk_srv_tgt_add_transport_cb_ctx
{
	struct spdk_srv_tgt_add_transport_ctx *ctx;
	struct spdk_srv_poll_group *new_group;
};

static int
srv_poll_group_poll(void *ctx)
{
	struct spdk_srv_poll_group *group = ctx;
	int rc;
	int count = 0;
	struct spdk_srv_transport_poll_group *tgroup;

	TAILQ_FOREACH(tgroup, &group->tgroups, link)
	{
		rc = srv_transport_poll_group_poll(tgroup);
		if (rc < 0)
		{
			return SPDK_POLLER_BUSY;
		}
		count += rc;
	}

	return count > 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}
// TODO: 需要取消io_device的概念

static void
srv_tgt_create_poll_groups_done(void *args)
{
	int pool_groups_cnt = 0;
	struct spdk_srv_poll_group *tmp;
	struct spdk_srv_tgt_add_transport_cb_ctx *wapper = (struct spdk_srv_tgt_add_transport_cb_ctx *)args;

	TAILQ_FOREACH(tmp, &wapper->ctx->tgt->poll_groups, link)
	{
		pool_groups_cnt++;
	}
	assert(pool_groups_cnt < spdk_env_get_core_count());

	TAILQ_INSERT_TAIL(&wapper->ctx->tgt->poll_groups, wapper->new_group, link);

	if (++pool_groups_cnt == spdk_env_get_core_count())
	{
		fprintf(stdout, "create targets's poll groups done\n");
		(*wapper->ctx->cb_fn)(wapper->ctx->cb_arg, 0);
		free(wapper->ctx);
	}
	free(wapper);
	return;
}

static int
srv_tgt_create_poll_group(void *args)
{
	struct spdk_srv_tgt_add_transport_ctx *ctx = (struct spdk_srv_tgt_add_transport_ctx *)args;
	struct spdk_srv_tgt_add_transport_cb_ctx *ctx_wapper;
	struct spdk_srv_poll_group *group;
	struct spdk_srv_transport *transport = ctx->transport;
	struct spdk_thread *thread = spdk_get_thread();
	int rc;

	group = calloc(1, sizeof(*group));
	if (!group)
	{
		SPDK_ERRLOG("Failed to allocate memory for srv_tgt_create_poll_group\n");
		exit(-1);
	}

	TAILQ_INIT(&group->tgroups);
	TAILQ_INIT(&group->conns);
	group->thread = thread;

	rc = srv_poll_group_add_transport(group, transport);
	if (rc != 0)
	{
		return rc;
	}

	group->poller = SPDK_POLLER_REGISTER(srv_poll_group_poll, group, 0);

	SPDK_DTRACE_PROBE1(srv_create_poll_group, spdk_thread_get_id(thread));

	ctx_wapper = calloc(1, sizeof(*ctx_wapper));
	if (!ctx_wapper)
	{
		SPDK_ERRLOG("Failed to allocate memory for srv_tgt_create_poll_group\n");
		exit(-1);
	}

	ctx_wapper->ctx = ctx;
	ctx_wapper->new_group = group;
	spdk_thread_send_msg(g_init_thread, srv_tgt_create_poll_groups_done, ctx_wapper);

	return 0;
}

static void
srv_tgt_destroy_poll_group(void *io_device, void *ctx_buf)
{
	struct spdk_srv_tgt *tgt = io_device;
	struct spdk_srv_poll_group *group = ctx_buf;
	struct spdk_srv_transport_poll_group *tgroup, *tmp;

	SPDK_DTRACE_PROBE1(srv_destroy_poll_group, spdk_thread_get_id(group->thread));

	pthread_mutex_lock(&tgt->mutex);
	TAILQ_REMOVE(&tgt->poll_groups, group, link);
	pthread_mutex_unlock(&tgt->mutex);

	TAILQ_FOREACH_SAFE(tgroup, &group->tgroups, link, tmp)
	{
		TAILQ_REMOVE(&group->tgroups, tgroup, link);
		srv_transport_poll_group_destroy(tgroup);
	}

	spdk_poller_unregister(&group->poller);

	if (group->destroy_cb_fn)
	{
		group->destroy_cb_fn(group->destroy_cb_arg, 0);
	}
}

static void
_srv_tgt_disconnect_next_conn(void *ctx)
{
	struct spdk_srv_conn *conn;
	struct srv_conn_disconnect_many_ctx *conn_ctx = ctx;
	struct spdk_srv_poll_group *group = conn_ctx->group;
	struct spdk_io_channel *ch;
	int rc = 0;

	conn = TAILQ_FIRST(&group->conns);

	if (conn)
	{
		rc = spdk_srv_conn_disconnect(conn, _srv_tgt_disconnect_next_conn, ctx);
	}

	if (!conn || rc != 0)
	{
		/* When the refcount from the channels reaches 0, srv_tgt_destroy_poll_group will be called. */
		ch = spdk_io_channel_from_ctx(group);
		spdk_put_io_channel(ch);
		free(conn_ctx);
	}
}

static void
srv_tgt_destroy_poll_group_conns(struct spdk_srv_poll_group *group)
{
	struct srv_conn_disconnect_many_ctx *ctx;

	SPDK_DTRACE_PROBE1(srv_destroy_poll_group_conns, spdk_thread_get_id(group->thread));

	ctx = calloc(1, sizeof(struct srv_conn_disconnect_many_ctx));
	if (!ctx)
	{
		SPDK_ERRLOG("Failed to allocate memory for destroy poll group ctx\n");
		return;
	}

	ctx->group = group;
	_srv_tgt_disconnect_next_conn(ctx);
}

struct spdk_srv_tgt *
spdk_srv_tgt_create(struct spdk_srv_target_opts *opts)
{
	struct spdk_srv_tgt *tgt, *tmp_tgt;
	if (strnlen(opts->name, SRV_TGT_NAME_MAX_LENGTH) == SRV_TGT_NAME_MAX_LENGTH)
	{
		SPDK_ERRLOG("Provided target name exceeds the max length of %u.\n", SRV_TGT_NAME_MAX_LENGTH);
		return NULL;
	}

	if (g_srv_tgt != NULL)
	{
		SPDK_ERRLOG("tgt already created \n");
		return NULL;
	}

	TAILQ_FOREACH(tmp_tgt, &g_srv_tgts, link)
	{
		if (!strncmp(opts->name, tmp_tgt->name, SRV_TGT_NAME_MAX_LENGTH))
		{
			SPDK_ERRLOG("Provided target name must be unique.\n");
			return NULL;
		}
	}

	tgt = calloc(1, sizeof(*tgt));
	if (!tgt)
	{
		return NULL;
	}

	snprintf(tgt->name, SRV_TGT_NAME_MAX_LENGTH, "%s", opts->name);

	TAILQ_INIT(&tgt->transports);
	TAILQ_INIT(&tgt->poll_groups);

	pthread_mutex_init(&tgt->mutex, NULL);
	// TODO:不需要注册IODEVICE，但是怎么去触发创建srv_tgt_create_poll_group呢？

	// spdk_io_device_register(tgt,
	// 			srv_tgt_create_poll_group,
	// 			srv_tgt_destroy_poll_group,
	// 			sizeof(struct spdk_srv_poll_group),
	// 			tgt->name);

	// tmp_pg = calloc(1, sizeof(*tmp_pg));
	// if (!tmp_pg) {
	// 	return NULL;
	// }
	// TODO:什么时候销毁呢？
	g_init_thread = spdk_get_thread();
	g_srv_tgt = tgt;
	TAILQ_INSERT_HEAD(&g_srv_tgts, tgt, link);

	return tgt;
}

static void
_srv_tgt_destroy_next_transport(void *ctx)
{
	struct spdk_srv_tgt *tgt = ctx;
	struct spdk_srv_transport *transport;

	if (!TAILQ_EMPTY(&tgt->transports))
	{
		transport = TAILQ_FIRST(&tgt->transports);
		TAILQ_REMOVE(&tgt->transports, transport, link);
		spdk_srv_transport_destroy(transport, _srv_tgt_destroy_next_transport, tgt);
	}
	else
	{
		spdk_srv_tgt_destroy_done_fn *destroy_cb_fn = tgt->destroy_cb_fn;
		void *destroy_cb_arg = tgt->destroy_cb_arg;

		pthread_mutex_destroy(&tgt->mutex);
		free(tgt);

		if (destroy_cb_fn)
		{
			destroy_cb_fn(destroy_cb_arg, 0);
		}
	}
}

static void
srv_tgt_destroy_cb(void *io_device)
{
	struct spdk_srv_tgt *tgt = io_device;

	_srv_tgt_destroy_next_transport(tgt);
}

void spdk_srv_tgt_destroy(struct spdk_srv_tgt *tgt,
						  spdk_srv_tgt_destroy_done_fn cb_fn,
						  void *cb_arg)
{
	tgt->destroy_cb_fn = cb_fn;
	tgt->destroy_cb_arg = cb_arg;

	TAILQ_REMOVE(&g_srv_tgts, tgt, link);

	spdk_io_device_unregister(tgt, srv_tgt_destroy_cb);
}

int spdk_srv_tgt_stop_listen(struct spdk_srv_tgt *tgt,
							 struct spdk_srv_transport_id *trid)
{
	struct spdk_srv_transport *transport;
	int rc;

	transport = spdk_srv_tgt_get_transport(tgt, trid->trstring);
	if (!transport)
	{
		SPDK_ERRLOG("Unable to find %s transport. The transport must be created first also make sure it is properly registered.\n",
					trid->trstring);
		return -EINVAL;
	}

	rc = spdk_srv_transport_stop_listen(transport, trid);
	if (rc < 0)
	{
		SPDK_ERRLOG("Failed to stop listening on address '%s'\n", trid->traddr);
		return rc;
	}
	return 0;
}

static void
_srv_tgt_remove_transport_done(struct spdk_io_channel_iter *i, int status)
{
	struct spdk_srv_tgt_add_transport_ctx *ctx = spdk_io_channel_iter_get_ctx(i);

	ctx->cb_fn(ctx->cb_arg, ctx->status);
	free(ctx);
}

static void
_srv_tgt_remove_transport(struct spdk_io_channel_iter *i)
{
	struct spdk_srv_tgt_add_transport_ctx *ctx = spdk_io_channel_iter_get_ctx(i);
	struct spdk_io_channel *ch = spdk_io_channel_iter_get_channel(i);
	struct spdk_srv_poll_group *group = spdk_io_channel_get_ctx(ch);
	struct spdk_srv_transport_poll_group *tgroup, *tmp;

	TAILQ_FOREACH_SAFE(tgroup, &group->tgroups, link, tmp)
	{
		if (tgroup->transport == ctx->transport)
		{
			TAILQ_REMOVE(&group->tgroups, tgroup, link);
			srv_transport_poll_group_destroy(tgroup);
		}
	}

	spdk_for_each_channel_continue(i, 0);
}

void spdk_srv_tgt_add_transport(struct spdk_srv_tgt *tgt,
								struct spdk_srv_transport *transport,
								spdk_srv_tgt_add_transport_done_fn cb_fn,
								void *cb_arg)
{
	struct spdk_srv_tgt_add_transport_ctx *ctx;
	struct spdk_cpuset tmp_cpumask = {};
	uint32_t i;
	char thread_name[32];
	struct spdk_thread *thread;
	SPDK_DTRACE_PROBE2(srv_tgt_add_transport, transport, tgt->name);

	if (spdk_srv_tgt_get_transport(tgt, transport->ops->name))
	{
		cb_fn(cb_arg, -EEXIST);
		return; /* transport already created */
	}

	TAILQ_INSERT_TAIL(&tgt->transports, transport, link);

	assert(g_init_thread != NULL);

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
	{
		cb_fn(cb_arg, -ENOMEM);
		return;
	}

	ctx->tgt = tgt;
	ctx->transport = transport;
	ctx->cb_fn = cb_fn;
	ctx->cb_arg = cb_arg;

	SPDK_ENV_FOREACH_CORE(i)
	{
		spdk_cpuset_zero(&tmp_cpumask);
		spdk_cpuset_set_cpu(&tmp_cpumask, i, true);
		snprintf(thread_name, sizeof(thread_name), "srv_tgt_poll_group_%u", i);

		thread = spdk_thread_create(thread_name, &tmp_cpumask);
		assert(thread != NULL);

		spdk_thread_send_msg(thread, srv_tgt_create_poll_group, ctx);
	}

	return;
}

struct spdk_srv_transport *
spdk_srv_tgt_get_transport(struct spdk_srv_tgt *tgt, const char *transport_name)
{
	struct spdk_srv_transport *transport;

	TAILQ_FOREACH(transport, &tgt->transports, link)
	{
		if (!strncasecmp(transport->ops->name, transport_name, SPDK_SRV_TRSTRING_MAX_LEN))
		{
			return transport;
		}
	}
	return NULL;
}

struct srv_new_conn_ctx
{
	struct spdk_srv_conn *conn;
	struct spdk_srv_poll_group *group;
};

static int
spdk_srv_poll_group_add(struct spdk_srv_poll_group *group,
						struct spdk_srv_conn *conn)
{
	int rc = -1;
	struct spdk_srv_transport_poll_group *tgroup;

	TAILQ_INIT(&conn->outstanding);
	conn->group = group;
	conn->disconnect_started = false;

	TAILQ_FOREACH(tgroup, &group->tgroups, link)
	{
		if (tgroup->transport == conn->transport)
		{
			rc = srv_transport_poll_group_add(tgroup, conn);
			break;
		}
	}

	/* We add the conn to the group only it is successfully added into the tgroup */
	if (rc == 0)
	{
		SPDK_DTRACE_PROBE2(srv_poll_group_add_conn, conn, spdk_thread_get_id(group->thread));
		TAILQ_INSERT_TAIL(&group->conns, conn, link);
		srv_conn_set_state(conn, SPDK_SRV_CONN_ACTIVE);
	}

	return rc;
}

static void
_srv_poll_group_add(void *_ctx)
{
	struct srv_new_conn_ctx *ctx = _ctx;
	struct spdk_srv_conn *conn = ctx->conn;
	struct spdk_srv_poll_group *group = ctx->group;

	free(_ctx);

	if (spdk_srv_poll_group_add(group, conn) != 0)
	{
		SPDK_ERRLOG("Unable to add the conn to a poll group.\n");
		spdk_srv_conn_disconnect(conn, NULL, NULL);
	}
}

static struct spdk_srv_poll_group *
spdk_srv_get_optimal_poll_group(struct spdk_srv_conn *conn)
{
	struct spdk_srv_transport_poll_group *tgroup;

	tgroup = srv_transport_get_optimal_poll_group(conn->transport, conn);

	if (tgroup == NULL)
	{
		return NULL;
	}

	return tgroup->group;
}

void spdk_srv_tgt_new_conn(struct spdk_srv_tgt *tgt, struct spdk_srv_conn *conn)
{
	struct spdk_srv_poll_group *group;
	struct srv_new_conn_ctx *ctx;

	group = spdk_srv_get_optimal_poll_group(conn);
	if (group == NULL)
	{
		if (tgt->next_poll_group == NULL)
		{
			tgt->next_poll_group = TAILQ_FIRST(&tgt->poll_groups);
			if (tgt->next_poll_group == NULL)
			{
				SPDK_ERRLOG("No poll groups exist.\n");
				spdk_srv_conn_disconnect(conn, NULL, NULL);
				return;
			}
		}
		group = tgt->next_poll_group;
		tgt->next_poll_group = TAILQ_NEXT(group, link);
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
	{
		SPDK_ERRLOG("Unable to send message to poll group.\n");
		spdk_srv_conn_disconnect(conn, NULL, NULL);
		return;
	}

	ctx->conn = conn;
	ctx->group = group;

	spdk_thread_send_msg(group->thread, _srv_poll_group_add, ctx);
}

struct spdk_srv_poll_group *
spdk_srv_poll_group_create(struct spdk_srv_tgt *tgt)
{
	struct spdk_io_channel *ch;

	ch = spdk_get_io_channel(tgt);
	if (!ch)
	{
		SPDK_ERRLOG("Unable to get I/O channel for target\n");
		return NULL;
	}

	return spdk_io_channel_get_ctx(ch);
}

void spdk_srv_poll_group_destroy(struct spdk_srv_poll_group *group,
								 spdk_srv_poll_group_destroy_done_fn cb_fn,
								 void *cb_arg)
{
	assert(group->destroy_cb_fn == NULL);
	group->destroy_cb_fn = cb_fn;
	group->destroy_cb_arg = cb_arg;

	/* This function will put the io_channel associated with this poll group */
	srv_tgt_destroy_poll_group_conns(group);
}

void spdk_srv_poll_group_remove(struct spdk_srv_conn *conn)
{
	struct spdk_srv_transport_poll_group *tgroup;
	int rc;

	SPDK_DTRACE_PROBE2(srv_poll_group_remove_conn, conn,
					   spdk_thread_get_id(conn->group->thread));
	srv_conn_set_state(conn, SPDK_SRV_CONN_ERROR);

	/* Find the tgroup and remove the conn from the tgroup */
	TAILQ_FOREACH(tgroup, &conn->group->tgroups, link)
	{
		if (tgroup->transport == conn->transport)
		{
			rc = srv_transport_poll_group_remove(tgroup, conn);
			if (rc && (rc != ENOTSUP))
			{
				SPDK_ERRLOG("Cannot remove conn=%p from transport group=%p\n",
							conn, tgroup);
			}
			break;
		}
	}

	TAILQ_REMOVE(&conn->group->conns, conn, link);
	conn->group = NULL;
}

int srv_poll_group_add_transport(struct spdk_srv_poll_group *group,
								 struct spdk_srv_transport *transport)
{
	struct spdk_srv_transport_poll_group *tgroup;

	TAILQ_FOREACH(tgroup, &group->tgroups, link)
	{
		if (tgroup->transport == transport)
		{
			/* Transport already in the poll group */
			return 0;
		}
	}

	tgroup = srv_transport_poll_group_create(transport);
	if (!tgroup)
	{
		SPDK_ERRLOG("Unable to create poll group for transport\n");
		return -1;
	}
	SPDK_DTRACE_PROBE2(srv_transport_poll_group_create, transport, spdk_thread_get_id(group->thread));

	tgroup->group = group;
	TAILQ_INSERT_TAIL(&group->tgroups, tgroup, link);

	return 0;
}