#ifndef SPDK_SRV_INTERNAL_H
#define SPDK_SRV_INTERNAL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "spdk/bdev.h"
#include "spdk/memory.h"
#include "spdk/likely.h"
#include "spdk/rdma_server.h"

int srv_transport_poll_group_add(struct spdk_srv_transport_poll_group *group,
								 struct spdk_srv_conn *conn);

int srv_transport_poll_group_poll(struct spdk_srv_transport_poll_group *group);

struct spdk_srv_transport_poll_group *
srv_transport_poll_group_create(struct spdk_srv_transport *transport);

void srv_transport_poll_group_destroy(struct spdk_srv_transport_poll_group *group);

struct spdk_srv_listener *
srv_transport_find_listener(struct spdk_srv_transport *transport,
							const struct spdk_srv_transport_id *trid);

void srv_conn_set_state(struct spdk_srv_conn *conn,
						enum spdk_srv_conn_state state);

struct spdk_srv_transport_poll_group *
srv_transport_get_optimal_poll_group(struct spdk_srv_transport *transport,
									 struct spdk_srv_conn *conn);

int srv_transport_poll_group_remove(struct spdk_srv_transport_poll_group *group,
									struct spdk_srv_conn *conn);

int srv_transport_conn_get_peer_trid(struct spdk_srv_conn *conn,
									 struct spdk_srv_transport_id *trid);

int srv_transport_conn_get_listen_trid(struct spdk_srv_conn *conn,
									   struct spdk_srv_transport_id *trid);

int srv_transport_conn_get_local_trid(struct spdk_srv_conn *conn,
									  struct spdk_srv_transport_id *trid);

#ifdef __cplusplus
}
#endif

#endif