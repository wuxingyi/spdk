/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2021 Mellanox Technologies LTD. All rights reserved.
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
 * Client transport abstraction
 */

#include "spdk_internal/rdma_client.h"
#include "spdk/queue.h"

#define SPDK_MAX_NUM_OF_TRANSPORTS 16

struct spdk_client_transport
{
	struct spdk_client_transport_ops ops;
	TAILQ_ENTRY(spdk_client_transport)
	link;
};

TAILQ_HEAD(client_transport_list, spdk_client_transport)
g_spdk_client_transports =
	TAILQ_HEAD_INITIALIZER(g_spdk_client_transports);

struct spdk_client_transport g_spdk_transports_dif[SPDK_MAX_NUM_OF_TRANSPORTS] = {};
int g_current_transport_index_dif = 0;

const struct spdk_client_transport *
client_get_first_transport(void)
{
	return TAILQ_FIRST(&g_spdk_client_transports);
}

const struct spdk_client_transport *
client_get_next_transport(const struct spdk_client_transport *transport)
{
	return TAILQ_NEXT(transport, link);
}

/*
 * Unfortunately, due to Client PCIe multiprocess support, we cannot store the
 * transport object in either the controller struct or the admin qpair. THis means
 * that a lot of admin related transport calls will have to call client_get_transport
 * in order to knwo which functions to call.
 * In the I/O path, we have the ability to store the transport struct in the I/O
 * qpairs to avoid taking a performance hit.
 */
const struct spdk_client_transport *
client_get_transport(const char *transport_name)
{
	struct spdk_client_transport *registered_transport;

	TAILQ_FOREACH(registered_transport, &g_spdk_client_transports, link)
	{
		if (strcasecmp(transport_name, registered_transport->ops.name) == 0)
		{
			return registered_transport;
		}
	}

	return NULL;
}

void spdk_client_transport_register(const struct spdk_client_transport_ops *ops)
{
	struct spdk_client_transport *new_transport;

	if (client_get_transport(ops->name))
	{
		SPDK_ERRLOG("Double registering Client transport %s is prohibited.\n", ops->name);
		assert(false);
	}

	if (g_current_transport_index_dif == SPDK_MAX_NUM_OF_TRANSPORTS)
	{
		SPDK_ERRLOG("Unable to register new Client transport.\n");
		assert(false);
		return;
	}
	new_transport = &g_spdk_transports_dif[g_current_transport_index_dif++];

	new_transport->ops = *ops;
	TAILQ_INSERT_TAIL(&g_spdk_client_transports, new_transport, link);
}

int get_random_str(char *random_str, const int random_len)
{
	int i, random_num, seed_str_len;
	char seed_str[] = "abcdefghijklmnopqrstuvwxyz"
					  "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	seed_str_len = strlen(seed_str);

	for (i = 0; i < random_len; i++)
	{
		random_num = rand() % seed_str_len;
		random_str[i] = seed_str[random_num];
	}

	return 0;
}

struct spdk_client_ctrlr *client_transport_ctrlr_construct(const char *trstring,
														   const struct spdk_client_ctrlr_opts *opts,
														   void *devhandle)
{
	const struct spdk_client_transport *transport = client_get_transport(trstring);
	struct spdk_client_ctrlr *ctrlr;

	if (transport == NULL)
	{
		SPDK_ERRLOG("Transport %s doesn't exist.", trstring);
		return NULL;
	}
	ctrlr = transport->ops.ctrlr_construct(opts, devhandle);
	ctrlr->trtype = transport->ops.type;
	strncpy(ctrlr->trstring, trstring, sizeof(ctrlr->trstring));
	ctrlr->ioccsz_bytes = 8192;
	ctrlr->icdoff = 0;
	ctrlr->max_sges = client_transport_ctrlr_get_max_sges(ctrlr);
	ctrlr->io_unit_size = ctrlr->opts.sector_size * ctrlr->opts.sectors_per_max_io / ctrlr->max_sges;

	char str[8];
	get_random_str(str, 8);

	ctrlr->rpc_data_mp = spdk_mempool_create(str,
											 SPDK_SRV_MEMORY_POOL_ELEMENT_SIZE, /* src + dst */
											 ctrlr->io_unit_size,
											 SPDK_MEMPOOL_DEFAULT_CACHE_SIZE,
											 SPDK_ENV_SOCKET_ID_ANY);
	assert(ctrlr->rpc_data_mp != NULL);
	SPDK_INFOLOG(rdma, "create rpc data mem pool, item size = %d\n", ctrlr->io_unit_size);
	return ctrlr;
}

int client_transport_ctrlr_destruct(struct spdk_client_ctrlr *ctrlr)
{
	const struct spdk_client_transport *transport = client_get_transport(ctrlr->trstring);

	assert(transport != NULL);
	return transport->ops.ctrlr_destruct(ctrlr);
}

uint16_t
client_transport_ctrlr_get_max_sges(struct spdk_client_ctrlr *ctrlr)
{
	const struct spdk_client_transport *transport = client_get_transport(ctrlr->trstring);

	assert(transport != NULL);
	return transport->ops.ctrlr_get_max_sges(ctrlr);
}

struct spdk_client_qpair *
client_transport_ctrlr_create_io_qpair(struct spdk_client_ctrlr *ctrlr, uint16_t qid,
									   const struct spdk_client_io_qpair_opts *opts)
{
	struct spdk_client_qpair *qpair;
	const struct spdk_client_transport *transport = client_get_transport(ctrlr->trstring);

	assert(transport != NULL);
	qpair = transport->ops.ctrlr_create_io_qpair(ctrlr, qid, opts);

	if (qpair != NULL)
	{
		qpair->transport = transport;
	}

	return qpair;
}

void client_transport_ctrlr_delete_io_qpair(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair)
{
	const struct spdk_client_transport *transport = client_get_transport(ctrlr->trstring);
	int rc;

	assert(transport != NULL);

	/* Do not rely on qpair->transport.  For multi-process cases, a foreign process may delete
	 * the IO qpair, in which case the transport object would be invalid (each process has their
	 * own unique transport objects since they contain function pointers).  So we look up the
	 * transport object in the delete_io_qpair case.
	 */
	rc = transport->ops.ctrlr_delete_io_qpair(ctrlr, qpair);
	if (rc != 0)
	{
		SPDK_ERRLOG("transport %s returned non-zero for ctrlr_delete_io_qpair op\n",
					transport->ops.name);
		assert(false);
	}
}

static void
client_transport_connect_qpair_fail(struct spdk_client_qpair *qpair, void *unused)
{
	struct spdk_client_ctrlr *ctrlr = qpair->ctrlr;

	/* If the qpair was unable to reconnect, restore the original failure reason */
	qpair->transport_failure_reason = qpair->last_transport_failure_reason;
	client_transport_ctrlr_disconnect_qpair(ctrlr, qpair);
}

int client_transport_ctrlr_connect_qpair(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair)
{
	const struct spdk_client_transport *transport = client_get_transport(ctrlr->trstring);
	int rc;

	assert(transport != NULL);

	qpair->transport = transport;
	qpair->last_transport_failure_reason = qpair->transport_failure_reason;
	qpair->transport_failure_reason = SPDK_CLIENT_QPAIR_FAILURE_NONE;

	client_qpair_set_state(qpair, CLIENT_QPAIR_CONNECTING);
	rc = transport->ops.ctrlr_connect_qpair(ctrlr, qpair);
	if (rc != 0)
	{
		goto err;
	}

	if (qpair->poll_group)
	{
		rc = client_poll_group_connect_qpair(qpair);
		if (rc)
		{
			goto err;
		}
	}

	if (!qpair->async)
	{
		/* Busy wait until the qpair exits the connecting state */
		while (client_qpair_get_state(qpair) == CLIENT_QPAIR_CONNECTING)
		{
			if (qpair->poll_group)
			{
				rc = spdk_client_poll_group_process_completions(
					qpair->poll_group->group, 0,
					client_transport_connect_qpair_fail);
			}
			else
			{
				rc = spdk_client_qpair_process_completions(qpair, 0);
			}

			if (rc < 0)
			{
				goto err;
			}
		}
	}

	return 0;
err:
	client_transport_connect_qpair_fail(qpair, NULL);
	if (client_qpair_get_state(qpair) == CLIENT_QPAIR_DISCONNECTING)
	{
		assert(qpair->async == true);
		/* Let the caller to poll the qpair until it is actually disconnected. */
		return 0;
	}

	return rc;
}

int client_transport_ctrlr_connect_qpair_async(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair)
{
	const struct spdk_client_transport *transport = client_get_transport(ctrlr->trstring);
	int rc;

	assert(transport != NULL);

	qpair->transport = transport;
	qpair->last_transport_failure_reason = qpair->transport_failure_reason;
	qpair->transport_failure_reason = SPDK_CLIENT_QPAIR_FAILURE_NONE;

	client_qpair_set_state(qpair, CLIENT_QPAIR_CONNECTING);
	rc = transport->ops.ctrlr_connect_qpair(ctrlr, qpair);
	if (rc != 0)
	{
		goto err;
	}

	if (qpair->poll_group)
	{
		rc = client_poll_group_connect_qpair(qpair);
		if (rc)
		{
			goto err;
		}
	}

	if (!qpair->async)
	{
		/* Busy wait until the qpair exits the connecting state */
		if (client_qpair_get_state(qpair) == CLIENT_QPAIR_CONNECTING)
		{
			if (qpair->poll_group)
			{
				rc = spdk_client_poll_group_process_completions(
					qpair->poll_group->group, 0,
					client_transport_connect_qpair_fail);
			}
			else
			{
				rc = spdk_client_qpair_process_completions(qpair, 0);
			}

			if (rc < 0)
			{
				goto err;
			}
		}
	}

	return 0;
err:
	client_transport_connect_qpair_fail(qpair, NULL);
	if (client_qpair_get_state(qpair) == CLIENT_QPAIR_DISCONNECTING)
	{
		assert(qpair->async == true);
		/* Let the caller to poll the qpair until it is actually disconnected. */
		return 0;
	}

	return rc;
}

void client_transport_ctrlr_disconnect_qpair(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair)
{
	const struct spdk_client_transport *transport = client_get_transport(ctrlr->trstring);

	if (client_qpair_get_state(qpair) == CLIENT_QPAIR_DISCONNECTING ||
		client_qpair_get_state(qpair) == CLIENT_QPAIR_DISCONNECTED)
	{
		return;
	}

	client_qpair_set_state(qpair, CLIENT_QPAIR_DISCONNECTING);
	assert(transport != NULL);
	if (qpair->poll_group)
	{
		client_poll_group_disconnect_qpair(qpair);
	}

	transport->ops.ctrlr_disconnect_qpair(ctrlr, qpair);

	client_qpair_abort_all_queued_reqs(qpair, 0);
	client_transport_qpair_abort_reqs(qpair, 0);
	client_qpair_set_state(qpair, CLIENT_QPAIR_DISCONNECTED);
}

void client_transport_qpair_abort_reqs(struct spdk_client_qpair *qpair, uint32_t dnr)
{
	const struct spdk_client_transport *transport;

	assert(dnr <= 1);

	transport = client_get_transport(qpair->ctrlr->trstring);
	assert(transport != NULL);
	transport->ops.qpair_abort_reqs(qpair, dnr);
}

int client_transport_qpair_submit_request(struct spdk_client_qpair *qpair, struct client_request *req)
{
	const struct spdk_client_transport *transport;

	transport = client_get_transport(qpair->ctrlr->trstring);
	assert(transport != NULL);
	return transport->ops.qpair_submit_request(qpair, req);
}

int32_t
client_transport_qpair_process_completions(struct spdk_client_qpair *qpair, uint32_t max_completions)
{
	const struct spdk_client_transport *transport;

	transport = client_get_transport(qpair->ctrlr->trstring);
	assert(transport != NULL);
	return transport->ops.qpair_process_completions(qpair, max_completions);
}

struct spdk_client_transport_poll_group *
client_transport_poll_group_create(const struct spdk_client_transport *transport)
{
	struct spdk_client_transport_poll_group *group = NULL;

	group = transport->ops.poll_group_create();
	if (group)
	{
		group->transport = transport;
		STAILQ_INIT(&group->connected_qpairs);
		STAILQ_INIT(&group->disconnected_qpairs);
	}

	return group;
}

struct spdk_client_transport_poll_group *
client_transport_qpair_get_optimal_poll_group(const struct spdk_client_transport *transport,
											  struct spdk_client_qpair *qpair)
{
	if (transport->ops.qpair_get_optimal_poll_group)
	{
		return transport->ops.qpair_get_optimal_poll_group(qpair);
	}
	else
	{
		return NULL;
	}
}

int client_transport_poll_group_add(struct spdk_client_transport_poll_group *tgroup,
									struct spdk_client_qpair *qpair)
{
	int rc;

	rc = tgroup->transport->ops.poll_group_add(tgroup, qpair);
	if (rc == 0)
	{
		qpair->poll_group = tgroup;
		assert(client_qpair_get_state(qpair) < CLIENT_QPAIR_CONNECTED);
		qpair->poll_group_tailq_head = &tgroup->disconnected_qpairs;
		STAILQ_INSERT_TAIL(&tgroup->disconnected_qpairs, qpair, poll_group_stailq);
	}

	return rc;
}

int client_transport_poll_group_remove(struct spdk_client_transport_poll_group *tgroup,
									   struct spdk_client_qpair *qpair)
{
	int rc __attribute__((unused));

	if (qpair->poll_group_tailq_head == &tgroup->connected_qpairs)
	{
		return -EINVAL;
	}
	else if (qpair->poll_group_tailq_head != &tgroup->disconnected_qpairs)
	{
		return -ENOENT;
	}

	rc = tgroup->transport->ops.poll_group_remove(tgroup, qpair);
	assert(rc == 0);

	STAILQ_REMOVE(&tgroup->disconnected_qpairs, qpair, spdk_client_qpair, poll_group_stailq);

	qpair->poll_group = NULL;
	qpair->poll_group_tailq_head = NULL;

	return 0;
}

int64_t
client_transport_poll_group_process_completions(struct spdk_client_transport_poll_group *tgroup,
												uint32_t completions_per_qpair, spdk_client_disconnected_qpair_cb disconnected_qpair_cb)
{
	return tgroup->transport->ops.poll_group_process_completions(tgroup, completions_per_qpair,
																 disconnected_qpair_cb);
}

int client_transport_poll_group_destroy(struct spdk_client_transport_poll_group *tgroup)
{
	return tgroup->transport->ops.poll_group_destroy(tgroup);
}

int client_transport_poll_group_disconnect_qpair(struct spdk_client_qpair *qpair)
{
	struct spdk_client_transport_poll_group *tgroup;
	int rc __attribute__((unused));

	tgroup = qpair->poll_group;

	if (qpair->poll_group_tailq_head == &tgroup->disconnected_qpairs)
	{
		return 0;
	}

	if (qpair->poll_group_tailq_head == &tgroup->connected_qpairs)
	{
		rc = tgroup->transport->ops.poll_group_disconnect_qpair(qpair);
		assert(rc == 0);

		qpair->poll_group_tailq_head = &tgroup->disconnected_qpairs;
		STAILQ_REMOVE(&tgroup->connected_qpairs, qpair, spdk_client_qpair, poll_group_stailq);
		STAILQ_INSERT_TAIL(&tgroup->disconnected_qpairs, qpair, poll_group_stailq);

		return 0;
	}

	return -EINVAL;
}

int client_transport_poll_group_connect_qpair(struct spdk_client_qpair *qpair)
{
	struct spdk_client_transport_poll_group *tgroup;
	int rc;

	tgroup = qpair->poll_group;

	if (qpair->poll_group_tailq_head == &tgroup->connected_qpairs)
	{
		return 0;
	}

	if (qpair->poll_group_tailq_head == &tgroup->disconnected_qpairs)
	{
		rc = tgroup->transport->ops.poll_group_connect_qpair(qpair);
		if (rc == 0)
		{
			qpair->poll_group_tailq_head = &tgroup->connected_qpairs;
			STAILQ_REMOVE(&tgroup->disconnected_qpairs, qpair, spdk_client_qpair, poll_group_stailq);
			STAILQ_INSERT_TAIL(&tgroup->connected_qpairs, qpair, poll_group_stailq);
		}

		return rc == -EINPROGRESS ? 0 : rc;
	}

	return -EINVAL;
}

int client_transport_poll_group_get_stats(struct spdk_client_transport_poll_group *tgroup,
										  struct spdk_client_transport_poll_group_stat **stats)
{
	if (tgroup->transport->ops.poll_group_get_stats)
	{
		return tgroup->transport->ops.poll_group_get_stats(tgroup, stats);
	}
	return -ENOTSUP;
}

void client_transport_poll_group_free_stats(struct spdk_client_transport_poll_group *tgroup,
											struct spdk_client_transport_poll_group_stat *stats)
{
	if (tgroup->transport->ops.poll_group_free_stats)
	{
		tgroup->transport->ops.poll_group_free_stats(tgroup, stats);
	}
}

enum spdk_client_transport_type client_transport_get_trtype(const struct spdk_client_transport *transport)
{
	return transport->ops.type;
}
