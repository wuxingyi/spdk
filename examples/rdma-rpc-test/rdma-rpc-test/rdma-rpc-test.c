/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
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
#include "spdk/thread.h"
#include "spdk/env.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/sock.h"
#include "spdk/util.h"
#include "spdk/rdma_server.h"
#include "spdk/rdma_client.h"

#define ACCEPT_TIMEOUT_US 1000
#define CLOSE_TIMEOUT_US 1000000
#define ADDR_STR_LEN INET6_ADDRSTRLEN

static bool g_is_running;

static char *g_host;
static char *g_sock_impl_name;
static int g_port;
static int g_size;
static int g_io_depth;
static int g_submit_type;
static int g_response_size;
static bool g_chesk_sum;
static bool g_is_server;
static bool g_verbose;
static uint64_t g_elapsed_time_in_usec;
static bool g_exit;
static uint32_t g_io_size_bytes;
static uint64_t g_tsc_rate;
static uint64_t g_io_align = 512;
static uint64_t g_io_unit_size = 1024 * 8;

struct ns_worker_stats
{
	uint64_t io_completed;
	uint64_t last_io_completed;
	uint64_t total_tsc;
	uint64_t min_tsc;
	uint64_t max_tsc;
	uint64_t last_tsc;
	uint64_t busy_tsc;
	uint64_t idle_tsc;
	uint64_t last_busy_tsc;
	uint64_t last_idle_tsc;
};

/*
 * We'll use this struct to gather housekeeping hello_context to pass between
 * our events and callbacks.
 */

enum
{
	TEST_RAFT_SERVICE,
	TEST_DATA_SERVICE,
};

struct hello_context_t
{
	bool is_server;
	char *name;
	char *host;
	char *sock_impl_name;
	int port;

	bool verbose;
	int bytes_in;
	int bytes_out;

	struct spdk_sock *sock;

	struct spdk_sock_group *group;
	struct spdk_poller *poller_in;
	struct spdk_poller *poller_out;
	struct spdk_poller *time_out;

	// server
	struct spdk_srv_transport_opts opts;
	struct spdk_srv_transport *transport;
	struct spdk_srv_tgt *tgt;

	// client
	struct spdk_client_transport_id trid;
	struct ns_worker_stats stats;
	int current_queue_depth;
	struct spdk_client_ctrlr_opts ops;
	struct spdk_client_io_qpair_opts conn_opts;
	struct spdk_client_qpair *conn;
	bool is_draining;

	struct client_poll_group pg;
	// buffer
	void *buf_out;
	struct spdk_mempool *mp;

	int rc;
};

/*
 * Usage function for printing parameters that are specific to this application
 */
static void
hello_sock_usage(void)
{
	printf(" -H host_addr  host address\n");
	printf(" -P port       port number\n");
	printf(" -N sock_impl  socket implementation, e.g., -N posix or -N uring\n");
	printf(" -S            start in server mode\n");
	printf(" -Y            do md5sum check when send data\n");
	printf(" -I io_size    send io size, e.g. -I 4096\n");
	printf(" -t response_size    server response data size, e.g. -t 4096\n");
	printf(" -T submit_type submit type 0 or 1\n");
	printf(" -X iodepth    iodepth of perf work\n");
	printf(" -V            print out additional informations\n");
}

/*
 * This function is called to parse the parameters that are specific to this application
 */
static int hello_sock_parse_arg(int ch, char *arg)
{
	switch (ch)
	{
	case 'H':
		g_host = arg;
		break;
	case 'N':
		g_sock_impl_name = arg;
		break;
	case 'P':
		g_port = spdk_strtol(arg, 10);
		if (g_port < 0)
		{
			fprintf(stderr, "Invalid port ID\n");
			return g_port;
		}
		break;
	case 'S':
		g_is_server = 1;
		break;
	case 'I':
		fprintf(stderr, "I %s\n", arg);
		g_size = spdk_strtol(arg, 10);
		break;

	case 'T':
		fprintf(stderr, "T %s\n", arg);
		g_submit_type = spdk_strtol(arg, 10);
		break;

	case 't':
		fprintf(stderr, "t %s\n", arg);
		g_response_size = spdk_strtol(arg, 10);
		break;

	case 'X':
		fprintf(stderr, "X %s\n", arg);
		g_io_depth = spdk_strtol(arg, 10);
		break;
	case 'Y':
		g_chesk_sum = true;
		break;
	case 'V':
		g_verbose = true;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void
sig_handler(int signo)
{
	printf("triger signo\n");
	g_exit = true;
	spdk_app_stop(0);
}

static int
SIsetup_sig_handlers(void)
{
	struct sigaction sigact = {};
	int rc;

	sigemptyset(&sigact.sa_mask);
	sigact.sa_handler = sig_handler;
	rc = sigaction(SIGINT, &sigact, NULL);
	if (rc < 0)
	{
		fprintf(stderr, "sigaction(SIGINT) failed, errno %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	rc = sigaction(SIGTERM, &sigact, NULL);
	if (rc < 0)
	{
		fprintf(stderr, "sigaction(SIGTERM) failed, errno %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

struct perf_task
{
	struct hello_context_t *ctx;

	uint64_t submit_tsc;
	bool is_read;
	void *buf;
	struct iovec iov;
	struct spdk_dif_ctx dif_ctx;
	struct rpc_request *rpc_req;
#if HAVE_LIBAIO
	struct iocb iocb;
#endif
};

static void rdma_write_cb(void *ctx, const struct spdk_req_cpl *cpl)
{
	SPDK_DEBUGLOG(rdma, "call write cb %d %d %d %d %d %d\n", cpl->cdw0, cpl->cdw1, cpl->cid, cpl->status_raw, cpl->status.sc, cpl->status.sct);
	return;
}

void print_performance(struct hello_context_t *ctx)
{
	uint64_t total_io_completed, total_io_tsc;
	double io_per_second, mb_per_second, average_latency, min_latency, max_latency;
	double sum_ave_latency, min_latency_so_far, max_latency_so_far;
	double total_io_per_second, total_mb_per_second;
	int ns_count;
	struct worker_thread *worker;
	struct ns_worker_ctx *ns_ctx;
	uint32_t max_strlen;

	total_io_per_second = 0;
	total_mb_per_second = 0;
	total_io_completed = 0;
	total_io_tsc = 0;
	min_latency_so_far = (double)UINT64_MAX;
	max_latency_so_far = 0;
	ns_count = 0;

	max_strlen = strlen("test-device");

	printf("========================================================\n");
	printf("%*s\n", max_strlen + 60, "Latency(us)");
	printf("%-*s: %10s %10s %10s %10s %10s\n",
		   max_strlen + 13, "Device Information", "IOPS", "MiB/s", "Average", "min", "max");

	if (ctx->stats.io_completed != 0)
	{
		io_per_second = (double)ctx->stats.io_completed * 1000 * 1000 / g_elapsed_time_in_usec;
		mb_per_second = io_per_second * g_io_size_bytes / (1024 * 1024);
		average_latency = ((double)ctx->stats.total_tsc / ctx->stats.io_completed) * 1000 * 1000 /
						  g_tsc_rate;
		min_latency = (double)ctx->stats.min_tsc * 1000 * 1000 / g_tsc_rate;
		if (min_latency < min_latency_so_far)
		{
			min_latency_so_far = min_latency;
		}

		max_latency = (double)ctx->stats.max_tsc * 1000 * 1000 / g_tsc_rate;
		if (max_latency > max_latency_so_far)
		{
			max_latency_so_far = max_latency;
		}

		printf("%-*.*s from core %2u: %10.2f %10.2f %10.2f %10.2f %10.2f\n",
			   max_strlen, max_strlen, "test-device", 0,
			   io_per_second, mb_per_second,
			   average_latency, min_latency, max_latency);
		total_io_per_second += io_per_second;
		total_mb_per_second += mb_per_second;
		total_io_completed += ctx->stats.io_completed;
		total_io_tsc += ctx->stats.total_tsc;
	}

	if (ns_count != 0 && total_io_completed)
	{
		sum_ave_latency = ((double)total_io_tsc / total_io_completed) * 1000 * 1000 / g_tsc_rate;
		printf("========================================================\n");
		printf("%-*s: %10.2f %10.2f %10.2f %10.2f %10.2f\n",
			   max_strlen + 13, "Total", total_io_per_second, total_mb_per_second,
			   sum_ave_latency, min_latency_so_far, max_latency_so_far);
		printf("\n");
	}
}

void print_stats(struct hello_context_t *ctx)
{
	print_performance(ctx);
}

void nvme_setup_payload(struct perf_task *task)
{
	uint32_t max_io_size_bytes, max_io_md_size;
	void *buf;
	int rc;

	/* maximum extended lba format size from all active namespace,
	 * it's same with g_io_size_bytes for namespace without metadata.
	 */
	max_io_size_bytes = g_io_size_bytes;

	buf = spdk_mempool_get(task->ctx->mp);
	memset(buf, 0, max_io_size_bytes);

	task->buf = buf;

	task->iov.iov_base = buf;
	task->iov.iov_len = max_io_size_bytes;
}

static struct perf_task *
allocate_task(struct hello_context_t *ctx, int queue_depth)
{
	struct perf_task *task;

	task = calloc(1, sizeof(*task));
	if (task == NULL)
	{
		fprintf(stderr, "Out of memory allocating tasks\n");
		exit(1);
	}
	task->ctx = ctx;
	nvme_setup_payload(task);

	return task;
}

void rpc_callback(void *cb_args, int status, struct iovec *iovs, int iovcnt, int length)
{
	struct perf_task *task = (struct perf_task *)cb_args;
	struct hello_context_t *ctx;
	uint64_t tsc_diff;
	struct ns_entry *entry;
	ctx = task->ctx;
	ctx->current_queue_depth--;
	ctx->stats.io_completed++;
	tsc_diff = spdk_get_ticks() - task->submit_tsc;
	ctx->stats.total_tsc += tsc_diff;
	if (spdk_unlikely(ctx->stats.min_tsc > tsc_diff))
	{
		ctx->stats.min_tsc = tsc_diff;
	}
	if (spdk_unlikely(ctx->stats.max_tsc < tsc_diff))
	{
		ctx->stats.max_tsc = tsc_diff;
	}

	SPDK_DEBUGLOG(rdma, "rpc_callback iovs=%ld, iovcnt=%d, length=%d\n", (uint64_t)iovs, iovcnt, length);
	/*
	 * is_draining indicates when time has expired for the test run
	 * and we are just waiting for the previously submitted I/O
	 * to complete.  In this case, do not submit a new I/O to replace
	 * the one just completed.
	 */
	if (spdk_unlikely(ctx->is_draining))
	{
		SPDK_NOTICELOG("free task\n");
		spdk_mempool_put(ctx->mp, task->buf);
		free(task);
	}
	else
	{
		spdk_mempool_put(ctx->mp, task->buf);
		nvme_setup_payload(task);
		submit_single_io(task);
	}
}

void submit_single_io(struct perf_task *task)
{
	uint64_t offset_in_ios;
	int rc;
	struct hello_context_t *ctx = task->ctx;

	task->submit_tsc = spdk_get_ticks();

	if (g_submit_type == SPDK_CLIENT_SUBMIT_CONTING)
	{
		rc = spdk_client_submit_rpc_request(ctx->conn, TEST_RAFT_SERVICE, task->buf, g_io_size_bytes, rpc_callback, task, g_chesk_sum);
		if (rc != 0)
		{
			printf("spdk_client_rpc_request_submit failed\n");
			exit(-1);
		}
	}
	else
	{
		rc = spdk_client_submit_rpc_request_iovs(ctx->conn, TEST_RAFT_SERVICE, &task->iov, 1, g_io_size_bytes, rpc_callback, task, g_chesk_sum);
		if (rc != 0)
		{
			printf("spdk_client_rpc_request_submit failed\n");
			exit(-1);
		}
	}
}

static void
submit_io(struct hello_context_t *ctx, int queue_depth)
{
	struct perf_task *task;
	int cnt = 0;
	while (queue_depth-- > 0)
	{
		task = allocate_task(ctx, queue_depth);
		cnt++;
		printf("submit_io times %d\n", cnt);
		submit_single_io(task);
	}
}

static void
print_periodic_performance(struct hello_context_t *ctx)
{
	uint64_t io_this_second;
	double mb_this_second;
	struct worker_thread *worker;
	struct ns_worker_ctx *ns_ctx;
	uint64_t busy_tsc;
	uint64_t idle_tsc;
	uint64_t core_busy_tsc = 0;
	uint64_t core_idle_tsc = 0;
	double core_busy_perc = 0;

	if (!isatty(STDOUT_FILENO))
	{
		/* Don't print periodic stats if output is not going
		 * to a terminal.
		 */
		return;
	}

	io_this_second = 0;

	busy_tsc = 0;
	idle_tsc = 0;

	io_this_second += ctx->stats.io_completed - ctx->stats.last_io_completed;
	ctx->stats.last_io_completed = ctx->stats.io_completed;

	mb_this_second = (double)io_this_second * g_io_size_bytes / (1024 * 1024);

	printf("%9ju IOPS, %8.2f MiB/s", io_this_second, mb_this_second);
	printf("\r");
	fflush(stdout);
}

static uint64_t g_worker_fun_cnt = 0;
static uint64_t g_last_ticks = 0;

static int
rdma_poll(void *arg)
{
	struct hello_context_t *ctx = arg;
	int64_t num_completions;
	uint64_t now, avg_ns;
	if (!g_exit)
	{
		if (g_worker_fun_cnt == 0)
		{
			g_last_ticks = spdk_get_ticks();
		};
		if (g_worker_fun_cnt == 1000000)
		{
			now = spdk_get_ticks();
			avg_ns = (now - g_last_ticks) * SPDK_SEC_TO_NSEC / spdk_get_ticks_hz() / g_worker_fun_cnt;
			// SPDK_ERRLOG("avg_ns = %ld\n", avg_ns);
			g_last_ticks = now;
			g_worker_fun_cnt = 0;
		}
		g_worker_fun_cnt++;
		num_completions = spdk_client_poll_group_process_completions(ctx->pg.group, 0,
																	 client_disconnected_qpair_cb);
	}
	else
	{
		spdk_poller_unregister(&ctx->pg.poller);
		return SPDK_POLLER_IDLE;
	}

	return num_completions > 0 ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
}

static int worker_fun(void *arg)
{
	uint64_t tsc_start, tsc_end, tsc_current, tsc_next_print;
	tsc_start = spdk_get_ticks();
	tsc_current = tsc_start;
	tsc_next_print = tsc_current + g_tsc_rate;
	struct hello_context_t *ctx = arg;
	uint64_t check_now;
	uint32_t unfinished_ns_ctx;
	submit_io(ctx, g_io_depth);
	SPDK_NOTICELOG("outside loop print %ld %ld %ld\n", tsc_start, g_tsc_rate, tsc_next_print);
	while (spdk_likely(!g_exit))
	{
		/*
		 * Check for completed I/O for each controller. A new
		 * I/O will be submitted in the io_complete callback
		 * to replace each I/O that is completed.
		 */
		check_now = spdk_get_ticks();
		ctx->stats.last_tsc = check_now;

		tsc_current = spdk_get_ticks();
		rdma_poll(arg);
		if (tsc_current > tsc_next_print)
		{
			tsc_next_print += g_tsc_rate;
			print_periodic_performance(ctx);
		}
	}

	/* Capture the actual elapsed time when we break out of the main loop. This will account
	 * for cases where we exit prematurely due to a signal. We only need to capture it on
	 * one core, so use the main core.
	 */

	g_elapsed_time_in_usec = (tsc_current - tsc_start) * SPDK_SEC_TO_USEC / g_tsc_rate;

	/* drain the io of each ns_ctx in round robin to make the fairness */
	do
	{
		unfinished_ns_ctx = 0;
		/* first time will enter into this if case */
		if (!ctx->is_draining)
		{
			ctx->is_draining = true;
		}

		if (ctx->current_queue_depth > 0)
		{
			unfinished_ns_ctx++;
		}
		SPDK_NOTICELOG("WAIT IO COMPLETE\n");
	} while (unfinished_ns_ctx > 0);

	print_stats(ctx);
	spdk_poller_unregister(&ctx->poller_out);
	spdk_mempool_free(ctx->mp);
	return 0;
}

static int
hello_rdma_client_init(struct hello_context_t *ctx)
{
	int rc;
	char saddr[ADDR_STR_LEN], caddr[ADDR_STR_LEN];
	uint16_t cport, sport;

	SPDK_NOTICELOG("Connecting to the server on %s:%d with sock_impl(%s)\n", ctx->host, ctx->port,
				   ctx->sock_impl_name);
	rc = spdk_client_transport_id_parse(&ctx->trid, "trtype:RDMA adrfam:IPV4 traddr:172.31.77.144 trsvcid:9999");
	if (rc != 0)
	{
		SPDK_ERRLOG("spdk_client_transport_id_parse() failed, errno %d: %s\n",
					errno, spdk_strerror(errno));
		return -1;
	}
	spdk_client_ctrlr_get_default_ctrlr_opts(&ctx->ops, sizeof(ctx->ops));

	SPDK_NOTICELOG("ctrlr options : io_queue_size %d\n", ctx->ops.io_queue_size);
	ctx->pg.ctrlr = spdk_client_transport_ctrlr_construct(ctx->trid.trstring, &ctx->ops, NULL);
	if (ctx->pg.ctrlr == NULL)
	{
		SPDK_ERRLOG("client_transport_ctrlr_construct() failed, errno %d: %s\n",
					errno, spdk_strerror(errno));
		return -1;
	}
	ctx->pg.group = spdk_client_poll_group_create(&ctx->pg, NULL);
	if (ctx->pg.group == NULL)
	{
		SPDK_ERRLOG("spdk_client_poll_group_create() failed, errno %d: %s\n",
					errno, spdk_strerror(errno));
		return -1;
	}

	ctx->conn = spdk_client_ctrlr_alloc_io_qpair(ctx->pg.ctrlr, NULL, 0, &ctx->trid, ctx->pg.group); // use default conn opts
	if (ctx->conn != NULL)
	{
		g_is_running = true;
	}
	else
	{
		SPDK_ERRLOG("spdk_client_ctrlr_alloc_io_qpair() failed, errno %d: %s\n",
					errno, spdk_strerror(errno));
		return -1;
	}
	ctx->poller_out = SPDK_POLLER_REGISTER(worker_fun, ctx, 0);

	return 0;
}

static void
tgt_add_transport_done(void *cb_arg, int status)
{
	struct hello_context_t *ctx = cb_arg;

	if (status)
	{
		SPDK_ERRLOG("Failed to add transport to tgt.(%d)\n", status);
		spdk_srv_transport_destroy(ctx->transport, NULL, NULL);
		return;
	}
}

void service_finish_cb(void *cb_arg)
{
	assert(cb_arg != NULL);
	free(cb_arg);
}

void service_finish_iov_cb(void *cb_arg)
{
	assert(cb_arg != NULL);
	struct iovec *iov = (struct iovec *)cb_arg;
	free(iov->iov_base);
	free(iov);
}

void loop_delay_us(int duration)
{
	uint64_t tsc, time_out_tsc;
	tsc = spdk_get_ticks();
	time_out_tsc = tsc + spdk_get_ticks_hz() * duration / SPDK_SEC_TO_USEC;
	while (1)
	{
		tsc = spdk_get_ticks();
		if (tsc >= time_out_tsc)
		{
			break;
		}
	}
}

void rpc_dispatcher(uint32_t opc, struct iovec *iovs, int iov_cnt, int length, spdk_srv_rpc_dispatcher_cb cb, void *cb_arg)
{
	void *data;
	switch (opc)
	{
	case TEST_RAFT_SERVICE:
	case TEST_DATA_SERVICE:
		data = calloc(1, 1024);
		(*cb)(cb_arg, 0, data, 1024, service_finish_cb, data);
	default:
		return;
	}
}

void rpc_dispatcher_iovs(uint32_t opc, struct iovec *iovs, int iov_cnt, int length, spdk_srv_rpc_dispatcher_iovs_cb cb, void *cb_arg)
{
	void *data;
	struct iovec *iov;
	switch (opc)
	{
	case TEST_RAFT_SERVICE:
	case TEST_DATA_SERVICE:
		data = calloc(1, g_response_size);
		iov = calloc(1, sizeof(struct iovec));
		iov->iov_base = data;
		iov->iov_len = g_response_size;
		(*cb)(cb_arg, 0, iov, 1, g_response_size, service_finish_iov_cb, iov);
	default:
		return;
	}
}

static int hello_rdma_init(struct hello_context_t *ctx)
{
	struct spdk_srv_target_opts opts = {"test_tgt"};
	struct spdk_srv_transport_id tid = {"test", SPDK_SRV_TRANSPORT_RDMA, SPDK_SRV_ADRFAM_IPV4, "172.31.77.144", "9999", 0};
	ctx->tgt = spdk_srv_tgt_create(&opts);
	spdk_srv_transport_opts_init("RDMA", &ctx->opts, sizeof(ctx->opts));
	ctx->transport = spdk_srv_transport_create(ctx->name, &ctx->opts);
	spdk_srv_tgt_add_transport(ctx->tgt, ctx->transport, tgt_add_transport_done, ctx);
	spdk_srv_rpc_register_dispatcher(rpc_dispatcher, SPDK_CLIENT_SUBMIT_CONTING);
	spdk_srv_rpc_register_dispatcher(rpc_dispatcher_iovs, SPDK_CLIENT_SUBMIT_IOVES);
	int ret = spdk_srv_transport_listen(ctx->transport, &tid, NULL);
	if (ret != 0)
	{
		return -1;
	}
	g_is_running = true;
	return 0;
}

static void
hello_sock_shutdown_cb(void)
{
	g_is_running = false;
}

/*
 * Our initial event that kicks off everything from main().
 */
static void
hello_start(void *arg1)
{
	struct hello_context_t *ctx = arg1;

	int rc;

	SPDK_NOTICELOG("Successfully started the application\n");
	if (ctx->is_server)
	{
		rc = hello_rdma_init(ctx);
	}
	else
	{
		ctx->mp = spdk_mempool_create("rdma",
									  128, /* src + dst */
									  g_size,
									  SPDK_MEMPOOL_DEFAULT_CACHE_SIZE,
									  SPDK_ENV_SOCKET_ID_ANY);
		if (ctx->mp != NULL)
		{
			g_tsc_rate = spdk_get_ticks_hz();
			printf("spdk_get_ticks_hz %ld %ld\n", spdk_get_ticks_hz(), spdk_get_ticks());
			rc = hello_rdma_client_init(ctx);
		}
		else
		{
			SPDK_ERRLOG("ERROR spdk_dma_zmalloc\n");
			rc = 1;
		}
	}

	if (rc)
	{
		spdk_app_stop(-1);
		return;
	}
}

int main(int argc, char **argv)
{
	struct spdk_app_opts opts = {};
	int rc = 0;
	struct hello_context_t hello_context = {};

	/* Set default values in opts structure. */
	spdk_app_opts_init(&opts, sizeof(opts));
	opts.name = "hello_rdma";
	opts.shutdown_cb = hello_sock_shutdown_cb;

	if ((rc = spdk_app_parse_args(argc, argv, &opts, "H:N:P:I:T:t:X:YSV:", NULL, hello_sock_parse_arg,
								  hello_sock_usage)) != SPDK_APP_PARSE_ARGS_SUCCESS)
	{
		exit(rc);
	}
	g_io_size_bytes = g_size;
	hello_context.name = "RDMA";
	hello_context.is_server = g_is_server;
	hello_context.host = g_host;
	hello_context.sock_impl_name = g_sock_impl_name;
	hello_context.port = g_port;
	hello_context.verbose = g_verbose;

	rc = spdk_app_start(&opts, hello_start, &hello_context);
	if (rc)
	{
		SPDK_ERRLOG("ERROR starting application\n");
	}

	SPDK_NOTICELOG("Exiting from application\n");

	if (hello_context.verbose)
	{
		printf("** %d bytes received, %d bytes sent **\n",
			   hello_context.bytes_in, hello_context.bytes_out);
	}

	/* Gracefully close out all of the SPDK subsystems. */
	spdk_app_fini();
	spdk_dma_free(hello_context.buf_out);
	return rc;
}
