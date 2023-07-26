/*
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation. All rights reserved.
 *   Copyright (c) 2020, 2021 Mellanox Technologies LTD. All rights reserved.
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

#ifndef __CLIENT_INTERNAL_H__
#define __CLIENT_INTERNAL_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "spdk/config.h"
#include "spdk/likely.h"
#include "spdk/stdinc.h"

#if defined(__i386__) || defined(__x86_64__)
#include <x86intrin.h>
#endif

#include "spdk/queue.h"
#include "spdk/barrier.h"
#include "spdk/bit_array.h"
#include "spdk/mmio.h"
#include "spdk/pci_ids.h"
#include "spdk/util.h"
#include "spdk/memory.h"
#include "spdk/tree.h"
#include "spdk/uuid.h"

#include "spdk/log.h"
#include "spdk/rdma_client.h"

extern pid_t g_spdk_client_pid;

#define SPDK_CLIENT_MAX_IO_QUEUES (65535)

#define SPDK_CLIENT_IO_QUEUE_MIN_ENTRIES 2
#define SPDK_CLIENT_IO_QUEUE_MAX_ENTRIES 65536

enum spdk_client_sgl_descriptor_type
{
	SPDK_CLIENT_SGL_TYPE_DATA_BLOCK = 0x0,
	SPDK_CLIENT_SGL_TYPE_BIT_BUCKET = 0x1,
	SPDK_CLIENT_SGL_TYPE_SEGMENT = 0x2,
	SPDK_CLIENT_SGL_TYPE_LAST_SEGMENT = 0x3,
	SPDK_CLIENT_SGL_TYPE_KEYED_DATA_BLOCK = 0x4,
	SPDK_CLIENT_SGL_TYPE_TRANSPORT_DATA_BLOCK = 0x5,
	/* 0x6 - 0xE reserved */
	SPDK_CLIENT_SGL_TYPE_VENDOR_SPECIFIC = 0xF
};

enum spdk_client_sgl_descriptor_subtype
{
	SPDK_CLIENT_SGL_SUBTYPE_ADDRESS = 0x0,
	SPDK_CLIENT_SGL_SUBTYPE_OFFSET = 0x1,
	SPDK_CLIENT_SGL_SUBTYPE_TRANSPORT = 0xa,
};

enum spdk_client_psdt_value
{
	SPDK_CLIENT_PSDT_PRP = 0x0,
	SPDK_CLIENT_PSDT_SGL_MPTR_CONTIG = 0x1,
	SPDK_CLIENT_PSDT_SGL_MPTR_SGL = 0x2,
	SPDK_CLIENT_PSDT_RESERVED = 0x3
};

enum spdk_client_data_transfer
{
	/** Opcode does not transfer data */
	SPDK_CLIENT_DATA_NONE = 0,
	/** Opcode transfers data from host to controller (e.g. Write) */
	SPDK_CLIENT_DATA_HOST_TO_CONTROLLER = 1,
	/** Opcode transfers data from controller to host (e.g. Read) */
	SPDK_CLIENT_DATA_CONTROLLER_TO_HOST = 2,
	/** Opcode transfers data both directions */
	SPDK_CLIENT_DATA_BIDIRECTIONAL = 3
};

/*
 * CLIENT_MAX_IO_QUEUES in client_spec.h defines the 64K spec-limit, but this
 *  define specifies the maximum number of queues this driver will actually
 *  try to configure, if available.
 */
#define DEFAULT_MAX_IO_QUEUES (1024)
#define DEFAULT_IO_QUEUE_SIZE (128)
#define DEFAULT_IO_QUEUE_SIZE_FOR_QUIRK (1024) /* Matches Linux kernel driver */

#define DEFAULT_IO_QUEUE_REQUESTS (4096)

#define DEFAULT_SECTOR_SIZE (512)

#define DEFAULT_SECTORS_PER_MAX_IO (256)

#define DEFAULT_SECTORS_PER_STRIPE (0)

#define DEFAULT_EXTENDED_LBA_SIZE (0)

#define DEFAULT_MD_SIZE (0)

#define SPDK_CLIENT_DEFAULT_RETRY_COUNT (4)

#define SPDK_CLIENT_TRANSPORT_ACK_TIMEOUT_DISABLED (0)
#define SPDK_CLIENT_DEFAULT_TRANSPORT_ACK_TIMEOUT SPDK_CLIENT_TRANSPORT_ACK_TIMEOUT_DISABLED

/* We want to fit submission and completion rings each in a single 2MB
 * hugepage to ensure physical address contiguity.
 */
#define MAX_IO_QUEUE_ENTRIES (VALUE_2MB / spdk_max(                            \
											  sizeof(struct spdk_rpc_req_cmd), \
											  sizeof(struct spdk_rpc_req_cpl)))

/* Default timeout for fabrics connect commands. */
#ifdef DEBUG
#define CLIENT_FABRIC_CONNECT_COMMAND_TIMEOUT 0
#else
/* 500 millisecond timeout. */
#define CLIENT_FABRIC_CONNECT_COMMAND_TIMEOUT 500000
#endif

/* This value indicates that a read from a PCIe register is invalid. This can happen when a device is no longer present */
#define SPDK_CLIENT_INVALID_REGISTER_VALUE 0xFFFFFFFFu

enum client_payload_type
{
	CLIENT_PAYLOAD_TYPE_INVALID = 0,

	/** client_request::u.payload.contig_buffer is valid for this request */
	CLIENT_PAYLOAD_TYPE_CONTIG,

	/** client_request::u.sgl is valid for this request */
	CLIENT_PAYLOAD_TYPE_SGL,
};

/**
 * Descriptor for a request data payload.
 */
struct client_payload
{
	/**
	 * Functions for retrieving physical addresses for scattered payloads.
	 */
	spdk_client_req_reset_sgl_cb reset_sgl_fn;
	spdk_client_req_next_sge_cb next_sge_fn;

	/**
	 * If reset_sgl_fn == NULL, this is a contig payload, and contig_or_cb_arg contains the
	 * virtual memory address of a single virtually contiguous buffer.
	 *
	 * If reset_sgl_fn != NULL, this is a SGL payload, and contig_or_cb_arg contains the
	 * cb_arg that will be passed to the SGL callback functions.
	 */
	void *contig_or_cb_arg;

	/** Virtual memory address of a single virtually contiguous metadata buffer */
	void *md;

	// used for rpc write/read
	uint32_t rpc_request_id;
	uint32_t data_length;
	uint32_t rpc_opc;
	uint32_t submit_type;
	uint8_t *md5sum;
};

#define CLIENT_PAYLOAD_CONTIG(contig_, md_) \
(struct client_payload)                     \
{                                           \
	.reset_sgl_fn = NULL,                   \
	.next_sge_fn = NULL,                    \
	.contig_or_cb_arg = (contig_),          \
	.md = (md_),                            \
}

#define CLIENT_PAYLOAD_SGL(reset_sgl_fn_, next_sge_fn_, cb_arg_, md_, rpc_request_id_, data_length_, rpc_opc_, submit_type_, md5sum_) \
(struct client_payload)                                                                                                               \
{                                                                                                                                     \
	.reset_sgl_fn = (reset_sgl_fn_),                                                                                                  \
	.next_sge_fn = (next_sge_fn_),                                                                                                    \
	.contig_or_cb_arg = (cb_arg_),                                                                                                    \
	.md = (md_),                                                                                                                      \
	.rpc_request_id = (rpc_request_id_),                                                                                              \
	.data_length = (data_length_),                                                                                                    \
	.rpc_opc = (rpc_opc_),                                                                                                            \
	.submit_type = (submit_type_),                                                                                                    \
	.md5sum = (md5sum_),                                                                                                              \
}

static inline enum client_payload_type
client_payload_type(const struct client_payload *payload)
{
	return payload->reset_sgl_fn ? CLIENT_PAYLOAD_TYPE_SGL : CLIENT_PAYLOAD_TYPE_CONTIG;
}

struct client_error_cmd
{
	bool do_not_submit;
	uint64_t timeout_tsc;
	uint32_t err_count;
	uint8_t opc;
	struct spdk_req_status status;
	TAILQ_ENTRY(client_error_cmd)
	link;
};

struct client_request
{
	struct spdk_rpc_req_cmd cmd;

	uint8_t retries;

	uint8_t timed_out : 1;

	/**
	 * True if the request is in the queued_req list.
	 */
	uint8_t queued : 1;
	uint8_t reserved : 6;

	/**
	 * Number of children requests still outstanding for this
	 *  request which was split into multiple child requests.
	 */
	uint16_t num_children;

	/**
	 * Offset in bytes from the beginning of payload for this request.
	 * This is used for I/O commands that are split into multiple requests.
	 */
	uint32_t payload_offset;

	uint32_t payload_size;

	/**
	 * Timeout ticks for error injection requests, can be extended in future
	 * to support per-request timeout feature.
	 */
	uint64_t timeout_tsc;

	/**
	 * Data payload for this request's command.
	 */
	struct client_payload payload;

	spdk_req_cmd_cb cb_fn;
	void *cb_arg;
	STAILQ_ENTRY(client_request)
	stailq;

	struct spdk_client_qpair *qpair;

	/*
	 * The value of spdk_get_ticks() when the request was submitted to the hardware.
	 * Only set if ctrlr->timeout_enabled is true.
	 */
	uint64_t submit_tick;

	/**
	 * The active admin request can be moved to a per process pending
	 *  list based on the saved pid to tell which process it belongs
	 *  to. The cpl saves the original completion information which
	 *  is used in the completion callback.
	 * NOTE: these below two fields are only used for admin request.
	 */
	pid_t pid;
	struct spdk_rpc_req_cpl cpl;

	/**
	 * The following members should not be reordered with members
	 *  above.  These members are only needed when splitting
	 *  requests which is done rarely, and the driver is careful
	 *  to not touch the following fields until a split operation is
	 *  needed, to avoid touching an extra cacheline.
	 */

	/**
	 * Points to the outstanding child requests for a parent request.
	 *  Only valid if a request was split into multiple children
	 *  requests, and is not initialized for non-split requests.
	 */
	TAILQ_HEAD(, client_request)
	children;

	/**
	 * Linked-list pointers for a child request in its parent's list.
	 */
	TAILQ_ENTRY(client_request)
	child_tailq;

	/**
	 * Points to a parent request if part of a split request,
	 *   NULL otherwise.
	 */
	struct client_request *parent;

	/**
	 * Completion status for a parent request.  Initialized to all 0's
	 *  (SUCCESS) before child requests are submitted.  If a child
	 *  request completes with error, the error status is copied here,
	 *  to ensure that the parent request is also completed with error
	 *  status once all child requests are completed.
	 */
	struct spdk_rpc_req_cpl parent_status;

	/**
	 * The user_cb_fn and user_cb_arg fields are used for holding the original
	 * callback data when using client_allocate_request_user_copy.
	 */
	spdk_req_cmd_cb user_cb_fn;
	void *user_cb_arg;
	void *user_buffer;
};

struct client_completion_poll_status
{
	struct spdk_rpc_req_cpl cpl;
	uint64_t timeout_tsc;
	/**
	 * DMA buffer retained throughout the duration of the command.  It'll be released
	 * automatically if the command times out, otherwise the user is responsible for freeing it.
	 */
	void *dma_data;
	bool done;
	/* This flag indicates that the request has been timed out and the memory
	   must be freed in a completion callback */
	bool timed_out;
};

enum client_qpair_state
{
	CLIENT_QPAIR_DISCONNECTED,
	CLIENT_QPAIR_DISCONNECTING,
	CLIENT_QPAIR_CONNECTING,
	CLIENT_QPAIR_CONNECTED,
	CLIENT_QPAIR_ENABLED,
	CLIENT_QPAIR_DESTROYING,
};

struct spdk_client_qpair
{
	struct spdk_client_ctrlr *ctrlr;

	spdk_connected_cb cb;
	void *cb_args;
	uint16_t id;

	uint8_t qprio;

	uint8_t state : 3;

	uint8_t async : 1;

	uint8_t is_new_qpair : 1;

	/*
	 * Members for handling IO qpair deletion inside of a completion context.
	 * These are specifically defined as single bits, so that they do not
	 *  push this data structure out to another cacheline.
	 */
	uint8_t in_completion_context : 1;
	uint8_t delete_after_completion_context : 1;

	/*
	 * Set when no deletion notification is needed. For example, the process
	 * which allocated this qpair exited unexpectedly.
	 */
	uint8_t no_deletion_notification_needed : 1;

	uint8_t last_fuse : 2;

	uint8_t transport_failure_reason : 2;
	uint8_t last_transport_failure_reason : 2;

	enum spdk_client_transport_type trtype;

	/* request object used only for this qpair's FABRICS/CONNECT command (if needed) */
	struct client_request *reserved_req;

	STAILQ_HEAD(, rpc_request)
	free_rpc_req;

	STAILQ_HEAD(, client_request)
	free_req;
	STAILQ_HEAD(, client_request)
	queued_req;

	/* List entry for spdk_client_transport_poll_group::qpairs */
	STAILQ_ENTRY(spdk_client_qpair)
	poll_group_stailq;

	/** Commands opcode in this list will return error */
	TAILQ_HEAD(, client_error_cmd)
	err_cmd_head;
	/** Requests in this list will return error */
	STAILQ_HEAD(, client_request)
	err_req_head;

	struct spdk_client_ctrlr_process *active_proc;

	struct spdk_client_transport_poll_group *poll_group;

	void *poll_group_tailq_head;

	const struct spdk_client_transport *transport;

	/* Entries below here are not touched in the main I/O path. */

	struct client_completion_poll_status *poll_status;

	/* List entry for spdk_client_ctrlr::active_io_qpairs */
	TAILQ_ENTRY(spdk_client_qpair)
	tailq;

	/* List entry for spdk_client_ctrlr_process::allocated_io_qpairs */
	TAILQ_ENTRY(spdk_client_qpair)
	per_process_tailq;

	STAILQ_HEAD(, client_request)
	aborting_queued_req;

	void *req_buf;
	void *rpc_req_buf;
	struct spdk_client_transport_id *trid;
};

struct spdk_client_poll_group
{
	void *ctx;
	STAILQ_HEAD(, spdk_client_transport_poll_group)
	tgroups;
};

struct spdk_client_transport_poll_group
{
	struct spdk_client_poll_group *group;
	const struct spdk_client_transport *transport;
	STAILQ_HEAD(, spdk_client_qpair)
	connected_qpairs;
	STAILQ_HEAD(, spdk_client_qpair)
	disconnected_qpairs;
	STAILQ_ENTRY(spdk_client_transport_poll_group)
	link;
	bool in_completion_context;
	uint64_t num_qpairs_to_delete;
};

#define SPDK_CLIENT_SC_SUCCESS 0x0
#define SPDK_CLIENT_SCT_GENERIC 0x1
#define SPDK_CLIENT_SC_QUEUE_ABORTED 0x2

#define spdk_req_cpl_is_error(cpl) \
((cpl)->status.sc != SPDK_CLIENT_SC_SUCCESS)

#define spdk_req_cpl_is_success(cpl) (!spdk_req_cpl_is_error(cpl))

#define spdk_req_cpl_is_abort_success(cpl) \
(spdk_req_cpl_is_success(cpl) && !((cpl)->cdw0 & 1U))

#define spdk_req_cpl_is_path_error(cpl) \
((cpl)->status.sct == SPDK_CLIENT_SCT_PATH)

#define spdk_req_cpl_is_ana_error(cpl)                                    \
((cpl)->status.sct == SPDK_CLIENT_SCT_PATH &&                             \
 ((cpl)->status.sc == SPDK_CLIENT_SC_ASYMMETRIC_ACCESS_PERSISTENT_LOSS || \
  (cpl)->status.sc == SPDK_CLIENT_SC_ASYMMETRIC_ACCESS_INACCESSIBLE ||    \
  (cpl)->status.sc == SPDK_CLIENT_SC_ASYMMETRIC_ACCESS_TRANSITION))

#define spdk_req_cpl_is_aborted_sq_deletion(cpl) \
((cpl)->status.sct == SPDK_CLIENT_SCT_GENERIC && \
 (cpl)->status.sc == SPDK_CLIENT_SC_ABORTED_SQ_DELETION)

#define spdk_req_cpl_is_aborted_by_request(cpl)  \
((cpl)->status.sct == SPDK_CLIENT_SCT_GENERIC && \
 (cpl)->status.sc == SPDK_CLIENT_SC_ABORTED_BY_REQUEST)

#define CLIENT_TIMEOUT_INFINITE 0
#define CLIENT_TIMEOUT_KEEP_EXISTING UINT64_MAX

/*
 * Used to track properties for all processes accessing the controller.
 */
struct spdk_client_ctrlr_process
{
	/** Whether it is the primary process  */
	bool is_primary;

	/** Process ID */
	pid_t pid;

	/** Active admin requests to be completed */
	STAILQ_HEAD(, client_request)
	active_reqs;

	TAILQ_ENTRY(spdk_client_ctrlr_process)
	tailq;

	/** Per process PCI device handle */
	struct spdk_pci_device *devhandle;

	/** Reference to track the number of attachment to this controller. */
	int ref;

	/** Allocated IO qpairs */
	TAILQ_HEAD(, spdk_client_qpair)
	allocated_io_qpairs;

	void *timeout_cb_arg;
	/** separate timeout values for io vs. admin reqs */
	uint64_t timeout_io_ticks;
};

#define SPDK_CLIENT_MAX_OPC 0xff

/*
 * One of these per allocated PCI device.
 */
struct spdk_client_ctrlr
{
	bool is_removed;

	bool is_resetting;

	bool is_failed;

	bool is_destructed;

	bool timeout_enabled;

	/* The application is preparing to reset the controller.  Transports
	 * can use this to skip unnecessary parts of the qpair deletion process
	 * for example, like the DELETE_SQ/CQ commands.
	 */
	bool prepare_for_reset;

	uint16_t max_sges;

	uint16_t cntlid;

	/** Controller support flags */
	uint64_t flags;

	/** CLIENToF in-capsule data size in bytes */
	uint32_t ioccsz_bytes;

	/** CLIENToF in-capsule data offset in 16 byte units */
	uint16_t icdoff;

	char trstring[SPDK_SRV_TRSTRING_MAX_LEN + 1];
	enum spdk_client_transport_type trtype;

	int state;

	TAILQ_ENTRY(spdk_client_ctrlr)
	tailq;

	/** selected memory page size for this controller in bytes */
	uint32_t page_size;

	/** guards access to the controller itself, including admin queues */
	pthread_mutex_t ctrlr_lock;

	struct spdk_bit_array *free_io_qids;
	TAILQ_HEAD(, spdk_client_qpair)
	active_io_qpairs;
	STAILQ_HEAD(, rpc_request)
	pending_rpc_requests;

	struct spdk_client_ctrlr_opts opts;

	/* Extra sleep time during controller initialization */
	uint64_t sleep_timeout_tsc;

	/** Track all the processes manage this controller */
	TAILQ_HEAD(, spdk_client_ctrlr_process)
	active_procs;

	STAILQ_HEAD(, client_request)
	queued_aborts;
	uint32_t outstanding_aborts;

	void *cb_ctx;

	/* scratchpad pointer that can be used to send data between two CLIENT_CTRLR_STATEs */
	void *tmp_ptr;

	/* maximum zone append size in bytes */
	uint32_t max_zone_append_size;

	struct spdk_mempool *rpc_data_mp;
	uint32_t io_unit_size;
};

typedef void (*client_ctrlr_detach_cb)(struct spdk_client_ctrlr *ctrlr);

enum client_ctrlr_detach_state
{
	CLIENT_CTRLR_DETACH_SET_CC,
	CLIENT_CTRLR_DETACH_CHECK_CSTS,
	CLIENT_CTRLR_DETACH_GET_CSTS,
	CLIENT_CTRLR_DETACH_GET_CSTS_DONE,
};

struct client_ctrlr_detach_ctx
{
	struct spdk_client_ctrlr *ctrlr;
	client_ctrlr_detach_cb cb_fn;
	uint64_t shutdown_start_tsc;
	uint32_t shutdown_timeout_ms;
	bool shutdown_complete;
	enum client_ctrlr_detach_state state;
	TAILQ_ENTRY(client_ctrlr_detach_ctx)
	link;
};

struct client_driver
{
	pthread_mutex_t lock;

	/** Multi-process shared attached controller list */
	TAILQ_HEAD(, spdk_client_ctrlr)
	shared_attached_ctrlrs;

	bool initialized;
	struct spdk_uuid default_extended_host_id;

	/** netlink socket fd for hotplug messages */
	int hotplug_fd;
};

#define client_delay usleep

/**
 * Extract the Data Transfer bits from an Client opcode.
 *
 * This determines whether a command requires a data buffer and
 * which direction (host to controller or controller to host) it is
 * transferred.
 */
static inline enum spdk_client_data_transfer spdk_client_opc_get_data_transfer(uint8_t opc)
{
	return (enum spdk_client_data_transfer)(opc & 3);
}

static inline int
client_robust_mutex_lock(pthread_mutex_t *mtx)
{
	int rc = pthread_mutex_lock(mtx);

#ifndef __FreeBSD__
	if (rc == EOWNERDEAD)
	{
		rc = pthread_mutex_consistent(mtx);
	}
#endif

	return rc;
}

static inline int
client_robust_mutex_unlock(pthread_mutex_t *mtx)
{
	return pthread_mutex_unlock(mtx);
}

/* Poll group management functions. */
int client_poll_group_connect_qpair(struct spdk_client_qpair *qpair);
int client_poll_group_disconnect_qpair(struct spdk_client_qpair *qpair);

struct spdk_client_ctrlr_process *client_ctrlr_get_process(struct spdk_client_ctrlr *ctrlr,
														   pid_t pid);
struct spdk_client_ctrlr_process *client_ctrlr_get_current_process(struct spdk_client_ctrlr *ctrlr);
int client_ctrlr_add_process(struct spdk_client_ctrlr *ctrlr, void *devhandle);

int client_ctrlr_construct(struct spdk_client_ctrlr *ctrlr);
void client_ctrlr_destruct_finish(struct spdk_client_ctrlr *ctrlr);
void client_ctrlr_destruct(struct spdk_client_ctrlr *ctrlr);
void client_ctrlr_destruct_async(struct spdk_client_ctrlr *ctrlr,
								 struct client_ctrlr_detach_ctx *ctx);
int client_ctrlr_destruct_poll_async(struct spdk_client_ctrlr *ctrlr,
									 struct client_ctrlr_detach_ctx *ctx);
void client_ctrlr_fail(struct spdk_client_ctrlr *ctrlr, bool hot_remove);

void client_ctrlr_process_async_event(struct spdk_client_ctrlr *ctrlr,
									  const struct spdk_rpc_req_cpl *cpl);
void client_ctrlr_disconnect_qpair(struct spdk_client_qpair *qpair);
int client_qpair_init(struct spdk_client_qpair *qpair, uint16_t id,
					  struct spdk_client_ctrlr *ctrlr,
					  enum spdk_client_qprio qprio,
					  uint32_t num_requests, bool async);
void client_qpair_deinit(struct spdk_client_qpair *qpair);
void client_qpair_complete_error_reqs(struct spdk_client_qpair *qpair);
int client_qpair_submit_request(struct spdk_client_qpair *qpair,
								struct client_request *req);
void client_qpair_abort_all_queued_reqs(struct spdk_client_qpair *qpair, uint32_t dnr);
uint32_t client_qpair_abort_queued_reqs_with_cbarg(struct spdk_client_qpair *qpair, void *cmd_cb_arg);
void client_qpair_abort_queued_reqs(struct spdk_client_qpair *qpair, uint32_t dnr);
void client_qpair_resubmit_requests(struct spdk_client_qpair *qpair, uint32_t num_requests);

#define CLIENT_INIT_REQUEST(req, _cb_fn, _cb_arg, _payload, _payload_size) \
do                                                                         \
{                                                                          \
	req->cb_fn = _cb_fn;                                                   \
	req->cb_arg = _cb_arg;                                                 \
	req->payload = _payload;                                               \
	req->payload_size = _payload_size;                                     \
	req->pid = g_spdk_client_pid;                                          \
	req->submit_tick = 0;                                                  \
} while (0);

static inline struct client_request *
client_allocate_request(struct spdk_client_qpair *qpair,
						const struct client_payload *payload, uint32_t payload_size,
						spdk_req_cmd_cb cb_fn, void *cb_arg)
{
	struct client_request *req;

	req = STAILQ_FIRST(&qpair->free_req);
	if (req == NULL)
	{
		return req;
	}

	STAILQ_REMOVE_HEAD(&qpair->free_req, stailq);

	/*
	 * Only memset/zero fields that need it.  All other fields
	 *  will be initialized appropriately either later in this
	 *  function, or before they are needed later in the
	 *  submission patch.  For example, the children
	 *  TAILQ_ENTRY and following members are
	 *  only used as part of I/O splitting so we avoid
	 *  memsetting them until it is actually needed.
	 *  They will be initialized in client_request_add_child()
	 *  if the request is split.
	 */
	memset(req, 0, offsetof(struct client_request, payload_size));

	CLIENT_INIT_REQUEST(req, cb_fn, cb_arg, *payload, payload_size);

	return req;
}

static inline struct client_request *
client_allocate_request_contig(struct spdk_client_qpair *qpair,
							   void *buffer, uint32_t payload_size,
							   spdk_req_cmd_cb cb_fn, void *cb_arg)
{
	struct client_payload payload;

	payload = CLIENT_PAYLOAD_CONTIG(buffer, NULL);

	return client_allocate_request(qpair, &payload, payload_size, cb_fn, cb_arg);
}

static inline struct client_request *
client_allocate_request_null(struct spdk_client_qpair *qpair, spdk_req_cmd_cb cb_fn, void *cb_arg)
{
	return client_allocate_request_contig(qpair, NULL, 0, cb_fn, cb_arg);
}

static inline void
client_complete_request(spdk_req_cmd_cb cb_fn, void *cb_arg, struct spdk_client_qpair *qpair,
						struct client_request *req, struct spdk_rpc_req_cpl *cpl)
{
	struct spdk_rpc_req_cpl err_cpl;
	struct client_error_cmd *cmd;

	/* error injection at completion path,
	 * only inject for successful completed commands
	 */
	if (spdk_unlikely(!TAILQ_EMPTY(&qpair->err_cmd_head) &&
					  !spdk_req_cpl_is_error(cpl)))
	{
		TAILQ_FOREACH(cmd, &qpair->err_cmd_head, link)
		{

			if (cmd->do_not_submit)
			{
				continue;
			}

			if ((cmd->opc == req->cmd.opc) && cmd->err_count)
			{

				err_cpl = *cpl;
				err_cpl.status.sct = cmd->status.sct;
				err_cpl.status.sc = cmd->status.sc;

				cpl = &err_cpl;
				cmd->err_count--;
				break;
			}
		}
	}

	if (cb_fn)
	{
		cb_fn(cb_arg, cpl);
	}
}

static inline void
client_free_request(struct client_request *req)
{
	assert(req != NULL);
	assert(req->num_children == 0);
	assert(req->qpair != NULL);

	/* The reserved_req does not go in the free_req STAILQ - it is
	 * saved only for use with a FABRICS/CONNECT command.
	 */
	if (spdk_likely(req->qpair->reserved_req != req))
	{
		STAILQ_INSERT_HEAD(&req->qpair->free_req, req, stailq);
	}
}

static inline void
client_qpair_set_state(struct spdk_client_qpair *qpair, enum client_qpair_state state)
{
	qpair->state = state;
	if (state == CLIENT_QPAIR_ENABLED)
	{
		qpair->is_new_qpair = false;
	}
}

static inline enum client_qpair_state
client_qpair_get_state(struct spdk_client_qpair *qpair)
{
	return qpair->state;
}

static inline void
client_qpair_free_request(struct spdk_client_qpair *qpair, struct client_request *req)
{
	assert(req != NULL);
	assert(req->num_children == 0);

	STAILQ_INSERT_HEAD(&qpair->free_req, req, stailq);
}

static inline void
client_request_remove_child(struct client_request *parent, struct client_request *child)
{
	assert(parent != NULL);
	assert(child != NULL);
	assert(child->parent == parent);
	assert(parent->num_children != 0);

	parent->num_children--;
	child->parent = NULL;
	TAILQ_REMOVE(&parent->children, child, child_tailq);
}

static inline void
client_cb_complete_child(void *child_arg, const struct spdk_rpc_req_cpl *cpl)
{
	struct client_request *child = child_arg;
	struct client_request *parent = child->parent;

	client_request_remove_child(parent, child);

	memcpy(&parent->parent_status, cpl, sizeof(*cpl));

	if (parent->num_children == 0)
	{
		client_complete_request(parent->cb_fn, parent->cb_arg, parent->qpair,
								parent, &parent->parent_status);
		client_free_request(parent);
	}
}

static inline void
client_request_add_child(struct client_request *parent, struct client_request *child)
{
	assert(parent->num_children != UINT16_MAX);

	if (parent->num_children == 0)
	{
		/*
		 * Defer initialization of the children TAILQ since it falls
		 *  on a separate cacheline.  This ensures we do not touch this
		 *  cacheline except on request splitting cases, which are
		 *  relatively rare.
		 */
		TAILQ_INIT(&parent->children);
		parent->parent = NULL;
		memset(&parent->parent_status, 0, sizeof(struct spdk_rpc_req_cpl));
	}

	parent->num_children++;
	TAILQ_INSERT_TAIL(&parent->children, child, child_tailq);
	child->parent = parent;
	child->cb_fn = client_cb_complete_child;
	child->cb_arg = child;
}

static inline void
client_request_free_children(struct client_request *req)
{
	struct client_request *child, *tmp;

	if (req->num_children == 0)
	{
		return;
	}

	/* free all child client_request */
	TAILQ_FOREACH_SAFE(child, &req->children, child_tailq, tmp)
	{
		client_request_remove_child(req, child);
		client_request_free_children(child);
		client_free_request(child);
	}
}

int client_request_check_timeout(struct client_request *req, uint16_t cid,
								 struct spdk_client_ctrlr_process *active_proc, uint64_t now_tick);

int client_robust_mutex_init_shared(pthread_mutex_t *mtx);
int client_robust_mutex_init_recursive_shared(pthread_mutex_t *mtx);

const struct spdk_client_transport *client_get_transport(const char *transport_name);
const struct spdk_client_transport *client_get_first_transport(void);
const struct spdk_client_transport *client_get_next_transport(const struct spdk_client_transport
																  *transport);

/* Transport specific functions */
struct spdk_client_ctrlr *client_transport_ctrlr_construct(const char *trstring,
														   const struct spdk_client_ctrlr_opts *opts,
														   void *devhandle);
int client_transport_ctrlr_destruct(struct spdk_client_ctrlr *ctrlr);

uint16_t client_transport_ctrlr_get_max_sges(struct spdk_client_ctrlr *ctrlr);
struct spdk_client_qpair *client_transport_ctrlr_create_io_qpair(struct spdk_client_ctrlr *ctrlr,
																 uint16_t qid, const struct spdk_client_io_qpair_opts *opts);

void client_transport_ctrlr_delete_io_qpair(struct spdk_client_ctrlr *ctrlr,
											struct spdk_client_qpair *qpair);
int client_transport_ctrlr_connect_qpair(struct spdk_client_ctrlr *ctrlr,
										 struct spdk_client_qpair *qpair);
int client_transport_ctrlr_connect_qpair_async(struct spdk_client_ctrlr *ctrlr,
											   struct spdk_client_qpair *qpair);
void client_transport_ctrlr_disconnect_qpair(struct spdk_client_ctrlr *ctrlr,
											 struct spdk_client_qpair *qpair);
int client_transport_qpair_reset(struct spdk_client_qpair *qpair);
int client_transport_qpair_submit_request(struct spdk_client_qpair *qpair, struct client_request *req);
int32_t client_transport_qpair_process_completions(struct spdk_client_qpair *qpair,
												   uint32_t max_completions);
struct spdk_client_transport_poll_group *client_transport_poll_group_create(
	const struct spdk_client_transport *transport);
struct spdk_client_transport_poll_group *client_transport_qpair_get_optimal_poll_group(
	const struct spdk_client_transport *transport,
	struct spdk_client_qpair *qpair);
int client_transport_poll_group_add(struct spdk_client_transport_poll_group *tgroup,
									struct spdk_client_qpair *qpair);
int client_transport_poll_group_remove(struct spdk_client_transport_poll_group *tgroup,
									   struct spdk_client_qpair *qpair);
int client_transport_poll_group_disconnect_qpair(struct spdk_client_qpair *qpair);
int client_transport_poll_group_connect_qpair(struct spdk_client_qpair *qpair);
int64_t client_transport_poll_group_process_completions(struct spdk_client_transport_poll_group *tgroup,
														uint32_t completions_per_qpair, spdk_client_disconnected_qpair_cb disconnected_qpair_cb);
int client_transport_poll_group_destroy(struct spdk_client_transport_poll_group *tgroup);
int client_transport_poll_group_get_stats(struct spdk_client_transport_poll_group *tgroup,
										  struct spdk_client_transport_poll_group_stat **stats);
void client_transport_poll_group_free_stats(struct spdk_client_transport_poll_group *tgroup,
											struct spdk_client_transport_poll_group_stat *stats);
enum spdk_client_transport_type client_transport_get_trtype(const struct spdk_client_transport
																*transport);

#ifdef __cplusplus
}
#endif

#endif /* __CLIENT_INTERNAL_H__ */
