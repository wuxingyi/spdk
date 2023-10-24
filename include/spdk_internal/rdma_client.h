/*-
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
 * Some Intel devices support vendor-unique read latency log page even
 * though the log page directory says otherwise.
 */
#define CLIENT_INTEL_QUIRK_READ_LATENCY 0x1

/*
 * Some Intel devices support vendor-unique write latency log page even
 * though the log page directory says otherwise.
 */
#define CLIENT_INTEL_QUIRK_WRITE_LATENCY 0x2

/*
 * The controller needs a delay before starts checking the device
 * readiness, which is done by reading the CLIENT_CSTS_RDY bit.
 */
#define CLIENT_QUIRK_DELAY_BEFORE_CHK_RDY 0x4

/*
 * The controller performs best when I/O is split on particular
 * LBA boundaries.
 */
#define CLIENT_INTEL_QUIRK_STRIPING 0x8

/*
 * The controller needs a delay after allocating an I/O queue pair
 * before it is ready to accept I/O commands.
 */
#define CLIENT_QUIRK_DELAY_AFTER_QUEUE_ALLOC 0x10

/*
 * Earlier Client devices do not indicate whether unmapped blocks
 * will read all zeroes or not. This define indicates that the
 * device does in fact read all zeroes after an unmap event
 */
#define CLIENT_QUIRK_READ_ZERO_AFTER_DEALLOCATE 0x20

/*
 * The controller doesn't handle Identify value others than 0 or 1 correctly.
 */
#define CLIENT_QUIRK_IDENTIFY_CNS 0x40

/*
 * The controller supports Open Channel command set if matching additional
 * condition, like the first byte (value 0x1) in the vendor specific
 * bits of the namespace identify structure is set.
 */
#define CLIENT_QUIRK_OCSSD 0x80

/*
 * The controller has an Intel vendor ID but does not support Intel vendor-specific
 * log pages.  This is primarily for QEMU emulated SSDs which report an Intel vendor
 * ID but do not support these log pages.
 */
#define CLIENT_INTEL_QUIRK_NO_LOG_PAGES 0x100

/*
 * The controller does not set SHST_COMPLETE in a reasonable amount of time.  This
 * is primarily seen in virtual VMWare Client SSDs.  This quirk merely adds an additional
 * error message that on VMWare Client SSDs, the shutdown timeout may be expected.
 */
#define CLIENT_QUIRK_SHST_COMPLETE 0x200

/*
 * The controller requires an extra delay before starting the initialization process
 * during attach.
 */
#define CLIENT_QUIRK_DELAY_BEFORE_INIT 0x400

/*
 * Some SSDs exhibit poor performance with the default SPDK Client IO queue size.
 * This quirk will increase the default to 1024 which matches other operating
 * systems, at the cost of some extra memory usage.  Users can still override
 * the increased default by changing the spdk_client_io_qpair_opts when allocating
 * a new queue pair.
 */
#define CLIENT_QUIRK_MINIMUM_IO_QUEUE_SIZE 0x800

/**
 * The maximum access width to PCI memory space is 8 Bytes, don't use AVX2 or
 * SSE instructions to optimize the memory access(memcpy or memset) larger than
 * 8 Bytes.
 */
#define CLIENT_QUIRK_MAXIMUM_PCI_ACCESS_WIDTH 0x1000

/**
 * The SSD does not support OPAL even through it sets the security bit in OACS.
 */
#define CLIENT_QUIRK_OACS_SECURITY 0x2000

/**
 * Intel P55XX SSDs can't support Dataset Management command with SGL format,
 * so use PRP with DSM command.
 */
#define CLIENT_QUIRK_NO_SGL_FOR_DSM 0x4000

/**
 * Maximum Data Transfer Size(MDTS) excludes interleaved metadata.
 */
#define CLIENT_QUIRK_MDTS_EXCLUDE_MD 0x8000

#define CLIENT_MAX_ASYNC_EVENTS (8)

#define CLIENT_MAX_ADMIN_TIMEOUT_IN_SECS (30)

/* Maximum log page size to fetch for AERs. */
#define CLIENT_MAX_AER_LOG_SIZE (4096)

/*
 * CLIENT_MAX_IO_QUEUES in client_spec.h defines the 64K spec-limit, but this
 *  define specifies the maximum number of queues this driver will actually
 *  try to configure, if available.
 */
#define DEFAULT_MAX_IO_QUEUES (1024)
#define DEFAULT_ADMIN_QUEUE_SIZE (32)
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

#define MIN_KEEP_ALIVE_TIMEOUT_IN_MS (10000)

/* We want to fit submission and completion rings each in a single 2MB
 * hugepage to ensure physical address contiguity.
 */
#define MAX_IO_QUEUE_ENTRIES (VALUE_2MB / spdk_max(                        \
											  sizeof(struct spdk_req_cmd), \
											  sizeof(struct spdk_req_cpl)))

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

/** Boot partition write states */
enum client_bp_write_state
{
	SPDK_CLIENT_BP_WS_DOWNLOADING = 0x0,
	SPDK_CLIENT_BP_WS_DOWNLOADED = 0x1,
	SPDK_CLIENT_BP_WS_REPLACE = 0x2,
	SPDK_CLIENT_BP_WS_ACTIVATE = 0x3,
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
	 * Extended IO options passed by the user
	 */
	struct spdk_client_ns_cmd_ext_io_opts *opts;
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
	(struct client_payload)                 \
	{                                       \
		.reset_sgl_fn = NULL,               \
		.next_sge_fn = NULL,                \
		.contig_or_cb_arg = (contig_),      \
		.md = (md_),                        \
	}

#define CLIENT_PAYLOAD_SGL(reset_sgl_fn_, next_sge_fn_, cb_arg_, md_, rpc_request_id_, data_length_, rpc_opc_, submit_type_, md5sum_) \
	(struct client_payload)                                                                                                           \
	{                                                                                                                                 \
		.reset_sgl_fn = (reset_sgl_fn_),                                                                                              \
		.next_sge_fn = (next_sge_fn_),                                                                                                \
		.contig_or_cb_arg = (cb_arg_),                                                                                                \
		.md = (md_),                                                                                                                  \
		.rpc_request_id = (rpc_request_id_),                                                                                          \
		.data_length = (data_length_),                                                                                                \
		.rpc_opc = (rpc_opc_),                                                                                                        \
		.submit_type = (submit_type_),                                                                                                \
		.md5sum = (md5sum_),                                                                                                          \
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
	struct spdk_req_cmd cmd;

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
	uint32_t md_offset;

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
	struct spdk_req_cpl cpl;

	uint32_t md_size;

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
	struct spdk_req_cpl parent_status;

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
	struct spdk_req_cpl cpl;
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

struct client_async_event_request
{
	struct spdk_client_ctrlr *ctrlr;
	struct client_request *req;
	struct spdk_req_cpl cpl;
};

enum client_qpair_state
{
	CLIENT_QPAIR_DISCONNECTED,
	CLIENT_QPAIR_DISCONNECTING,
	CLIENT_QPAIR_CONNECTING,
	CLIENT_QPAIR_CONNECTED,
	CLIENT_QPAIR_ENABLING,
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
	struct spdk_client_accel_fn_table accel_fn_table;
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

struct spdk_client_ns
{
	struct spdk_client_ctrlr *ctrlr;
	uint32_t sector_size;

	/*
	 * Size of data transferred as part of each block,
	 * including metadata if FLBAS indicates the metadata is transferred
	 * as part of the data buffer at the end of each LBA.
	 */
	uint32_t extended_lba_size;

	uint32_t md_size;
	uint32_t pi_type;
	uint32_t sectors_per_max_io;
	uint32_t sectors_per_max_io_no_md;
	uint32_t sectors_per_stripe;
	uint32_t id;
	uint16_t flags;
	bool active;

	RB_ENTRY(spdk_client_ns)
	node;
};

/**
 * State of struct spdk_client_ctrlr (in particular, during initialization).
 */
enum client_ctrlr_state
{
	/**
	 * Wait before initializing the controller.
	 */
	CLIENT_CTRLR_STATE_INIT_DELAY,

	/**
	 * Connect the admin queue.
	 */
	CLIENT_CTRLR_STATE_CONNECT_ADMINQ,

	/**
	 * Controller has not started initialized yet.
	 */
	CLIENT_CTRLR_STATE_INIT = CLIENT_CTRLR_STATE_CONNECT_ADMINQ,

	/**
	 * Waiting for admin queue to connect.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_CONNECT_ADMINQ,

	/**
	 * Read Version (VS) register.
	 */
	CLIENT_CTRLR_STATE_READ_VS,

	/**
	 * Waiting for Version (VS) register to be read.
	 */
	CLIENT_CTRLR_STATE_READ_VS_WAIT_FOR_VS,

	/**
	 * Read Capabilities (CAP) register.
	 */
	CLIENT_CTRLR_STATE_READ_CAP,

	/**
	 * Waiting for Capabilities (CAP) register to be read.
	 */
	CLIENT_CTRLR_STATE_READ_CAP_WAIT_FOR_CAP,

	/**
	 * Check EN to prepare for controller initialization.
	 */
	CLIENT_CTRLR_STATE_CHECK_EN,

	/**
	 * Waiting for CC to be read as part of EN check.
	 */
	CLIENT_CTRLR_STATE_CHECK_EN_WAIT_FOR_CC,

	/**
	 * Waiting for CSTS.RDY to transition from 0 to 1 so that CC.EN may be set to 0.
	 */
	CLIENT_CTRLR_STATE_DISABLE_WAIT_FOR_READY_1,

	/**
	 * Waiting for CSTS register to be read as part of waiting for CSTS.RDY = 1.
	 */
	CLIENT_CTRLR_STATE_DISABLE_WAIT_FOR_READY_1_WAIT_FOR_CSTS,

	/**
	 * Disabling the controller by setting CC.EN to 0.
	 */
	CLIENT_CTRLR_STATE_SET_EN_0,

	/**
	 * Waiting for the CC register to be read as part of disabling the controller.
	 */
	CLIENT_CTRLR_STATE_SET_EN_0_WAIT_FOR_CC,

	/**
	 * Waiting for CSTS.RDY to transition from 1 to 0 so that CC.EN may be set to 1.
	 */
	CLIENT_CTRLR_STATE_DISABLE_WAIT_FOR_READY_0,

	/**
	 * Waiting for CSTS register to be read as part of waiting for CSTS.RDY = 0.
	 */
	CLIENT_CTRLR_STATE_DISABLE_WAIT_FOR_READY_0_WAIT_FOR_CSTS,

	/**
	 * Enable the controller by writing CC.EN to 1
	 */
	CLIENT_CTRLR_STATE_ENABLE,

	/**
	 * Waiting for CC register to be written as part of enabling the controller.
	 */
	CLIENT_CTRLR_STATE_ENABLE_WAIT_FOR_CC,

	/**
	 * Waiting for CSTS.RDY to transition from 0 to 1 after enabling the controller.
	 */
	CLIENT_CTRLR_STATE_ENABLE_WAIT_FOR_READY_1,

	/**
	 * Waiting for CSTS register to be read as part of waiting for CSTS.RDY = 1.
	 */
	CLIENT_CTRLR_STATE_ENABLE_WAIT_FOR_READY_1_WAIT_FOR_CSTS,

	/**
	 * Reset the Admin queue of the controller.
	 */
	CLIENT_CTRLR_STATE_RESET_ADMIN_QUEUE,

	/**
	 * Identify Controller command will be sent to then controller.
	 */
	CLIENT_CTRLR_STATE_IDENTIFY,

	/**
	 * Waiting for Identify Controller command be completed.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_IDENTIFY,

	/**
	 * Configure AER of the controller.
	 */
	CLIENT_CTRLR_STATE_CONFIGURE_AER,

	/**
	 * Waiting for the Configure AER to be completed.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_CONFIGURE_AER,

	/**
	 * Set Keep Alive Timeout of the controller.
	 */
	CLIENT_CTRLR_STATE_SET_KEEP_ALIVE_TIMEOUT,

	/**
	 * Waiting for Set Keep Alive Timeout to be completed.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_KEEP_ALIVE_TIMEOUT,

	/**
	 * Get Identify I/O Command Set Specific Controller data structure.
	 */
	CLIENT_CTRLR_STATE_IDENTIFY_IOCS_SPECIFIC,

	/**
	 * Waiting for Identify I/O Command Set Specific Controller command to be completed.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_IDENTIFY_IOCS_SPECIFIC,

	/**
	 * Get Commands Supported and Effects log page for the Zoned Namespace Command Set.
	 */
	CLIENT_CTRLR_STATE_GET_ZNS_CMD_EFFECTS_LOG,

	/**
	 * Waiting for the Get Log Page command to be completed.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_GET_ZNS_CMD_EFFECTS_LOG,

	/**
	 * Set Number of Queues of the controller.
	 */
	CLIENT_CTRLR_STATE_SET_NUM_QUEUES,

	/**
	 * Waiting for Set Num of Queues command to be completed.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_SET_NUM_QUEUES,

	/**
	 * Get active Namespace list of the controller.
	 */
	CLIENT_CTRLR_STATE_IDENTIFY_ACTIVE_NS,

	/**
	 * Waiting for the Identify Active Namespace commands to be completed.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_IDENTIFY_ACTIVE_NS,

	/**
	 * Get Identify Namespace Data structure for each NS.
	 */
	CLIENT_CTRLR_STATE_IDENTIFY_NS,

	/**
	 * Waiting for the Identify Namespace commands to be completed.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_IDENTIFY_NS,

	/**
	 * Get Identify Namespace Identification Descriptors.
	 */
	CLIENT_CTRLR_STATE_IDENTIFY_ID_DESCS,

	/**
	 * Get Identify I/O Command Set Specific Namespace data structure for each NS.
	 */
	CLIENT_CTRLR_STATE_IDENTIFY_NS_IOCS_SPECIFIC,

	/**
	 * Waiting for the Identify I/O Command Set Specific Namespace commands to be completed.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_IDENTIFY_NS_IOCS_SPECIFIC,

	/**
	 * Waiting for the Identify Namespace Identification
	 * Descriptors to be completed.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_IDENTIFY_ID_DESCS,

	/**
	 * Set supported log pages of the controller.
	 */
	CLIENT_CTRLR_STATE_SET_SUPPORTED_LOG_PAGES,

	/**
	 * Set supported log pages of INTEL controller.
	 */
	CLIENT_CTRLR_STATE_SET_SUPPORTED_INTEL_LOG_PAGES,

	/**
	 * Waiting for supported log pages of INTEL controller.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_SUPPORTED_INTEL_LOG_PAGES,

	/**
	 * Set supported features of the controller.
	 */
	CLIENT_CTRLR_STATE_SET_SUPPORTED_FEATURES,

	/**
	 * Set Doorbell Buffer Config of the controller.
	 */
	CLIENT_CTRLR_STATE_SET_DB_BUF_CFG,

	/**
	 * Waiting for Doorbell Buffer Config to be completed.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_DB_BUF_CFG,

	/**
	 * Set Host ID of the controller.
	 */
	CLIENT_CTRLR_STATE_SET_HOST_ID,

	/**
	 * Waiting for Set Host ID to be completed.
	 */
	CLIENT_CTRLR_STATE_WAIT_FOR_HOST_ID,

	/**
	 * Controller initialization has completed and the controller is ready.
	 */
	CLIENT_CTRLR_STATE_READY,

	/**
	 * Controller initialization has an error.
	 */
	CLIENT_CTRLR_STATE_ERROR
};

#define spdk_req_cpl_is_error(cpl)                 \
	((cpl)->status.sc != SPDK_CLIENT_SC_SUCCESS || \
	 (cpl)->status.sct != SPDK_CLIENT_SCT_GENERIC)

#define spdk_req_cpl_is_success(cpl) (!spdk_req_cpl_is_error(cpl))

#define spdk_req_cpl_is_pi_error(cpl)                                   \
	((cpl)->status.sct == SPDK_CLIENT_SCT_MEDIA_ERROR &&                \
	 ((cpl)->status.sc == SPDK_CLIENT_SC_GUARD_CHECK_ERROR ||           \
	  (cpl)->status.sc == SPDK_CLIENT_SC_APPLICATION_TAG_CHECK_ERROR || \
	  (cpl)->status.sc == SPDK_CLIENT_SC_REFERENCE_TAG_CHECK_ERROR))

#define spdk_req_cpl_is_abort_success(cpl) \
	(spdk_req_cpl_is_success(cpl) && !((cpl)->cdw0 & 1U))

#define spdk_req_cpl_is_path_error(cpl) \
	((cpl)->status.sct == SPDK_CLIENT_SCT_PATH)

#define spdk_req_cpl_is_ana_error(cpl)                                        \
	((cpl)->status.sct == SPDK_CLIENT_SCT_PATH &&                             \
	 ((cpl)->status.sc == SPDK_CLIENT_SC_ASYMMETRIC_ACCESS_PERSISTENT_LOSS || \
	  (cpl)->status.sc == SPDK_CLIENT_SC_ASYMMETRIC_ACCESS_INACCESSIBLE ||    \
	  (cpl)->status.sc == SPDK_CLIENT_SC_ASYMMETRIC_ACCESS_TRANSITION))

#define spdk_req_cpl_is_aborted_sq_deletion(cpl)     \
	((cpl)->status.sct == SPDK_CLIENT_SCT_GENERIC && \
	 (cpl)->status.sc == SPDK_CLIENT_SC_ABORTED_SQ_DELETION)

#define spdk_req_cpl_is_aborted_by_request(cpl)      \
	((cpl)->status.sct == SPDK_CLIENT_SCT_GENERIC && \
	 (cpl)->status.sc == SPDK_CLIENT_SC_ABORTED_BY_REQUEST)

#define CLIENT_TIMEOUT_INFINITE 0
#define CLIENT_TIMEOUT_KEEP_EXISTING UINT64_MAX

struct spdk_client_ctrlr_aer_completion_list
{
	struct spdk_req_cpl cpl;
	STAILQ_ENTRY(spdk_client_ctrlr_aer_completion_list)
	link;
};

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

	spdk_client_aer_cb aer_cb_fn;
	void *aer_cb_arg;

	/**
	 * A function pointer to timeout callback function
	 */
	spdk_client_timeout_cb timeout_cb_fn;
	void *timeout_cb_arg;
	/** separate timeout values for io vs. admin reqs */
	uint64_t timeout_io_ticks;
	uint64_t timeout_admin_ticks;

	/** List to publish AENs to all procs in multiprocess setup */
	STAILQ_HEAD(, spdk_client_ctrlr_aer_completion_list)
	async_events;
};

struct client_register_completion
{
	struct spdk_req_cpl cpl;
	uint64_t value;
	spdk_client_reg_cb cb_fn;
	void *cb_ctx;
	STAILQ_ENTRY(client_register_completion)
	stailq;
};

union spdk_client_cc_register
{
	uint32_t raw;
	struct
	{
		/** enable */
		uint32_t en : 1;

		uint32_t reserved1 : 3;

		/** i/o command set selected */
		uint32_t css : 3;

		/** memory page size */
		uint32_t mps : 4;

		/** arbitration mechanism selected */
		uint32_t ams : 3;

		/** shutdown notification */
		uint32_t shn : 2;

		/** i/o submission queue entry size */
		uint32_t iosqes : 4;

		/** i/o completion queue entry size */
		uint32_t iocqes : 4;

		uint32_t reserved2 : 8;
	} bits;
};
SPDK_STATIC_ASSERT(sizeof(union spdk_client_cc_register) == 4, "Incorrect size");

union spdk_client_csts_register
{
	uint32_t raw;
	struct
	{
		/** ready */
		uint32_t rdy : 1;

		/** controller fatal status */
		uint32_t cfs : 1;

		/** shutdown status */
		uint32_t shst : 2;

		/** NVM subsystem reset occurred */
		uint32_t nssro : 1;

		/** Processing paused */
		uint32_t pp : 1;

		uint32_t reserved1 : 26;
	} bits;
};
SPDK_STATIC_ASSERT(sizeof(union spdk_client_csts_register) == 4, "Incorrect size");

enum spdk_client_shst_value
{
	SPDK_CLIENT_SHST_NORMAL = 0x0,
	SPDK_CLIENT_SHST_OCCURRING = 0x1,
	SPDK_CLIENT_SHST_COMPLETE = 0x2,
};

/**
 * Status code types
 */
enum spdk_client_status_code_type
{
	SPDK_CLIENT_SCT_GENERIC = 0x0,
	SPDK_CLIENT_SCT_COMMAND_SPECIFIC = 0x1,
	SPDK_CLIENT_SCT_MEDIA_ERROR = 0x2,
	SPDK_CLIENT_SCT_PATH = 0x3,
	/* 0x4-0x6 - reserved */
	SPDK_CLIENT_SCT_VENDOR_SPECIFIC = 0x7,
};

/**
 * Generic command status codes
 */
enum spdk_client_generic_command_status_code
{
	SPDK_CLIENT_SC_SUCCESS = 0x00,
	SPDK_CLIENT_SC_INVALID_OPCODE = 0x01,
	SPDK_CLIENT_SC_INVALID_FIELD = 0x02,
	SPDK_CLIENT_SC_COMMAND_ID_CONFLICT = 0x03,
	SPDK_CLIENT_SC_DATA_TRANSFER_ERROR = 0x04,
	SPDK_CLIENT_SC_ABORTED_POWER_LOSS = 0x05,
	SPDK_CLIENT_SC_INTERNAL_DEVICE_ERROR = 0x06,
	SPDK_CLIENT_SC_ABORTED_BY_REQUEST = 0x07,
	SPDK_CLIENT_SC_ABORTED_SQ_DELETION = 0x08,
	SPDK_CLIENT_SC_ABORTED_FAILED_FUSED = 0x09,
	SPDK_CLIENT_SC_ABORTED_MISSING_FUSED = 0x0a,
	SPDK_CLIENT_SC_INVALID_NAMESPACE_OR_FORMAT = 0x0b,
	SPDK_CLIENT_SC_COMMAND_SEQUENCE_ERROR = 0x0c,
	SPDK_CLIENT_SC_INVALID_SGL_SEG_DESCRIPTOR = 0x0d,
	SPDK_CLIENT_SC_INVALID_NUM_SGL_DESCIRPTORS = 0x0e,
	SPDK_CLIENT_SC_DATA_SGL_LENGTH_INVALID = 0x0f,
	SPDK_CLIENT_SC_METADATA_SGL_LENGTH_INVALID = 0x10,
	SPDK_CLIENT_SC_SGL_DESCRIPTOR_TYPE_INVALID = 0x11,
	SPDK_CLIENT_SC_INVALID_CONTROLLER_MEM_BUF = 0x12,
	SPDK_CLIENT_SC_INVALID_PRP_OFFSET = 0x13,
	SPDK_CLIENT_SC_ATOMIC_WRITE_UNIT_EXCEEDED = 0x14,
	SPDK_CLIENT_SC_OPERATION_DENIED = 0x15,
	SPDK_CLIENT_SC_INVALID_SGL_OFFSET = 0x16,
	/* 0x17 - reserved */
	SPDK_CLIENT_SC_HOSTID_INCONSISTENT_FORMAT = 0x18,
	SPDK_CLIENT_SC_KEEP_ALIVE_EXPIRED = 0x19,
	SPDK_CLIENT_SC_KEEP_ALIVE_INVALID = 0x1a,
	SPDK_CLIENT_SC_ABORTED_PREEMPT = 0x1b,
	SPDK_CLIENT_SC_SANITIZE_FAILED = 0x1c,
	SPDK_CLIENT_SC_SANITIZE_IN_PROGRESS = 0x1d,
	SPDK_CLIENT_SC_SGL_DATA_BLOCK_GRANULARITY_INVALID = 0x1e,
	SPDK_CLIENT_SC_COMMAND_INVALID_IN_CMB = 0x1f,
	SPDK_CLIENT_SC_COMMAND_NAMESPACE_IS_PROTECTED = 0x20,
	SPDK_CLIENT_SC_COMMAND_INTERRUPTED = 0x21,
	SPDK_CLIENT_SC_COMMAND_TRANSIENT_TRANSPORT_ERROR = 0x22,

	SPDK_CLIENT_SC_LBA_OUT_OF_RANGE = 0x80,
	SPDK_CLIENT_SC_CAPACITY_EXCEEDED = 0x81,
	SPDK_CLIENT_SC_NAMESPACE_NOT_READY = 0x82,
	SPDK_CLIENT_SC_RESERVATION_CONFLICT = 0x83,
	SPDK_CLIENT_SC_FORMAT_IN_PROGRESS = 0x84,
};

/**
 * Command specific status codes
 */
enum spdk_client_command_specific_status_code
{
	SPDK_CLIENT_SC_COMPLETION_QUEUE_INVALID = 0x00,
	SPDK_CLIENT_SC_INVALID_QUEUE_IDENTIFIER = 0x01,
	SPDK_CLIENT_SC_INVALID_QUEUE_SIZE = 0x02,
	SPDK_CLIENT_SC_ABORT_COMMAND_LIMIT_EXCEEDED = 0x03,
	/* 0x04 - reserved */
	SPDK_CLIENT_SC_ASYNC_EVENT_REQUEST_LIMIT_EXCEEDED = 0x05,
	SPDK_CLIENT_SC_INVALID_FIRMWARE_SLOT = 0x06,
	SPDK_CLIENT_SC_INVALID_FIRMWARE_IMAGE = 0x07,
	SPDK_CLIENT_SC_INVALID_INTERRUPT_VECTOR = 0x08,
	SPDK_CLIENT_SC_INVALID_LOG_PAGE = 0x09,
	SPDK_CLIENT_SC_INVALID_FORMAT = 0x0a,
	SPDK_CLIENT_SC_FIRMWARE_REQ_CONVENTIONAL_RESET = 0x0b,
	SPDK_CLIENT_SC_INVALID_QUEUE_DELETION = 0x0c,
	SPDK_CLIENT_SC_FEATURE_ID_NOT_SAVEABLE = 0x0d,
	SPDK_CLIENT_SC_FEATURE_NOT_CHANGEABLE = 0x0e,
	SPDK_CLIENT_SC_FEATURE_NOT_NAMESPACE_SPECIFIC = 0x0f,
	SPDK_CLIENT_SC_FIRMWARE_REQ_NVM_RESET = 0x10,
	SPDK_CLIENT_SC_FIRMWARE_REQ_RESET = 0x11,
	SPDK_CLIENT_SC_FIRMWARE_REQ_MAX_TIME_VIOLATION = 0x12,
	SPDK_CLIENT_SC_FIRMWARE_ACTIVATION_PROHIBITED = 0x13,
	SPDK_CLIENT_SC_OVERLAPPING_RANGE = 0x14,
	SPDK_CLIENT_SC_NAMESPACE_INSUFFICIENT_CAPACITY = 0x15,
	SPDK_CLIENT_SC_NAMESPACE_ID_UNAVAILABLE = 0x16,
	/* 0x17 - reserved */
	SPDK_CLIENT_SC_NAMESPACE_ALREADY_ATTACHED = 0x18,
	SPDK_CLIENT_SC_NAMESPACE_IS_PRIVATE = 0x19,
	SPDK_CLIENT_SC_NAMESPACE_NOT_ATTACHED = 0x1a,
	SPDK_CLIENT_SC_THINPROVISIONING_NOT_SUPPORTED = 0x1b,
	SPDK_CLIENT_SC_CONTROLLER_LIST_INVALID = 0x1c,
	SPDK_CLIENT_SC_DEVICE_SELF_TEST_IN_PROGRESS = 0x1d,
	SPDK_CLIENT_SC_BOOT_PARTITION_WRITE_PROHIBITED = 0x1e,
	SPDK_CLIENT_SC_INVALID_CTRLR_ID = 0x1f,
	SPDK_CLIENT_SC_INVALID_SECONDARY_CTRLR_STATE = 0x20,
	SPDK_CLIENT_SC_INVALID_NUM_CTRLR_RESOURCES = 0x21,
	SPDK_CLIENT_SC_INVALID_RESOURCE_ID = 0x22,

	SPDK_CLIENT_SC_IOCS_NOT_SUPPORTED = 0x29,
	SPDK_CLIENT_SC_IOCS_NOT_ENABLED = 0x2a,
	SPDK_CLIENT_SC_IOCS_COMBINATION_REJECTED = 0x2b,
	SPDK_CLIENT_SC_INVALID_IOCS = 0x2c,

	SPDK_CLIENT_SC_STREAM_RESOURCE_ALLOCATION_FAILED = 0x7f,
	SPDK_CLIENT_SC_CONFLICTING_ATTRIBUTES = 0x80,
	SPDK_CLIENT_SC_INVALID_PROTECTION_INFO = 0x81,
	SPDK_CLIENT_SC_ATTEMPTED_WRITE_TO_RO_RANGE = 0x82,
	SPDK_CLIENT_SC_CMD_SIZE_LIMIT_SIZE_EXCEEDED = 0x83,
};

/**
 * Media error status codes
 */
enum spdk_client_media_error_status_code
{
	SPDK_CLIENT_SC_WRITE_FAULTS = 0x80,
	SPDK_CLIENT_SC_UNRECOVERED_READ_ERROR = 0x81,
	SPDK_CLIENT_SC_GUARD_CHECK_ERROR = 0x82,
	SPDK_CLIENT_SC_APPLICATION_TAG_CHECK_ERROR = 0x83,
	SPDK_CLIENT_SC_REFERENCE_TAG_CHECK_ERROR = 0x84,
	SPDK_CLIENT_SC_COMPARE_FAILURE = 0x85,
	SPDK_CLIENT_SC_ACCESS_DENIED = 0x86,
	SPDK_CLIENT_SC_DEALLOCATED_OR_UNWRITTEN_BLOCK = 0x87,
};

/**
 * Path related status codes
 */
enum spdk_client_path_status_code
{
	SPDK_CLIENT_SC_INTERNAL_PATH_ERROR = 0x00,
	SPDK_CLIENT_SC_ASYMMETRIC_ACCESS_PERSISTENT_LOSS = 0x01,
	SPDK_CLIENT_SC_ASYMMETRIC_ACCESS_INACCESSIBLE = 0x02,
	SPDK_CLIENT_SC_ASYMMETRIC_ACCESS_TRANSITION = 0x03,

	SPDK_CLIENT_SC_CONTROLLER_PATH_ERROR = 0x60,

	SPDK_CLIENT_SC_HOST_PATH_ERROR = 0x70,
	SPDK_CLIENT_SC_ABORTED_BY_HOST = 0x71,
};

#define SPDK_CLIENT_MAX_OPC 0xff

/**
 * Admin opcodes
 */
enum spdk_client_admin_opcode
{
	SPDK_CLIENT_OPC_DELETE_IO_SQ = 0x00,
	SPDK_CLIENT_OPC_CREATE_IO_SQ = 0x01,
	SPDK_CLIENT_OPC_GET_LOG_PAGE = 0x02,
	/* 0x03 - reserved */
	SPDK_CLIENT_OPC_DELETE_IO_CQ = 0x04,
	SPDK_CLIENT_OPC_CREATE_IO_CQ = 0x05,
	SPDK_CLIENT_OPC_IDENTIFY = 0x06,
	/* 0x07 - reserved */
	SPDK_CLIENT_OPC_ABORT = 0x08,
	SPDK_CLIENT_OPC_SET_FEATURES = 0x09,
	SPDK_CLIENT_OPC_GET_FEATURES = 0x0a,
	/* 0x0b - reserved */
	SPDK_CLIENT_OPC_ASYNC_EVENT_REQUEST = 0x0c,
	SPDK_CLIENT_OPC_NS_MANAGEMENT = 0x0d,
	/* 0x0e-0x0f - reserved */
	SPDK_CLIENT_OPC_FIRMWARE_COMMIT = 0x10,
	SPDK_CLIENT_OPC_FIRMWARE_IMAGE_DOWNLOAD = 0x11,

	SPDK_CLIENT_OPC_DEVICE_SELF_TEST = 0x14,
	SPDK_CLIENT_OPC_NS_ATTACHMENT = 0x15,

	SPDK_CLIENT_OPC_KEEP_ALIVE = 0x18,
	SPDK_CLIENT_OPC_DIRECTIVE_SEND = 0x19,
	SPDK_CLIENT_OPC_DIRECTIVE_RECEIVE = 0x1a,

	SPDK_CLIENT_OPC_VIRTUALIZATION_MANAGEMENT = 0x1c,
	SPDK_CLIENT_OPC_CLIENT_MI_SEND = 0x1d,
	SPDK_CLIENT_OPC_CLIENT_MI_RECEIVE = 0x1e,

	SPDK_CLIENT_OPC_DOORBELL_BUFFER_CONFIG = 0x7c,

	SPDK_CLIENT_OPC_FORMAT_NVM = 0x80,
	SPDK_CLIENT_OPC_SECURITY_SEND = 0x81,
	SPDK_CLIENT_OPC_SECURITY_RECEIVE = 0x82,

	SPDK_CLIENT_OPC_SANITIZE = 0x84,

	SPDK_CLIENT_OPC_GET_LBA_STATUS = 0x86,
};

struct spdk_client_ns_list
{
	uint32_t ns_list[1024];
};
SPDK_STATIC_ASSERT(sizeof(struct spdk_client_ns_list) == 4096, "Incorrect size");

/*
 * One of these per allocated PCI device.
 */
struct spdk_client_ctrlr
{
	/* Hot data (accessed in I/O path) starts here. */

	/* Tree of namespaces */
	RB_HEAD(client_ns_tree, spdk_client_ns)
	ns;

	/* The number of active namespaces */
	uint32_t active_ns_count;

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
	uint64_t state_timeout_tsc;

	uint64_t next_keep_alive_tick;
	uint64_t keep_alive_interval_ticks;

	TAILQ_ENTRY(spdk_client_ctrlr)
	tailq;

	/** maximum i/o size in bytes */
	uint32_t max_xfer_size;

	/** minimum page size supported by this controller in bytes */
	uint32_t min_page_size;

	/** selected memory page size for this controller in bytes */
	uint32_t page_size;

	/** guards access to the controller itself, including admin queues */
	pthread_mutex_t ctrlr_lock;

	struct spdk_client_qpair *adminq;

	struct spdk_bit_array *free_io_qids;
	TAILQ_HEAD(, spdk_client_qpair)
	active_io_qpairs;
	STAILQ_HEAD(, rpc_request)
	pending_rpc_requests;

	struct spdk_client_ctrlr_opts opts;

	uint64_t quirks;

	/* Extra sleep time during controller initialization */
	uint64_t sleep_timeout_tsc;

	/** Track all the processes manage this controller */
	TAILQ_HEAD(, spdk_client_ctrlr_process)
	active_procs;

	STAILQ_HEAD(, client_request)
	queued_aborts;
	uint32_t outstanding_aborts;

	/* CB to notify the user when the ctrlr is removed/failed. */
	spdk_client_remove_cb remove_cb;
	void *cb_ctx;

	/* scratchpad pointer that can be used to send data between two CLIENT_CTRLR_STATEs */
	void *tmp_ptr;

	/* maximum zone append size in bytes */
	uint32_t max_zone_append_size;

	/* PMR size in bytes */
	uint64_t pmr_size;

	/* Boot Partition Info */
	enum client_bp_write_state bp_ws;
	uint32_t bpid;
	spdk_req_cmd_cb bp_write_cb_fn;
	void *bp_write_cb_arg;

	/* Firmware Download */
	void *fw_payload;
	unsigned int fw_size_remaining;
	unsigned int fw_offset;
	unsigned int fw_transfer_size;

	/* Completed register operations */
	STAILQ_HEAD(, client_register_completion)
	register_operations;

	union spdk_client_cc_register process_init_cc;

	struct spdk_mempool *rpc_data_mp;
	uint32_t io_unit_size;
};

struct spdk_client_probe_ctx
{
	struct spdk_client_transport_id trid;
	void *cb_ctx;
	spdk_client_probe_cb probe_cb;
	spdk_client_attach_cb attach_cb;
	spdk_client_remove_cb remove_cb;
	TAILQ_HEAD(, spdk_client_ctrlr)
	init_ctrlrs;
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
	union spdk_client_csts_register csts;
	TAILQ_ENTRY(client_ctrlr_detach_ctx)
	link;
};

struct spdk_client_detach_ctx
{
	TAILQ_HEAD(, client_ctrlr_detach_ctx)
	head;
};

struct spdk_client_ctrlr_reset_ctx
{
	struct spdk_client_ctrlr *ctrlr;
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

extern struct client_driver *g_spdk_client_driver;

int client_driver_init(void);

#define client_delay usleep

static inline bool
client_qpair_is_admin_queue(struct spdk_client_qpair *qpair)
{
	return qpair->id == 0;
}

static inline bool
client_qpair_is_io_queue(struct spdk_client_qpair *qpair)
{
	return qpair->id != 0;
}

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

/* Admin functions */
int client_ctrlr_cmd_identify(struct spdk_client_ctrlr *ctrlr,
							  uint8_t cns, uint16_t cntid, uint32_t nsid,
							  uint8_t csi, void *payload, size_t payload_size,
							  spdk_req_cmd_cb cb_fn, void *cb_arg);
int client_ctrlr_cmd_set_num_queues(struct spdk_client_ctrlr *ctrlr,
									uint32_t num_queues, spdk_req_cmd_cb cb_fn,
									void *cb_arg);
int client_ctrlr_cmd_get_num_queues(struct spdk_client_ctrlr *ctrlr,
									spdk_req_cmd_cb cb_fn, void *cb_arg);

int client_ctrlr_cmd_set_host_id(struct spdk_client_ctrlr *ctrlr, void *host_id, uint32_t host_id_size,
								 spdk_req_cmd_cb cb_fn, void *cb_arg);

int client_ctrlr_cmd_format(struct spdk_client_ctrlr *ctrlr, uint32_t nsid,
							struct spdk_client_format *format, spdk_req_cmd_cb cb_fn, void *cb_arg);

void client_completion_poll_cb(void *arg, const struct spdk_req_cpl *cpl);
int client_wait_for_completion(struct spdk_client_qpair *qpair,
							   struct client_completion_poll_status *status);
int client_wait_for_completion_robust_lock(struct spdk_client_qpair *qpair,
										   struct client_completion_poll_status *status,
										   pthread_mutex_t *robust_mutex);
int client_wait_for_completion_timeout(struct spdk_client_qpair *qpair,
									   struct client_completion_poll_status *status,
									   uint64_t timeout_in_usecs);
int client_wait_for_completion_robust_lock_timeout(struct spdk_client_qpair *qpair,
												   struct client_completion_poll_status *status,
												   pthread_mutex_t *robust_mutex,
												   uint64_t timeout_in_usecs);
int client_wait_for_completion_robust_lock_timeout_poll(struct spdk_client_qpair *qpair,
														struct client_completion_poll_status *status,
														pthread_mutex_t *robust_mutex);

struct spdk_client_ctrlr_process *client_ctrlr_get_process(struct spdk_client_ctrlr *ctrlr,
														   pid_t pid);
struct spdk_client_ctrlr_process *client_ctrlr_get_current_process(struct spdk_client_ctrlr *ctrlr);
int client_ctrlr_add_process(struct spdk_client_ctrlr *ctrlr, void *devhandle);
void client_ctrlr_free_processes(struct spdk_client_ctrlr *ctrlr);
struct spdk_pci_device *client_ctrlr_proc_get_devhandle(struct spdk_client_ctrlr *ctrlr);

int client_ctrlr_probe(const struct spdk_client_transport_id *trid,
					   struct spdk_client_probe_ctx *probe_ctx, void *devhandle);

int client_ctrlr_construct(struct spdk_client_ctrlr *ctrlr);
void client_ctrlr_destruct_finish(struct spdk_client_ctrlr *ctrlr);
void client_ctrlr_destruct(struct spdk_client_ctrlr *ctrlr);
void client_ctrlr_destruct_async(struct spdk_client_ctrlr *ctrlr,
								 struct client_ctrlr_detach_ctx *ctx);
int client_ctrlr_destruct_poll_async(struct spdk_client_ctrlr *ctrlr,
									 struct client_ctrlr_detach_ctx *ctx);
void client_ctrlr_fail(struct spdk_client_ctrlr *ctrlr, bool hot_remove);
int client_ctrlr_process_init(struct spdk_client_ctrlr *ctrlr);
void client_ctrlr_connected(struct spdk_client_probe_ctx *probe_ctx,
							struct spdk_client_ctrlr *ctrlr);

int client_ctrlr_submit_admin_request(struct spdk_client_ctrlr *ctrlr,
									  struct client_request *req);
int client_ctrlr_get_cap(struct spdk_client_ctrlr *ctrlr, union spdk_client_cap_register *cap);
int client_ctrlr_get_vs(struct spdk_client_ctrlr *ctrlr, union spdk_client_vs_register *vs);
int client_ctrlr_get_cmbsz(struct spdk_client_ctrlr *ctrlr, union spdk_client_cmbsz_register *cmbsz);
int client_ctrlr_get_pmrcap(struct spdk_client_ctrlr *ctrlr, union spdk_client_pmrcap_register *pmrcap);
int client_ctrlr_get_bpinfo(struct spdk_client_ctrlr *ctrlr, union spdk_client_bpinfo_register *bpinfo);
int client_ctrlr_set_bpmbl(struct spdk_client_ctrlr *ctrlr, uint64_t bpmbl_value);
bool client_ctrlr_multi_iocs_enabled(struct spdk_client_ctrlr *ctrlr);
void client_ctrlr_process_async_event(struct spdk_client_ctrlr *ctrlr,
									  const struct spdk_req_cpl *cpl);
void client_ctrlr_disconnect_qpair(struct spdk_client_qpair *qpair);
void client_ctrlr_complete_queued_async_events(struct spdk_client_ctrlr *ctrlr);
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
int client_ctrlr_identify_active_ns(struct spdk_client_ctrlr *ctrlr);
int client_ctrlr_construct_namespace(struct spdk_client_ctrlr *ctrlr, uint32_t nsid);
void client_ns_set_identify_data(struct spdk_client_ns *ns);
void client_ns_set_id_desc_list_data(struct spdk_client_ns *ns);
void client_ns_free_zns_specific_data(struct spdk_client_ns *ns);
void client_ns_free_iocs_specific_data(struct spdk_client_ns *ns);
bool client_ns_has_supported_iocs_specific_data(struct spdk_client_ns *ns);
int client_ns_construct(struct spdk_client_ns *ns, uint32_t id,
						struct spdk_client_ctrlr *ctrlr);
int client_ns_cmd_zone_append_with_md(struct spdk_client_ns *ns, struct spdk_client_qpair *qpair,
									  void *buffer, void *metadata, uint64_t zslba,
									  uint32_t lba_count, spdk_req_cmd_cb cb_fn, void *cb_arg,
									  uint32_t io_flags, uint16_t apptag_mask, uint16_t apptag);
int client_ns_cmd_zone_appendv_with_md(struct spdk_client_ns *ns, struct spdk_client_qpair *qpair,
									   uint64_t zslba, uint32_t lba_count,
									   spdk_req_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
									   spdk_client_req_reset_sgl_cb reset_sgl_fn,
									   spdk_client_req_next_sge_cb next_sge_fn, void *metadata,
									   uint16_t apptag_mask, uint16_t apptag);

int client_fabric_ctrlr_set_reg_4(struct spdk_client_ctrlr *ctrlr, uint32_t offset, uint32_t value);
int client_fabric_ctrlr_set_reg_8(struct spdk_client_ctrlr *ctrlr, uint32_t offset, uint64_t value);
int client_fabric_ctrlr_get_reg_4(struct spdk_client_ctrlr *ctrlr, uint32_t offset, uint32_t *value);
int client_fabric_ctrlr_get_reg_8(struct spdk_client_ctrlr *ctrlr, uint32_t offset, uint64_t *value);
int client_fabric_ctrlr_set_reg_4_async(struct spdk_client_ctrlr *ctrlr, uint32_t offset,
										uint32_t value, spdk_client_reg_cb cb_fn, void *cb_arg);
int client_fabric_ctrlr_set_reg_8_async(struct spdk_client_ctrlr *ctrlr, uint32_t offset,
										uint64_t value, spdk_client_reg_cb cb_fn, void *cb_arg);
int client_fabric_ctrlr_get_reg_4_async(struct spdk_client_ctrlr *ctrlr, uint32_t offset,
										spdk_client_reg_cb cb_fn, void *cb_arg);
int client_fabric_ctrlr_get_reg_8_async(struct spdk_client_ctrlr *ctrlr, uint32_t offset,
										spdk_client_reg_cb cb_fn, void *cb_arg);
int client_fabric_ctrlr_scan(struct spdk_client_probe_ctx *probe_ctx, bool direct_connect);
int client_fabric_ctrlr_discover(struct spdk_client_ctrlr *ctrlr,
								 struct spdk_client_probe_ctx *probe_ctx);
int client_fabric_qpair_connect(struct spdk_client_qpair *qpair, uint32_t num_entries);
int client_fabric_qpair_connect_async(struct spdk_client_qpair *qpair, uint32_t num_entries);
int client_fabric_qpair_connect_poll(struct spdk_client_qpair *qpair);

#define CLIENT_INIT_REQUEST(req, _cb_fn, _cb_arg, _payload, _payload_size, _md_size) \
	do                                                                               \
	{                                                                                \
		req->cb_fn = _cb_fn;                                                         \
		req->cb_arg = _cb_arg;                                                       \
		req->payload = _payload;                                                     \
		req->payload_size = _payload_size;                                           \
		req->md_size = _md_size;                                                     \
		req->pid = g_spdk_client_pid;                                                \
		req->submit_tick = 0;                                                        \
	} while (0);

static inline struct client_request *
client_allocate_request(struct spdk_client_qpair *qpair,
						const struct client_payload *payload, uint32_t payload_size, uint32_t md_size,
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

	CLIENT_INIT_REQUEST(req, cb_fn, cb_arg, *payload, payload_size, md_size);

	return req;
}

static inline struct client_request *
client_allocate_request_contig(struct spdk_client_qpair *qpair,
							   void *buffer, uint32_t payload_size,
							   spdk_req_cmd_cb cb_fn, void *cb_arg)
{
	struct client_payload payload;

	payload = CLIENT_PAYLOAD_CONTIG(buffer, NULL);

	return client_allocate_request(qpair, &payload, payload_size, 0, cb_fn, cb_arg);
}

static inline struct client_request *
client_allocate_request_null(struct spdk_client_qpair *qpair, spdk_req_cmd_cb cb_fn, void *cb_arg)
{
	return client_allocate_request_contig(qpair, NULL, 0, cb_fn, cb_arg);
}

struct client_request *client_allocate_request_user_copy(struct spdk_client_qpair *qpair,
														 void *buffer, uint32_t payload_size,
														 spdk_req_cmd_cb cb_fn, void *cb_arg, bool host_to_controller);

static inline void
client_complete_request(spdk_req_cmd_cb cb_fn, void *cb_arg, struct spdk_client_qpair *qpair,
						struct client_request *req, struct spdk_req_cpl *cpl)
{
	struct spdk_req_cpl err_cpl;
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
client_cb_complete_child(void *child_arg, const struct spdk_req_cpl *cpl)
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
		memset(&parent->parent_status, 0, sizeof(struct spdk_req_cpl));
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
uint64_t client_get_quirks(const struct spdk_pci_id *id);

int client_robust_mutex_init_shared(pthread_mutex_t *mtx);
int client_robust_mutex_init_recursive_shared(pthread_mutex_t *mtx);

bool client_completion_is_retry(const struct spdk_req_cpl *cpl);

struct spdk_client_ctrlr *client_get_ctrlr_by_trid_unsafe(
	const struct spdk_client_transport_id *trid);

const struct spdk_client_transport *client_get_transport(const char *transport_name);
const struct spdk_client_transport *client_get_first_transport(void);
const struct spdk_client_transport *client_get_next_transport(const struct spdk_client_transport
																  *transport);
void client_ctrlr_update_namespaces(struct spdk_client_ctrlr *ctrlr);

/* Transport specific functions */
struct spdk_client_ctrlr *client_transport_ctrlr_construct(const char *trstring,
														   const struct spdk_client_ctrlr_opts *opts,
														   void *devhandle);
int client_transport_ctrlr_destruct(struct spdk_client_ctrlr *ctrlr);
int client_transport_ctrlr_scan(struct spdk_client_probe_ctx *probe_ctx, bool direct_connect);
int client_transport_ctrlr_enable(struct spdk_client_ctrlr *ctrlr);
int client_transport_ctrlr_set_reg_4(struct spdk_client_ctrlr *ctrlr, uint32_t offset, uint32_t value);
int client_transport_ctrlr_set_reg_8(struct spdk_client_ctrlr *ctrlr, uint32_t offset, uint64_t value);
int client_transport_ctrlr_get_reg_4(struct spdk_client_ctrlr *ctrlr, uint32_t offset, uint32_t *value);
int client_transport_ctrlr_get_reg_8(struct spdk_client_ctrlr *ctrlr, uint32_t offset, uint64_t *value);
int client_transport_ctrlr_set_reg_4_async(struct spdk_client_ctrlr *ctrlr, uint32_t offset,
										   uint32_t value, spdk_client_reg_cb cb_fn, void *cb_arg);
int client_transport_ctrlr_set_reg_8_async(struct spdk_client_ctrlr *ctrlr, uint32_t offset,
										   uint64_t value, spdk_client_reg_cb cb_fn, void *cb_arg);
int client_transport_ctrlr_get_reg_4_async(struct spdk_client_ctrlr *ctrlr, uint32_t offset,
										   spdk_client_reg_cb cb_fn, void *cb_arg);
int client_transport_ctrlr_get_reg_8_async(struct spdk_client_ctrlr *ctrlr, uint32_t offset,
										   spdk_client_reg_cb cb_fn, void *cb_arg);
uint32_t client_transport_ctrlr_get_max_xfer_size(struct spdk_client_ctrlr *ctrlr);
uint16_t client_transport_ctrlr_get_max_sges(struct spdk_client_ctrlr *ctrlr);
struct spdk_client_qpair *client_transport_ctrlr_create_io_qpair(struct spdk_client_ctrlr *ctrlr,
																 uint16_t qid, const struct spdk_client_io_qpair_opts *opts);
int client_transport_ctrlr_reserve_cmb(struct spdk_client_ctrlr *ctrlr);
void *client_transport_ctrlr_map_cmb(struct spdk_client_ctrlr *ctrlr, size_t *size);
int client_transport_ctrlr_unmap_cmb(struct spdk_client_ctrlr *ctrlr);
int client_transport_ctrlr_enable_pmr(struct spdk_client_ctrlr *ctrlr);
int client_transport_ctrlr_disable_pmr(struct spdk_client_ctrlr *ctrlr);
void *client_transport_ctrlr_map_pmr(struct spdk_client_ctrlr *ctrlr, size_t *size);
int client_transport_ctrlr_unmap_pmr(struct spdk_client_ctrlr *ctrlr);
void client_transport_ctrlr_delete_io_qpair(struct spdk_client_ctrlr *ctrlr,
											struct spdk_client_qpair *qpair);
int client_transport_ctrlr_connect_qpair(struct spdk_client_ctrlr *ctrlr,
										 struct spdk_client_qpair *qpair);
int client_transport_ctrlr_connect_qpair_async(struct spdk_client_ctrlr *ctrlr,
											   struct spdk_client_qpair *qpair);
void client_transport_ctrlr_disconnect_qpair(struct spdk_client_ctrlr *ctrlr,
											 struct spdk_client_qpair *qpair);
int client_transport_ctrlr_get_memory_domains(const struct spdk_client_ctrlr *ctrlr,
											  struct spdk_memory_domain **domains, int array_size);
void client_transport_qpair_abort_reqs(struct spdk_client_qpair *qpair, uint32_t dnr);
int client_transport_qpair_reset(struct spdk_client_qpair *qpair);
int client_transport_qpair_submit_request(struct spdk_client_qpair *qpair, struct client_request *req);
int32_t client_transport_qpair_process_completions(struct spdk_client_qpair *qpair,
												   uint32_t max_completions);
void client_transport_admin_qpair_abort_aers(struct spdk_client_qpair *qpair);
int client_transport_qpair_iterate_requests(struct spdk_client_qpair *qpair,
											int (*iter_fn)(struct client_request *req, void *arg),
											void *arg);

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
/*
 * Below ref related functions must be called with the global
 *  driver lock held for the multi-process condition.
 *  Within these functions, the per ctrlr ctrlr_lock is also
 *  acquired for the multi-thread condition.
 */
void client_ctrlr_proc_get_ref(struct spdk_client_ctrlr *ctrlr);
void client_ctrlr_proc_put_ref(struct spdk_client_ctrlr *ctrlr);
int client_ctrlr_get_ref_count(struct spdk_client_ctrlr *ctrlr);

static inline bool
_is_page_aligned(uint64_t address, uint64_t page_size)
{
	return (address & (page_size - 1)) == 0;
}

#ifdef __cplusplus
}
#endif

#endif /* __CLIENT_INTERNAL_H__ */