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

/** \file
 * Client driver public API
 */

#ifndef SPDK_RDMA_CLIENT_H
#define SPDK_RDMA_CLIENT_H

#include "spdk/stdinc.h"

#ifdef __cplusplus
extern "C"
{
#endif

#include "spdk/env.h"
#include "spdk/rdma_common.h"
#define SPDK_CLIENT_TRANSPORT_NAME_RDMA "RDMA"

#define SPDK_SRV_PRIORITY_MAX_LEN 4
#define SPDK_SRV_MEMORY_POOL_ELEMENT_SIZE 4096

	struct spdk_client_ctrlr;

	struct spdk_memory_domain;

	struct rpc_response
	{
		struct iovec *iovs; /* array of iovecs to transfer. */
		int iovcnt;			/* Number of iovecs in iovs array. */
		uint32_t length;
	};

	typedef void (*spdk_rpc_request_cb)(void *cb_args, int status, struct iovec *iovs, int iovcnt, int length);

	struct rpc_request
	{
		struct spdk_client_qpair *qpair;
		spdk_rpc_request_cb cb;
		void *cb_args;
		char *raw_data;			 // SPDK_CLIENT_SUBMIT_CONTING use this field
		struct iovec *raw_ioves; // SPDK_CLIENT_SUBMIT_IOVES use this field
		int raw_iov_cnt;		 // SPDK_CLIENT_SUBMIT_IOVES use this field
		int submit_type;		 // SPDK_CLIENT_SUBMIT_CONTING or SPDK_CLIENT_SUBMIT_IOVES
		uint32_t out_length;
		uint32_t out_payload_length;
		struct iovec *out_iovs; /* array of iovecs to transfer. */
		int out_iovcnt;			/* Number of iovecs in iovs array. */
		int iovpos;				/* Current iovec position. */
		uint32_t iov_offset;	/* Offset in current iovec. */
		uint32_t opc;
		uint32_t in_length;
		struct iovec *in_iovs;
		int in_iovcnt;
		uint32_t in_payload_length;
		bool check_md5;
		uint8_t md5sum[SPDK_MD5DIGEST_LEN];
		uint64_t tsc_last;
		// uint32_t rpc_receied_index;
		STAILQ_ENTRY(rpc_request)
		stailq;
		uint32_t request_id;
	};

	struct spdk_client_ctrlr_list
	{
		uint16_t ctrlr_count;
		uint16_t ctrlr_list[2047];
	};
	SPDK_STATIC_ASSERT(sizeof(struct spdk_client_ctrlr_list) == 4096, "Incorrect size");

	struct client_poll_group
	{
		struct spdk_client_poll_group *group;
		struct spdk_poller *poller;
		struct spdk_client_ctrlr *ctrlr;
	};

	/**
	 * Client controller initialization options.
	 *
	 */
	struct spdk_client_ctrlr_opts
	{
		/**
		 * Number of I/O queues to request (used to set Number of Queues feature)
		 */
		uint32_t num_io_queues;

		/**
		 * Enable submission queue in controller memory buffer
		 */
		bool use_cmb_sqs;

		/**
		 * Don't initiate shutdown processing
		 */
		bool no_shn_notification;

				/**
		 * Keep alive timeout in milliseconds (0 = disabled).
		 *
		 * The Client library will set the Keep Alive Timer feature to this value and automatically
		 * send Keep Alive commands as needed.  The library user must call
		 * spdk_client_ctrlr_process_admin_completions() periodically to ensure Keep Alive commands
		 * are sent.
		 */
		uint32_t keep_alive_timeout_ms;

		/**
		 * Specify the retry number when there is issue with the transport
		 */
		uint8_t transport_retry_count;

		/**
		 * The queue depth of each Client I/O queue.
		 */
		uint32_t io_queue_size;

		/**
		 * The host NQN to use when connecting to Client over Fabrics controllers.
		 *
		 * If empty, a default value will be used.
		 */
		// char hostnqn[SPDK_SRV_NQN_MAX_LEN + 1];

		/**
		 * The number of requests to allocate for each Client I/O queue.
		 *
		 * This should be at least as large as io_queue_size.
		 *
		 * A single I/O may allocate more than one request, since splitting may be necessary to
		 * conform to the device's maximum transfer size, PRP list compatibility requirements,
		 * or driver-assisted striping.
		 */
		uint32_t io_queue_requests;

		/**
		 * Source address for Client-oF connections.
		 * Set src_addr and src_svcid to empty strings if no source address should be
		 * specified.
		 */
		char src_addr[SPDK_SRV_TRADDR_MAX_LEN + 1];

		/**
		 * Source service ID (port) for Client-oF connections.
		 * Set src_addr and src_svcid to empty strings if no source address should be
		 * specified.
		 */
		char src_svcid[SPDK_SRV_TRSVCID_MAX_LEN + 1];

		/**
		 * The host identifier to use when connecting to controllers with 64-bit host ID support.
		 *
		 * Set to all zeroes to specify that no host ID should be provided to the controller.
		 */
		uint8_t host_id[8];

		/**
		 * The host identifier to use when connecting to controllers with extended (128-bit) host ID support.
		 *
		 * Set to all zeroes to specify that no host ID should be provided to the controller.
		 */
		uint8_t extended_host_id[16];

		/**
		 * Disable logging of requests that are completed with error status.
		 *
		 * Defaults to 'false' (errors are logged).
		 */
		bool disable_error_logging;

		/**
		 * It is used for RDMA transport
		 * Specify the transport ACK timeout. The value should be in range 0-31 where 0 means
		 * use driver-specific default value. The value is applied to each RDMA qpair
		 * and affects the time that qpair waits for transport layer acknowledgement
		 * until it retransmits a packet. The value should be chosen empirically
		 * to meet the needs of a particular application. A low value means less time
		 * the qpair waits for ACK which can increase the number of retransmissions.
		 * A large value can increase the time the connection is closed.
		 * The value of ACK timeout is calculated according to the formula
		 * 4.096 * 2^(transport_ack_timeout) usec.
		 */
		uint8_t transport_ack_timeout;

		/**
		 * The size of spdk_client_ctrlr_opts according to the caller of this library is used for ABI
		 * compatibility.  The library uses this field to know how many fields in this
		 * structure are valid. And the library will populate any remaining fields with default values.
		 */
		size_t opts_size;

		/**
		 * The amount of time to spend before timing out during fabric connect on qpairs associated with
		 * this controller in microseconds.
		 */
		uint64_t fabrics_connect_timeout_us;

		uint32_t sector_size;

		// original ns fields
		/*
		 * Size of data transferred as part of each block,
		 * including metadata if FLBAS indicates the metadata is transferred
		 * as part of the data buffer at the end of each LBA.
		 */
		uint32_t extended_lba_size;
		uint32_t sectors_per_max_io;
		uint32_t sectors_per_stripe;
	};

	/**
	 * Get the default options for the creation of a specific Client controller.
	 *
	 * \param[out] opts Will be filled with the default option.
	 * \param opts_size Must be set to sizeof(struct spdk_client_ctrlr_opts).
	 */
	void spdk_client_ctrlr_get_default_ctrlr_opts(struct spdk_client_ctrlr_opts *opts,
												  size_t opts_size);

	/*
	 * Get the options in use for a given controller.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 */
	const struct spdk_client_ctrlr_opts *spdk_client_ctrlr_get_opts(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Reason for qpair disconnect at the transport layer.
	 *
	 * NONE implies that the qpair is still connected while UNKNOWN means that the
	 * qpair is disconnected, but the cause was not apparent.
	 */
	enum spdk_client_qp_failure_reason
	{
		SPDK_CLIENT_QPAIR_FAILURE_NONE = 0,
		SPDK_CLIENT_QPAIR_FAILURE_LOCAL,
		SPDK_CLIENT_QPAIR_FAILURE_REMOTE,
		SPDK_CLIENT_QPAIR_FAILURE_UNKNOWN,
	};

	typedef enum spdk_client_qp_failure_reason spdk_client_qp_failure_reason;

	/**
	 * Client library transports
	 *
	 * NOTE: These are mapped directly to the Client over Fabrics TRTYPE values, except for PCIe,
	 * which is a special case since Client over Fabrics does not define a TRTYPE for local PCIe.
	 *
	 * Currently, this uses 256 for PCIe which is intentionally outside of the 8-bit range of TRTYPE.
	 * If the Client-oF specification ever defines a PCIe TRTYPE, this should be updated.
	 */
	enum spdk_client_transport_type
	{
		/**
		 * RDMA Transport (RoCE, iWARP, etc.)
		 */
		SPDK_CLIENT_TRANSPORT_RDMA = SPDK_SRV_TRTYPE_RDMA,
	};

	struct spdk_client_ctrlr *spdk_client_transport_ctrlr_construct(const char *trstring,
																	const struct spdk_client_ctrlr_opts *opts,
																	void *devhandle);

	static inline bool spdk_client_trtype_is_fabrics(enum spdk_client_transport_type trtype)
	{
		/* We always define non-fabrics trtypes outside of the 8-bit range
		 * of Client-oF trtype.
		 */
		return trtype <= UINT8_MAX;
	}

	/* typedef added for coding style reasons */
	typedef enum spdk_client_transport_type spdk_client_transport_type_t;

	/**
	 * Client transport identifier.
	 *
	 * This identifies a unique endpoint on an Client fabric.
	 *
	 * A string representation of a transport ID may be converted to this type using
	 * spdk_client_transport_id_parse().
	 */
	struct spdk_client_transport_id
	{
		/**
		 * Client transport string.
		 */
		char trstring[SPDK_SRV_TRSTRING_MAX_LEN + 1];

		/**
		 * Client transport type.
		 */
		enum spdk_client_transport_type trtype;

		/**
		 * Address family of the transport address.
		 *
		 * For PCIe, this value is ignored.
		 */
		enum spdk_srv_adrfam adrfam;

		/**
		 * Transport address of the Client-oF endpoint. For transports which use IP
		 * addressing (e.g. RDMA), this should be an IP address. For PCIe, this
		 * can either be a zero length string (the whole bus) or a PCI address
		 * in the format DDDD:BB:DD.FF or DDDD.BB.DD.FF. For FC the string is
		 * formatted as: nn-0xWWNN:pn-0xWWPN” where WWNN is the Node_Name of the
		 * target Client_Port and WWPN is the N_Port_Name of the target Client_Port.
		 */
		char traddr[SPDK_SRV_TRADDR_MAX_LEN + 1];

		/**
		 * Transport service id of the Client-oF endpoint.  For transports which use
		 * IP addressing (e.g. RDMA), this field should be the port number. For PCIe,
		 * and FC this is always a zero length string.
		 */
		char trsvcid[SPDK_SRV_TRSVCID_MAX_LEN + 1];

		/**
		 * Subsystem NQN of the Client over Fabrics endpoint. May be a zero length string.
		 */
		// char subnqn[SPDK_SRV_NQN_MAX_LEN + 1];

		/**
		 * The Transport connection priority of the Client-oF endpoint. Currently this is
		 * only supported by posix based sock implementation on Kernel TCP stack. More
		 * information of this field can be found from the socket(7) man page.
		 */
		int priority;
	};

	/**
	 * Client host identifier
	 *
	 * Used for defining the host identity for an Client-oF connection.
	 *
	 * In terms of configuration, this object can be considered a subtype of TransportID
	 * Please see etc/spdk/srv.conf.in for more details.
	 *
	 * A string representation of this type may be converted to this type using
	 * spdk_client_host_id_parse().
	 */
	struct spdk_client_host_id
	{
		/**
		 * Transport address to be used by the host when connecting to the Client-oF endpoint.
		 * May be an IP address or a zero length string for transports which
		 * use IP addressing (e.g. RDMA).
		 * For PCIe and FC this is always a zero length string.
		 */
		char hostaddr[SPDK_SRV_TRADDR_MAX_LEN + 1];

		/**
		 * Transport service ID used by the host when connecting to the Client.
		 * May be a port number or a zero length string for transports which
		 * use IP addressing (e.g. RDMA).
		 * For PCIe and FC this is always a zero length string.
		 */
		char hostsvcid[SPDK_SRV_TRSVCID_MAX_LEN + 1];
	};

	struct spdk_client_rdma_device_stat
	{
		const char *name;
		uint64_t polls;
		uint64_t idle_polls;
		uint64_t completions;
		uint64_t queued_requests;
		uint64_t total_send_wrs;
		uint64_t send_doorbell_updates;
		uint64_t total_recv_wrs;
		uint64_t recv_doorbell_updates;
	};

	struct spdk_client_tcp_stat
	{
		uint64_t polls;
		uint64_t idle_polls;
		uint64_t socket_completions;
		uint64_t client_completions;
		uint64_t submitted_requests;
		uint64_t queued_requests;
	};

	struct spdk_client_transport_poll_group_stat
	{
		spdk_client_transport_type_t trtype;
		union
		{
			struct
			{
				uint32_t num_devices;
				struct spdk_client_rdma_device_stat *device_stats;
			} rdma;
			struct spdk_client_tcp_stat tcp;
		};
	};

	struct spdk_client_poll_group_stat
	{
		uint32_t num_transports;
		struct spdk_client_transport_poll_group_stat **transport_stat;
	};

	/**
	 * Parse the string representation of a transport ID.
	 *
	 * \param trid Output transport ID structure (must be allocated and initialized by caller).
	 * \param str Input string representation of a transport ID to parse.
	 *
	 * str must be a zero-terminated C string containing one or more key:value pairs
	 * separated by whitespace.
	 *
	 * Key          | Value
	 * ------------ | -----
	 * trtype       | Transport type (e.g. PCIe, RDMA)
	 * adrfam       | Address family (e.g. IPv4, IPv6)
	 * traddr       | Transport address (e.g. 192.168.100.8 for RDMA)
	 * trsvcid      | Transport service identifier (e.g. 4420)
	 * subnqn       | Subsystem NQN
	 *
	 * Unspecified fields of trid are left unmodified, so the caller must initialize
	 * trid (for example, memset() to 0) before calling this function.
	 *
	 * \return 0 if parsing was successful and trid is filled out, or negated errno
	 * values on failure.
	 */
	int spdk_client_transport_id_parse(struct spdk_client_transport_id *trid, const char *str);

	/**
	 * Parse the string representation of a host ID.
	 *
	 * \param hostid Output host ID structure (must be allocated and initialized by caller).
	 * \param str Input string representation of a transport ID to parse (hostid is a sub-configuration).
	 *
	 * str must be a zero-terminated C string containing one or more key:value pairs
	 * separated by whitespace.
	 *
	 * Key            | Value
	 * -------------- | -----
	 * hostaddr       | Transport address (e.g. 192.168.100.8 for RDMA)
	 * hostsvcid      | Transport service identifier (e.g. 4420)
	 *
	 * Unspecified fields of trid are left unmodified, so the caller must initialize
	 * hostid (for example, memset() to 0) before calling this function.
	 *
	 * This function should not be used with Fiber Channel or PCIe as these transports
	 * do not require host information for connections.
	 *
	 * \return 0 if parsing was successful and hostid is filled out, or negated errno
	 * values on failure.
	 */
	int spdk_client_host_id_parse(struct spdk_client_host_id *hostid, const char *str);

	/**
	 * Parse the string representation of a transport ID transport type into the trid struct.
	 *
	 * \param trid The trid to write to
	 * \param trstring Input string representation of transport type (e.g. "PCIe", "RDMA").
	 *
	 * \return 0 if parsing was successful and trtype is filled out, or negated errno
	 * values if the provided string was an invalid transport string.
	 */
	int spdk_client_transport_id_populate_trstring(struct spdk_client_transport_id *trid,
												   const char *trstring);

	/**
	 * Parse the string representation of a transport ID transport type.
	 *
	 * \param trtype Output transport type (allocated by caller).
	 * \param str Input string representation of transport type (e.g. "PCIe", "RDMA").
	 *
	 * \return 0 if parsing was successful and trtype is filled out, or negated errno
	 * values on failure.
	 */
	int spdk_client_transport_id_parse_trtype(enum spdk_client_transport_type *trtype, const char *str);

	/**
	 * Look up the string representation of a transport ID transport type.
	 *
	 * \param trtype Transport type to convert.
	 *
	 * \return static string constant describing trtype, or NULL if trtype not found.
	 */
	const char *spdk_client_transport_id_trtype_str(enum spdk_client_transport_type trtype);

	/**
	 * Look up the string representation of a transport ID address family.
	 *
	 * \param adrfam Address family to convert.
	 *
	 * \return static string constant describing adrfam, or NULL if adrfam not found.
	 */
	const char *spdk_client_transport_id_adrfam_str(enum spdk_srv_adrfam adrfam);

	/**
	 * Parse the string representation of a transport ID address family.
	 *
	 * \param adrfam Output address family (allocated by caller).
	 * \param str Input string representation of address family (e.g. "IPv4", "IPv6").
	 *
	 * \return 0 if parsing was successful and adrfam is filled out, or negated errno
	 * values on failure.
	 */
	int spdk_client_transport_id_parse_adrfam(enum spdk_srv_adrfam *adrfam, const char *str);

	/**
	 * Disconnect the given Client controller.
	 *
	 * This function is used as the first operation of a full reset sequence of the given Client
	 * controller. The Client controller is ready to reconnect after completing this function.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return 0 on success, -EBUSY if controller is already resetting, or -ENXIO if controller
	 * has been removed.
	 */
	int spdk_client_ctrlr_disconnect(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Start re-enabling the given Client controller in a full reset sequence
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 */
	void spdk_client_ctrlr_reconnect_async(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Proceed with re-enabling the given Client controller.
	 *
	 * Users must call this function in a full reset sequence until it returns a value other
	 * than -EAGAIN.
	 *
	 * \return 0 if the given Client controller is enabled, or -EBUSY if there are still
	 * pending operations to enable it.
	 */
	int spdk_client_ctrlr_reconnect_poll_async(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Fail the given Client controller.
	 *
	 * This function gives the application the opportunity to fail a controller
	 * at will. When a controller is failed, any calls to process completions or
	 * submit I/O on qpairs associated with that controller will fail with an error
	 * code of -ENXIO.
	 * The controller can only be taken from the failed state by
	 * calling spdk_client_ctrlr_reset. After the controller has been successfully
	 * reset, any I/O pending when the controller was moved to failed will be
	 * aborted back to the application and can be resubmitted. I/O can then resume.
	 *
	 * \param ctrlr Opaque handle to an Client controller.
	 */
	void spdk_client_ctrlr_fail(struct spdk_client_ctrlr *ctrlr);

	/**
	 * This function returns the failed status of a given controller.
	 *
	 * \param ctrlr Opaque handle to an Client controller.
	 *
	 * \return True if the controller is failed, false otherwise.
	 */
	bool spdk_client_ctrlr_is_failed(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Signature for callback function invoked when a command is completed.
	 *
	 * \param ctx Callback context provided when the command was submitted.
	 * \param cpl Completion queue entry that contains the completion status.
	 */
	typedef void (*spdk_req_cmd_cb)(void *ctx, const struct spdk_rpc_req_cpl *cpl);

	/**
	 * Opaque handle to a queue pair.
	 *
	 * I/O queue pairs may be allocated using spdk_client_ctrlr_alloc_io_qpair().
	 */
	typedef void (*spdk_connected_cb)(void *cb_args, int status);
	struct spdk_client_qpair;

	/**
	 * Submission queue priority values for Create I/O Submission Queue Command.
	 *
	 * Only valid for weighted round robin arbitration method.
	 */
	enum spdk_client_qprio
	{
		SPDK_CLIENT_QPRIO_URGENT = 0x0,
		SPDK_CLIENT_QPRIO_HIGH = 0x1,
		SPDK_CLIENT_QPRIO_MEDIUM = 0x2,
		SPDK_CLIENT_QPRIO_LOW = 0x3
	};

	/**
	 * Client I/O queue pair initialization options.
	 *
	 * These options may be passed to spdk_client_ctrlr_alloc_io_qpair() to configure queue pair
	 * options at queue creation time.
	 *
	 * The user may retrieve the default I/O queue pair creation options for a controller using
	 * spdk_client_ctrlr_get_default_io_qpair_opts().
	 */
	struct spdk_client_io_qpair_opts
	{
		/**
		 * Queue priority for weighted round robin arbitration.  If a different arbitration
		 * method is in use, pass 0.
		 */
		enum spdk_client_qprio qprio;

		/**
		 * The queue depth of this Client I/O queue. Overrides spdk_client_ctrlr_opts::io_queue_size.
		 */
		uint32_t io_queue_size;

		/**
		 * The number of requests to allocate for this Client I/O queue.
		 *
		 * Overrides spdk_client_ctrlr_opts::io_queue_requests.
		 *
		 * This should be at least as large as io_queue_size.
		 *
		 * A single I/O may allocate more than one request, since splitting may be
		 * necessary to conform to the device's maximum transfer size, PRP list
		 * compatibility requirements, or driver-assisted striping.
		 */
		uint32_t io_queue_requests;

		/**
		 * When submitting I/O via spdk_client_ns_read/write and similar functions,
		 * don't immediately submit it to hardware. Instead, queue up new commands
		 * and submit them to the hardware inside spdk_client_qpair_process_completions().
		 *
		 * This results in better batching of I/O commands. Often, it is more efficient
		 * to submit batches of commands to the underlying hardware than each command
		 * individually.
		 *
		 * This only applies to PCIe and RDMA transports.
		 *
		 * The flag was originally named delay_pcie_doorbell. To allow backward compatibility
		 * both names are kept in unnamed union.
		 */
		union
		{
			bool delay_cmd_submit;
			bool delay_pcie_doorbell;
		};

		/**
		 * These fields allow specifying the memory buffers for the submission and/or
		 * completion queues.
		 * By default, vaddr is set to NULL meaning SPDK will allocate the memory to be used.
		 * If vaddr is NULL then paddr must be set to 0.
		 * If vaddr is non-NULL, and paddr is zero, SPDK derives the physical
		 * address for the Client device, in this case the memory must be registered.
		 * If a paddr value is non-zero, SPDK uses the vaddr and paddr as passed
		 * SPDK assumes that the memory passed is both virtually and physically
		 * contiguous.
		 * If these fields are used, SPDK will NOT impose any restriction
		 * on the number of elements in the queues.
		 * The buffer sizes are in number of bytes, and are used to confirm
		 * that the buffers are large enough to contain the appropriate queue.
		 * These fields are only used by PCIe attached Client devices.  They
		 * are presently ignored for other transports.
		 */
		struct
		{
			struct spdk_rpc_req_cmd *vaddr;
			uint64_t paddr;
			uint64_t buffer_size;
		} sq;
		struct
		{
			struct spdk_rpc_req_cpl *vaddr;
			uint64_t paddr;
			uint64_t buffer_size;
		} cq;

		/**
		 * This flag indicates to the alloc_io_qpair function that it should not perform
		 * the connect portion on this qpair. This allows the user to add the qpair to a
		 * poll group and then connect it later.
		 */
		bool create_only;

		/**
		 * This flag if set to true enables the creation of submission and completion queue
		 * asynchronously. This mode is currently supported at PCIe layer and tracks the
		 * qpair creation with state machine and returns to the user.Default mode is set to
		 * false to create io qpair synchronously.
		 */
		bool async_mode;
	};

	/**
	 * Get the default options for I/O qpair creation for a specific Client controller.
	 *
	 * \param ctrlr Client controller to retrieve the defaults from.
	 * \param[out] opts Will be filled with the default options for
	 * spdk_client_ctrlr_alloc_io_qpair().
	 * \param opts_size Must be set to sizeof(struct spdk_client_io_qpair_opts).
	 */
	void spdk_client_ctrlr_get_default_io_qpair_opts(struct spdk_client_ctrlr *ctrlr,
													 struct spdk_client_io_qpair_opts *opts,
													 size_t opts_size);

	/**
	 * Allocate an I/O queue pair (submission and completion queue).
	 *
	 * This function by default also performs any connection activities required for
	 * a newly created qpair. To avoid that behavior, the user should set the create_only
	 * flag in the opts structure to true.
	 *
	 * Each queue pair should only be used from a single thread at a time (mutual
	 * exclusion must be enforced by the user).
	 *
	 * \param ctrlr Client controller for which to allocate the I/O queue pair.
	 * \param opts I/O qpair creation options, or NULL to use the defaults as returned
	 * by spdk_client_ctrlr_get_default_io_qpair_opts().
	 * \param opts_size Must be set to sizeof(struct spdk_client_io_qpair_opts), or 0
	 * if opts is NULL.
	 *
	 * \return a pointer to the allocated I/O queue pair.
	 */
	struct spdk_client_qpair *spdk_client_ctrlr_alloc_io_qpair(struct spdk_client_ctrlr *ctrlr,
															   const struct spdk_client_io_qpair_opts *opts,
															   size_t opts_size, struct spdk_client_transport_id *id, struct spdk_client_poll_group *client_pg);

	struct spdk_client_qpair *
	spdk_client_ctrlr_alloc_io_qpair_async(struct spdk_client_ctrlr *ctrlr,
										   const struct spdk_client_io_qpair_opts *user_opts,
										   size_t opts_size, struct spdk_client_transport_id *id, struct spdk_client_poll_group *client_pg, spdk_connected_cb cb_fn, void *cb_arg);
	/**
	 * Connect a newly created I/O qpair.
	 *
	 * This function does any connection activities required for a newly created qpair.
	 * It should be called after spdk_client_ctrlr_alloc_io_qpair has been called with the
	 * create_only flag set to true in the spdk_client_io_qpair_opts structure.
	 *
	 * This call will fail if performed on a qpair that is already connected.
	 * For reconnecting qpairs, see spdk_client_ctrlr_reconnect_io_qpair.
	 *
	 * For fabrics like TCP and RDMA, this function actually sends the commands over the wire
	 * that connect the qpair. For PCIe, this function performs some internal state machine operations.
	 *
	 * \param ctrlr Client controller for which to allocate the I/O queue pair.
	 * \param qpair Opaque handle to the qpair to connect.
	 *
	 * return 0 on success or negated errno on failure. Specifically -EISCONN if the qpair is already connected.
	 *
	 */
	int spdk_client_ctrlr_connect_io_qpair(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair);

	/**
	 * Disconnect the given I/O qpair.
	 *
	 * This function must be called from the same thread as spdk_client_qpair_process_completions
	 * and the spdk_client_ns_cmd_* functions.
	 *
	 * After disconnect, calling spdk_client_qpair_process_completions or one of the
	 * spdk_client_ns_cmd* on a qpair will result in a return value of -ENXIO. A
	 * disconnected qpair may be reconnected with either the spdk_client_ctrlr_connect_io_qpair
	 * or spdk_client_ctrlr_reconnect_io_qpair APIs.
	 *
	 * \param qpair The qpair to disconnect.
	 */
	void spdk_client_ctrlr_disconnect_io_qpair(struct spdk_client_qpair *qpair);

	/**
	 * Attempt to reconnect the given qpair.
	 *
	 * This function is intended to be called on qpairs that have already been connected,
	 * but have since entered a failed state as indicated by a return value of -ENXIO from
	 * either spdk_client_qpair_process_completions or one of the spdk_client_ns_cmd_* functions.
	 * This function must be called from the same thread as spdk_client_qpair_process_completions
	 * and the spdk_client_ns_cmd_* functions.
	 *
	 * Calling this function has the same effect as calling spdk_client_ctrlr_disconnect_io_qpair
	 * followed by spdk_client_ctrlr_connect_io_qpair.
	 *
	 * This function may be called on newly created qpairs, but it does extra checks and attempts
	 * to disconnect the qpair before connecting it. The recommended API for newly created qpairs
	 * is spdk_client_ctrlr_connect_io_qpair.
	 *
	 * \param qpair The qpair to reconnect.
	 *
	 * \return 0 on success, or if the qpair was already connected.
	 * -EAGAIN if the driver was unable to reconnect during this call,
	 * but the controller is still connected and is either resetting or enabled.
	 * -ENODEV if the controller is removed. In this case, the controller cannot be recovered
	 * and the application will have to destroy it and the associated qpairs.
	 * -ENXIO if the controller is in a failed state but is not yet resetting. In this case,
	 * the application should call spdk_client_ctrlr_reset to reset the entire controller.
	 */
	int spdk_client_ctrlr_reconnect_io_qpair(struct spdk_client_qpair *qpair);

	/**
	 * Free an I/O queue pair that was allocated by spdk_client_ctrlr_alloc_io_qpair().
	 *
	 * The qpair must not be accessed after calling this function.
	 *
	 * \param qpair I/O queue pair to free.
	 *
	 * \return 0 on success.  This function will never return any value other than 0.
	 */
	int spdk_client_ctrlr_free_io_qpair(struct spdk_client_qpair *qpair);

	/**
	 * Process any outstanding completions for I/O submitted on a queue pair.
	 *
	 * This call is non-blocking, i.e. it only processes completions that are ready
	 * at the time of this function call. It does not wait for outstanding commands
	 * to finish.
	 *
	 * For each completed command, the request's callback function will be called if
	 * specified as non-NULL when the request was submitted.
	 *
	 * The caller must ensure that each queue pair is only used from one thread at a
	 * time.
	 *
	 * This function may be called at any point while the controller is attached to
	 * the SPDK Client driver.
	 *
	 * \sa spdk_req_cmd_cb
	 *
	 * \param qpair Queue pair to check for completions.
	 * \param max_completions Limit the number of completions to be processed in one
	 * call, or 0 for unlimited.
	 *
	 * \return number of completions processed (may be 0) or negated on error. -ENXIO
	 * in the special case that the qpair is failed at the transport layer.
	 */
	int32_t spdk_client_qpair_process_completions(struct spdk_client_qpair *qpair,
												  uint32_t max_completions);

	/**
	 * Returns the reason the qpair is disconnected.
	 *
	 * \param qpair The qpair to check.
	 *
	 * \return a valid spdk_client_qp_failure_reason.
	 */
	spdk_client_qp_failure_reason spdk_client_qpair_get_failure_reason(struct spdk_client_qpair *qpair);

	/**
	 * \brief Alloc Client I/O queue identifier.
	 *
	 * This function is only needed for the non-standard case of allocating queues using the raw
	 * command interface. In most cases \ref spdk_client_ctrlr_alloc_io_qpair should be sufficient.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \return qid on success, -1 on failure.
	 */
	int32_t spdk_client_ctrlr_alloc_qid(struct spdk_client_ctrlr *ctrlr);

	/**
	 * \brief Free Client I/O queue identifier.
	 *
	 * This function must only be called with qids previously allocated with \ref spdk_client_ctrlr_alloc_qid.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param qid Client Queue Identifier.
	 */
	void spdk_client_ctrlr_free_qid(struct spdk_client_ctrlr *ctrlr, uint16_t qid);

	/**
	 * Opaque handle for a poll group. A poll group is a collection of spdk_client_qpair
	 * objects that are polled for completions as a unit.
	 *
	 * Returned by spdk_client_poll_group_create().
	 */
	struct spdk_client_poll_group;

	/**
	 * This function alerts the user to disconnected qpairs when calling
	 * spdk_client_poll_group_process_completions.
	 */
	typedef void (*spdk_client_disconnected_qpair_cb)(struct spdk_client_qpair *qpair,
													  void *poll_group_ctx);

	/**
	 * Create a new poll group.
	 *
	 * \param ctx A user supplied context that can be retrieved later with spdk_client_poll_group_get_ctx
	 *
	 * \return Pointer to the new poll group, or NULL on error.
	 */
	struct spdk_client_poll_group *spdk_client_poll_group_create(void *ctx);

	/**
	 * Add an spdk_client_qpair to a poll group. qpairs may only be added to
	 * a poll group if they are in the disconnected state; i.e. either they were
	 * just allocated and not yet connected or they have been disconnected with a call
	 * to spdk_client_ctrlr_disconnect_io_qpair.
	 *
	 * \param group The group to which the qpair will be added.
	 * \param qpair The qpair to add to the poll group.
	 *
	 * return 0 on success, -EINVAL if the qpair is not in the disabled state, -ENODEV if the transport
	 * doesn't exist, -ENOMEM on memory allocation failures, or -EPROTO on a protocol (transport) specific failure.
	 */
	int spdk_client_poll_group_add(struct spdk_client_poll_group *group, struct spdk_client_qpair *qpair);

	/**
	 * Remove a disconnected spdk_client_qpair from a poll group.
	 *
	 * \param group The group from which to remove the qpair.
	 * \param qpair The qpair to remove from the poll group.
	 *
	 * return 0 on success, -ENOENT if the qpair is not found in the group, -EINVAL if the qpair is not
	 * disconnected in the group, or -EPROTO on a protocol (transport) specific failure.
	 */
	int spdk_client_poll_group_remove(struct spdk_client_poll_group *group, struct spdk_client_qpair *qpair);

	/**
	 * Destroy an empty poll group.
	 *
	 * \param group The group to destroy.
	 *
	 * return 0 on success, -EBUSY if the poll group is not empty.
	 */
	int spdk_client_poll_group_destroy(struct spdk_client_poll_group *group);

	/**
	 * Poll for completions on all qpairs in this poll group.
	 *
	 * the disconnected_qpair_cb will be called for all disconnected qpairs in the poll group
	 * including qpairs which fail within the context of this call.
	 * The user is responsible for trying to reconnect or destroy those qpairs.
	 *
	 * \param group The group on which to poll for completions.
	 * \param completions_per_qpair The maximum number of completions per qpair.
	 * \param disconnected_qpair_cb A callback function of type spdk_client_disconnected_qpair_cb. Must be non-NULL.
	 *
	 * return The number of completions across all qpairs, -EINVAL if no disconnected_qpair_cb is passed, or
	 * -EIO if the shared completion queue cannot be polled for the RDMA transport.
	 */
	int64_t spdk_client_poll_group_process_completions(struct spdk_client_poll_group *group,
													   uint32_t completions_per_qpair, spdk_client_disconnected_qpair_cb disconnected_qpair_cb);

	/**
	 * Retrieves transport statistics for the given poll group.
	 *
	 * Note: the structure returned by this function should later be freed with
	 * @b spdk_client_poll_group_free_stats function
	 *
	 * \param group Pointer to CLIENT poll group
	 * \param stats Double pointer to statistics to be filled by this function
	 * \return 0 on success or negated errno on failure
	 */
	int spdk_client_poll_group_get_stats(struct spdk_client_poll_group *group,
										 struct spdk_client_poll_group_stat **stats);

	/**
	 * Frees poll group statistics retrieved using @b spdk_client_poll_group_get_stats function
	 *
	 * @param group Pointer to a poll group
	 * @param stat Pointer to statistics to be released
	 */
	void spdk_client_poll_group_free_stats(struct spdk_client_poll_group *group,
										   struct spdk_client_poll_group_stat *stat);

	/**
	 * Restart the SGL walk to the specified offset when the command has scattered payloads.
	 *
	 * \param cb_arg Argument passed to readv/writev.
	 * \param offset Offset for SGL.
	 */
	typedef void (*spdk_client_req_reset_sgl_cb)(void *cb_arg, uint32_t offset);

	/**
	 * Fill out *address and *length with the current SGL entry and advance to the next
	 * entry for the next time the callback is invoked.
	 *
	 * The described segment must be physically contiguous.
	 *
	 * \param cb_arg Argument passed to readv/writev.
	 * \param address Virtual address of this segment, a value of UINT64_MAX
	 * means the segment should be described via Bit Bucket SGL.
	 * \param length Length of this physical segment.
	 */
	typedef int (*spdk_client_req_next_sge_cb)(void *cb_arg, void **address, uint32_t *length);

	/**
	 * \brief Gets the Client qpair ID for the specified qpair.
	 *
	 * \param qpair Pointer to the Client queue pair.
	 * \returns ID for the specified qpair.
	 */
	uint16_t spdk_client_qpair_get_id(struct spdk_client_qpair *qpair);

	struct ibv_context;
	struct ibv_pd;
	struct ibv_mr;

	/**

	 * Opaque handle for a transport poll group. Used by the transport function table.
	 */
	struct spdk_client_transport_poll_group;

	/**
	 * Signature for callback invoked after completing a register read/write operation.
	 *
	 * \param ctx Context passed by the user.
	 * \param value Value of the register, undefined in case of a failure.
	 * \param cpl Completion queue entry that contains the status of the command.
	 */
	typedef void (*spdk_client_reg_cb)(void *ctx, uint64_t value, const struct spdk_rpc_req_cpl *cpl);

	struct client_request;

	struct spdk_client_transport;

	struct spdk_client_transport_ops
	{
		char name[SPDK_SRV_TRSTRING_MAX_LEN + 1];

		enum spdk_client_transport_type type;

		struct spdk_client_ctrlr *(*ctrlr_construct)(
			const struct spdk_client_ctrlr_opts *opts,
			void *devhandle);

		int (*ctrlr_destruct)(struct spdk_client_ctrlr *ctrlr);

		int (*ctrlr_enable)(struct spdk_client_ctrlr *ctrlr);

		uint32_t (*ctrlr_get_max_xfer_size)(struct spdk_client_ctrlr *ctrlr);

		uint16_t (*ctrlr_get_max_sges)(struct spdk_client_ctrlr *ctrlr);

		int (*ctrlr_reserve_cmb)(struct spdk_client_ctrlr *ctrlr);

		void *(*ctrlr_map_cmb)(struct spdk_client_ctrlr *ctrlr, size_t *size);

		int (*ctrlr_unmap_cmb)(struct spdk_client_ctrlr *ctrlr);

		int (*ctrlr_enable_pmr)(struct spdk_client_ctrlr *ctrlr);

		int (*ctrlr_disable_pmr)(struct spdk_client_ctrlr *ctrlr);

		void *(*ctrlr_map_pmr)(struct spdk_client_ctrlr *ctrlr, size_t *size);

		int (*ctrlr_unmap_pmr)(struct spdk_client_ctrlr *ctrlr);

		struct spdk_client_qpair *(*ctrlr_create_io_qpair)(struct spdk_client_ctrlr *ctrlr, uint16_t qid,
														   const struct spdk_client_io_qpair_opts *opts);

		int (*ctrlr_delete_io_qpair)(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair);

		int (*ctrlr_connect_qpair)(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair);

		void (*ctrlr_disconnect_qpair)(struct spdk_client_ctrlr *ctrlr, struct spdk_client_qpair *qpair);

		void (*qpair_abort_reqs)(struct spdk_client_qpair *qpair, uint32_t dnr);

		int (*qpair_submit_request)(struct spdk_client_qpair *qpair, struct client_request *req);

		int32_t (*qpair_process_completions)(struct spdk_client_qpair *qpair, uint32_t max_completions);

		int (*qpair_iterate_requests)(struct spdk_client_qpair *qpair,
									  int (*iter_fn)(struct client_request *req, void *arg),
									  void *arg);

		struct spdk_client_transport_poll_group *(*poll_group_create)(void);
		struct spdk_client_transport_poll_group *(*qpair_get_optimal_poll_group)(
			struct spdk_client_qpair *qpair);

		int (*poll_group_add)(struct spdk_client_transport_poll_group *tgroup, struct spdk_client_qpair *qpair);

		int (*poll_group_remove)(struct spdk_client_transport_poll_group *tgroup,
								 struct spdk_client_qpair *qpair);

		int (*poll_group_connect_qpair)(struct spdk_client_qpair *qpair);

		int (*poll_group_disconnect_qpair)(struct spdk_client_qpair *qpair);

		int64_t (*poll_group_process_completions)(struct spdk_client_transport_poll_group *tgroup,
												  uint32_t completions_per_qpair, spdk_client_disconnected_qpair_cb disconnected_qpair_cb);

		int (*poll_group_destroy)(struct spdk_client_transport_poll_group *tgroup);

		int (*poll_group_get_stats)(struct spdk_client_transport_poll_group *tgroup,
									struct spdk_client_transport_poll_group_stat **stats);

		void (*poll_group_free_stats)(struct spdk_client_transport_poll_group *tgroup,
									  struct spdk_client_transport_poll_group_stat *stats);

		int (*ctrlr_get_memory_domains)(const struct spdk_client_ctrlr *ctrlr,
										struct spdk_memory_domain **domains,
										int array_size);
	};

	/**
	 * Register the operations for a given transport type.
	 *
	 * This function should be invoked by referencing the macro
	 * SPDK_CLIENT_TRANSPORT_REGISTER macro in the transport's .c file.
	 *
	 * \param ops The operations associated with an Client-oF transport.
	 */
	void spdk_client_transport_register(const struct spdk_client_transport_ops *ops);

	void
	client_disconnected_qpair_cb(struct spdk_client_qpair *qpair, void *poll_group_ctx);

	int spdk_client_submit_rpc_request(struct spdk_client_qpair *qpair, uint32_t opc, char *raw_data, uint32_t length,
									   spdk_rpc_request_cb cb_fn, void *cb_arg, bool chek_md5);
	int spdk_client_submit_rpc_request_iovs(struct spdk_client_qpair *qpair, uint32_t opc, struct iovec *raw_ioves, int raw_iov_cnt, uint32_t length,
											spdk_rpc_request_cb cb_fn, void *cb_arg, bool chek_md5);

	int spdk_client_empty_free_request(struct spdk_client_qpair *qpair);

	int spdk_client_submit_rpc_request_iovs_directly(struct spdk_client_qpair *qpair, struct iovec *out_ioves, int out_iov_cnt, uint32_t length, spdk_rpc_request_cb cb_fn, void *cb_arg);

	void spdk_client_reclaim_rpc_request(struct rpc_request *req);
	bool spdk_client_ctrlr_has_free_memory(struct spdk_client_qpair *qpair, size_t size);

/*
 * Macro used to register new transports.
 */
#define SPDK_CLIENT_TRANSPORT_REGISTER(name, transport_ops)                               \
	static void __attribute__((constructor)) _spdk_client_transport_register_##name(void) \
	{                                                                                     \
		spdk_client_transport_register(transport_ops);                                    \
	}

#ifdef __cplusplus
}
#endif

#endif
