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
#define SPDK_CLIENT_TRANSPORT_NAME_FC "FC"
#define SPDK_CLIENT_TRANSPORT_NAME_PCIE "PCIE"
#define SPDK_CLIENT_TRANSPORT_NAME_RDMA "RDMA"
#define SPDK_CLIENT_TRANSPORT_NAME_TCP "TCP"
#define SPDK_CLIENT_TRANSPORT_NAME_VFIOUSER "VFIOUSER"
#define SPDK_CLIENT_TRANSPORT_NAME_CUSTOM "CUSTOM"

#define SPDK_SRV_PRIORITY_MAX_LEN 4
#define SPDK_SRV_MEMORY_POOL_ELEMENT_SIZE 4096

	/**
	 * Opaque handle to a controller. Returned by spdk_client_probe()'s attach_cb.
	 */
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

	enum spdk_client_cc_css
	{
		SPDK_CLIENT_CC_CSS_NVM = 0x0,  /**< NVM command set */
		SPDK_CLIENT_CC_CSS_IOCS = 0x6, /**< One or more I/O command sets */
		SPDK_CLIENT_CC_CSS_NOIO = 0x7, /**< No I/O, only admin */
	};

#define SPDK_CLIENT_CAP_CSS_NVM (1u << SPDK_CLIENT_CC_CSS_NVM)	 /**< NVM command set supported */
#define SPDK_CLIENT_CAP_CSS_IOCS (1u << SPDK_CLIENT_CC_CSS_IOCS) /**< One or more I/O Command sets supported */
#define SPDK_CLIENT_CAP_CSS_NOIO (1u << SPDK_CLIENT_CC_CSS_NOIO) /**< No I/O, only admin */

	struct spdk_client_format
	{
		uint32_t lbaf : 4;
		uint32_t ms : 1;
		uint32_t pi : 3;
		uint32_t pil : 1;
		uint32_t ses : 3;
		uint32_t reserved : 20;
	};
	SPDK_STATIC_ASSERT(sizeof(struct spdk_client_format) == 4, "Incorrect size");

	/**
	 * Client controller initialization options.
	 *
	 * A pointer to this structure will be provided for each probe callback from spdk_client_probe() to
	 * allow the user to request non-default options, and the actual options enabled on the controller
	 * will be provided during the attach callback.
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
		 * The I/O command set to select.
		 *
		 * If the requested command set is not supported, the controller
		 * initialization process will not proceed. By default, the NVM
		 * command set is used.
		 */
		enum spdk_client_cc_css command_set;

		/**
		 * Admin commands timeout in milliseconds (0 = no timeout).
		 *
		 * The timeout value is used for admin commands submitted internally
		 * by the client driver during initialization, before the user is able
		 * to call spdk_client_ctrlr_register_timeout_callback(). By default,
		 * this is set to 120 seconds, users can change it in the probing
		 * callback.
		 */
		uint32_t admin_timeout_ms;

		/**
		 * It is used for TCP transport.
		 *
		 * Set to true, means having header digest for the header in the Client/TCP PDU
		 */
		bool header_digest;

		/**
		 * It is used for TCP transport.
		 *
		 * Set to true, means having data digest for the data in the Client/TCP PDU
		 */
		bool data_digest;

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
		 * The queue depth of Client Admin queue.
		 */
		uint16_t admin_queue_size;

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

		/**
		 * Disable reading ANA log page. The upper layer should reading ANA log page instead
		 * if set to true.
		 *
		 * Default is `false` (ANA log page is read).
		 */
		bool disable_read_ana_log_page;

		uint32_t sector_size;

		// original ns fields
		/*
		 * Size of data transferred as part of each block,
		 * including metadata if FLBAS indicates the metadata is transferred
		 * as part of the data buffer at the end of each LBA.
		 */
		uint32_t extended_lba_size;
		uint32_t md_size;
		//	uint32_t			pi_type;
		uint32_t sectors_per_max_io;
		//	uint32_t			sectors_per_max_io_no_md;
		uint32_t sectors_per_stripe;
	};

	/**
	 * Client acceleration operation callback.
	 *
	 * \param cb_arg The user provided arg which is passed to the corresponding accelerated function call
	 * defined in struct spdk_client_accel_fn_table.
	 * \param status 0 if it completed successfully, or negative errno if it failed.
	 */
	typedef void (*spdk_client_accel_completion_cb)(void *cb_arg, int status);

	/**
	 * Function table for the Client accelerator device.
	 *
	 * This table provides a set of APIs to allow user to leverage
	 * accelerator functions.
	 */
	struct spdk_client_accel_fn_table
	{
		/**
		 * The size of spdk_client_accel_fun_table according to the caller of
		 * this library is used for ABI compatibility.  The library uses this
		 * field to know how many fields in this structure are valid.
		 * And the library will populate any remaining fields with default values.
		 * Newly added fields should be put at the end of the struct.
		 */
		size_t table_size;

		/** The accelerated crc32c function. */
		void (*submit_accel_crc32c)(void *ctx, uint32_t *dst, struct iovec *iov,
									uint32_t iov_cnt, uint32_t seed, spdk_client_accel_completion_cb cb_fn, void *cb_arg);
	};

	/**
	 * Indicate whether a ctrlr handle is associated with a Discovery controller.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return true if a discovery controller, else false.
	 */
	bool spdk_client_ctrlr_is_discovery(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Indicate whether a ctrlr handle is associated with a fabrics controller.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return true if a fabrics controller, else false.
	 */
	bool spdk_client_ctrlr_is_fabrics(struct spdk_client_ctrlr *ctrlr);

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
		 * PCIe Transport (locally attached devices)
		 */
		SPDK_CLIENT_TRANSPORT_PCIE = 256,

		/**
		 * RDMA Transport (RoCE, iWARP, etc.)
		 */
		SPDK_CLIENT_TRANSPORT_RDMA = SPDK_SRV_TRTYPE_RDMA,

		/**
		 * TCP Transport
		 */
		SPDK_CLIENT_TRANSPORT_TCP = SPDK_SRV_TRTYPE_TCP,

		/**
		 * Custom VFIO User Transport (Not spec defined)
		 */
		SPDK_CLIENT_TRANSPORT_VFIOUSER = 1024,

		/**
		 * Custom Transport (Not spec defined)
		 */
		SPDK_CLIENT_TRANSPORT_CUSTOM = 4096,
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

	struct spdk_client_pcie_stat
	{
		uint64_t polls;
		uint64_t idle_polls;
		uint64_t completions;
		uint64_t cq_doorbell_updates;
		uint64_t submitted_requests;
		uint64_t queued_requests;
		uint64_t sq_doobell_updates;
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
			struct spdk_client_pcie_stat pcie;
			struct spdk_client_tcp_stat tcp;
		};
	};

	struct spdk_client_poll_group_stat
	{
		uint32_t num_transports;
		struct spdk_client_transport_poll_group_stat **transport_stat;
	};

	/*
	 * Controller support flags
	 *
	 * Used for identifying if the controller supports these flags.
	 */
	enum spdk_client_ctrlr_flags
	{
		SPDK_CLIENT_CTRLR_SGL_SUPPORTED = 1 << 0,				 /**< SGL is supported */
		SPDK_CLIENT_CTRLR_SECURITY_SEND_RECV_SUPPORTED = 1 << 1, /**< security send/receive is supported */
		SPDK_CLIENT_CTRLR_WRR_SUPPORTED = 1 << 2,				 /**< Weighted Round Robin is supported */
		SPDK_CLIENT_CTRLR_COMPARE_AND_WRITE_SUPPORTED = 1 << 3,	 /**< Compare and write fused operations supported */
		SPDK_CLIENT_CTRLR_SGL_REQUIRES_DWORD_ALIGNMENT = 1 << 4, /**< Dword alignment is required for SGL */
		SPDK_CLIENT_CTRLR_ZONE_APPEND_SUPPORTED = 1 << 5,		 /**< Zone Append is supported (within Zoned Namespaces) */
		SPDK_CLIENT_CTRLR_DIRECTIVES_SUPPORTED = 1 << 6,		 /**< The Directives is supported */
	};

	/**
	 * Structure with optional IO request parameters
	 */
	struct spdk_client_ns_cmd_ext_io_opts
	{
		/** size of this structure in bytes */
		size_t size;
		/** Memory domain which describes data payload in IO request. The controller must support
		 * the corresponding memory domain type, refer to \ref spdk_client_ctrlr_get_memory_domains */
		struct spdk_memory_domain *memory_domain;
		/** User context to be passed to memory domain operations */
		void *memory_domain_ctx;
		/** Flags for this IO, defined in client_spec.h */
		uint32_t io_flags;
		/** Virtual address pointer to the metadata payload, the length of metadata is specified by \ref spdk_client_ns_get_md_size */
		void *metadata;
		/** Application tag mask to use end-to-end protection information. */
		uint16_t apptag_mask;
		/** Application tag to use end-to-end protection information. */
		uint16_t apptag;
	};

	/**
	 * Signature for callback function invoked when a command is completed.
	 *
	 * \param ctx Callback context provided when the command was submitted.
	 * \param cpl Completion queue entry that contains the completion status.
	 */
	typedef void (*spdk_client_cmd_cb)(void *ctx, const struct spdk_req_cpl *cpl);

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
	 * traddr       | Transport address (e.g. 0000:04:00.0 for PCIe, 192.168.100.8 for RDMA, or WWN for FC)
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
	 * Fill in the trtype and trstring fields of this trid based on a known transport type.
	 *
	 * \param trid The trid to fill out.
	 * \param trtype The transport type to use for filling the trid fields. Only valid for
	 * transport types referenced in the Client-oF spec.
	 */
	void spdk_client_trid_populate_transport(struct spdk_client_transport_id *trid,
											 enum spdk_client_transport_type trtype);

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
	 * Compare two transport IDs.
	 *
	 * The result of this function may be used to sort transport IDs in a consistent
	 * order; however, the comparison result is not guaranteed to be consistent across
	 * library versions.
	 *
	 * This function uses a case-insensitive comparison for string fields, but it does
	 * not otherwise normalize the transport ID. It is the caller's responsibility to
	 * provide the transport IDs in a consistent format.
	 *
	 * \param trid1 First transport ID to compare.
	 * \param trid2 Second transport ID to compare.
	 *
	 * \return 0 if trid1 == trid2, less than 0 if trid1 < trid2, greater than 0 if
	 * trid1 > trid2.
	 */
	int spdk_client_transport_id_compare(const struct spdk_client_transport_id *trid1,
										 const struct spdk_client_transport_id *trid2);

	/**
	 * Determine whether the Client library can handle a specific Client over Fabrics
	 * transport type.
	 *
	 * \param trtype Client over Fabrics transport type to check.
	 *
	 * \return true if trtype is supported or false if it is not supported or if
	 * SPDK_CLIENT_TRANSPORT_CUSTOM is supplied as trtype since it can represent multiple
	 * transports.
	 */
	bool spdk_client_transport_available(enum spdk_client_transport_type trtype);

	/**
	 * Determine whether the Client library can handle a specific Client over Fabrics
	 * transport type.
	 *
	 * \param transport_name Name of the Client over Fabrics transport type to check.
	 *
	 * \return true if transport_name is supported or false if it is not supported.
	 */
	bool spdk_client_transport_available_by_name(const char *transport_name);

	/**
	 * Callback for spdk_client_probe() enumeration.
	 *
	 * \param cb_ctx Opaque value passed to spdk_client_probe().
	 * \param trid Client transport identifier.
	 * \param opts Client controller initialization options. This structure will be
	 * populated with the default values on entry, and the user callback may update
	 * any options to request a different value. The controller may not support all
	 * requested parameters, so the final values will be provided during the attach
	 * callback.
	 *
	 * \return true to attach to this device.
	 */
	typedef bool (*spdk_client_probe_cb)(void *cb_ctx, const struct spdk_client_transport_id *trid,
										 struct spdk_client_ctrlr_opts *opts);

	/**
	 * Callback for spdk_client_attach() to report a device that has been attached to
	 * the userspace Client driver.
	 *
	 * \param cb_ctx Opaque value passed to spdk_client_attach_cb().
	 * \param trid Client transport identifier.
	 * \param ctrlr Opaque handle to Client controller.
	 * \param opts Client controller initialization options that were actually used.
	 * Options may differ from the requested options from the attach call depending
	 * on what the controller supports.
	 */
	typedef void (*spdk_client_attach_cb)(void *cb_ctx, const struct spdk_client_transport_id *trid,
										  struct spdk_client_ctrlr *ctrlr,
										  const struct spdk_client_ctrlr_opts *opts);

	/**
	 * Callback for spdk_client_remove() to report that a device attached to the userspace
	 * Client driver has been removed from the system.
	 *
	 * The controller will remain in a failed state (any new I/O submitted will fail).
	 *
	 * The controller must be detached from the userspace driver by calling spdk_client_detach()
	 * once the controller is no longer in use. It is up to the library user to ensure
	 * that no other threads are using the controller before calling spdk_client_detach().
	 *
	 * \param cb_ctx Opaque value passed to spdk_client_remove_cb().
	 * \param ctrlr Client controller instance that was removed.
	 */
	typedef void (*spdk_client_remove_cb)(void *cb_ctx, struct spdk_client_ctrlr *ctrlr);

	typedef bool (*spdk_client_pcie_hotplug_filter_cb)(const struct spdk_pci_addr *addr);

	/**
	 * Enumerate the bus indicated by the transport ID and attach the userspace Client
	 * driver to each device found if desired.
	 *
	 * This function is not thread safe and should only be called from one thread at
	 * a time while no other threads are actively using any Client devices.
	 *
	 * If called from a secondary process, only devices that have been attached to
	 * the userspace driver in the primary process will be probed.
	 *
	 * If called more than once, only devices that are not already attached to the
	 * SPDK Client driver will be reported.
	 *
	 * To stop using the the controller and release its associated resources,
	 * call spdk_client_detach() with the spdk_client_ctrlr instance from the attach_cb()
	 * function.
	 *
	 * \param trid The transport ID indicating which bus to enumerate. If the trtype
	 * is PCIe or trid is NULL, this will scan the local PCIe bus. If the trtype is
	 * RDMA, the traddr and trsvcid must point at the location of an Client-oF discovery
	 * service.
	 * \param cb_ctx Opaque value which will be passed back in cb_ctx parameter of
	 * the callbacks.
	 * \param probe_cb will be called once per Client device found in the system.
	 * \param attach_cb will be called for devices for which probe_cb returned true
	 * once that Client controller has been attached to the userspace driver.
	 * \param remove_cb will be called for devices that were attached in a previous
	 * spdk_client_probe() call but are no longer attached to the system. Optional;
	 * specify NULL if removal notices are not desired.
	 *
	 * \return 0 on success, -1 on failure.
	 */
	int spdk_client_probe(const struct spdk_client_transport_id *trid,
						  void *cb_ctx,
						  spdk_client_probe_cb probe_cb,
						  spdk_client_attach_cb attach_cb,
						  spdk_client_remove_cb remove_cb);

	/**
	 * Connect the Client driver to the device located at the given transport ID.
	 *
	 * This function is not thread safe and should only be called from one thread at
	 * a time while no other threads are actively using this Client device.
	 *
	 * If called from a secondary process, only the device that has been attached to
	 * the userspace driver in the primary process will be connected.
	 *
	 * If connecting to multiple controllers, it is suggested to use spdk_client_probe()
	 * and filter the requested controllers with the probe callback. For PCIe controllers,
	 * spdk_client_probe() will be more efficient since the controller resets will happen
	 * in parallel.
	 *
	 * To stop using the the controller and release its associated resources, call
	 * spdk_client_detach() with the spdk_client_ctrlr instance returned by this function.
	 *
	 * \param trid The transport ID indicating which device to connect. If the trtype
	 * is PCIe, this will connect the local PCIe bus. If the trtype is RDMA, the traddr
	 * and trsvcid must point at the location of an Client-oF service.
	 * \param opts Client controller initialization options. Default values will be used
	 * if the user does not specify the options. The controller may not support all
	 * requested parameters.
	 * \param opts_size Must be set to sizeof(struct spdk_client_ctrlr_opts), or 0 if
	 * opts is NULL.
	 *
	 * \return pointer to the connected Client controller or NULL if there is any failure.
	 *
	 */
	struct spdk_client_ctrlr *spdk_client_connect(const struct spdk_client_transport_id *trid,
												  const struct spdk_client_ctrlr_opts *opts,
												  size_t opts_size);

	struct spdk_client_probe_ctx;

	/**
	 * Connect the Client driver to the device located at the given transport ID.
	 *
	 * The function will return a probe context on success, controller associates with
	 * the context is not ready for use, user must call spdk_client_probe_poll_async()
	 * until spdk_client_probe_poll_async() returns 0.
	 *
	 * \param trid The transport ID indicating which device to connect. If the trtype
	 * is PCIe, this will connect the local PCIe bus. If the trtype is RDMA, the traddr
	 * and trsvcid must point at the location of an Client-oF service.
	 * \param opts Client controller initialization options. Default values will be used
	 * if the user does not specify the options. The controller may not support all
	 * requested parameters.
	 * \param attach_cb will be called once the Client controller has been attached
	 * to the userspace driver.
	 *
	 * \return probe context on success, NULL on failure.
	 *
	 */
	struct spdk_client_probe_ctx *spdk_client_connect_async(const struct spdk_client_transport_id *trid,
															const struct spdk_client_ctrlr_opts *opts,
															spdk_client_attach_cb attach_cb);

	/**
	 * Probe and add controllers to the probe context list.
	 *
	 * Users must call spdk_client_probe_poll_async() to initialize
	 * controllers in the probe context list to the READY state.
	 *
	 * \param trid The transport ID indicating which bus to enumerate. If the trtype
	 * is PCIe or trid is NULL, this will scan the local PCIe bus. If the trtype is
	 * RDMA, the traddr and trsvcid must point at the location of an Client-oF discovery
	 * service.
	 * \param cb_ctx Opaque value which will be passed back in cb_ctx parameter of
	 * the callbacks.
	 * \param probe_cb will be called once per Client device found in the system.
	 * \param attach_cb will be called for devices for which probe_cb returned true
	 * once that Client controller has been attached to the userspace driver.
	 * \param remove_cb will be called for devices that were attached in a previous
	 * spdk_client_probe() call but are no longer attached to the system. Optional;
	 * specify NULL if removal notices are not desired.
	 *
	 * \return probe context on success, NULL on failure.
	 */
	struct spdk_client_probe_ctx *spdk_client_probe_async(const struct spdk_client_transport_id *trid,
														  void *cb_ctx,
														  spdk_client_probe_cb probe_cb,
														  spdk_client_attach_cb attach_cb,
														  spdk_client_remove_cb remove_cb);

	/**
	 * Proceed with attaching controllers associated with the probe context.
	 *
	 * The probe context is one returned from a previous call to
	 * spdk_client_probe_async().  Users must call this function on the
	 * probe context until it returns 0.
	 *
	 * If any controllers fail to attach, there is no explicit notification.
	 * Users can detect attachment failure by comparing attach_cb invocations
	 * with the number of times where the user returned true for the
	 * probe_cb.
	 *
	 * \param probe_ctx Context used to track probe actions.
	 *
	 * \return 0 if all probe operations are complete; the probe_ctx
	 * is also freed and no longer valid.
	 * \return -EAGAIN if there are still pending probe operations; user must call
	 * spdk_client_probe_poll_async again to continue progress.
	 */
	int spdk_client_probe_poll_async(struct spdk_client_probe_ctx *probe_ctx);

	/**
	 * Detach specified device returned by spdk_client_probe()'s attach_cb from the
	 * Client driver.
	 *
	 * On success, the spdk_client_ctrlr handle is no longer valid.
	 *
	 * This function should be called from a single thread while no other threads
	 * are actively using the Client device.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return 0 on success, -1 on failure.
	 */
	int spdk_client_detach(struct spdk_client_ctrlr *ctrlr);

	struct spdk_client_detach_ctx;

	/**
	 * Allocate a context to track detachment of multiple controllers if this call is the
	 * first successful start of detachment in a sequence, or use the passed context otherwise.
	 *
	 * Then, start detaching the specified device returned by spdk_client_probe()'s attach_cb
	 * from the Client driver, and append this detachment to the context.
	 *
	 * User must call spdk_client_detach_poll_async() to complete the detachment.
	 *
	 * If the context is not allocated before this call, and if the specified device is detached
	 * locally from the caller process but any other process still attaches it or failed to be
	 * detached, context is not allocated.
	 *
	 * This function should be called from a single thread while no other threads are
	 * actively using the Client device.
	 *
	 * \param ctrlr Opaque handle to HVMe controller.
	 * \param detach_ctx Reference to the context in a sequence. An new context is allocated
	 * if this call is the first successful start of detachment in a sequence, or use the
	 * passed context.
	 */
	int spdk_client_detach_async(struct spdk_client_ctrlr *ctrlr,
								 struct spdk_client_detach_ctx **detach_ctx);

	/**
	 * Poll detachment of multiple controllers until they complete.
	 *
	 * User must call this function until it returns 0.
	 *
	 * \param detach_ctx Context to track the detachment.
	 *
	 * \return 0 if all detachments complete; the context is also freed and no longer valid.
	 * \return -EAGAIN if any detachment is still in progress; users must call
	 * spdk_client_detach_poll_async() again to continue progress.
	 */
	int spdk_client_detach_poll_async(struct spdk_client_detach_ctx *detach_ctx);

	/**
	 * Continue calling spdk_client_detach_poll_async() internally until it returns 0.
	 *
	 * \param detach_ctx Context to track the detachment.
	 */
	void spdk_client_detach_poll(struct spdk_client_detach_ctx *detach_ctx);

	/**
	 * Set the remove callback and context to be invoked if the controller is removed.
	 *
	 * This will override any remove_cb and/or ctx specified when the controller was
	 * probed.
	 *
	 * This function may only be called from the primary process.  This function has
	 * no effect if called from a secondary process.
	 *
	 * \param ctrlr Opaque handle to an Client controller.
	 * \param remove_cb remove callback
	 * \param remove_ctx remove callback context
	 */
	void spdk_client_ctrlr_set_remove_cb(struct spdk_client_ctrlr *ctrlr,
										 spdk_client_remove_cb remove_cb, void *remove_ctx);

	/**
	 * Perform a full hardware reset of the Client controller.
	 *
	 * This function should be called from a single thread while no other threads
	 * are actively using the Client device.
	 *
	 * Any pointers returned from spdk_client_ctrlr_get_ns(), spdk_client_ns_get_data(),
	 * spdk_client_zns_ns_get_data(), and spdk_client_zns_ctrlr_get_data()
	 * may be invalidated by calling this function. The number of namespaces as returned
	 * by spdk_client_ctrlr_get_num_ns() may also change.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return 0 on success, -1 on failure.
	 */
	int spdk_client_ctrlr_reset(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Inform the driver that the application is preparing to reset the specified Client controller.
	 *
	 * This function allows the driver to make decisions knowing that a reset is about to happen.
	 * For example, the pcie transport in this case could skip sending DELETE_CQ and DELETE_SQ
	 * commands to the controller if an io qpair is freed after this function is called.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 */
	void spdk_client_ctrlr_prepare_for_reset(struct spdk_client_ctrlr *ctrlr);

	struct spdk_client_ctrlr_reset_ctx;

	/**
	 * Create a context object that can be polled to perform a full hardware reset of the Client controller.
	 * (Deprecated, please use spdk_client_ctrlr_disconnect(), spdk_client_ctrlr_reconnect_async(), and
	 * spdk_client_ctrlr_reconnect_poll_async() instead.)
	 *
	 * The function will set the controller reset context on success, user must call
	 * spdk_client_ctrlr_reset_poll_async() until it returns a value other than -EAGAIN.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param reset_ctx Double pointer to reset context.
	 *
	 * \return 0 on success.
	 * \return -ENOMEM if context could not be allocated.
	 * \return -EBUSY if controller is already resetting.
	 * \return -ENXIO if controller has been removed.
	 *
	 */
	int spdk_client_ctrlr_reset_async(struct spdk_client_ctrlr *ctrlr,
									  struct spdk_client_ctrlr_reset_ctx **reset_ctx);

	/**
	 * Proceed with resetting controller associated with the controller reset context.
	 * (Deprecated, please use spdk_client_ctrlr_disconnect(), spdk_client_ctrlr_reconnect_async(), and
	 * spdk_client_ctrlr_reconnect_poll_async() instead.)
	 *
	 * The controller reset context is one returned from a previous call to
	 * spdk_client_ctrlr_reset_async().  Users must call this function on the
	 * controller reset context until it returns a value other than -EAGAIN.
	 *
	 * \param ctrlr_reset_ctx Context used to track controller reset actions.
	 *
	 * \return 0 if all controller reset operations are complete; the ctrlr_reset_ctx
	 * is also freed and no longer valid.
	 * \return -EAGAIN if there are still pending controller reset operations; user must call
	 * spdk_client_ctrlr_reset_poll_async again to continue progress.
	 */
	int spdk_client_ctrlr_reset_poll_async(struct spdk_client_ctrlr_reset_ctx *ctrlr_reset_ctx);

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
	 * Perform a Client subsystem reset.
	 *
	 * This function should be called from a single thread while no other threads
	 * are actively using the Client device.
	 * A subsystem reset is typically seen by the OS as a hot remove, followed by a
	 * hot add event.
	 *
	 * Any pointers returned from spdk_client_ctrlr_get_ns(), spdk_client_ns_get_data(),
	 * spdk_client_zns_ns_get_data(), and spdk_client_zns_ctrlr_get_data()
	 * may be invalidated by calling this function. The number of namespaces as returned
	 * by spdk_client_ctrlr_get_num_ns() may also change.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return 0 on success, -1 on failure, -ENOTSUP if subsystem reset is not supported.
	 */
	int spdk_client_ctrlr_reset_subsystem(struct spdk_client_ctrlr *ctrlr);

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
	 * Get the identify controller data as defined by the Client specification.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return pointer to the identify controller data.
	 */
	const struct spdk_client_ctrlr_data *spdk_client_ctrlr_get_data(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Get the Client controller CSTS (Status) register.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return the Client controller CSTS (Status) register.
	 */
	union spdk_client_csts_register spdk_client_ctrlr_get_regs_csts(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Get the Client controller CC (Configuration) register.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return the Client controller CC (Configuration) register.
	 */
	union spdk_client_cc_register spdk_client_ctrlr_get_regs_cc(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Get the Client controller CAP (Capabilities) register.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return the Client controller CAP (Capabilities) register.
	 */
	union spdk_client_cap_register spdk_client_ctrlr_get_regs_cap(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Get the Client controller VS (Version) register.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return the Client controller VS (Version) register.
	 */
	union spdk_client_vs_register spdk_client_ctrlr_get_regs_vs(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Get the Client controller CMBSZ (Controller Memory Buffer Size) register
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return the Client controller CMBSZ (Controller Memory Buffer Size) register.
	 */
	union spdk_client_cmbsz_register spdk_client_ctrlr_get_regs_cmbsz(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Get the Client controller PMRCAP (Persistent Memory Region Capabilities) register.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return the Client controller PMRCAP (Persistent Memory Region Capabilities) register.
	 */
	union spdk_client_pmrcap_register spdk_client_ctrlr_get_regs_pmrcap(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Get the Client controller BPINFO (Boot Partition Information) register.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return the Client controller BPINFO (Boot Partition Information) register.
	 */
	union spdk_client_bpinfo_register spdk_client_ctrlr_get_regs_bpinfo(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Get the Client controller PMR size.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return the Client controller PMR size or 0 if PMR is not supported.
	 */
	uint64_t spdk_client_ctrlr_get_pmrsz(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Get the maximum NSID value that will ever be used for the given controller
	 *
	 * This function is thread safe and can be called at any point while the
	 * controller is attached to the SPDK Client driver.
	 *
	 * This is equivalent to calling spdk_client_ctrlr_get_data() to get the
	 * spdk_client_ctrlr_data and then reading the nn field.
	 *
	 * The NN field in the Client specification represents the maximum value that a
	 * namespace ID can ever have. Prior to Client 1.2, this was also the number of
	 * active namespaces, but from 1.2 onward the list of namespaces may be
	 * sparsely populated. Unfortunately, the meaning of this field is often
	 * misinterpreted by drive manufacturers and Client-oF implementers so it is
	 * not considered reliable. AVOID USING THIS FUNCTION WHENEVER POSSIBLE.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return the number of namespaces.
	 */
	uint32_t spdk_client_ctrlr_get_num_ns(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Get the PCI device of a given Client controller.
	 *
	 * This only works for local (PCIe-attached) Client controllers; other transports
	 * will return NULL.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return PCI device of the Client controller, or NULL if not available.
	 */
	struct spdk_pci_device *spdk_client_ctrlr_get_pci_device(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Get the maximum data transfer size of a given Client controller.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return Maximum data transfer size of the Client controller in bytes.
	 *
	 * The I/O command helper functions, such as spdk_client_ns_cmd_read(), will split
	 * large I/Os automatically; however, it is up to the user to obey this limit for
	 * commands submitted with the raw command functions, such as spdk_client_ctrlr_cmd_io_raw().
	 */
	uint32_t spdk_client_ctrlr_get_max_xfer_size(const struct spdk_client_ctrlr *ctrlr);

	/**
	 * Check whether the nsid is an active nv for the given Client controller.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param nsid Namespace id.
	 *
	 * \return true if nsid is an active ns, or false otherwise.
	 */
	bool spdk_client_ctrlr_is_active_ns(struct spdk_client_ctrlr *ctrlr, uint32_t nsid);

	/**
	 * Get the nsid of the first active namespace.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return the nsid of the first active namespace, 0 if there are no active namespaces.
	 */
	uint32_t spdk_client_ctrlr_get_first_active_ns(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Get next active namespace given the previous nsid.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param prev_nsid Namespace id.
	 *
	 * \return a next active namespace given the previous nsid, 0 when there are no
	 * more active namespaces.
	 */
	uint32_t spdk_client_ctrlr_get_next_active_ns(struct spdk_client_ctrlr *ctrlr, uint32_t prev_nsid);

	/**
	 * Determine if a particular log page is supported by the given Client controller.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \sa spdk_client_ctrlr_cmd_get_log_page().
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param log_page Log page to query.
	 *
	 * \return true if supported, or false otherwise.
	 */
	bool spdk_client_ctrlr_is_log_page_supported(struct spdk_client_ctrlr *ctrlr, uint8_t log_page);

	/**
	 * Determine if a particular feature is supported by the given Client controller.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \sa spdk_client_ctrlr_cmd_get_feature().
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param feature_code Feature to query.
	 *
	 * \return true if supported, or false otherwise.
	 */
	bool spdk_client_ctrlr_is_feature_supported(struct spdk_client_ctrlr *ctrlr, uint8_t feature_code);

	/**
	 * Signature for callback function invoked when a command is completed.
	 *
	 * \param ctx Callback context provided when the command was submitted.
	 * \param cpl Completion queue entry that contains the completion status.
	 */
	typedef void (*spdk_req_cmd_cb)(void *ctx, const struct spdk_req_cpl *cpl);

	/**
	 * Signature for callback function invoked when an asynchronous error request
	 * command is completed.
	 *
	 * \param aer_cb_arg Context specified by spdk_client_register_aer_callback().
	 * \param cpl Completion queue entry that contains the completion status
	 * of the asynchronous event request that was completed.
	 */
	typedef void (*spdk_client_aer_cb)(void *aer_cb_arg,
									   const struct spdk_req_cpl *cpl);

	/**
	 * Register callback function invoked when an AER command is completed for the
	 * given Client controller.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param aer_cb_fn Callback function invoked when an asynchronous error request
	 * command is completed.
	 * \param aer_cb_arg Argument passed to callback function.
	 */
	void spdk_client_ctrlr_register_aer_callback(struct spdk_client_ctrlr *ctrlr,
												 spdk_client_aer_cb aer_cb_fn,
												 void *aer_cb_arg);

	/**
	 * Opaque handle to a queue pair.
	 *
	 * I/O queue pairs may be allocated using spdk_client_ctrlr_alloc_io_qpair().
	 */
	typedef void (*spdk_connected_cb)(void *cb_args, int status);
	struct spdk_client_qpair;

	/**
	 * Signature for the callback function invoked when a timeout is detected on a
	 * request.
	 *
	 * For timeouts detected on the admin queue pair, the qpair returned here will
	 * be NULL.  If the controller has a serious error condition and is unable to
	 * communicate with driver via completion queue, the controller can set Controller
	 * Fatal Status field to 1, then reset is required to recover from such error.
	 * Users may detect Controller Fatal Status when timeout happens.
	 *
	 * \param cb_arg Argument passed to callback function.
	 * \param ctrlr Opaque handle to Client controller.
	 * \param qpair Opaque handle to a queue pair.
	 * \param cid Command ID.
	 */
	typedef void (*spdk_client_timeout_cb)(void *cb_arg,
										   struct spdk_client_ctrlr *ctrlr,
										   struct spdk_client_qpair *qpair,
										   uint16_t cid);

	/**
	 * Register for timeout callback on a controller.
	 *
	 * The application can choose to register for timeout callback or not register
	 * for timeout callback.
	 *
	 * \param ctrlr Client controller on which to monitor for timeout.
	 * \param timeout_io_us Timeout value in microseconds for io commands.
	 * \param timeout_admin_us Timeout value in microseconds for admin commands.
	 * \param cb_fn A function pointer that points to the callback function.
	 * \param cb_arg Argument to the callback function.
	 */
	void spdk_client_ctrlr_register_timeout_callback(struct spdk_client_ctrlr *ctrlr,
													 uint64_t timeout_io_us, uint64_t timeout_admin_us,
													 spdk_client_timeout_cb cb_fn, void *cb_arg);

	/**
	 * Get a full discovery log page from the specified controller.
	 *
	 * This function will first read the discovery log header to determine the
	 * total number of valid entries in the discovery log, then it will allocate
	 * a buffer to hold the entire log and issue multiple GET_LOG_PAGE commands to
	 * get all of the entries.
	 *
	 * The application is responsible for calling
	 * \ref spdk_client_ctrlr_process_admin_completions to trigger processing of
	 * completions submitted by this function.
	 *
	 * \param ctrlr Pointer to the discovery controller.
	 * \param cb_fn Function to call when the operation is complete.
	 * \param cb_arg Argument to pass to cb_fn.
	 */
	// int spdk_client_ctrlr_get_discovery_log_page(struct spdk_client_ctrlr *ctrlr,
	// 		spdk_client_discovery_cb cb_fn, void *cb_arg);

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
			struct spdk_req_cmd *vaddr;
			uint64_t paddr;
			uint64_t buffer_size;
		} sq;
		struct
		{
			struct spdk_req_cpl *vaddr;
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

    struct spdk_mempool* spdk_client_ctrlr_get_mempool(struct spdk_client_qpair *qpair);

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
	 * Returns the reason the admin qpair for a given controller is disconnected.
	 *
	 * \param ctrlr The controller to check.
	 *
	 * \return a valid spdk_client_qp_failure_reason.
	 */
	spdk_client_qp_failure_reason spdk_client_ctrlr_get_admin_qp_failure_reason(
		struct spdk_client_ctrlr *ctrlr);

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
	 * Send the given NVM I/O command, I/O buffers, lists and all to the Client controller.
	 *
	 * This is a low level interface for submitting I/O commands directly.
	 *
	 * This function allows a caller to submit an I/O request that is
	 * COMPLETELY pre-defined, right down to the "physical" memory buffers.
	 * It is intended for testing hardware, specifying exact buffer location,
	 * alignment, and offset.  It also allows for specific choice of PRP
	 * and SGLs.
	 *
	 * The driver sets the CID.  EVERYTHING else is assumed set by the caller.
	 * Needless to say, this is potentially extremely dangerous for both the host
	 * (accidental/malicious storage usage/corruption), and the device.
	 * Thus its intent is for very specific hardware testing and environment
	 * reproduction.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * This function can only be used on PCIe controllers and qpairs.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param qpair I/O qpair to submit command.
	 * \param cmd NVM I/O command to submit.
	 * \param cb_fn Callback function invoked when the I/O command completes.
	 * \param cb_arg Argument passed to callback function.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */

	int spdk_client_ctrlr_io_cmd_raw_no_payload_build(struct spdk_client_ctrlr *ctrlr,
													  struct spdk_client_qpair *qpair,
													  struct spdk_req_cmd *cmd,
													  spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Send the given NVM I/O command to the Client controller.
	 *
	 * This is a low level interface for submitting I/O commands directly. Prefer
	 * the spdk_client_ns_cmd_* functions instead. The validity of the command will
	 * not be checked!
	 *
	 * When constructing the client_command it is not necessary to fill out the PRP
	 * list/SGL or the CID. The driver will handle both of those for you.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param qpair I/O qpair to submit command.
	 * \param cmd NVM I/O command to submit.
	 * \param buf Virtual memory address of a single physically contiguous buffer.
	 * \param len Size of buffer.
	 * \param cb_fn Callback function invoked when the I/O command completes.
	 * \param cb_arg Argument passed to callback function.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ctrlr_cmd_io_raw(struct spdk_client_ctrlr *ctrlr,
									 struct spdk_client_qpair *qpair,
									 struct spdk_req_cmd *cmd,
									 void *buf, uint32_t len,
									 spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Send the given NVM I/O command with metadata to the Client controller.
	 *
	 * This is a low level interface for submitting I/O commands directly. Prefer
	 * the spdk_client_ns_cmd_* functions instead. The validity of the command will
	 * not be checked!
	 *
	 * When constructing the client_command it is not necessary to fill out the PRP
	 * list/SGL or the CID. The driver will handle both of those for you.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param qpair I/O qpair to submit command.
	 * \param cmd NVM I/O command to submit.
	 * \param buf Virtual memory address of a single physically contiguous buffer.
	 * \param len Size of buffer.
	 * \param md_buf Virtual memory address of a single physically contiguous metadata
	 * buffer.
	 * \param cb_fn Callback function invoked when the I/O command completes.
	 * \param cb_arg Argument passed to callback function.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ctrlr_cmd_io_raw_with_md(struct spdk_client_ctrlr *ctrlr,
											 struct spdk_client_qpair *qpair,
											 struct spdk_req_cmd *cmd,
											 void *buf, uint32_t len, void *md_buf,
											 spdk_req_cmd_cb cb_fn, void *cb_arg);

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
	 * Send the given admin command to the Client controller.
	 *
	 * This is a low level interface for submitting admin commands directly. Prefer
	 * the spdk_client_ctrlr_cmd_* functions instead. The validity of the command will
	 * not be checked!
	 *
	 * When constructing the client_command it is not necessary to fill out the PRP
	 * list/SGL or the CID. The driver will handle both of those for you.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * Call spdk_client_ctrlr_process_admin_completions() to poll for completion
	 * of commands submitted through this function.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param cmd NVM admin command to submit.
	 * \param buf Virtual memory address of a single physically contiguous buffer.
	 * \param len Size of buffer.
	 * \param cb_fn Callback function invoked when the admin command completes.
	 * \param cb_arg Argument passed to callback function.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be
	 * allocated for this request, -ENXIO if the admin qpair is failed at the transport layer.
	 */
	int spdk_client_ctrlr_cmd_admin_raw(struct spdk_client_ctrlr *ctrlr,
										struct spdk_req_cmd *cmd,
										void *buf, uint32_t len,
										spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Process any outstanding completions for admin commands.
	 *
	 * This will process completions for admin commands submitted on any thread.
	 *
	 * This call is non-blocking, i.e. it only processes completions that are ready
	 * at the time of this function call. It does not wait for outstanding commands
	 * to finish.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 *
	 * \return number of completions processed (may be 0) or negated on error. -ENXIO
	 * in the special case that the qpair is failed at the transport layer.
	 */
	// int32_t spdk_client_ctrlr_process_admin_completions(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Opaque handle to a namespace. Obtained by calling spdk_client_ctrlr_get_ns().
	 */
	struct spdk_client_ns;

	/**
	 * Get a handle to a namespace for the given controller.
	 *
	 * Namespaces are numbered from 1 to the total number of namespaces. There will
	 * never be any gaps in the numbering. The number of namespaces is obtained by
	 * calling spdk_client_ctrlr_get_num_ns().
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param ns_id Namespace id.
	 *
	 * \return a pointer to the namespace.
	 */
	struct spdk_client_ns *spdk_client_ctrlr_get_ns(struct spdk_client_ctrlr *ctrlr, uint32_t ns_id);

	/**
	 * Get a specific log page from the Client controller.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * Call spdk_client_ctrlr_process_admin_completions() to poll for completion of
	 * commands submitted through this function.
	 *
	 * \sa spdk_client_ctrlr_is_log_page_supported()
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param log_page The log page identifier.
	 * \param nsid Depending on the log page, this may be 0, a namespace identifier,
	 * or SPDK_CLIENT_GLOBAL_NS_TAG.
	 * \param payload The pointer to the payload buffer.
	 * \param payload_size The size of payload buffer.
	 * \param offset Offset in bytes within the log page to start retrieving log page
	 * data. May only be non-zero if the controller supports extended data for Get Log
	 * Page as reported in the controller data log page attributes.
	 * \param cb_fn Callback function to invoke when the log page has been retrieved.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be
	 * allocated for this request, -ENXIO if the admin qpair is failed at the transport layer.
	 */
	int spdk_client_ctrlr_cmd_get_log_page(struct spdk_client_ctrlr *ctrlr,
										   uint8_t log_page, uint32_t nsid,
										   void *payload, uint32_t payload_size,
										   uint64_t offset,
										   spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Get a specific log page from the Client controller.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * This function allows specifying extra fields in cdw10 and cdw11 such as
	 * Retain Asynchronous Event and Log Specific Field.
	 *
	 * Call spdk_client_ctrlr_process_admin_completions() to poll for completion of
	 * commands submitted through this function.
	 *
	 * \sa spdk_client_ctrlr_is_log_page_supported()
	 *
	 * \param ctrlr Opaque handle to Client controller.
	 * \param log_page The log page identifier.
	 * \param nsid Depending on the log page, this may be 0, a namespace identifier,
	 * or SPDK_CLIENT_GLOBAL_NS_TAG.
	 * \param payload The pointer to the payload buffer.
	 * \param payload_size The size of payload buffer.
	 * \param offset Offset in bytes within the log page to start retrieving log page
	 * data. May only be non-zero if the controller supports extended data for Get Log
	 * Page as reported in the controller data log page attributes.
	 * \param cdw10 Value to specify for cdw10.  Specify 0 for numdl - it will be
	 * set by this function based on the payload_size parameter.  Specify 0 for lid -
	 * it will be set by this function based on the log_page parameter.
	 * \param cdw11 Value to specify for cdw11.  Specify 0 for numdu - it will be
	 * set by this function based on the payload_size.
	 * \param cdw14 Value to specify for cdw14.
	 * \param cb_fn Callback function to invoke when the log page has been retrieved.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be
	 * allocated for this request, -ENXIO if the admin qpair is failed at the transport layer.
	 */
	int spdk_client_ctrlr_cmd_get_log_page_ext(struct spdk_client_ctrlr *ctrlr, uint8_t log_page,
											   uint32_t nsid, void *payload, uint32_t payload_size,
											   uint64_t offset, uint32_t cdw10, uint32_t cdw11,
											   uint32_t cdw14, spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Abort a specific previously-submitted Client command.
	 *
	 * \sa spdk_client_ctrlr_register_timeout_callback()
	 *
	 * \param ctrlr Client controller to which the command was submitted.
	 * \param qpair Client queue pair to which the command was submitted. For admin
	 *  commands, pass NULL for the qpair.
	 * \param cid Command ID of the command to abort.
	 * \param cb_fn Callback function to invoke when the abort has completed.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be
	 * allocated for this request, -ENXIO if the admin qpair is failed at the transport layer.
	 */
	int spdk_client_ctrlr_cmd_abort(struct spdk_client_ctrlr *ctrlr,
									struct spdk_client_qpair *qpair,
									uint16_t cid,
									spdk_req_cmd_cb cb_fn,
									void *cb_arg);

	/**
	 * Abort previously submitted commands which have cmd_cb_arg as its callback argument.
	 *
	 * \param ctrlr Client controller to which the commands were submitted.
	 * \param qpair Client queue pair to which the commands were submitted. For admin
	 * commands, pass NULL for the qpair.
	 * \param cmd_cb_arg Callback argument for the Client commands which this function
	 * attempts to abort.
	 * \param cb_fn Callback function to invoke when this function has completed.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, negated errno otherwise.
	 */
	int spdk_client_ctrlr_cmd_abort_ext(struct spdk_client_ctrlr *ctrlr,
										struct spdk_client_qpair *qpair,
										void *cmd_cb_arg,
										spdk_req_cmd_cb cb_fn,
										void *cb_arg);

	/**
	 * Set specific feature for the given Client controller.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * Call spdk_client_ctrlr_process_admin_completions() to poll for completion of
	 * commands submitted through this function.
	 *
	 * \sa spdk_client_ctrlr_cmd_get_feature().
	 *
	 * \param ctrlr Client controller to manipulate.
	 * \param feature The feature identifier.
	 * \param cdw11 as defined by the specification for this command.
	 * \param cdw12 as defined by the specification for this command.
	 * \param payload The pointer to the payload buffer.
	 * \param payload_size The size of payload buffer.
	 * \param cb_fn Callback function to invoke when the feature has been set.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be
	 * allocated for this request, -ENXIO if the admin qpair is failed at the transport layer.
	 */
	int spdk_client_ctrlr_cmd_set_feature(struct spdk_client_ctrlr *ctrlr,
										  uint8_t feature, uint32_t cdw11, uint32_t cdw12,
										  void *payload, uint32_t payload_size,
										  spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Get specific feature from given Client controller.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * Call spdk_client_ctrlr_process_admin_completions() to poll for completion of
	 * commands submitted through this function.
	 *
	 * \sa spdk_client_ctrlr_cmd_set_feature()
	 *
	 * \param ctrlr Client controller to query.
	 * \param feature The feature identifier.
	 * \param cdw11 as defined by the specification for this command.
	 * \param payload The pointer to the payload buffer.
	 * \param payload_size The size of payload buffer.
	 * \param cb_fn Callback function to invoke when the feature has been retrieved.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, -ENOMEM if resources could not be allocated
	 * for this request, -ENXIO if the admin qpair is failed at the transport layer.
	 */
	int spdk_client_ctrlr_cmd_get_feature(struct spdk_client_ctrlr *ctrlr,
										  uint8_t feature, uint32_t cdw11,
										  void *payload, uint32_t payload_size,
										  spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Get specific feature from given Client controller.
	 *
	 * \param ctrlr Client controller to query.
	 * \param feature The feature identifier.
	 * \param cdw11 as defined by the specification for this command.
	 * \param payload The pointer to the payload buffer.
	 * \param payload_size The size of payload buffer.
	 * \param cb_fn Callback function to invoke when the feature has been retrieved.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param ns_id The namespace identifier.
	 *
	 * \return 0 if successfully submitted, -ENOMEM if resources could not be allocated
	 * for this request, -ENXIO if the admin qpair is failed at the transport layer.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * Call \ref spdk_client_ctrlr_process_admin_completions() to poll for completion
	 * of commands submitted through this function.
	 *
	 * \sa spdk_client_ctrlr_cmd_set_feature_ns()
	 */
	int spdk_client_ctrlr_cmd_get_feature_ns(struct spdk_client_ctrlr *ctrlr, uint8_t feature,
											 uint32_t cdw11, void *payload, uint32_t payload_size,
											 spdk_req_cmd_cb cb_fn, void *cb_arg, uint32_t ns_id);

	/**
	 * Set specific feature for the given Client controller and namespace ID.
	 *
	 * \param ctrlr Client controller to manipulate.
	 * \param feature The feature identifier.
	 * \param cdw11 as defined by the specification for this command.
	 * \param cdw12 as defined by the specification for this command.
	 * \param payload The pointer to the payload buffer.
	 * \param payload_size The size of payload buffer.
	 * \param cb_fn Callback function to invoke when the feature has been set.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param ns_id The namespace identifier.
	 *
	 * \return 0 if successfully submitted, -ENOMEM if resources could not be allocated
	 * for this request, -ENXIO if the admin qpair is failed at the transport layer.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * Call \ref spdk_client_ctrlr_process_admin_completions() to poll for completion
	 * of commands submitted through this function.
	 *
	 * \sa spdk_client_ctrlr_cmd_get_feature_ns()
	 */
	int spdk_client_ctrlr_cmd_set_feature_ns(struct spdk_client_ctrlr *ctrlr, uint8_t feature,
											 uint32_t cdw11, uint32_t cdw12, void *payload,
											 uint32_t payload_size, spdk_req_cmd_cb cb_fn,
											 void *cb_arg, uint32_t ns_id);

	/**
	 * Receive security protocol data from controller.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 *
	 * \param ctrlr Client controller to use for security receive command submission.
	 * \param secp Security Protocol that is used.
	 * \param spsp Security Protocol Specific field.
	 * \param nssf Client Security Specific field. Indicate RPMB target when using Security
	 * Protocol EAh.
	 * \param payload The pointer to the payload buffer.
	 * \param payload_size The size of payload buffer.
	 * \param cb_fn Callback function to invoke when the command has been completed.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be allocated
	 * for this request.
	 */
	int spdk_client_ctrlr_cmd_security_receive(struct spdk_client_ctrlr *ctrlr, uint8_t secp,
											   uint16_t spsp, uint8_t nssf, void *payload,
											   uint32_t payload_size,
											   spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Send security protocol data to controller.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 *
	 * \param ctrlr Client controller to use for security send command submission.
	 * \param secp Security Protocol that is used.
	 * \param spsp Security Protocol Specific field.
	 * \param nssf Client Security Specific field. Indicate RPMB target when using Security
	 * Protocol EAh.
	 * \param payload The pointer to the payload buffer.
	 * \param payload_size The size of payload buffer.
	 * \param cb_fn Callback function to invoke when the command has been completed.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be allocated
	 * for this request.
	 */
	int spdk_client_ctrlr_cmd_security_send(struct spdk_client_ctrlr *ctrlr, uint8_t secp,
											uint16_t spsp, uint8_t nssf, void *payload,
											uint32_t payload_size, spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Receive security protocol data from controller.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 *
	 * \param ctrlr Client controller to use for security receive command submission.
	 * \param secp Security Protocol that is used.
	 * \param spsp Security Protocol Specific field.
	 * \param nssf Client Security Specific field. Indicate RPMB target when using Security
	 * Protocol EAh.
	 * \param payload The pointer to the payload buffer.
	 * \param size The size of payload buffer.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be allocated
	 * for this request.
	 */
	int spdk_client_ctrlr_security_receive(struct spdk_client_ctrlr *ctrlr, uint8_t secp,
										   uint16_t spsp, uint8_t nssf, void *payload, size_t size);

	/**
	 * Send security protocol data to controller.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 *
	 * \param ctrlr Client controller to use for security send command submission.
	 * \param secp Security Protocol that is used.
	 * \param spsp Security Protocol Specific field.
	 * \param nssf Client Security Specific field. Indicate RPMB target when using Security
	 * Protocol EAh.
	 * \param payload The pointer to the payload buffer.
	 * \param size The size of payload buffer.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be allocated
	 * for this request.
	 */
	int spdk_client_ctrlr_security_send(struct spdk_client_ctrlr *ctrlr, uint8_t secp,
										uint16_t spsp, uint8_t nssf, void *payload, size_t size);

	/**
	 * Receive data related to a specific Directive Type from the controller.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 *
	 * Call spdk_client_ctrlr_process_admin_completions() to poll for completion of
	 * commands submitted through this function.
	 *
	 * \param ctrlr Client controller to use for directive receive command submission.
	 * \param nsid Specific Namespace Identifier.
	 * \param doper Directive Operation defined in client_spec.h.
	 * \param dtype Directive Type defined in client_spec.h.
	 * \param dspec Directive Specific defined in client_spec.h.
	 * \param payload The pointer to the payload buffer.
	 * \param payload_size The size of payload buffer.
	 * \param cdw12 Command dword 12.
	 * \param cdw13 Command dword 13.
	 * \param cb_fn Callback function to invoke when the command has been completed.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be allocated
	 * for this request.
	 */
	int spdk_client_ctrlr_cmd_directive_receive(struct spdk_client_ctrlr *ctrlr, uint32_t nsid,
												uint32_t doper, uint32_t dtype, uint32_t dspec,
												void *payload, uint32_t payload_size, uint32_t cdw12,
												uint32_t cdw13, spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Send data related to a specific Directive Type to the controller.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 *
	 * Call spdk_client_ctrlr_process_admin_completions() to poll for completion of
	 * commands submitted through this function.
	 *
	 * \param ctrlr Client controller to use for directive send command submission.
	 * \param nsid Specific Namespace Identifier.
	 * \param doper Directive Operation defined in client_spec.h.
	 * \param dtype Directive Type defined in client_spec.h.
	 * \param dspec Directive Specific defined in client_spec.h.
	 * \param payload The pointer to the payload buffer.
	 * \param payload_size The size of payload buffer.
	 * \param cdw12 Command dword 12.
	 * \param cdw13 Command dword 13.
	 * \param cb_fn Callback function to invoke when the command has been completed.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be allocated
	 * for this request.
	 */
	int spdk_client_ctrlr_cmd_directive_send(struct spdk_client_ctrlr *ctrlr, uint32_t nsid,
											 uint32_t doper, uint32_t dtype, uint32_t dspec,
											 void *payload, uint32_t payload_size, uint32_t cdw12,
											 uint32_t cdw13, spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Get supported flags of the controller.
	 *
	 * \param ctrlr Client controller to get flags.
	 *
	 * \return supported flags of this controller.
	 */
	uint64_t spdk_client_ctrlr_get_flags(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Attach the specified namespace to controllers.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 *
	 * \param ctrlr Client controller to use for command submission.
	 * \param nsid Namespace identifier for namespace to attach.
	 * \param payload The pointer to the controller list.
	 *
	 * \return 0 if successfully submitted, ENOMEM if resources could not be allocated
	 * for this request.
	 */
	int spdk_client_ctrlr_attach_ns(struct spdk_client_ctrlr *ctrlr, uint32_t nsid,
									struct spdk_client_ctrlr_list *payload);

	/**
	 * Detach the specified namespace from controllers.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 *
	 * \param ctrlr Client controller to use for command submission.
	 * \param nsid Namespace ID to detach.
	 * \param payload The pointer to the controller list.
	 *
	 * \return 0 if successfully submitted, ENOMEM if resources could not be allocated
	 * for this request
	 */
	int spdk_client_ctrlr_detach_ns(struct spdk_client_ctrlr *ctrlr, uint32_t nsid,
									struct spdk_client_ctrlr_list *payload);

	/**
	 * Delete a namespace.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 *
	 * \param ctrlr Client controller to delete namespace from.
	 * \param nsid The namespace identifier.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be
	 * allocated
	 * for this request
	 */
	int spdk_client_ctrlr_delete_ns(struct spdk_client_ctrlr *ctrlr, uint32_t nsid);

	/**
	 * Format NVM.
	 *
	 * This function requests a low-level format of the media.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 *
	 * \param ctrlr Client controller to format.
	 * \param nsid The namespace identifier. May be SPDK_CLIENT_GLOBAL_NS_TAG to format
	 * all namespaces.
	 * \param format The format information for the command.
	 *
	 * \return 0 if successfully submitted, negated errno if resources could not be
	 * allocated for this request
	 */
	int spdk_client_ctrlr_format(struct spdk_client_ctrlr *ctrlr, uint32_t nsid,
								 struct spdk_client_format *format);

	/**
	 * Start the Read from a Boot Partition.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 *
	 * \param ctrlr Client controller to perform the Boot Partition read.
	 * \param payload The data buffer for Boot Partition read.
	 * \param bprsz Read size in multiples of 4 KiB to copy into the Boot Partition Memory Buffer.
	 * \param bprof Boot Partition offset to read from in 4 KiB units.
	 * \param bpid Boot Partition identifier for the Boot Partition read operation.
	 *
	 * \return 0 if Boot Partition read is successful. Negated errno on the following error conditions:
	 * -ENOMEM: if resources could not be allocated.
	 * -ENOTSUP: Boot Partition is not supported by the Controller.
	 * -EIO: Registers access failure.
	 * -EINVAL: Parameters are invalid.
	 * -EFAULT: Invalid address was specified as part of payload.
	 * -EALREADY: Boot Partition read already initiated.
	 */
	int spdk_client_ctrlr_read_boot_partition_start(struct spdk_client_ctrlr *ctrlr, void *payload,
													uint32_t bprsz, uint32_t bprof, uint32_t bpid);

	/**
	 * Poll the status of the Read from a Boot Partition.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 *
	 * \param ctrlr Client controller to perform the Boot Partition read.
	 *
	 * \return 0 if Boot Partition read is successful. Negated errno on the following error conditions:
	 * -EIO: Registers access failure.
	 * -EINVAL: Invalid read status or the Boot Partition read is not initiated yet.
	 * -EAGAIN: If the read is still in progress; users must call
	 * spdk_client_ctrlr_read_boot_partition_poll again to check the read status.
	 */
	int spdk_client_ctrlr_read_boot_partition_poll(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Write to a Boot Partition.
	 *
	 * This function is thread safe and can be called at any point after spdk_client_probe().
	 * Users will get the completion after the data is downloaded, image is replaced and
	 * Boot Partition is activated or when the sequence encounters an error.
	 *
	 * \param ctrlr Client controller to perform the Boot Partition write.
	 * \param payload The data buffer for Boot Partition write.
	 * \param size Data size to write to the Boot Partition.
	 * \param bpid Boot Partition identifier for the Boot Partition write operation.
	 * \param cb_fn Callback function to invoke when the operation is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if Boot Partition write submit is successful. Negated errno on the following error conditions:
	 * -ENOMEM: if resources could not be allocated.
	 * -ENOTSUP: Boot Partition is not supported by the Controller.
	 * -EIO: Registers access failure.
	 * -EINVAL: Parameters are invalid.
	 */
	int spdk_client_ctrlr_write_boot_partition(struct spdk_client_ctrlr *ctrlr, void *payload,
											   uint32_t size, uint32_t bpid, spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Return virtual address of PCIe NVM I/O registers
	 *
	 * This function returns a pointer to the PCIe I/O registers for a controller
	 * or NULL if unsupported for this transport.
	 *
	 * \param ctrlr Controller whose registers are to be accessed.
	 *
	 * \return Pointer to virtual address of register bank, or NULL.
	 */
	volatile struct spdk_client_registers *spdk_client_ctrlr_get_registers(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Reserve the controller memory buffer for data transfer use.
	 *
	 * This function reserves the full size of the controller memory buffer
	 * for use in data transfers. If submission queues or completion queues are
	 * already placed in the controller memory buffer, this call will fail.
	 *
	 * \param ctrlr Controller from which to allocate memory buffer
	 *
	 * \return The size of the controller memory buffer on success. Negated errno
	 * on failure.
	 */
	int spdk_client_ctrlr_reserve_cmb(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Map a previously reserved controller memory buffer so that it's data is
	 * visible from the CPU. This operation is not always possible.
	 *
	 * \param ctrlr Controller that contains the memory buffer
	 * \param size Size of buffer that was mapped.
	 *
	 * \return Pointer to controller memory buffer, or NULL on failure.
	 */
	void *spdk_client_ctrlr_map_cmb(struct spdk_client_ctrlr *ctrlr, size_t *size);

	/**
	 * Free a controller memory I/O buffer.
	 *
	 * \param ctrlr Controller from which to unmap the memory buffer.
	 */
	void spdk_client_ctrlr_unmap_cmb(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Enable the Persistent Memory Region
	 *
	 * \param ctrlr Controller that contains the Persistent Memory Region
	 *
	 * \return 0 on success. Negated errno on the following error conditions:
	 * -ENOTSUP: PMR is not supported by the Controller.
	 * -EIO: Registers access failure.
	 * -EINVAL: PMR Time Units Invalid or PMR is already enabled.
	 * -ETIMEDOUT: Timed out to Enable PMR.
	 * -ENOSYS: Transport does not support Enable PMR function.
	 */
	int spdk_client_ctrlr_enable_pmr(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Disable the Persistent Memory Region
	 *
	 * \param ctrlr Controller that contains the Persistent Memory Region
	 *
	 * \return 0 on success. Negated errno on the following error conditions:
	 * -ENOTSUP: PMR is not supported by the Controller.
	 * -EIO: Registers access failure.
	 * -EINVAL: PMR Time Units Invalid or PMR is already disabled.
	 * -ETIMEDOUT: Timed out to Disable PMR.
	 * -ENOSYS: Transport does not support Disable PMR function.
	 */
	int spdk_client_ctrlr_disable_pmr(struct spdk_client_ctrlr *ctrlr);

	/**
	 * Map the Persistent Memory Region so that it's data is
	 * visible from the CPU.
	 *
	 * \param ctrlr Controller that contains the Persistent Memory Region
	 * \param size Size of the region that was mapped.
	 *
	 * \return Pointer to Persistent Memory Region, or NULL on failure.
	 */
	void *spdk_client_ctrlr_map_pmr(struct spdk_client_ctrlr *ctrlr, size_t *size);

	/**
	 * Free the Persistent Memory Region.
	 *
	 * \param ctrlr Controller from which to unmap the Persistent Memory Region.
	 *
	 * \return 0 on success, negative errno on failure.
	 * -ENXIO: Either PMR is not supported by the Controller or the PMR is already unmapped.
	 * -ENOSYS: Transport does not support Unmap PMR function.
	 */
	int spdk_client_ctrlr_unmap_pmr(struct spdk_client_ctrlr *ctrlr);

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
	 * \param table The call back table defined by users which contains the accelerated functions
	 * which can be used to accelerate some operations such as crc32c.
	 *
	 * \return Pointer to the new poll group, or NULL on error.
	 */
	struct spdk_client_poll_group *spdk_client_poll_group_create(void *ctx,
																 struct spdk_client_accel_fn_table *table);

	/**
	 * Get a optimal poll group.
	 *
	 * \param qpair The qpair to get the optimal poll group.
	 *
	 * \return Pointer to the optimal poll group, or NULL if not found.
	 */
	struct spdk_client_poll_group *spdk_client_qpair_get_optimal_poll_group(struct spdk_client_qpair *qpair);

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
	 * Retrieve the user context for this specific poll group.
	 *
	 * \param group The poll group from which to retrieve the context.
	 *
	 * \return A pointer to the user provided poll group context.
	 */
	void *spdk_client_poll_group_get_ctx(struct spdk_client_poll_group *group);

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
	 * Get the identify namespace data as defined by the Client specification.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace.
	 *
	 * \return a pointer to the namespace data.
	 */
	const struct spdk_client_ns_data *spdk_client_ns_get_data(struct spdk_client_ns *ns);

	/**
	 * Get the namespace id (index number) from the given namespace handle.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace.
	 *
	 * \return namespace id.
	 */
	uint32_t spdk_client_ns_get_id(struct spdk_client_ns *ns);

	/**
	 * Get the controller with which this namespace is associated.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace.
	 *
	 * \return a pointer to the controller.
	 */
	struct spdk_client_ctrlr *spdk_client_ns_get_ctrlr(struct spdk_client_ns *ns);

	/**
	 * Determine whether a namespace is active.
	 *
	 * Inactive namespaces cannot be the target of I/O commands.
	 *
	 * \param ns Namespace to query.
	 *
	 * \return true if active, or false if inactive.
	 */
	bool spdk_client_ns_is_active(struct spdk_client_ns *ns);

	/**
	 * Get the maximum transfer size, in bytes, for an I/O sent to the given namespace.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace to query.
	 *
	 * \return the maximum transfer size in bytes.
	 */
	uint32_t spdk_client_ns_get_max_io_xfer_size(struct spdk_client_ns *ns);

	/**
	 * Get the sector size, in bytes, of the given namespace.
	 *
	 * This function returns the size of the data sector only.  It does not
	 * include metadata size.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace to query.
	 *
	 * /return the sector size in bytes.
	 */
	uint32_t spdk_client_ns_get_sector_size(struct spdk_client_ns *ns);

	/**
	 * Get the extended sector size, in bytes, of the given namespace.
	 *
	 * This function returns the size of the data sector plus metadata.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace to query.
	 *
	 * /return the extended sector size in bytes.
	 */
	uint32_t spdk_client_ns_get_extended_sector_size(struct spdk_client_ns *ns);

	/**
	 * Get the number of sectors for the given namespace.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace to query.
	 *
	 * \return the number of sectors.
	 */
	uint64_t spdk_client_ns_get_num_sectors(struct spdk_client_ns *ns);

	/**
	 * Get the size, in bytes, of the given namespace.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace to query.
	 *
	 * \return the size of the given namespace in bytes.
	 */
	uint64_t spdk_client_ns_get_size(struct spdk_client_ns *ns);

	/**
	 * Get the metadata size, in bytes, of the given namespace.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace to query.
	 *
	 * \return the metadata size of the given namespace in bytes.
	 */
	uint32_t spdk_client_ns_get_md_size(struct spdk_client_ns *ns);

	/**
	 * Check whether if the namespace can support extended LBA when end-to-end data
	 * protection enabled.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace to query.
	 *
	 * \return true if the namespace can support extended LBA when end-to-end data
	 * protection enabled, or false otherwise.
	 */
	bool spdk_client_ns_supports_extended_lba(struct spdk_client_ns *ns);

	/**
	 * Check whether if the namespace supports compare operation
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace to query.
	 *
	 * \return true if the namespace supports compare operation, or false otherwise.
	 */
	bool spdk_client_ns_supports_compare(struct spdk_client_ns *ns);

	/**
	 * Get the optimal I/O boundary, in blocks, for the given namespace.
	 *
	 * Read and write commands should not cross the optimal I/O boundary for best
	 * performance.
	 *
	 * \param ns Namespace to query.
	 *
	 * \return Optimal granularity of I/O commands, in blocks, or 0 if no optimal
	 * granularity is reported.
	 */
	uint32_t spdk_client_ns_get_optimal_io_boundary(struct spdk_client_ns *ns);

	/**
	 * Get the NGUID for the given namespace.
	 *
	 * \param ns Namespace to query.
	 *
	 * \return a pointer to namespace NGUID, or NULL if ns does not have a NGUID.
	 */
	const uint8_t *spdk_client_ns_get_nguid(const struct spdk_client_ns *ns);

	/**
	 * Get the UUID for the given namespace.
	 *
	 * \param ns Namespace to query.
	 *
	 * \return a pointer to namespace UUID, or NULL if ns does not have a UUID.
	 */
	const struct spdk_uuid *spdk_client_ns_get_uuid(const struct spdk_client_ns *ns);

	/**
	 * \brief Namespace command support flags.
	 */
	enum spdk_client_ns_flags
	{
		SPDK_CLIENT_NS_DEALLOCATE_SUPPORTED = 1 << 0,		   /**< The deallocate command is supported */
		SPDK_CLIENT_NS_FLUSH_SUPPORTED = 1 << 1,			   /**< The flush command is supported */
		SPDK_CLIENT_NS_RESERVATION_SUPPORTED = 1 << 2,		   /**< The reservation command is supported */
		SPDK_CLIENT_NS_WRITE_ZEROES_SUPPORTED = 1 << 3,		   /**< The write zeroes command is supported */
		SPDK_CLIENT_NS_DPS_PI_SUPPORTED = 1 << 4,			   /**< The end-to-end data protection is supported */
		SPDK_CLIENT_NS_EXTENDED_LBA_SUPPORTED = 1 << 5,		   /**< The extended lba format is supported,
										   metadata is transferred as a contiguous
										   part of the logical block that it is associated with */
		SPDK_CLIENT_NS_WRITE_UNCORRECTABLE_SUPPORTED = 1 << 6, /**< The write uncorrectable command is supported */
		SPDK_CLIENT_NS_COMPARE_SUPPORTED = 1 << 7,			   /**< The compare command is supported */
	};

	/**
	 * Get the flags for the given namespace.
	 *
	 * See spdk_client_ns_flags for the possible flags returned.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace to query.
	 *
	 * \return the flags for the given namespace.
	 */
	uint32_t spdk_client_ns_get_flags(struct spdk_client_ns *ns);

	/**
	 * Get the ANA group ID for the given namespace.
	 *
	 * This function should be called only if spdk_client_ctrlr_is_log_page_supported() returns
	 * true for the controller and log page ID SPDK_CLIENT_LOG_ASYMMETRIC_NAMESPACE_ACCESS.
	 *
	 * This function is thread safe and can be called at any point while the controller
	 * is attached to the SPDK Client driver.
	 *
	 * \param ns Namespace to query.
	 *
	 * \return the ANA group ID for the given namespace.
	 */
	uint32_t spdk_client_ns_get_ana_group_id(const struct spdk_client_ns *ns);

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
	 * Submit a write I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the write I/O.
	 * \param qpair I/O queue pair to submit the request.
	 * \param payload Virtual address pointer to the data payload.
	 * \param lba Starting LBA to write the data.
	 * \param lba_count Length (in sectors) for the write operation.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param io_flags Set flags, defined by the SPDK_CLIENT_IO_FLAGS_* entries in
	 * spdk/client_spec.h, for this I/O.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_write(struct spdk_client_qpair *qpair, void *payload,
								 uint64_t lba, uint32_t lba_count, spdk_req_cmd_cb cb_fn,
								 void *cb_arg, uint32_t io_flags);

	/**
	 * Submit a write I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the write I/O.
	 * \param qpair I/O queue pair to submit the request.
	 * \param lba Starting LBA to write the data.
	 * \param lba_count Length (in sectors) for the write operation.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param io_flags Set flags, defined in client_spec.h, for this I/O.
	 * \param reset_sgl_fn Callback function to reset scattered payload.
	 * \param next_sge_fn Callback function to iterate each scattered payload memory
	 * segment.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_writev(struct spdk_client_qpair *qpair,
								  uint64_t lba, uint32_t lba_count,
								  spdk_req_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
								  spdk_client_req_reset_sgl_cb reset_sgl_fn,
								  spdk_client_req_next_sge_cb next_sge_fn);

	/**
	 * Submit a write I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the write I/O
	 * \param qpair I/O queue pair to submit the request
	 * \param lba starting LBA to write the data
	 * \param lba_count length (in sectors) for the write operation
	 * \param cb_fn callback function to invoke when the I/O is completed
	 * \param cb_arg argument to pass to the callback function
	 * \param io_flags set flags, defined in client_spec.h, for this I/O
	 * \param reset_sgl_fn callback function to reset scattered payload
	 * \param next_sge_fn callback function to iterate each scattered
	 * payload memory segment
	 * \param metadata virtual address pointer to the metadata payload, the length
	 * of metadata is specified by spdk_client_ns_get_md_size()
	 * \param apptag_mask application tag mask.
	 * \param apptag application tag to use end-to-end protection information.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_writev_with_md(struct spdk_client_qpair *qpair,
										  uint64_t lba, uint32_t lba_count,
										  spdk_req_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
										  spdk_client_req_reset_sgl_cb reset_sgl_fn,
										  spdk_client_req_next_sge_cb next_sge_fn, void *metadata,
										  uint16_t apptag_mask, uint16_t apptag);

	/**
	 * Submit a write I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the write I/O
	 * \param qpair I/O queue pair to submit the request
	 * \param lba starting LBA to write the data
	 * \param lba_count length (in sectors) for the write operation
	 * \param cb_fn callback function to invoke when the I/O is completed
	 * \param cb_arg argument to pass to the callback function
	 * \param reset_sgl_fn callback function to reset scattered payload
	 * \param next_sge_fn callback function to iterate each scattered
	 * payload memory segment
	 * \param opts Optional structure with extended IO request options. If provided, the caller must
	 * guarantee that this structure is accessible until IO completes
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 * -EFAULT: Invalid address was specified as part of payload.  cb_fn is also called
	 *          with error status including dnr=1 in this case.
	 */
	int spdk_client_ns_cmd_writev_ext(struct spdk_client_qpair *qpair,
									  uint64_t lba, uint32_t lba_count,
									  spdk_req_cmd_cb cb_fn, void *cb_arg,
									  spdk_client_req_reset_sgl_cb reset_sgl_fn,
									  spdk_client_req_next_sge_cb next_sge_fn,
									  struct spdk_client_ns_cmd_ext_io_opts *opts);

	/**
	 * Submit a write I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the write I/O.
	 * \param qpair I/O queue pair to submit the request.
	 * \param payload Virtual address pointer to the data payload.
	 * \param metadata Virtual address pointer to the metadata payload, the length
	 * of metadata is specified by spdk_client_ns_get_md_size().
	 * \param lba Starting LBA to write the data.
	 * \param lba_count Length (in sectors) for the write operation.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param io_flags Set flags, defined by the SPDK_CLIENT_IO_FLAGS_* entries in
	 * spdk/client_spec.h, for this I/O.
	 * \param apptag_mask Application tag mask.
	 * \param apptag Application tag to use end-to-end protection information.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_write_with_md(struct spdk_client_qpair *qpair,
										 void *payload, void *metadata,
										 uint64_t lba, uint32_t lba_count, spdk_req_cmd_cb cb_fn,
										 void *cb_arg, uint32_t io_flags,
										 uint16_t apptag_mask, uint16_t apptag);

	/**
	 * Submit a write zeroes I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the write zeroes I/O.
	 * \param qpair I/O queue pair to submit the request.
	 * \param lba Starting LBA for this command.
	 * \param lba_count Length (in sectors) for the write zero operation.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param io_flags Set flags, defined by the SPDK_CLIENT_IO_FLAGS_* entries in
	 * spdk/client_spec.h, for this I/O.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_write_zeroes(struct spdk_client_qpair *qpair,
										uint64_t lba, uint32_t lba_count,
										spdk_req_cmd_cb cb_fn, void *cb_arg,
										uint32_t io_flags);

	/**
	 * Submit a write uncorrectable I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the write uncorrectable I/O.
	 * \param qpair I/O queue pair to submit the request.
	 * \param lba Starting LBA for this command.
	 * \param lba_count Length (in sectors) for the write uncorrectable operation.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_write_uncorrectable(struct spdk_client_qpair *qpair,
											   uint64_t lba, uint32_t lba_count,
											   spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * \brief Submits a read I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the read I/O.
	 * \param qpair I/O queue pair to submit the request.
	 * \param payload Virtual address pointer to the data payload.
	 * \param lba Starting LBA to read the data.
	 * \param lba_count Length (in sectors) for the read operation.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param io_flags Set flags, defined in client_spec.h, for this I/O.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_read(struct spdk_client_qpair *qpair, void *payload,
								uint64_t lba, uint32_t lba_count, spdk_req_cmd_cb cb_fn,
								void *cb_arg, uint32_t io_flags);

	/**
	 * Submit a read I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the read I/O.
	 * \param qpair I/O queue pair to submit the request.
	 * \param lba Starting LBA to read the data.
	 * \param lba_count Length (in sectors) for the read operation.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param io_flags Set flags, defined in client_spec.h, for this I/O.
	 * \param reset_sgl_fn Callback function to reset scattered payload.
	 * \param next_sge_fn Callback function to iterate each scattered payload memory
	 * segment.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_readv(struct spdk_client_qpair *qpair,
								 uint64_t lba, uint32_t lba_count,
								 spdk_req_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
								 spdk_client_req_reset_sgl_cb reset_sgl_fn,
								 spdk_client_req_next_sge_cb next_sge_fn);

	/**
	 * Submit a read I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any given time.
	 *
	 * \param ns Client namespace to submit the read I/O
	 * \param qpair I/O queue pair to submit the request
	 * \param lba starting LBA to read the data
	 * \param lba_count length (in sectors) for the read operation
	 * \param cb_fn callback function to invoke when the I/O is completed
	 * \param cb_arg argument to pass to the callback function
	 * \param io_flags set flags, defined in client_spec.h, for this I/O
	 * \param reset_sgl_fn callback function to reset scattered payload
	 * \param next_sge_fn callback function to iterate each scattered
	 * payload memory segment
	 * \param metadata virtual address pointer to the metadata payload, the length
	 *	           of metadata is specified by spdk_client_ns_get_md_size()
	 * \param apptag_mask application tag mask.
	 * \param apptag application tag to use end-to-end protection information.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_readv_with_md(struct spdk_client_qpair *qpair,
										 uint64_t lba, uint32_t lba_count,
										 spdk_req_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
										 spdk_client_req_reset_sgl_cb reset_sgl_fn,
										 spdk_client_req_next_sge_cb next_sge_fn, void *metadata,
										 uint16_t apptag_mask, uint16_t apptag);

	/**
	 * Submit a read I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any given time.
	 *
	 * \param ns Client namespace to submit the read I/O
	 * \param qpair I/O queue pair to submit the request
	 * \param lba starting LBA to read the data
	 * \param lba_count length (in sectors) for the read operation
	 * \param cb_fn callback function to invoke when the I/O is completed
	 * \param cb_arg argument to pass to the callback function
	 * \param reset_sgl_fn callback function to reset scattered payload
	 * \param next_sge_fn callback function to iterate each scattered
	 * payload memory segment
	 * \param opts Optional structure with extended IO request options. If provided, the caller must
	 * guarantee that this structure is accessible until IO completes
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 * -EFAULT: Invalid address was specified as part of payload.  cb_fn is also called
	 *          with error status including dnr=1 in this case.
	 */
	int spdk_client_ns_cmd_readv_ext(struct spdk_client_qpair *qpair,
									 uint64_t lba, uint32_t lba_count, spdk_req_cmd_cb cb_fn,
									 void *cb_arg, spdk_client_req_reset_sgl_cb reset_sgl_fn,
									 spdk_client_req_next_sge_cb next_sge_fn,
									 struct spdk_client_ns_cmd_ext_io_opts *opts);

	/**
	 * Submits a read I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the read I/O
	 * \param qpair I/O queue pair to submit the request
	 * \param payload virtual address pointer to the data payload
	 * \param metadata virtual address pointer to the metadata payload, the length
	 * of metadata is specified by spdk_client_ns_get_md_size().
	 * \param lba starting LBA to read the data.
	 * \param lba_count Length (in sectors) for the read operation.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param io_flags Set flags, defined in client_spec.h, for this I/O.
	 * \param apptag_mask Application tag mask.
	 * \param apptag Application tag to use end-to-end protection information.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_read_with_md(struct spdk_client_qpair *qpair,
										void *payload, void *metadata,
										uint64_t lba, uint32_t lba_count, spdk_req_cmd_cb cb_fn,
										void *cb_arg, uint32_t io_flags,
										uint16_t apptag_mask, uint16_t apptag);

	/**
	 * Submit a flush request to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the flush request.
	 * \param qpair I/O queue pair to submit the request.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_flush(struct spdk_client_qpair *qpair,
								 spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Submit a reservation report to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the reservation report request.
	 * \param qpair I/O queue pair to submit the request.
	 * \param payload Virtual address pointer for reservation status data.
	 * \param len Length bytes for reservation status data structure.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_reservation_report(struct spdk_client_ns *ns,
											  struct spdk_client_qpair *qpair,
											  void *payload, uint32_t len,
											  spdk_req_cmd_cb cb_fn, void *cb_arg);

	/**
	 * Submit a compare I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the compare I/O.
	 * \param qpair I/O queue pair to submit the request.
	 * \param payload Virtual address pointer to the data payload.
	 * \param lba Starting LBA to compare the data.
	 * \param lba_count Length (in sectors) for the compare operation.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param io_flags Set flags, defined in client_spec.h, for this I/O.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_compare(struct spdk_client_ns *ns, struct spdk_client_qpair *qpair, void *payload,
								   uint64_t lba, uint32_t lba_count, spdk_req_cmd_cb cb_fn,
								   void *cb_arg, uint32_t io_flags);

	/**
	 * Submit a compare I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the compare I/O.
	 * \param qpair I/O queue pair to submit the request.
	 * \param lba Starting LBA to compare the data.
	 * \param lba_count Length (in sectors) for the compare operation.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param io_flags Set flags, defined in client_spec.h, for this I/O.
	 * \param reset_sgl_fn Callback function to reset scattered payload.
	 * \param next_sge_fn Callback function to iterate each scattered payload memory
	 * segment.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_comparev(struct spdk_client_ns *ns, struct spdk_client_qpair *qpair,
									uint64_t lba, uint32_t lba_count,
									spdk_req_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
									spdk_client_req_reset_sgl_cb reset_sgl_fn,
									spdk_client_req_next_sge_cb next_sge_fn);

	/**
	 * Submit a compare I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the compare I/O.
	 * \param qpair I/O queue pair to submit the request.
	 * \param lba Starting LBA to compare the data.
	 * \param lba_count Length (in sectors) for the compare operation.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param io_flags Set flags, defined in client_spec.h, for this I/O.
	 * \param reset_sgl_fn Callback function to reset scattered payload.
	 * \param next_sge_fn Callback function to iterate each scattered payload memory
	 * segment.
	 * \param metadata Virtual address pointer to the metadata payload, the length
	 * of metadata is specified by spdk_client_ns_get_md_size()
	 * \param apptag_mask Application tag mask.
	 * \param apptag Application tag to use end-to-end protection information.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int
	spdk_client_ns_cmd_comparev_with_md(struct spdk_client_ns *ns, struct spdk_client_qpair *qpair,
										uint64_t lba, uint32_t lba_count,
										spdk_req_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
										spdk_client_req_reset_sgl_cb reset_sgl_fn,
										spdk_client_req_next_sge_cb next_sge_fn, void *metadata,
										uint16_t apptag_mask, uint16_t apptag);

	/**
	 * Submit a compare I/O to the specified Client namespace.
	 *
	 * The command is submitted to a qpair allocated by spdk_client_ctrlr_alloc_io_qpair().
	 * The user must ensure that only one thread submits I/O on a given qpair at any
	 * given time.
	 *
	 * \param ns Client namespace to submit the compare I/O.
	 * \param qpair I/O queue pair to submit the request.
	 * \param payload Virtual address pointer to the data payload.
	 * \param metadata Virtual address pointer to the metadata payload, the length
	 * of metadata is specified by spdk_client_ns_get_md_size().
	 * \param lba Starting LBA to compare the data.
	 * \param lba_count Length (in sectors) for the compare operation.
	 * \param cb_fn Callback function to invoke when the I/O is completed.
	 * \param cb_arg Argument to pass to the callback function.
	 * \param io_flags Set flags, defined in client_spec.h, for this I/O.
	 * \param apptag_mask Application tag mask.
	 * \param apptag Application tag to use end-to-end protection information.
	 *
	 * \return 0 if successfully submitted, negated errnos on the following error conditions:
	 * -EINVAL: The request is malformed.
	 * -ENOMEM: The request cannot be allocated.
	 * -ENXIO: The qpair is failed at the transport level.
	 */
	int spdk_client_ns_cmd_compare_with_md(struct spdk_client_ns *ns, struct spdk_client_qpair *qpair,
										   void *payload, void *metadata,
										   uint64_t lba, uint32_t lba_count, spdk_req_cmd_cb cb_fn,
										   void *cb_arg, uint32_t io_flags,
										   uint16_t apptag_mask, uint16_t apptag);

	/**
	 * \brief Inject an error for the next request with a given opcode.
	 *
	 * \param ctrlr Client controller.
	 * \param qpair I/O queue pair to add the error command,
	 *              NULL for Admin queue pair.
	 * \param opc Opcode for Admin or I/O commands.
	 * \param do_not_submit True if matching requests should not be submitted
	 *                      to the controller, but instead completed manually
	 *                      after timeout_in_us has expired.  False if matching
	 *                      requests should be submitted to the controller and
	 *                      have their completion status modified after the
	 *                      controller completes the request.
	 * \param timeout_in_us Wait specified microseconds when do_not_submit is true.
	 * \param err_count Number of matching requests to inject errors.
	 * \param sct Status code type.
	 * \param sc Status code.
	 *
	 * \return 0 if successfully enabled, ENOMEM if an error command
	 *	     structure cannot be allocated.
	 *
	 * The function can be called multiple times to inject errors for different
	 * commands.  If the opcode matches an existing entry, the existing entry
	 * will be updated with the values specified.
	 */
	int spdk_client_qpair_add_cmd_error_injection(struct spdk_client_ctrlr *ctrlr,
												  struct spdk_client_qpair *qpair,
												  uint8_t opc,
												  bool do_not_submit,
												  uint64_t timeout_in_us,
												  uint32_t err_count,
												  uint8_t sct, uint8_t sc);

	/**
	 * \brief Clear the specified Client command with error status.
	 *
	 * \param ctrlr Client controller.
	 * \param qpair I/O queue pair to remove the error command,
	 * \            NULL for Admin queue pair.
	 * \param opc Opcode for Admin or I/O commands.
	 *
	 * The function will remove specified command in the error list.
	 */
	void spdk_client_qpair_remove_cmd_error_injection(struct spdk_client_ctrlr *ctrlr,
													  struct spdk_client_qpair *qpair,
													  uint8_t opc);

	/**
	 * \brief Given Client status, return ASCII string for that error.
	 *
	 * \param status Status from Client completion queue element.
	 * \return Returns status as an ASCII string.
	 */
	const char *spdk_req_cpl_get_status_string(const struct spdk_req_status *status);

	/**
	 * \brief Prints (SPDK_NOTICELOG) the contents of an Client submission queue entry (command).
	 *
	 * \param qpair Pointer to the Client queue pair - used to determine admin versus I/O queue.
	 * \param cmd Pointer to the submission queue command to be formatted.
	 */
	void spdk_client_qpair_print_command(struct spdk_client_qpair *qpair,
										 struct spdk_req_cmd *cmd);

	/**
	 * \brief Prints (SPDK_NOTICELOG) the contents of an Client completion queue entry.
	 *
	 * \param qpair Pointer to the Client queue pair - presently unused.
	 * \param cpl Pointer to the completion queue element to be formatted.
	 */
	void spdk_client_qpair_print_completion(struct spdk_client_qpair *qpair,
											struct spdk_req_cpl *cpl);

	/**
	 * \brief Gets the Client qpair ID for the specified qpair.
	 *
	 * \param qpair Pointer to the Client queue pair.
	 * \returns ID for the specified qpair.
	 */
	uint16_t spdk_client_qpair_get_id(struct spdk_client_qpair *qpair);

	/**
	 * \brief Prints (SPDK_NOTICELOG) the contents of an Client submission queue entry (command).
	 *
	 * \param qid Queue identifier.
	 * \param cmd Pointer to the submission queue command to be formatted.
	 */
	void spdk_client_print_command(uint16_t qid, struct spdk_req_cmd *cmd);

	/**
	 * \brief Prints (SPDK_NOTICELOG) the contents of an Client completion queue entry.
	 *
	 * \param qid Queue identifier.
	 * \param cpl Pointer to the completion queue element to be formatted.
	 */
	void spdk_client_print_completion(uint16_t qid, struct spdk_req_cpl *cpl);

	struct ibv_context;
	struct ibv_pd;
	struct ibv_mr;

	/**
	 * RDMA Transport Hooks
	 */
	struct spdk_client_rdma_hooks
	{
		/**
		 * \brief Get an InfiniBand Verbs protection domain.
		 *
		 * \param trid the transport id
		 * \param verbs Infiniband verbs context
		 *
		 * \return pd of the client ctrlr
		 */
		struct ibv_pd *(*get_ibv_pd)(const struct spdk_client_transport_id *trid,
									 struct ibv_context *verbs);

		/**
		 * \brief Get an InfiniBand Verbs memory region for a buffer.
		 *
		 * \param pd The protection domain returned from get_ibv_pd
		 * \param buf Memory buffer for which an rkey should be returned.
		 * \param size size of buf
		 *
		 * \return Infiniband remote key (rkey) for this buf
		 */
		uint64_t (*get_rkey)(struct ibv_pd *pd, void *buf, size_t size);

		/**
		 * \brief Put back keys got from get_rkey.
		 *
		 * \param key The Infiniband remote key (rkey) got from get_rkey
		 *
		 */
		void (*put_rkey)(uint64_t key);
	};

	/**
	 * \brief Set the global hooks for the RDMA transport, if necessary.
	 *
	 * This call is optional and must be performed prior to probing for
	 * any devices. By default, the RDMA transport will use the ibverbs
	 * library to create protection domains and register memory. This
	 * is a mechanism to subvert that and use an existing registration.
	 *
	 * This function may only be called one time per process.
	 *
	 * \param hooks for initializing global hooks
	 */
	void spdk_client_rdma_init_hooks(struct spdk_client_rdma_hooks *hooks);

	/**
	 * Get SPDK memory domains used by the given client controller.
	 *
	 * The user can call this function with \b domains set to NULL and \b array_size set to 0 to get the
	 * number of memory domains used by client controller
	 *
	 * \param ctrlr Opaque handle to the Client controller.
	 * \param domains Pointer to an array of memory domains to be filled by this function. The user should allocate big enough
	 * array to keep all memory domains used by client controller
	 * \param array_size size of \b domains array
	 * \return the number of entries in \b domains array or negated errno. If returned value is bigger than \b array_size passed by the user
	 * then the user should increase the size of \b domains array and call this function again. There is no guarantees that
	 * the content of \b domains array is valid in that case.
	 *         -EINVAL if input parameters were invalid

	 */
	int spdk_client_ctrlr_get_memory_domains(const struct spdk_client_ctrlr *ctrlr,
											 struct spdk_memory_domain **domains, int array_size);

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
	typedef void (*spdk_client_reg_cb)(void *ctx, uint64_t value, const struct spdk_req_cpl *cpl);

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

		int (*qpair_reset)(struct spdk_client_qpair *qpair);

		int (*qpair_submit_request)(struct spdk_client_qpair *qpair, struct client_request *req);

		int32_t (*qpair_process_completions)(struct spdk_client_qpair *qpair, uint32_t max_completions);

		int (*qpair_iterate_requests)(struct spdk_client_qpair *qpair,
									  int (*iter_fn)(struct client_request *req, void *arg),
									  void *arg);

		void (*admin_qpair_abort_aers)(struct spdk_client_qpair *qpair);

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
