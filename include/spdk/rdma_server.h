#ifndef SPDK_RDMA_SERVER_H
#define SPDK_RDMA_SERVER_H

#include "spdk/stdinc.h"

#include "spdk/env.h"
#include "spdk/queue.h"
#include "spdk/uuid.h"
#include "spdk/rdma_common.h"
#ifdef __cplusplus
extern "C"
{
#endif

	struct spdk_srv_tgt;
	struct spdk_srv_conn;
	struct spdk_srv_request;
	struct spdk_srv_request;
	struct spdk_srv_poll_group;
	struct spdk_json_write_ctx;
	struct spdk_json_val;
	struct spdk_srv_transport;
	struct spdk_srv_transport_opts;
	struct spdk_srv_transport_id;

#define SPDK_SRV_TRANSPORT_NAME_RDMA "RDMA"

	typedef void (*spdk_srv_state_change_done)(void *cb_arg, int status);
	typedef void (*spdk_srv_transport_destroy_done_cb)(void *cb_arg);
	typedef void (*spdk_srv_transport_conn_fini_cb)(void *cb_arg);
	typedef void (*spdk_srv_poll_group_destroy_done_fn)(void *cb_arg, int status);
	typedef void(spdk_srv_tgt_destroy_done_fn)(void *ctx, int status);
	typedef void (*spdk_srv_rpc_service_complete_cb)(void *cb_arg, int status);
	typedef void (*spdk_srv_rpc_dispatcher_cb)(void *cb_arg, int status, char *data, int length, spdk_srv_rpc_service_complete_cb service_cb, void *service_cb_arg);
	typedef void (*spdk_srv_rpc_dispatcher)(uint32_t opc, struct iovec *iovs, int iov_cnt, int length, spdk_srv_rpc_dispatcher_cb cb, void *cb_arg);
	typedef void (*spdk_srv_rpc_dispatcher_iovs_cb)(void *cb_arg, int status, struct iovec *iovs, int iov_cnt, int length, spdk_srv_rpc_service_complete_cb service_cb, void *service_cb_arg);
	typedef void (*spdk_srv_rpc_dispatcher_iovs)(uint32_t opc, struct iovec *iovs, int iov_cnt, int length, spdk_srv_rpc_dispatcher_iovs_cb cb, void *cb_arg);

#define SRV_TRANSPORT_DEFAULT_ASSOCIATION_TIMEOUT_IN_MS 120000
#define SPDK_SRV_DEFAULT_ACCEPT_POLL_RATE_US 10000

#define SRV_TGT_NAME_MAX_LENGTH 256

#define SPDK_SRV_MAX_SGL_ENTRIES 16
/* The maximum number of buffers per request */
#define SRV_REQ_MAX_BUFFERS (SPDK_SRV_MAX_SGL_ENTRIES * 2 + 1)

#define SRV_DATA_BUFFER_ALIGNMENT VALUE_4KB
#define SRV_DATA_BUFFER_MASK (SRV_DATA_BUFFER_ALIGNMENT - 1LL)

	enum spdk_srv_conn_state
	{
		SPDK_SRV_CONN_UNINITIALIZED = 0,
		SPDK_SRV_CONN_ACTIVE,
		SPDK_SRV_CONN_DEACTIVATING,
		SPDK_SRV_CONN_ERROR,
	};

	enum spdk_req_sgl_descriptor_type
	{
		SPDK_SRV_SGL_TYPE_DATA_BLOCK = 0x0,
		SPDK_SRV_SGL_TYPE_BIT_BUCKET = 0x1,
		SPDK_SRV_SGL_TYPE_SEGMENT = 0x2,
		SPDK_SRV_SGL_TYPE_LAST_SEGMENT = 0x3,
		SPDK_SRV_SGL_TYPE_KEYED_DATA_BLOCK = 0x4,
		SPDK_SRV_SGL_TYPE_TRANSPORT_DATA_BLOCK = 0x5,
		/* 0x6 - 0xE reserved */
		SPDK_SRV_SGL_TYPE_VENDOR_SPECIFIC = 0xF
	};

	enum spdk_req_sgl_descriptor_subtype
	{
		SPDK_SRV_SGL_SUBTYPE_ADDRESS = 0x0,
		SPDK_SRV_SGL_SUBTYPE_OFFSET = 0x1,
		SPDK_SRV_SGL_SUBTYPE_TRANSPORT = 0xa,
	};

#define SPDK_SRV_SGL_SUBTYPE_INVALIDATE_KEY 0xF

	enum spdk_srv_generic_command_status_code
	{
		SPDK_SRV_SC_SUCCESS = 0x00,
		SPDK_SRV_SC_INVALID_OPCODE = 0x01,
		SPDK_SRV_SC_INTERNAL_DEVICE_ERROR = 0x02,
		SPDK_SRV_SC_DATA_SGL_LENGTH_INVALID = 0x03,
		SPDK_SRV_SC_SGL_DESCRIPTOR_TYPE_INVALID = 0x04,
		SPDK_SRV_SC_INVALID_SGL_OFFSET = 0x05,
	};

	enum spdk_srv_rdma_transport_error
	{
		SPDK_SRV_RDMA_ERROR_INVALID_PRIVATE_DATA_LENGTH = 0x1,
		SPDK_SRV_RDMA_ERROR_NO_RESOURCES = 0x2,
	};

	enum spdk_srv_request_exec_status
	{
		SPDK_SRV_REQUEST_EXEC_STATUS_COMPLETE,
		SPDK_SRV_REQUEST_EXEC_STATUS_ASYNCHRONOUS,
	};

	struct spdk_srv_transport_id
	{
		/**
		 * Srv transport string.
		 */
		char trstring[SPDK_SRV_TRSTRING_MAX_LEN + 1];

		/**
		 * Srv transport type.
		 */
		enum spdk_srv_transport_type trtype;

		/**
		 * Address family of the transport address.
		 *
		 * For PCIe, this value is ignored.
		 */
		enum spdk_srv_adrfam adrfam;

		/**
		 * Transport address of the Srv-oF endpoint. For transports which use IP
		 * addressing (e.g. RDMA), this should be an IP address. For PCIe, this
		 * can either be a zero length string (the whole bus) or a PCI address
		 * in the format DDDD:BB:DD.FF or DDDD.BB.DD.FF. For FC the string is
		 * formatted as: nn-0xWWNN:pn-0xWWPN” where WWNN is the Node_Name of the
		 * target Srv_Port and WWPN is the N_Port_Name of the target Srv_Port.
		 */
		char traddr[SPDK_SRV_TRADDR_MAX_LEN + 1];

		/**
		 * Transport service id of the Srv-oF endpoint.  For transports which use
		 * IP addressing (e.g. RDMA), this field should be the port number. For PCIe,
		 * and FC this is always a zero length string.
		 */
		char trsvcid[SPDK_SRV_TRSVCID_MAX_LEN + 1];

		/**
		 * The Transport connection priority of the Srv-oF endpoint. Currently this is
		 * only supported by posix based sock implementation on Kernel TCP stack. More
		 * information of this field can be found from the socket(7) man page.
		 */
		int priority;
	};

	struct spdk_srv_listener
	{
		struct spdk_srv_transport_id trid;
		uint32_t ref;

		TAILQ_ENTRY(spdk_srv_listener)
		link;
	};

	struct spdk_srv_conn
	{
		enum spdk_srv_conn_state state;
		spdk_srv_state_change_done state_cb;
		void *state_cb_arg;

		struct spdk_srv_transport *transport;
		//	struct spdk_srv_ctrlr			*ctrlr;
		struct spdk_srv_poll_group *group;

		uint16_t qid;
		uint16_t sq_head;
		uint16_t sq_head_max;
		bool disconnect_started;

		struct spdk_srv_request *first_fused_req;

		TAILQ_HEAD(, spdk_srv_request)
		outstanding;
		TAILQ_ENTRY(spdk_srv_conn)
		link;
	};

	struct spdk_srv_target_opts
	{
		char name[SRV_TGT_NAME_MAX_LENGTH];
	};

	struct spdk_srv_transport_opts
	{
		uint16_t max_queue_depth;
		uint32_t in_capsule_data_size;
		/* used to calculate mdts */
		uint32_t max_io_size;
		uint32_t io_unit_size;
		uint32_t num_shared_buffers;
		uint32_t buf_cache_size;

		/**
		 * The size of spdk_srv_transport_opts according to the caller of this library is used for ABI
		 * compatibility. The library uses this field to know how many fields in this
		 * structure are valid. And the library will populate any remaining fields with default values.
		 * New added fields should be put at the end of the struct.
		 */
		size_t opts_size;
		uint32_t acceptor_poll_rate;
	};

	struct spdk_srv_transport_ops
	{
		/**
		 * Transport name
		 */
		char name[SPDK_SRV_TRSTRING_MAX_LEN];

		/**
		 * Transport type
		 */
		enum spdk_srv_transport_type type;

		/**
		 * Initialize transport options to default value
		 */
		void (*opts_init)(struct spdk_srv_transport_opts *opts);

		/**
		 * Create a transport for the given transport opts
		 */
		struct spdk_srv_transport *(*create)(struct spdk_srv_transport_opts *opts);

		/**
		 * Dump transport-specific opts into JSON
		 */
		void (*dump_opts)(struct spdk_srv_transport *transport,
						  struct spdk_json_write_ctx *w);

		/**
		 * Destroy the transport
		 */
		int (*destroy)(struct spdk_srv_transport *transport,
					   spdk_srv_transport_destroy_done_cb cb_fn, void *cb_arg);

		/**
		 * Instruct the transport to accept new connections at the address
		 * provided. This may be called multiple times.
		 */
		int (*listen)(struct spdk_srv_transport *transport, const struct spdk_srv_transport_id *trid);

		/**
		 * Stop accepting new connections at the given address.
		 */
		void (*stop_listen)(struct spdk_srv_transport *transport,
							const struct spdk_srv_transport_id *trid);

		/**
		 * Create a new poll group
		 */
		struct spdk_srv_transport_poll_group *(*poll_group_create)(struct spdk_srv_transport *transport);

		/**
		 * Get the polling group of the queue pair optimal for the specific transport
		 */
		struct spdk_srv_transport_poll_group *(*get_optimal_poll_group)(struct spdk_srv_conn *conn);

		/**
		 * Destroy a poll group
		 */
		void (*poll_group_destroy)(struct spdk_srv_transport_poll_group *group);

		/**
		 * Add a qpair to a poll group
		 */
		int (*poll_group_add)(struct spdk_srv_transport_poll_group *group,
							  struct spdk_srv_conn *conn);

		/**
		 * Remove a qpair from a poll group
		 */
		int (*poll_group_remove)(struct spdk_srv_transport_poll_group *group,
								 struct spdk_srv_conn *conn);

		/**
		 * Poll the group to process I/O
		 */
		int (*poll_group_poll)(struct spdk_srv_transport_poll_group *group);

		/*
		 * Free the request without sending a response
		 * to the originator. Release memory tied to this request.
		 */
		int (*req_free)(struct spdk_srv_request *req);

		/*
		 * Signal request completion, which sends a response
		 * to the originator.
		 */
		int (*req_complete)(struct spdk_srv_request *req);

		/*
		 * Deinitialize a connection.
		 */
		void (*conn_fini)(struct spdk_srv_conn *conn,
						  spdk_srv_transport_conn_fini_cb cb_fn,
						  void *cb_args);

		/*
		 * Get the peer transport ID for the queue pair.
		 */
		int (*conn_get_peer_trid)(struct spdk_srv_conn *conn,
								  struct spdk_srv_transport_id *trid);

		/*
		 * Get the local transport ID for the queue pair.
		 */
		int (*conn_get_local_trid)(struct spdk_srv_conn *conn,
								   struct spdk_srv_transport_id *trid);

		/*
		 * Get the listener transport ID that accepted this qpair originally.
		 */
		int (*conn_get_listen_trid)(struct spdk_srv_conn *conn,
									struct spdk_srv_transport_id *trid);

		/*
		 * Dump transport poll group statistics into JSON.
		 */
		void (*poll_group_dump_stat)(struct spdk_srv_transport_poll_group *group,
									 struct spdk_json_write_ctx *w);
	};

	struct spdk_srv_request
	{
		struct spdk_srv_conn *conn;
		uint32_t length;
		uint8_t xfer; /* type enum spdk_srv_data_transfer */
		bool data_from_pool;
		bool dif_enabled;
		void *data;
		struct spdk_rpc_req_cmd *cmd;
		struct spdk_rpc_req_cpl *rsp;
		STAILQ_ENTRY(spdk_srv_request)
		buf_link;
		uint64_t timeout_tsc;

		uint32_t iovcnt;
		struct iovec iov[SRV_REQ_MAX_BUFFERS];
		void *buffers[SRV_REQ_MAX_BUFFERS];

		struct spdk_bdev_io_wait_entry bdev_io_wait;
		struct spdk_srv_request *req_to_abort;
		struct spdk_poller *poller;
		struct spdk_bdev_io *zcopy_bdev_io; /* Contains the bdev_io when using ZCOPY */

		TAILQ_ENTRY(spdk_srv_request)
		link;
	};

	struct spdk_srv_transport_pg_cache_buf
	{
		STAILQ_ENTRY(spdk_srv_transport_pg_cache_buf)
		link;
	};

	struct spdk_srv_transport_poll_group
	{
		struct spdk_srv_transport *transport;
		/* Requests that are waiting to obtain a data buffer */
		STAILQ_HEAD(, spdk_srv_request)
		pending_buf_queue;
		STAILQ_HEAD(, spdk_srv_transport_pg_cache_buf)
		buf_cache;
		uint32_t buf_cache_count;
		uint32_t buf_cache_size;
		struct spdk_srv_poll_group *group;
		TAILQ_ENTRY(spdk_srv_transport_poll_group)
		link;
	};

	struct spdk_srv_poll_group_stat
	{
		/* cumulative io qpair count */
		uint32_t conns;
		/* current io qpair count */
		uint32_t current_conns;
		uint64_t pending_bdev_io;
	};

	struct spdk_srv_poll_group
	{
		struct spdk_thread *thread;
		struct spdk_poller *poller;
		uint64_t poll_cnt;
		uint64_t last_tick;
		TAILQ_HEAD(, spdk_srv_transport_poll_group)
		tgroups;

		/* All of the queue pairs that belong to this poll group */
		TAILQ_HEAD(, spdk_srv_conn)
		conns;

		/* Statistics */
		struct spdk_srv_poll_group_stat stat;

		spdk_srv_poll_group_destroy_done_fn destroy_cb_fn;
		void *destroy_cb_arg;

		TAILQ_ENTRY(spdk_srv_poll_group)
		link;
	};

	static inline enum spdk_srv_data_transfer
	spdk_srv_req_get_xfer(struct spdk_srv_request *req)
	{
		enum spdk_srv_data_transfer xfer;
		struct spdk_rpc_req_cmd *cmd = req->cmd;
		struct spdk_req_sgl_descriptor *sgl = &cmd->sgld;

		xfer = spdk_srv_opc_get_data_transfer(cmd->opc);

		if (xfer == SPDK_SRV_DATA_NONE)
		{
			return xfer;
		}

		/* Even for commands that may transfer data, they could have specified 0 length.
		 * We want those to show up with xfer SPDK_SRV_DATA_NONE.
		 */
		switch (sgl->generic.type)
		{
		case SPDK_SRV_SGL_TYPE_DATA_BLOCK:
		case SPDK_SRV_SGL_TYPE_BIT_BUCKET:
		case SPDK_SRV_SGL_TYPE_SEGMENT:
		case SPDK_SRV_SGL_TYPE_LAST_SEGMENT:
		case SPDK_SRV_SGL_TYPE_TRANSPORT_DATA_BLOCK:
			if (sgl->unkeyed.length == 0)
			{
				xfer = SPDK_SRV_DATA_NONE;
			}
			break;
		case SPDK_SRV_SGL_TYPE_KEYED_DATA_BLOCK:
			if (sgl->keyed.length == 0)
			{
				xfer = SPDK_SRV_DATA_NONE;
			}
			break;
		}

		return xfer;
	}

	struct spdk_srv_transport
	{
		struct spdk_srv_tgt *tgt;
		const struct spdk_srv_transport_ops *ops;
		struct spdk_srv_transport_opts opts;

		/* A mempool for transport related data transfers */
		struct spdk_mempool *data_buf_pool;

		TAILQ_HEAD(, spdk_srv_listener)
		listeners;
		TAILQ_ENTRY(spdk_srv_transport)
		link;
	};

	typedef enum spdk_srv_transport_type spdk_srv_transport_type_t;

	struct spdk_srv_tgt
	{
		char name[SRV_TGT_NAME_MAX_LENGTH];

		pthread_mutex_t mutex;

		uint64_t discovery_genctr;

		TAILQ_HEAD(, spdk_srv_transport)
		transports;
		TAILQ_HEAD(, spdk_srv_poll_group)
		poll_groups;

		/* Used for round-robin assignment of connections to poll groups */
		struct spdk_srv_poll_group *next_poll_group;

		spdk_srv_tgt_destroy_done_fn *destroy_cb_fn;
		void *destroy_cb_arg;

		uint16_t crdt[3];

		TAILQ_ENTRY(spdk_srv_tgt)
		link;
	};

	typedef void (*spdk_srv_poll_group_mod_done)(void *cb_arg, int status);

	/**
	 * Initialize transport options
	 *
	 * \param transport_name The transport type to create
	 * \param opts The transport options (e.g. max_io_size)
	 * \param opts_size Must be set to sizeof(struct spdk_srv_transport_opts).
	 *
	 * \return bool. true if successful, false if transport type
	 *	   not found.
	 */
	bool
	spdk_srv_transport_opts_init(const char *transport_name,
								 struct spdk_srv_transport_opts *opts, size_t opts_size);

	/**
	 * Create a protocol transport
	 *
	 * \param transport_name The transport type to create
	 * \param opts The transport options (e.g. max_io_size). It should not be NULL, and opts_size
	 *        pointed in this structure should not be zero value.
	 *
	 * \return new transport or NULL if create fails
	 */
	struct spdk_srv_transport *spdk_srv_transport_create(const char *transport_name,
														 struct spdk_srv_transport_opts *opts);

	typedef void (*spdk_srv_transport_destroy_done_cb)(void *cb_arg);

	/**
	 * Destroy a protocol transport
	 *
	 * \param transport The transport to destroy
	 * \param cb_fn A callback that will be called once the transport is destroyed
	 * \param cb_arg A context argument passed to cb_fn.
	 *
	 * \return 0 on success, -1 on failure.
	 */
	int spdk_srv_transport_destroy(struct spdk_srv_transport *transport,
								   spdk_srv_transport_destroy_done_cb cb_fn, void *cb_arg);

	/**
	 * Get an existing transport from the target
	 *
	 * \param tgt The target
	 * \param transport_name The name of the transport type to get.
	 *
	 * \return the transport or NULL if not found
	 */
	struct spdk_srv_transport *spdk_srv_tgt_get_transport(struct spdk_srv_tgt *tgt,
														  const char *transport_name);

	/**
	 * Get the first transport registered with the given target
	 *
	 * \param tgt The target
	 *
	 * \return The first transport registered on the target
	 */
	struct spdk_srv_transport *spdk_srv_transport_get_first(struct spdk_srv_tgt *tgt);

	/**
	 * Get the next transport in a target's list.
	 *
	 * \param transport A handle to a transport object
	 *
	 * \return The next transport associated with the target
	 */
	struct spdk_srv_transport *spdk_srv_transport_get_next(struct spdk_srv_transport *transport);

	/**
	 * Get the opts for a given transport.
	 *
	 * \param transport The transport to query
	 *
	 * \return The opts associated with the given transport
	 */
	const struct spdk_srv_transport_opts *spdk_srv_get_transport_opts(struct spdk_srv_transport
																		  *transport);

	/**
	 * Get the transport type for a given transport.
	 *
	 * \param transport The transport to query
	 *
	 * \return the transport type for the given transport
	 */
	spdk_srv_transport_type_t spdk_srv_get_transport_type(struct spdk_srv_transport *transport);

	/**
	 * Get the transport name for a given transport.
	 *
	 * \param transport The transport to query
	 *
	 * \return the transport name for the given transport
	 */
	const char *spdk_srv_get_transport_name(struct spdk_srv_transport *transport);

	/**
	 * Function to be called once transport add is complete
	 *
	 * \param cb_arg Callback argument passed to this function.
	 * \param status 0 if it completed successfully, or negative errno if it failed.
	 */
	typedef void (*spdk_srv_tgt_add_transport_done_fn)(void *cb_arg, int status);

	/**
	 * Add a transport to a target
	 *
	 * \param tgt The target
	 * \param transport The transport to add
	 * \param cb_fn A callback that will be called once the transport is created
	 * \param cb_arg A context argument passed to cb_fn.
	 */
	void spdk_srv_tgt_add_transport(struct spdk_srv_tgt *tgt,
									struct spdk_srv_transport *transport,
									spdk_srv_tgt_add_transport_done_fn cb_fn,
									void *cb_arg);

	/**
	 * Add listener to transport and begin accepting new connections.
	 *
	 * \param transport The transport to add listener to.
	 * \param trid The address to listen at.
	 * \param opts Listener options.
	 *
	 * \return int. 0 if it completed successfully, or negative errno if it failed.
	 */
	int
	spdk_srv_transport_listen(struct spdk_srv_transport *transport,
							  const struct spdk_srv_transport_id *trid);

	/**
	 * Remove listener from transport and stop accepting new connections.
	 *
	 * \param transport The transport to remove listener from
	 * \param trid Address to stop listen at
	 *
	 * \return int. 0 if it completed successfully, or negative errno if it failed.
	 */
	int
	spdk_srv_transport_stop_listen(struct spdk_srv_transport *transport,
								   const struct spdk_srv_transport_id *trid);

	struct spdk_srv_tgt *
	spdk_srv_tgt_create(struct spdk_srv_target_opts *opts);

	void
	spdk_srv_tgt_destroy(struct spdk_srv_tgt *tgt,
						 spdk_srv_tgt_destroy_done_fn cb_fn,
						 void *cb_arg);

	int
	spdk_srv_tgt_stop_listen(struct spdk_srv_tgt *tgt,
							 struct spdk_srv_transport_id *trid);

	void
	spdk_srv_tgt_new_conn(struct spdk_srv_tgt *tgt, struct spdk_srv_conn *conn);

	struct spdk_srv_poll_group *
	spdk_srv_poll_group_create(struct spdk_srv_tgt *tgt);

	void
	spdk_srv_poll_group_destroy(struct spdk_srv_poll_group *group,
								spdk_srv_poll_group_destroy_done_fn cb_fn,
								void *cb_arg);

	void
	spdk_srv_poll_group_destroy(struct spdk_srv_poll_group *group,
								spdk_srv_poll_group_destroy_done_fn cb_fn,
								void *cb_arg);

	void
	spdk_srv_poll_group_remove(struct spdk_srv_conn *conn);

	void spdk_srv_transport_register(const struct spdk_srv_transport_ops *ops);
	int spdk_srv_request_complete(struct spdk_srv_request *req);
	int spdk_srv_request_get_buffers(struct spdk_srv_request *req,
									 struct spdk_srv_transport_poll_group *group,
									 struct spdk_srv_transport *transport,
									 uint32_t length);
	void
	spdk_srv_request_free_buffers(struct spdk_srv_request *req,
								  struct spdk_srv_transport_poll_group *group,
								  struct spdk_srv_transport *transport);

	int
	spdk_srv_transport_id_compare(const struct spdk_srv_transport_id *trid1,
								  const struct spdk_srv_transport_id *trid2);

	void
	spdk_srv_request_exec(struct spdk_srv_request *req);

	void
	spdk_srv_trid_populate_transport(struct spdk_srv_transport_id *trid,
									 enum spdk_srv_transport_type trtype);

	void spdk_srv_rpc_register_dispatcher(void *dispatcher, int submit_type);

	typedef void (*srv_conn_disconnect_cb)(void *ctx);
	int
	spdk_srv_conn_disconnect(struct spdk_srv_conn *conn, srv_conn_disconnect_cb cb_fn, void *ctx);

#define SPDK_SRV_TRANSPORT_REGISTER(name, transport_ops)                               \
	static void __attribute__((constructor)) _spdk_srv_transport_register_##name(void) \
	{                                                                                  \
		spdk_srv_transport_register(transport_ops);                                    \
	}

#ifdef __cplusplus
}
#endif

#endif