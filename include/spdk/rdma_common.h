#ifndef SPDK_RDMA_COMMON_H
#define SPDK_RDMA_COMMON_H
#include "spdk/bdev.h"
#include "spdk/memory.h"
#include "spdk/likely.h"

#define SPDK_SRV_TRSTRING_MAX_LEN 32
#define SPDK_SERVER_TRADDR_MAX_LEN 256

#define SPDK_SRV_TRADDR_MAX_LEN 256
#define SPDK_SRV_TRSVCID_MAX_LEN 32

#define SPDK_CLIENT_SGL_SUBTYPE_INVALIDATE_KEY 0xF

#include <openssl/md5.h>
#include <openssl/evp.h>
struct spdk_md5ctx
{
	EVP_MD_CTX *md5ctx;
};
#define SPDK_MD5DIGEST_LEN 16

/**
 * NVM command set opcodes
 */
enum spdk_client_nvm_opcode
{
	SPDK_CLIENT_OPC_FLUSH = 0x00,
	SPDK_CLIENT_OPC_WRITE = 0x01,
	SPDK_CLIENT_OPC_READ = 0x02,
	/* 0x03 - reserved */
	SPDK_CLIENT_OPC_RPC_WRITE = 0x05,
	SPDK_CLIENT_OPC_RPC_READ = 0x06,
};

enum spdk_client_submit_data_type
{
	SPDK_CLIENT_SUBMIT_CONTING = 0,
	SPDK_CLIENT_SUBMIT_IOVES = 1,
	SPDK_CLIENT_SUBMIT_TYPES_TOTAL = 2,
};

enum spdk_srv_data_transfer
{
	/** Opcode does not transfer data */
	SPDK_SRV_DATA_NONE = 0,
	/** Opcode transfers data from host to controller (e.g. Write) */
	SPDK_SRV_DATA_HOST_TO_CONTROLLER = 1,
	/** Opcode transfers data from controller to host (e.g. Read) */
	SPDK_SRV_DATA_CONTROLLER_TO_HOST = 2,
	/** Opcode transfers data both directions */
	SPDK_SRV_DATA_BIDIRECTIONAL = 3
};

/**
 * Srv over Fabrics transport types
 */
enum spdk_srv_trtype
{
	/** RDMA */
	SPDK_SRV_TRTYPE_RDMA = 0x1,

	/** TCP */
	SPDK_SRV_TRTYPE_TCP = 0x2,

	/** Intra-host transport (loopback) */
	SPDK_SRV_TRTYPE_INTRA_HOST = 0xfe,
};

enum spdk_srv_transport_type
{
	/**
	 * RDMA Transport (RoCE, iWARP, etc.)
	 */
	SPDK_SRV_TRANSPORT_RDMA = SPDK_SRV_TRTYPE_RDMA,

	/**
	 * TCP Transport
	 */
	SPDK_SRV_TRANSPORT_TCP = SPDK_SRV_TRTYPE_TCP,

	/**
	 * Custom Transport (Not spec defined)
	 */
	SPDK_SRV_TRANSPORT_CUSTOM = 4096,
};

/**
 * Extract the Data Transfer bits from an Srv opcode.
 *
 * This determines whether a command requires a data buffer and
 * which direction (host to controller or controller to host) it is
 * transferred.
 */
static inline enum spdk_srv_data_transfer spdk_srv_opc_get_data_transfer(uint8_t opc)
{
	return (enum spdk_srv_data_transfer)(opc & 3);
}

struct spdk_srv_rdma_accept_private_data
{
	uint16_t recfmt;  /* record format */
	uint16_t crqsize; /* controller receive queue size */
	uint8_t reserved[28];
};

SPDK_STATIC_ASSERT(sizeof(struct spdk_srv_rdma_accept_private_data) == 32, "Incorrect size");

struct spdk_srv_rdma_reject_private_data
{
	uint16_t recfmt; /* record format */
	uint16_t sts;	 /* status */
};
SPDK_STATIC_ASSERT(sizeof(struct spdk_srv_rdma_reject_private_data) == 4, "Incorrect size");

struct spdk_srv_rdma_request_private_data
{
	uint16_t recfmt;  /* record format */
	uint16_t qid;	  /* queue id */
	uint16_t hrqsize; /* host receive queue size */
	uint16_t hsqsize; /* host send queue size */
	uint16_t cntlid;  /* controller id */
	uint8_t reserved[22];
};
SPDK_STATIC_ASSERT(sizeof(struct spdk_srv_rdma_request_private_data) == 32, "Incorrect size");

enum spdk_srv_adrfam
{
	/** IPv4 (AF_INET) */
	SPDK_SRV_ADRFAM_IPV4 = 0x1,

	/** IPv6 (AF_INET6) */
	SPDK_SRV_ADRFAM_IPV6 = 0x2,

	/** InfiniBand (AF_IB) */
	SPDK_SRV_ADRFAM_IB = 0x3,

	/** Fibre Channel address family */
	SPDK_SRV_ADRFAM_FC = 0x4,

	/** Intra-host transport (loopback) */
	SPDK_SRV_ADRFAM_INTRA_HOST = 0xfe,
};

struct __attribute__((packed)) spdk_req_sgl_descriptor
{
	uint64_t address;
	union
	{
		struct
		{
			uint8_t reserved[7];
			uint8_t subtype : 4;
			uint8_t type : 4;
		} generic;

		struct
		{
			uint32_t length;
			uint8_t reserved[3];
			uint8_t subtype : 4;
			uint8_t type : 4;
		} unkeyed;

		struct
		{
			uint64_t length : 24;
			uint64_t key : 32;
			uint64_t subtype : 4;
			uint64_t type : 4;
		} keyed;
	};
};
SPDK_STATIC_ASSERT(sizeof(struct spdk_req_sgl_descriptor) == 16, "Incorrect size");

struct spdk_rpc_req_cmd
{
	uint16_t opc; /* opcode */
	uint16_t cid; /* command identifier */
	uint32_t rpc_opc; /* rpc opc */
	uint32_t request_index;	 /* rpc request index */
	uint32_t request_length; /* rpc data length */
	struct spdk_req_sgl_descriptor sgld;
	uint32_t lba_start;
	uint32_t submit_type;							  /* submit type 0 SPDK_CLIENT_SUBMIT_CONTING or 1 SPDK_CLIENT_SUBMIT_IOVES*/
	uint32_t enable_md5_check; /* command-specific */ // check md5sum if enable_md5_check == 1
	uint8_t md5sum[16];
};

SPDK_STATIC_ASSERT(sizeof(struct spdk_rpc_req_cmd) == 60, "Incorrect size");

struct spdk_req_status
{
	uint16_t p : 1;	  /* phase tag */
	uint16_t sc : 8;  /* status code */
	uint16_t sct : 3; /* status code type */
	uint16_t crd : 2; /* command retry delay */
	uint16_t m : 1;	  /* more */
	uint16_t dnr : 1; /* do not retry */
};
SPDK_STATIC_ASSERT(sizeof(struct spdk_req_status) == 2, "Incorrect size");

/**
 * Completion queue entry
 * cdw0 -> rpc_
 *
 *
 */
struct spdk_req_cpl
{
	/* dword 0 */
	uint32_t cdw0; /* command-specific used as status code ? */

	/* dword 1 */
	uint32_t cdw1; /* command-specific required data length*/

	/* dword 2 */
	uint16_t sqhd; /* submission queue head pointer */
	uint16_t sqid; /* submission queue identifier */

	/* dword 3 */
	uint16_t cid; /* command identifier */
	union
	{
		uint16_t status_raw;
		struct spdk_req_status status;
	};
	uint8_t md5sum[16];
	// uint8_t			data[2048-16];
};
SPDK_STATIC_ASSERT(sizeof(struct spdk_req_cpl) == 32, "Incorrect size");

#endif