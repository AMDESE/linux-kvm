// SPDX-License-Identifier: GPL-2.0-only

// Interface to PSP for CCP/SEV-TIO/SNP-VM

#include <linux/pci.h>
#include <linux/tsm.h>
#include <linux/psp.h>
#include <linux/vmalloc.h>
#include <linux/bitfield.h>
#include <linux/pci-doe.h>
#include <linux/smp.h>
#include <uapi/linux/tsm.h>
#include <asm/sev-common.h>
#include <asm/sev.h>
#include <asm/page.h>
#include "sev-dev.h"
#include "sev-dev-tio.h"
#include "sev-dev-tio-dbg.h"

#define TIO_LOG_SPDM	(1<<0)
#define TIO_LOG_TIO	(1<<1)
#define TIO_LOG_DOBJ	(1<<3)
#define TIO_LOG_MEM	(1<<4)
#define TIO_LOG_GUEST	(1<<5)

static uint tiolog = TIO_LOG_SPDM | TIO_LOG_TIO | TIO_LOG_DOBJ | TIO_LOG_MEM | TIO_LOG_GUEST;
module_param_named(tiolog, tiolog, uint, 0660);
MODULE_PARM_DESC(tiolog, "Log level bitmask: 0 SPDM  1 TIOABI  3 DataObjects  4 STP  5 Guesti  6 WA");

#define to_tio_status(dev_data)	\
		(container_of((dev_data), struct tio_dsm, data)->sev->tio_status)

static void *__prep_data_pg(struct tsm_dsm_tio *dev_data, size_t len)
{
	void *r = dev_data->data_pg;

	if (snp_reclaim_pages(virt_to_phys(r), 1, false))
		return NULL;

	memset(r, 0, len);

	if (rmp_make_private(page_to_pfn(virt_to_page(r)), 0, PG_LEVEL_4K, 0, true))
		return NULL;

	return r;
}

#define DATA_PG(type, tdev) ((type *) __prep_data_pg((tdev), sizeof(type)))

#define SLA_PAGE_TYPE_DATA	0
#define SLA_PAGE_TYPE_SCATTER	1
#define SLA_PAGE_SIZE_4K	0
#define SLA_PAGE_SIZE_2M	1
#define SLA_SZ(s)		((s).page_size == SLA_PAGE_SIZE_2M ? SZ_2M : SZ_4K)
#define SLA_SCATTER_LEN(s)	(SLA_SZ(s) / sizeof(struct sla_addr_t))
#define SLA_EOL			((struct sla_addr_t) { .pfn = ((1UL << 40) - 1) })
#define SLA_NULL		((struct sla_addr_t) { 0 })
#define IS_SLA_NULL(s)		((s).sla == SLA_NULL.sla)
#define IS_SLA_EOL(s)		((s).sla == SLA_EOL.sla)

static phys_addr_t sla_to_pa(struct sla_addr_t sla)
{
	u64 pfn = sla.pfn;
	u64 pa = pfn << PAGE_SHIFT;

//	pr_err("___K___ %s %u: %llx => %llx, %llx\n", __func__, __LINE__, sla.sla, pa, sla.sla - pa);
	return pa;
}

static void *sla_to_va(struct sla_addr_t sla)
{
	void *va = __va(__sme_clr(sla_to_pa(sla)));

	return va;
}

#define sla_to_pfn(sla)		(__pa(sla_to_va(sla)) >> PAGE_SHIFT)
#define sla_to_page(sla)	virt_to_page(sla_to_va(sla))

static struct sla_addr_t make_sla(struct page *pg, bool stp)
{
	u64 pa = __sme_set(page_to_phys(pg));
	struct sla_addr_t ret = {
		.pfn = pa >> PAGE_SHIFT,
		.page_size = SLA_PAGE_SIZE_4K, /* Do not do SLA_PAGE_SIZE_2M ATM */
		.page_type = stp ? SLA_PAGE_TYPE_SCATTER : SLA_PAGE_TYPE_DATA
	};

//	pr_err("___K___ %s %u: %llx\n", __func__, __LINE__, ret.sla);
	return ret;
}

/* the BUFFER Structure */
#define SLA_BUFFER_FLAG_ENCRYPTION	BIT(0)

/*
 * struct sla_buffer_hdr - Scatter list address buffer header
 *
 * @capacity_sz: Total capacity of the buffer in bytes
 * @payload_sz: Size of buffer payload in bytes, must be multiple of 32B
 * @flags: Buffer flags (SLA_BUFFER_FLAG_ENCRYPTION: buffer is encrypted)
 * @iv: Initialization vector used for encryption
 * @authtag: Authentication tag for encrypted buffer
 */
struct sla_buffer_hdr {
	u32 capacity_sz;
	u32 payload_sz; /* The size of BUFFER_PAYLOAD in bytes. Must be multiple of 32B */
	u32 flags;
	u8 reserved1[4];
	u8 iv[16];	/* IV used for the encryption of this buffer */
	u8 authtag[16]; /* Authentication tag for this buffer */
	u8 reserved2[16];
} __packed;

enum spdm_data_type_t {
	DOBJ_DATA_TYPE_SPDM = 0x1,
	DOBJ_DATA_TYPE_SECURE_SPDM = 0x2,
};

struct spdm_dobj_hdr_req {
	struct spdm_dobj_hdr hdr; /* hdr.id == SPDM_DOBJ_ID_REQ */
	u8 data_type; /* spdm_data_type_t */
	u8 reserved2[5];
} __packed;

struct spdm_dobj_hdr_resp {
	struct spdm_dobj_hdr hdr; /* hdr.id == SPDM_DOBJ_ID_RESP */
	u8 data_type; /* spdm_data_type_t */
	u8 reserved2[5];
} __packed;

/* Defined in sev-dev-tio.h so sev-dev-tsm.c can read types of blobs */
struct spdm_dobj_hdr_cert;
struct spdm_dobj_hdr_meas;
struct spdm_dobj_hdr_report;

/* Used in all SPDM-aware TIO commands */
struct spdm_ctrl {
	struct sla_addr_t req;
	struct sla_addr_t resp;
	struct sla_addr_t scratch;
	struct sla_addr_t output;
} __packed;

static size_t sla_dobj_id_to_size(u8 id)
{
	size_t n;

	BUILD_BUG_ON(sizeof(struct spdm_dobj_hdr_resp) != 0x10);
	switch (id) {
	case SPDM_DOBJ_ID_REQ:
		n = sizeof(struct spdm_dobj_hdr_req);
		break;
	case SPDM_DOBJ_ID_RESP:
		n = sizeof(struct spdm_dobj_hdr_resp);
		break;
	case SPDM_DOBJ_ID_CERTIFICATE:
		n = sizeof(struct spdm_dobj_hdr_cert);
		break;
	case SPDM_DOBJ_ID_MEASUREMENT:
		n = sizeof(struct spdm_dobj_hdr_meas);
		break;
	case SPDM_DOBJ_ID_REPORT:
		n = sizeof(struct spdm_dobj_hdr_report);
		break;
	default:
		WARN_ON(1);
		n = 0;
		break;
	}

	return n;
}

#define SPDM_DOBJ_HDR_SIZE(hdr)		sla_dobj_id_to_size((hdr)->id)
#define SPDM_DOBJ_DATA(hdr)		((u8 *)(hdr) + SPDM_DOBJ_HDR_SIZE(hdr))
#define SPDM_DOBJ_LEN(hdr)		((hdr)->length - SPDM_DOBJ_HDR_SIZE(hdr))

#define sla_to_dobj_resp_hdr(buf)	((struct spdm_dobj_hdr_resp *) \
					sla_to_dobj_hdr_check((buf), SPDM_DOBJ_ID_RESP))
#define sla_to_dobj_req_hdr(buf)	((struct spdm_dobj_hdr_req *) \
					sla_to_dobj_hdr_check((buf), SPDM_DOBJ_ID_REQ))

static struct spdm_dobj_hdr *sla_to_dobj_hdr(struct sla_buffer_hdr *buf)
{
	if (!buf)
		return NULL;

	return (struct spdm_dobj_hdr *) &buf[1];
}

static struct spdm_dobj_hdr *sla_to_dobj_hdr_check(struct sla_buffer_hdr *buf, u32 check_dobjid)
{
	struct spdm_dobj_hdr *hdr = sla_to_dobj_hdr(buf);
	u8 type;

	if (WARN_ON_ONCE(!hdr))
		return NULL;

	if (hdr->id != check_dobjid) {
		pr_err("! ERROR: expected \"%s\" %d, found \"%s\" %d\n",
		       dobj_str(check_dobjid), check_dobjid, dobj_str(hdr->id), hdr->id);
		return NULL;
	}

	switch (check_dobjid) {
	case SPDM_DOBJ_ID_MEASUREMENT:
		type = ((struct spdm_dobj_hdr_meas *) hdr)->type;
		switch (type) {
		case TIO_SPDM_MEASUREMENTS:
		case TIO_SPDM_MEASUREMENTS_LOG:
			break;
		default:
			pr_err("! ERROR: unexpected measurements type=%d\n", type);
			goto error;
		}
		break;
	case SPDM_DOBJ_ID_CERTIFICATE:
		type = ((struct spdm_dobj_hdr_cert *) hdr)->type;
		switch (type) {
		case TIO_SPDM_CERTIFICATES:
			break;
		default:
			pr_err("! ERROR: unexpected certificate type=%d\n", type);
			goto error;
		}
		break;
	case SPDM_DOBJ_ID_REPORT:
		type = ((struct spdm_dobj_hdr_report *) hdr)->type;
		switch (type) {
		case TIO_SPDM_REPORT:
			break;
		default:
			pr_err("! ERROR: unexpected report type=%d\n", type);
			goto error;
		}
		break;
	}
	return hdr;

error:
	print_hex_dump(KERN_ERR, "DObj ", DUMP_PREFIX_OFFSET, 16, 1, hdr, sizeof(*hdr), false);
	return NULL;
}

static void *sla_to_data(struct sla_buffer_hdr *buf, u32 dobjid)
{
	struct spdm_dobj_hdr *hdr = sla_to_dobj_hdr(buf);

	if (WARN_ON_ONCE(dobjid != SPDM_DOBJ_ID_REQ && dobjid != SPDM_DOBJ_ID_RESP))
		return NULL;

	if (!hdr)
		return NULL;

	return (u8 *) hdr + sla_dobj_id_to_size(dobjid);
}

static void dobj_dump(struct sla_buffer_hdr *buf)
{
	struct spdm_dobj_hdr *hdr;
	char pfx[64] = "";
	size_t n, sz;

	if (WARN_ON(!buf))
		return;

	if (!(tiolog & TIO_LOG_DOBJ))
		return;

	hdr = sla_to_dobj_hdr(buf);
	if (WARN_ON(!hdr))
		return;

	sz = sizeof(*buf) + buf->payload_sz;
	if (buf->payload_sz != sla_dobj_id_to_size(hdr->id) + hdr->length)
		pr_err("!!! Mismatch in plsz=%d and hdrlen=%d\n",
			buf->payload_sz, hdr->length);
	n = min(sz, 256);

	snprintf(pfx, sizeof(pfx)-1, "DO=%s %d%s ",
		 dobj_str(hdr->id), hdr->id, (n == sz) ? "" : "~");
	print_hex_dump(KERN_INFO, pfx, DUMP_PREFIX_OFFSET, 16, 1, buf, n, false);
}

/**
 * struct sev_data_tio_status - SEV_CMD_TIO_STATUS command
 *
 * @length: Length of this command buffer in bytes
 * @status_paddr: System physical address of the TIO_STATUS structure
 */
struct sev_data_tio_status {
	u32 length;
	u8 reserved[4];
	u64 status_paddr;
} __packed;

/* TIO_INIT */
struct sev_data_tio_init {
	u32 length;
	u8 reserved[12];
} __packed;

/*
 * struct sev_data_tio_dev_create - TIO_DEV_CREATE command
 *
 * @length: Length in bytes of this command buffer
 * @dev_ctx_sla: Scatter list address pointing to a buffer to be used as a device context buffer
 * @device_id: PCIe Routing Identifier of the device to connect to
 * @root_port_id: PCIe Routing Identifier of the root port of the device
 * @segment_id: PCIe Segment Identifier of the device to connect to
 */
struct sev_data_tio_dev_create {
	u32 length;
	u8 reserved1[4];
	struct sla_addr_t dev_ctx_sla;
	u16 device_id;
	u16 root_port_id;
	u8 segment_id;
	u8 reserved2[11];
} __packed;

/*
 * struct sev_data_tio_dev_connect - TIO_DEV_CONNECT command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Section 5.1
 * @dev_ctx_sla: Scatter list address of the device context buffer
 * @tc_mask: Bitmask of the traffic classes to initialize for SEV-TIO usage.
 *           Setting the kth bit of the TC_MASK to 1 indicates that the traffic
 *           class k will be initialized
 * @cert_slot: Slot number of the certificate requested for constructing the SPDM session
 * @ide_stream_id: IDE stream IDs to be associated with this device.
 *                 Valid only if corresponding bit in TC_MASK is set
 */
struct sev_data_tio_dev_connect {
	u32 length;
	u8 reserved1[4];
	struct spdm_ctrl spdm_ctrl;
	u8 reserved2[8];
	struct sla_addr_t dev_ctx_sla;
	u8 tc_mask;
	u8 cert_slot;
	u8 reserved3[6];
	u8 ide_stream_id[8];
	u8 reserved4[8];
} __packed;

/*
 * struct sev_data_tio_dev_disconnect - TIO_DEV_DISCONNECT command
 *
 * @length: Length in bytes of this command buffer
 * @flags: Command flags (TIO_DEV_DISCONNECT_FLAG_FORCE: force disconnect)
 * @spdm_ctrl: SPDM control structure defined in Section 5.1
 * @dev_ctx_sla: Scatter list address of the device context buffer
 */
#define TIO_DEV_DISCONNECT_FLAG_FORCE	BIT(0)

struct sev_data_tio_dev_disconnect {
	u32 length;
	u32 flags;
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
} __packed;

/*
 * struct sev_data_tio_dev_meas - TIO_DEV_MEASUREMENTS command
 *
 * @length: Length in bytes of this command buffer
 * @flags: Command flags (TIO_DEV_MEAS_FLAG_RAW_BITSTREAM: request raw measurements)
 * @spdm_ctrl: SPDM control structure defined in Section 5.1
 * @dev_ctx_sla: Scatter list address of the device context buffer
 * @meas_nonce: Nonce for measurement freshness verification
 */
#define TIO_DEV_MEAS_FLAG_RAW_BITSTREAM	BIT(0)

struct sev_data_tio_dev_meas {
	u32 length;
	u32 flags;
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
	u8 meas_nonce[32];
} __packed;

/*
 * struct sev_data_tio_dev_certs - TIO_DEV_CERTIFICATES command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Section 5.1
 * @dev_ctx_sla: Scatter list address of the device context buffer
 */
struct sev_data_tio_dev_certs {
	u32 length;
	u8 reserved[4];
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
} __packed;

/*
 * struct sev_data_tio_dev_reclaim - TIO_DEV_RECLAIM command
 *
 * @length: Length in bytes of this command buffer
 * @dev_ctx_sla: Scatter list address of the device context buffer
 *
 * This command reclaims resources associated with a device context.
 */
struct sev_data_tio_dev_reclaim {
	u32 length;
	u8 reserved[4];
	struct sla_addr_t dev_ctx_sla;
} __packed;

/**
 * struct tio_spdm_algos - TIO SPDM algorithm identifiers
 *
 * @dhe: Diffie-Hellman Ephemeral algorithm identifier
 * @aead: Authenticated Encryption with Associated Data algorithm identifier
 * @asym: Asymmetric algorithm identifier
 * @hash: Hash algorithm identifier
 * @key_sched: Key schedule algorithm identifier
 */
struct tio_spdm_algos {
	u8 dhe;
	u8 aead;
	u8 asym;
	u8 hash;
	u8 key_sched;
	u8 reserved[3];
};

/**
 * struct sev_tio_dev_status - Device status structure returned by TIO_DEV_STATUS
 *
 * @length: Length of this status structure
 * @ctx_state: Current context state
 * @request_pending: Request pending flag
 * @request_pending_tdi: TDI-specific request pending flag
 * @certs_slot: Certificate slot number
 * @device_id: PCIe Routing Identifier of the device
 * @segment_id: PCIe Segment Identifier
 * @tc_mask: Traffic class mask
 * @request_pending_command: Command ID of pending request
 * @request_pending_interface_id: TDISP interface ID for pending request
 * @meas_digest_valid: Measurement digest validity flag
 * @no_fw_update: Firmware update disabled flag
 * @ide_stream_id: IDE stream IDs for traffic classes
 * @certs_digest: Certificate digest
 * @meas_digest: Measurement digest
 * @tdi_count: Total number of TDIs
 * @bound_tdi_count: Number of bound TDIs
 * @algos: TIO SPDM algorithms supported
 *
 * This structure is returned at sev_data_tio_dev_status::status_paddr for
 * the TIO_DEV_STATUS command.
 */
#define SEV_TIO_DEV_STATUS_P1_FLAG_REQUEST_PENDING		BIT(0)
#define SEV_TIO_DEV_STATUS_P1_FLAG_REQUEST_PENDING_TDI	BIT(1)
#define SEV_TIO_DEV_STATUS_P2_FLAG_MEAS_DIGEST_VALID	BIT(0)
#define SEV_TIO_DEV_STATUS_P2_FLAG_NO_FW_UPDATE		BIT(1)

struct sev_tio_dev_status {
	u32 length;
	u8 ctx_state;
	u8 reserved1;
	u8 p1_flags;
	u8 certs_slot;
	u16 device_id;
	u8 segment_id;
	u8 tc_mask;
	u16 request_pending_command;
	u16 reserved2;
	struct tdisp_interface_id request_pending_interface_id;
	u8 p2_flags;
	u8 reserved3[3];
	u8 ide_stream_id[8];
	u8 reserved4[8];
	u8 certs_digest[48];
	u8 meas_digest[48];
	u32 tdi_count;
	u32 bound_tdi_count;
	struct tio_spdm_algos algos;
} __packed;

/**
 * struct sev_data_tio_dev_status - TIO_DEV_STATUS command
 *
 * @length: Length in bytes of this command buffer
 * @dev_ctx_paddr: Scatter list address of device context
 * @status_paddr: System physical address where status will be written
 */
struct sev_data_tio_dev_status {
	u32 length;
	u32 reserved1;
	struct sla_addr_t dev_ctx_paddr;
	u64 status_paddr;
	u64 reserved2;
} __packed;

/**
 * struct sev_data_tio_tdi_create - TIO_TDI_CREATE command
 *
 * @length: Length in bytes of this command buffer
 * @dev_ctx_sla: Scatter list address of device context
 * @tdi_ctx_sla: Scatter list address of TDI context
 * @interface_id: Interface ID of the TDI as defined by TDISP (host PCIID)
 */
struct sev_data_tio_tdi_create {
	u32 length;
	u32 reserved;
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	struct tdisp_interface_id interface_id;
	u8 reserved2[12];
} __packed;

/**
 * struct sev_data_tio_tdi_reclaim - TIO_TDI_RECLAIM command
 *
 * @length: Length in bytes of this command buffer
 * @dev_ctx_sla: Scatter list address of device context
 * @tdi_ctx_sla: Scatter list address of TDI context
 *
 * This command reclaims resources associated with a TDI context.
 */
struct sev_data_tio_tdi_reclaim {
	u32 length;
	u32 reserved;
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 reserved2;
} __packed;

/**
 * struct sev_data_tio_tdi_bind - TIO_TDI_BIND command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2
 * @dev_ctx_sla: Scatter list address of device context
 * @tdi_ctx_sla: Scatter list address of TDI context
 * @gctx_paddr: System physical address of guest context page
 * @guest_device_id: PCIe Routing Identifier of the device in the guest
 * @tdisp_lock_if_flags: TDISP lock interface flags
 * @run_flags: Flags for TDI state transition
 *
 * This command binds a TDI to a guest context and prepares it for secure operation.
 */
#define TIO_TDI_BIND_FLAG_NO_FW_UPDATE		BIT(0)
#define TIO_TDI_BIND_FLAG_LOCK_MSIX		BIT(2)
#define TIO_TDI_BIND_FLAG_BIND_P2P		BIT(3)
#define TIO_TDI_BIND_FLAG_ALL_REQUEST_REDIRECT	BIT(4)

#define TIO_TDI_BIND_RUN_FORCE		BIT(0)

struct sev_data_tio_tdi_bind {
	u32 length;
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;
	u16 guest_device_id;
	u16 tdisp_lock_if_flags; /* TIO_TDI_BIND_FLAG_xxxx */
	u16 run_flags; /* TIO_TDI_BIND_RUN_xxxx */
	u8 reserved3[10];
} __packed;

/**
 * struct sev_data_tio_tdi_unbind - TIO_TDI_UNBIND command
 *
 * @length: Length in bytes of this command buffer
 * @flags: Command flags
 * @spdm_ctrl: SPDM control structure defined in Chapter 2
 * @dev_ctx_sla: Scatter list address of device context
 * @tdi_ctx_sla: Scatter list address of TDI context
 * @gctx_paddr: System physical address of guest context page
 *
 * This command unbinds a TDI from a guest context.
 */
#define TIO_TDI_UNBIND_FLAG_FORCE	BIT(0)

struct sev_data_tio_tdi_unbind {
	u32 length;
	u32 flags;
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;
} __packed;

/**
 * struct sev_data_tio_tdi_report - TIO_TDI_REPORT command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2
 * @dev_ctx_sla: Scatter list address of the device context buffer
 * @tdi_ctx_sla: Scatter list address of a TDI context buffer
 * @gctx_paddr: System physical address of a guest context page
 *
 * This command retrieves the TDISP interface report for a TDI.
 */
struct sev_data_tio_tdi_report {
	u32 length;
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;
} __packed;

/**
 * struct sev_data_tio_asid_fence_clear - TIO_ASID_FENCE_CLEAR command
 *
 * @length: Length in bytes of this command buffer
 * @dev_ctx_paddr: Scatter list address of device context
 * @gctx_paddr: System physical address of guest context page
 *
 * This command clears the ASID fence for a TDI.
 */
struct sev_data_tio_asid_fence_clear {
	u32 length;
	u32 reserved1;
	struct sla_addr_t dev_ctx_paddr;
	u64 gctx_paddr;
	u8 reserved2[8];
} __packed;

/**
 * struct sev_data_tio_asid_fence_status - TIO_ASID_FENCE_STATUS command
 *
 * @length: Length in bytes of this command buffer
 * @dev_ctx_paddr: Scatter list address of device context
 * @asid: Address Space Identifier to query
 * @status_pa: System physical address where fence status will be written
 *
 * This command queries the fence status for a specific ASID.
 */
#define TIO_FENCE_DMA_STATUS_MASK	GENMASK(1, 0)
#define TIO_FENCE_DMA_STATUS_SHIFT	0
#define TIO_FENCE_DMA_STATUS_NOT_FENCED	0
#define TIO_FENCE_DMA_STATUS_ERROR_FENCED 1
#define TIO_FENCE_DMA_STATUS_RESERVED	2
#define TIO_FENCE_DMA_STATUS_DEFAULT_FENCED 3

#define TIO_FENCE_MMIO_STATUS_MASK	GENMASK(3, 2)
#define TIO_FENCE_MMIO_STATUS_SHIFT	2
#define TIO_FENCE_MMIO_STATUS_NOT_FENCED 0
#define TIO_FENCE_MMIO_STATUS_RESERVED	1
#define TIO_FENCE_MMIO_STATUS_RESERVED2	2
#define TIO_FENCE_MMIO_STATUS_FENCED	3

struct sev_data_tio_asid_fence_status {
	u32 length;
	u8 reserved1[4];
	struct sla_addr_t dev_ctx_paddr;
	u32 asid;
	u64 status_pa;
	u8 reserved2[4];
} __packed;

/**
 * struct sev_data_tio_guest_request - TIO_GUEST_REQUEST command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2
 * @dev_ctx_sla: Scatter list address of device context
 * @tdi_ctx_sla: SPA of TDI context page donated by hypervisor
 * @gctx_paddr: System physical address of guest context page
 * @req_paddr: System physical address of request page
 * @res_paddr: System physical address of response page
 *
 * This command sends a guest request for TDISP operations through the PSP.
 */
struct sev_data_tio_guest_request {
	u32 length;
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;
	u64 req_paddr;
	u64 res_paddr;
} __packed;

struct sev_data_tio_roll_key {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	struct sla_addr_t dev_ctx_sla;			/* In */
} __packed;

#define sla_buffer_map(sla)	__sla_buffer_map((sla), __func__, __LINE__)
static struct sla_buffer_hdr *__sla_buffer_map(struct sla_addr_t sla, const char *fff, int nnn)
{
	struct sla_buffer_hdr *buf;
	char tmp[256] = "";

	BUILD_BUG_ON(sizeof(struct sla_buffer_hdr) != 0x40);
	if (IS_SLA_NULL(sla))
		return NULL;

	if (sla.page_type == SLA_PAGE_TYPE_SCATTER) {
		struct sla_addr_t *scatter = sla_to_va(sla);
		unsigned int i, npages = 0;

		for (i = 0; i < SLA_SCATTER_LEN(sla); ++i) {
			if (WARN_ON_ONCE(SLA_SZ(scatter[i]) > SZ_4K))
				return NULL;

			if (WARN_ON_ONCE(scatter[i].page_type == SLA_PAGE_TYPE_SCATTER))
				return NULL;

			if (IS_SLA_EOL(scatter[i])) {
				npages = i;
				break;
			}
		}
		if (WARN_ON_ONCE(!npages))
			return NULL;

		struct page **pp = kmalloc_array(npages, sizeof(pp[0]), GFP_KERNEL);

		if (!pp)
			return NULL;

		sprintf(tmp, "%d pages, %llx:", npages, sla.sla);
		for (i = 0; i < npages; ++i) {
			snprintf(tmp + strlen(tmp), sizeof(tmp) - strlen(tmp) - 1, " %llx", scatter[i].sla);
			pp[i] = sla_to_page(scatter[i]);
		}

		buf = vm_map_ram(pp, npages, 0);
		kfree(pp);
	} else {
		struct page *pg = sla_to_page(sla);

		buf = vm_map_ram(&pg, 1, 0);
		sprintf(tmp, "1 page = %llx", sla.sla);
	}
	if (tiolog & TIO_LOG_MEM)
		pr_info("sla vmap: %lx <- %s\n", (unsigned long) buf, tmp);

	return buf;
}

static void sla_buffer_unmap(struct sla_addr_t sla, struct sla_buffer_hdr *buf)
{
	char tmp[256] = "";

	if (!buf) {
		pr_err_once("___K___ %s %u\n", __func__, __LINE__);
		return;
	}

	if (sla.page_type == SLA_PAGE_TYPE_SCATTER) {
		struct sla_addr_t *scatter = sla_to_va(sla);
		unsigned int i, npages = 0;

		sprintf(tmp, "%d page(s), %llx:", npages, sla.sla);
		for (i = 0; i < SLA_SCATTER_LEN(sla); ++i) {
			snprintf(tmp + strlen(tmp), sizeof(tmp) - strlen(tmp) - 1, " %llx", scatter[i].sla);
			if (IS_SLA_EOL(scatter[i])) {
				npages = i;
				break;
			}
		}
		if (!npages)
			return;

		vm_unmap_ram(buf, npages);
	} else {
		vm_unmap_ram(buf, 1);
		sprintf(tmp, "1 page = %llx", sla.sla);
	}
	if (tiolog & TIO_LOG_MEM)
		pr_info("sla vunmap: %lx %s\n", (unsigned long) buf, tmp);
}

static void dobj_response_init(struct sla_buffer_hdr *buf)
{
	struct spdm_dobj_hdr *dobj = sla_to_dobj_hdr(buf);

	dobj->id = SPDM_DOBJ_ID_RESP;
	dobj->version.major = 0x1;
	dobj->version.minor = 0;
	dobj->length = 0;
	buf->payload_sz = sla_dobj_id_to_size(dobj->id) + dobj->length;

	dobj_dump(buf);
}

static void sla_free(struct sla_addr_t sla, size_t len, bool firmware_state)
{
	unsigned int npages = PAGE_ALIGN(len) >> PAGE_SHIFT;
	struct sla_addr_t *scatter = NULL;
	int ret = 0, i;
	char tmp[256];

	if (IS_SLA_NULL(sla))
		return;

	if (firmware_state) {
		if (sla.page_type == SLA_PAGE_TYPE_SCATTER) {
			scatter = sla_to_va(sla);

			tmp[0] = 0;
			for (i = 0; i < npages; ++i) {
				if (IS_SLA_EOL(scatter[i]))
					break;

				snprintf(tmp + strlen(tmp), sizeof(tmp) - strlen(tmp), " %llx",
					 scatter[i].sla);

				ret = snp_reclaim_pages(sla_to_pa(scatter[i]), 1, false);
				if (ret)
					break;
			}
			pr_notice("Reclaimed (ret %d) private %d: %s\n", ret, npages, tmp);
		} else {
			pr_err("Reclaiming %llx\n", sla.sla);
			ret = snp_reclaim_pages(sla_to_pa(sla), 1, false);
		}
	}

	if (WARN_ON(ret))
		return;

	if (scatter) {
		pr_notice("Freeing %d data pages\n", npages);
		for (i = 0; i < npages; ++i) {
			if (IS_SLA_EOL(scatter[i]))
				break;
			free_page((unsigned long)sla_to_va(scatter[i]));
		}
	}

	pr_notice("Freeing 1 data page\n");
	free_page((unsigned long)sla_to_va(sla));
}

#define sla_alloc(l, fs) __sla_alloc_dobj((l), (fs), __func__, __LINE__)
static struct sla_addr_t __sla_alloc_dobj(size_t len, bool firmware_state, const char *fff, int nnn)
{
	unsigned long i, npages = PAGE_ALIGN(len) >> PAGE_SHIFT;
	struct sla_addr_t *scatter = NULL;
	struct sla_addr_t ret = SLA_NULL;
	struct sla_buffer_hdr *buf;
	char tmp[256] = "";
	struct page *pg;

	if (npages == 0)
		return ret;

	if (WARN_ON_ONCE(npages > ((PAGE_SIZE / sizeof(struct sla_addr_t)) + 1)))
		return ret;

	BUILD_BUG_ON(PAGE_SIZE < SZ_4K);

	if (npages > 1) {
		pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!pg)
			return SLA_NULL;

		ret = make_sla(pg, true);
		scatter = page_to_virt(pg);
		for (i = 0; i < npages; ++i) {
			pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
			if (!pg)
				goto no_reclaim_exit;

			scatter[i] = make_sla(pg, false);
		}
		scatter[i] = SLA_EOL;
	} else {
		pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!pg)
			return SLA_NULL;

		ret = make_sla(pg, false);
	}

	buf = sla_buffer_map(ret);
	if (!buf)
		goto no_reclaim_exit;

	buf->capacity_sz = (npages << PAGE_SHIFT);
	sla_buffer_unmap(ret, buf);

	if (firmware_state) {
		if (scatter) {
			tmp[0] = 0;
			for (i = 0; i < npages; ++i) {
				if (rmp_make_private(sla_to_pfn(scatter[i]), 0, PG_LEVEL_4K, 0, true))
					goto free_exit;

				snprintf(tmp + strlen(tmp), sizeof(tmp) - strlen(tmp), " %llx",
					 scatter[i].sla);
			}
			pr_notice("_K_ %s %u: private %ld page(s)\n_K_ %s\n", fff, nnn, npages, tmp);
		} else {
			if (rmp_make_private(sla_to_pfn(ret), 0, PG_LEVEL_4K, 0, true))
				goto no_reclaim_exit;
			pr_notice("_K_ %s %u: %llx -> private\n", fff, nnn, ret.sla);
		}
	}

	pr_notice("%s %u: sla_alloc(len=%lx npages=%lx) => PFN#%lx/%s/%s %s\n", fff, nnn,
		  (unsigned long) len, (unsigned long) npages,
		  (unsigned long) ret.pfn, ret.page_type ? "STP":"data", ret.page_size ? "2M" : "4K",
		  firmware_state ? "FW":"HV");

	if (scatter)
		print_hex_dump(KERN_INFO, "SLA ", DUMP_PREFIX_OFFSET, 16, 8,
			       scatter, sizeof(struct sla_addr_t) * (npages + 1), false);
	return ret;

no_reclaim_exit:
	firmware_state = false;
free_exit:
	sla_free(ret, len, firmware_state);
	return SLA_NULL;
}

/* Expands a buffer, only firmware owned buffers allowed for now */
static int sla_expand(struct sla_addr_t *sla, size_t *len)
{
	struct sla_buffer_hdr *oldbuf = sla_buffer_map(*sla), *newbuf;
	struct sla_addr_t oldsla = *sla, newsla;
	size_t oldlen = *len, newlen;

	if (!oldbuf)
		return -EFAULT;

	newlen = oldbuf->capacity_sz;
	if (oldbuf->capacity_sz == oldlen) {
		/* This buffer does not require expansion, must be another buffer */
		sla_buffer_unmap(oldsla, oldbuf);
		return 1;
	}

	pr_notice("Expanding BUFFER from %ld to %ld bytes\n", oldlen, newlen);

	newsla = sla_alloc(newlen, true);
	if (IS_SLA_NULL(newsla))
		return -ENOMEM;

	newbuf = sla_buffer_map(newsla);
	if (!newbuf) {
		sla_free(newsla, newlen, true);
		return -EFAULT;
	}

	memcpy(newbuf, oldbuf, oldlen);

	sla_buffer_unmap(newsla, newbuf);
	sla_free(oldsla, oldlen, true);
	*sla = newsla;
	*len = newlen;

	return 0;
}

bool tio_save_output(struct tsm_blob **blob, struct sla_addr_t sla,
		     u32 check_dobjid, void *dobjhdr)
{
	struct sla_buffer_hdr *buf;
	struct spdm_dobj_hdr *hdr;

	tsm_blob_free(*blob);
	*blob = NULL;

	buf = sla_buffer_map(sla);
	if (!buf)
		return false;

	hdr = sla_to_dobj_hdr_check(buf, check_dobjid);
	if (hdr) {
		*blob = tsm_blob_new(SPDM_DOBJ_DATA(hdr), hdr->length);
		if (dobjhdr)
			memcpy(dobjhdr, hdr, SPDM_DOBJ_HDR_SIZE(hdr));
	}

//	dobj_dump(buf);
//
//	if ((tiolog & TIO_LOG_DOBJ) && (hdr->id == check_dobjid) &&
//	    (check_dobjid == SPDM_DOBJ_ID_REPORT) && *blob) {
//		char *buf1 = kmalloc(PAGE_SIZE, GFP_KERNEL);
//		if (tsm_report_gen(*blob, buf1, PAGE_SIZE) > 0)
//			pr_info("Interface report:\n%s", buf1);
//		kfree(buf1);
//	}

	dobj_dump(buf);

	sla_buffer_unmap(sla, buf);

	return *blob != NULL;
}

struct spdm_msg_hdr  {
	u8 ver;
	u8 request_response_code;
	u8 param1;
	u8 param2;
} __packed;

struct secured_session_hdr
{
	u32 session_id;
	//u16 sequence_num;
	u16 msg_len;
} __packed;

static inline char *pr_spdm(char *buf, size_t len, struct spdm_msg_hdr *sh, u8 secure)
{
	if (secure == DOBJ_DATA_TYPE_SECURE_SPDM) {
		struct secured_session_hdr *sec = (struct secured_session_hdr *) sh;
		snprintf(buf, len, " [SecSPDM id=%x len=%hd]", sec->session_id, sec->msg_len);
		return buf;
	}
	snprintf(buf, len, "[SPDM v%x %x=\"%s\" %02x %02x]",
		 sh->ver, sh->request_response_code, spdm_to_str(sh->request_response_code),
		 sh->param1, sh->param2);
	return buf;
}

static int sev_tio_do_cmd(int cmd, void *data, size_t data_len, int *psp_ret,
			  struct tsm_dsm_tio *dev_data)
{
	int rc;
	char pfx[128];
	char buf[256];

	sprintf(pfx, "#%d %s(%x) ", smp_processor_id(), tio_cmd_to_str(cmd), cmd);
	if (cmd == SEV_CMD_TIO_GUEST_REQUEST) {
		struct sev_data_tio_guest_request *gr = data_len ? data : dev_data->cmd_data;
		struct snp_guest_msg_hdr *rq = phys_to_virt(__sme_clr(gr->req_paddr));

		sprintf(pfx + strlen(pfx), "%s(%x) ",
			guest_req_to_str(rq->msg_type), rq->msg_type);
	}

	// We are continuing
	if (data_len == 0) {
		if (WARN_ON_ONCE(!dev_data))
			return -EFAULT;

		struct spdm_dobj_hdr_resp *resp_hdr = sla_to_dobj_resp_hdr(dev_data->respbuf);
		struct tsm_spdm *spdm = &dev_data->spdm;

		pr_notice(" - %s Resp %s, len=%ld\n",
			pfx,
			pr_spdm(buf, sizeof(buf) - 1, spdm->rsp, resp_hdr->data_type),
			spdm->rsp_len);
		if (tiolog & TIO_LOG_SPDM)
			print_hex_dump(KERN_INFO, "SPDM> ", DUMP_PREFIX_OFFSET, 16, 1,
				       spdm->rsp, min(spdm->rsp_len, 64), false);
	} else {
		// Dump only the first one
		pr_notice("%s cmdlen=%ld\n", pfx, data_len);
		if (tiolog & TIO_LOG_TIO)
			print_hex_dump(KERN_INFO, pfx, DUMP_PREFIX_OFFSET, 16,
				       1, data, *(u32 *) data, false);
	}

	*psp_ret = 0;
	rc = sev_do_cmd(cmd, data, psp_ret);

	if (WARN_ON(!dev_data && !rc && *psp_ret == SEV_RET_SPDM_REQUEST))
		return -EIO;

	if (rc == 0 && *psp_ret == SEV_RET_EXPAND_BUFFER_LENGTH_REQUEST) {
		int rc1, rc2;

		rc1 = sla_expand(&dev_data->output, &dev_data->output_len);
		if (rc1 < 0)
			return rc1;

		rc2 = sla_expand(&dev_data->scratch, &dev_data->scratch_len);
		if (rc2 < 0)
			return rc2;

		if (!rc1 && !rc2)
			/* Neither buffer requires expansion, this is wrong */
			return -EFAULT;

		*psp_ret = 0;
		rc = sev_do_cmd(cmd, data, psp_ret);
	}

	if (dev_data && (rc == 0 || rc == -EIO) && *psp_ret == SEV_RET_SPDM_REQUEST) {
		struct spdm_dobj_hdr_resp *resp_hdr;
		struct spdm_dobj_hdr_req *req_hdr;
		struct sev_tio_status *tio_status = to_tio_status(dev_data);
		size_t resp_len = tio_status->spdm_req_size_max -
			(sla_dobj_id_to_size(SPDM_DOBJ_ID_RESP) + sizeof(struct sla_buffer_hdr));

		if (!dev_data->cmd) {
			if (WARN_ON_ONCE(!data_len || (data_len != *(u32 *) data)))
				return -EINVAL;
			if (WARN_ON(data_len > sizeof(dev_data->cmd_data)))
				return -EFAULT;
			memcpy(dev_data->cmd_data, data, data_len);
			memset(&dev_data->cmd_data[data_len], 0xFF,
			       sizeof(dev_data->cmd_data) - data_len);
			dev_data->cmd = cmd;
		}

		req_hdr = sla_to_dobj_req_hdr(dev_data->reqbuf);
		resp_hdr = sla_to_dobj_resp_hdr(dev_data->respbuf);
		switch (req_hdr->data_type) {
		case DOBJ_DATA_TYPE_SPDM:
			rc = PCI_DOE_FEATURE_CMA;
			break;
		case DOBJ_DATA_TYPE_SECURE_SPDM:
			rc = PCI_DOE_FEATURE_SSESSION;
			break;
		default:
			return -EINVAL;
		}
		resp_hdr->data_type = req_hdr->data_type;
		dev_data->spdm.req_len = req_hdr->hdr.length -
			sla_dobj_id_to_size(SPDM_DOBJ_ID_REQ);
		dev_data->spdm.rsp_len = resp_len;
		if (tiolog & TIO_LOG_SPDM)
			print_hex_dump(KERN_INFO, "SPDM< ", DUMP_PREFIX_OFFSET, 16, 1,
				       dev_data->spdm.req,
				       min(dev_data->spdm.req_len, 64), false);
	} else if (dev_data && dev_data->cmd) {
		/* For either error or success just stop the bouncing */
		memset(dev_data->cmd_data, 0, sizeof(dev_data->cmd_data));
		dev_data->cmd = 0;
	}

	pr_notice(" . %s rc=%d psp=0x%x %s %s\n",
		  pfx, rc, *psp_ret, psp_ret_to_str(*psp_ret),
		  (*psp_ret == SEV_RET_SPDM_REQUEST) ? "...spdm..." :
		  ((*psp_ret != SEV_RET_SUCCESS) ? "---ERR---" : "done!"));

	if (*psp_ret != SEV_RET_SUCCESS && *psp_ret != SEV_RET_SPDM_REQUEST && !(tiolog & TIO_LOG_TIO))
		print_hex_dump(KERN_INFO, pfx, DUMP_PREFIX_OFFSET, 16,
			       1, data, *(u32 *) data, false);

	return rc;
}

#define sev_do_cmd(c, d, p) sev_tio_do_cmd((c), (d), sizeof(*(d)), (p), NULL)

int sev_tio_continue(struct tsm_dsm_tio *dev_data)
{
	struct spdm_dobj_hdr_resp *resp_hdr;
	int ret;

	if (!dev_data || !dev_data->cmd)
		return -EINVAL;

	resp_hdr = sla_to_dobj_resp_hdr(dev_data->respbuf);
	resp_hdr->hdr.length = ALIGN(sla_dobj_id_to_size(SPDM_DOBJ_ID_RESP) +
				     dev_data->spdm.rsp_len, 32);
	dev_data->respbuf->payload_sz = resp_hdr->hdr.length;

	ret = sev_tio_do_cmd(dev_data->cmd, dev_data->cmd_data, 0,
			     &dev_data->psp_ret, dev_data);
	if (ret)
		return ret;

	if (dev_data->psp_ret != SEV_RET_SUCCESS)
		return -EINVAL;

	return 0;
}

static void spdm_ctrl_init(struct spdm_ctrl *ctrl, struct tsm_dsm_tio *dev_data)
{
	ctrl->req = dev_data->req;
	ctrl->resp = dev_data->resp;
	ctrl->scratch = dev_data->scratch;
	ctrl->output = dev_data->output;
	if (tiolog & TIO_LOG_SPDM)
		print_hex_dump(KERN_INFO, "SPDMCTRL ", DUMP_PREFIX_OFFSET, 16, 8, ctrl, sizeof(*ctrl), false);
}

static void spdm_ctrl_free(struct tsm_dsm_tio *dev_data)
{
	struct sev_tio_status *tio_status = to_tio_status(dev_data);
	size_t len = tio_status->spdm_req_size_max -
		(sla_dobj_id_to_size(SPDM_DOBJ_ID_RESP) +
		 sizeof(struct sla_buffer_hdr));
	struct tsm_spdm *spdm = &dev_data->spdm;

	sla_buffer_unmap(dev_data->resp, dev_data->respbuf);
	sla_buffer_unmap(dev_data->req, dev_data->reqbuf);
	spdm->rsp = NULL;
	spdm->req = NULL;
	sla_free(dev_data->req, len, true);
	sla_free(dev_data->resp, len, false);
	sla_free(dev_data->scratch, tio_status->spdm_scratch_size_max, true);

	dev_data->req.sla = 0;
	dev_data->resp.sla = 0;
	dev_data->scratch.sla = 0;
	dev_data->respbuf = NULL;
	dev_data->reqbuf = NULL;
	sla_free(dev_data->output, tio_status->spdm_out_size_max, true);
}

static int spdm_ctrl_alloc(struct tsm_dsm_tio *dev_data)
{
	struct sev_tio_status *tio_status = to_tio_status(dev_data);
	struct tsm_spdm *spdm = &dev_data->spdm;
	int ret;

	dev_data->req = sla_alloc(tio_status->spdm_req_size_max, true);
	dev_data->resp = sla_alloc(tio_status->spdm_req_size_max, false);
	dev_data->scratch_len = tio_status->spdm_scratch_size_max;
	dev_data->scratch = sla_alloc(dev_data->scratch_len, true);
	dev_data->output_len = tio_status->spdm_out_size_max;
	dev_data->output = sla_alloc(dev_data->output_len, true);

	if (IS_SLA_NULL(dev_data->req) || IS_SLA_NULL(dev_data->resp) ||
	    IS_SLA_NULL(dev_data->scratch) || IS_SLA_NULL(dev_data->dev_ctx)) {
		ret = -ENOMEM;
		goto free_spdm_exit;
	}

	dev_data->reqbuf = sla_buffer_map(dev_data->req);
	dev_data->respbuf = sla_buffer_map(dev_data->resp);
	if (!dev_data->reqbuf || !dev_data->respbuf) {
		ret = -EFAULT;
		goto free_spdm_exit;
	}

	spdm->req = sla_to_data(dev_data->reqbuf, SPDM_DOBJ_ID_REQ);
	spdm->rsp = sla_to_data(dev_data->respbuf, SPDM_DOBJ_ID_RESP);
	if (!spdm->req || !spdm->rsp) {
		ret = -EFAULT;
		goto free_spdm_exit;
	}

	dobj_response_init(dev_data->respbuf);

	return 0;

free_spdm_exit:
	spdm_ctrl_free(dev_data);
	return ret;
}

int sev_tio_init_locked(void *tio_status_page)
{
	struct sev_tio_status *tio_status = tio_status_page;
	struct sev_data_tio_status data_status = {
		.length = sizeof(data_status),
	};
	int ret, psp_ret;

	data_status.status_paddr = __psp_pa(tio_status_page);
	ret = __sev_do_cmd_locked(SEV_CMD_TIO_STATUS, &data_status, &psp_ret);
	if (ret)
		return ret;

	print_hex_dump(KERN_INFO, "TIO_ST ", DUMP_PREFIX_OFFSET, 16, 1, tio_status,
		       min(512, tio_status->length), false);

	if (tio_status->length < offsetofend(struct sev_tio_status, tdictx_size) ||
	    tio_status->reserved)
		return -EFAULT;

	if (!tio_status->tio_en && !tio_status->tio_init_done)
		return -ENOENT;

	if (tio_status->tio_init_done)
		return -EBUSY;

	struct sev_data_tio_init ti = { .length = sizeof(ti) };

	ret = __sev_do_cmd_locked(SEV_CMD_TIO_INIT, &ti, &psp_ret);
	if (ret)
		return ret;

	ret = __sev_do_cmd_locked(SEV_CMD_TIO_STATUS, &data_status, &psp_ret);
	if (ret)
		return ret;

	return 0;
}

int sev_tio_dev_create(struct tsm_dsm_tio *dev_data, u16 device_id,
		       u16 root_port_id, u8 segment_id)
{
	struct sev_tio_status *tio_status = to_tio_status(dev_data);
	struct sev_data_tio_dev_create create = {
		.length = sizeof(create),
		.device_id = device_id,
		.root_port_id = root_port_id,
		.segment_id = segment_id,
	};
	void *data_pg;
	int ret;

	dev_data->dev_ctx = sla_alloc(tio_status->devctx_size, true);
	if (IS_SLA_NULL(dev_data->dev_ctx))
		return -ENOMEM;

	data_pg = snp_alloc_firmware_page(GFP_KERNEL_ACCOUNT);
	if (!data_pg) {
		ret = -ENOMEM;
		goto free_ctx_exit;
	}

	create.dev_ctx_sla = dev_data->dev_ctx;
	ret = sev_do_cmd(SEV_CMD_TIO_DEV_CREATE, &create, &dev_data->psp_ret);
	if (ret)
		goto free_data_pg_exit;

	dev_data->data_pg = data_pg;

	return 0;

free_data_pg_exit:
	snp_free_firmware_page(data_pg);
free_ctx_exit:
	sla_free(create.dev_ctx_sla, tio_status->devctx_size, true);
	return ret;
}

int sev_tio_dev_reclaim(struct tsm_dsm_tio *dev_data)
{
	struct sev_tio_status *tio_status = to_tio_status(dev_data);
	struct sev_data_tio_dev_reclaim r = {
		.length = sizeof(r),
		.dev_ctx_sla = dev_data->dev_ctx,
	};
	int ret;

	if (dev_data->data_pg) {
		snp_free_firmware_page(dev_data->data_pg);
		dev_data->data_pg = NULL;
	}

	if (IS_SLA_NULL(dev_data->dev_ctx))
		return 0;

	ret = sev_do_cmd(SEV_CMD_TIO_DEV_RECLAIM, &r, &dev_data->psp_ret);

	sla_free(dev_data->dev_ctx, tio_status->devctx_size, true);
	dev_data->dev_ctx = SLA_NULL;

	spdm_ctrl_free(dev_data);

	return ret;
}

int sev_tio_dev_connect(struct tsm_dsm_tio *dev_data, u8 tc_mask, u8 ids[8], u8 cert_slot)
{
	struct sev_data_tio_dev_connect connect = {
		.length = sizeof(connect),
		.tc_mask = tc_mask,
		.cert_slot = cert_slot,
		.dev_ctx_sla = dev_data->dev_ctx,
		.ide_stream_id = {
			ids[0], ids[1], ids[2], ids[3],
			ids[4], ids[5], ids[6], ids[7]
		},
	};
	int ret;

	if (WARN_ON(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;
	if (!(tc_mask & 1))
		return -EINVAL;

	ret = spdm_ctrl_alloc(dev_data);
	if (ret)
		return ret;

	spdm_ctrl_init(&connect.spdm_ctrl, dev_data);

	return sev_tio_do_cmd(SEV_CMD_TIO_DEV_CONNECT, &connect, sizeof(connect),
			      &dev_data->psp_ret, dev_data);
}

int sev_tio_dev_disconnect(struct tsm_dsm_tio *dev_data, bool force)
{
	struct sev_data_tio_dev_disconnect dc = {
		.length = sizeof(dc),
		.dev_ctx_sla = dev_data->dev_ctx,
		.flags = force ? TIO_DEV_DISCONNECT_FLAG_FORCE : 0,
	};

	if (WARN_ON_ONCE(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;

	spdm_ctrl_init(&dc.spdm_ctrl, dev_data);

	return sev_tio_do_cmd(SEV_CMD_TIO_DEV_DISCONNECT, &dc, sizeof(dc),
			      &dev_data->psp_ret, dev_data);
}

int sev_tio_dev_measurements(struct tsm_dsm_tio *dev_data,
			     spdm_measurements_nonce_t nonce)
{
	struct sev_data_tio_dev_meas meas = {
		.length = sizeof(meas),
		.flags = TIO_DEV_MEAS_FLAG_RAW_BITSTREAM,
	};

	if (WARN_ON(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;

	spdm_ctrl_init(&meas.spdm_ctrl, dev_data);
	meas.dev_ctx_sla = dev_data->dev_ctx;
	memcpy(meas.meas_nonce, nonce, sizeof(meas.meas_nonce));

	return sev_tio_do_cmd(SEV_CMD_TIO_DEV_MEASUREMENTS, &meas, sizeof(meas),
			      &dev_data->psp_ret, dev_data);
}

int sev_tio_dev_certificates(struct tsm_dsm_tio *dev_data)
{
	struct sev_data_tio_dev_certs c = {
		.length = sizeof(c),
	};

	if (WARN_ON(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;

	spdm_ctrl_init(&c.spdm_ctrl, dev_data);
	c.dev_ctx_sla = dev_data->dev_ctx;

	return sev_tio_do_cmd(SEV_CMD_TIO_DEV_CERTIFICATES, &c, sizeof(c),
			      &dev_data->psp_ret, dev_data);
}

int sev_tio_dev_status(struct tsm_dsm_tio *dev_data, struct tsm_dsm_status *s)
{
	struct sev_tio_dev_status *status =
		DATA_PG(struct sev_tio_dev_status, dev_data);
	struct sev_data_tio_dev_status data_status = {
		.length = sizeof(data_status),
		.dev_ctx_paddr = dev_data->dev_ctx,
		.status_paddr = __psp_pa(status),
	};
	int ret;

	if (!dev_data)
		return -ENODEV;

	if (IS_SLA_NULL(dev_data->dev_ctx))
		return -ENXIO;

	ret = sev_do_cmd(SEV_CMD_TIO_DEV_STATUS, &data_status, &dev_data->psp_ret);
	if (ret)
		return ret;

	s->ctx_state = status->ctx_state;
	s->device_id = status->device_id;
	s->tc_mask = status->tc_mask;
	memcpy(s->ide_stream_id, status->ide_stream_id, sizeof(status->ide_stream_id));
	s->certs_slot = status->certs_slot;
	s->no_fw_update = !!(status->p2_flags & SEV_TIO_DEV_STATUS_P2_FLAG_NO_FW_UPDATE);

	return 0;
}

int sev_tio_ide_refresh(struct tsm_dsm_tio *dev_data)
{
	struct sev_data_tio_roll_key rk = {
		.length = sizeof(rk),
		.dev_ctx_sla = dev_data->dev_ctx,
	};

	if (WARN_ON(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;

	spdm_ctrl_init(&rk.spdm_ctrl, dev_data);

	return sev_tio_do_cmd(SEV_CMD_TIO_ROLL_KEY, &rk, sizeof(rk),
			      &dev_data->psp_ret, dev_data);
}

int sev_tio_tdi_create(struct tsm_dsm_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		       u16 dev_id, u8 rseg)
{
	struct sev_tio_status *tio_status = to_tio_status(dev_data);
	struct sev_data_tio_tdi_create c = {
		.length = sizeof(c),
	};
	int ret;

	if (!dev_data || !tdi_data) /* Device is not "connected" */
		return -EPERM;

	if (WARN_ON_ONCE(IS_SLA_NULL(dev_data->dev_ctx) || !IS_SLA_NULL(tdi_data->tdi_ctx)))
		return -EFAULT;

	tdi_data->tdi_ctx = sla_alloc(tio_status->tdictx_size, true);
	if (IS_SLA_NULL(tdi_data->tdi_ctx))
		return -ENOMEM;

	c.dev_ctx_sla = dev_data->dev_ctx;
	c.tdi_ctx_sla = tdi_data->tdi_ctx;
	c.interface_id.function_id =
		FIELD_PREP(TSM_TDISP_IID_REQUESTER_ID, dev_id);
	if (rseg)
		c.interface_id.function_id |=
			FIELD_PREP(TSM_TDISP_IID_RSEG, rseg) |
			FIELD_PREP(TSM_TDISP_IID_RSEG_VALID, 1);

	ret = sev_do_cmd(SEV_CMD_TIO_TDI_CREATE, &c, &dev_data->psp_ret);
	if (ret)
		goto free_exit;

	return 0;

free_exit:
	sla_free(tdi_data->tdi_ctx, tio_status->tdictx_size, true);
	tdi_data->tdi_ctx = SLA_NULL;
	return ret;
}

void sev_tio_tdi_reclaim(struct tsm_dsm_tio *dev_data, struct tsm_tdi_tio *tdi_data)
{
	struct sev_tio_status *tio_status = to_tio_status(dev_data);
	struct sev_data_tio_tdi_reclaim r = {
		.length = sizeof(r),
	};

	if (WARN_ON(!dev_data || !tdi_data))
		return;
	if (IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx))
		return;

	r.dev_ctx_sla = dev_data->dev_ctx;
	r.tdi_ctx_sla = tdi_data->tdi_ctx;

	sev_do_cmd(SEV_CMD_TIO_TDI_RECLAIM, &r, &dev_data->psp_ret);

	sla_free(tdi_data->tdi_ctx, tio_status->tdictx_size, true);
	tdi_data->tdi_ctx = SLA_NULL;
}

int sev_tio_tdi_bind(struct tsm_dsm_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		     u32 guest_rid, u64 gctx_paddr, u32 asid, bool force_run)
{
	struct sev_data_tio_tdi_bind b = {
		.length = sizeof(b),
	};

	if (WARN_ON_ONCE(IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx)))
		return -EFAULT;

	tdi_data->gctx_paddr = gctx_paddr;
	tdi_data->asid = asid;

	spdm_ctrl_init(&b.spdm_ctrl, dev_data);
	b.dev_ctx_sla = dev_data->dev_ctx;
	b.tdi_ctx_sla = tdi_data->tdi_ctx;
	b.guest_device_id = guest_rid;
	b.gctx_paddr = tdi_data->gctx_paddr;
	b.run_flags = force_run ? TIO_TDI_BIND_RUN_FORCE : 0;

	return sev_tio_do_cmd(SEV_CMD_TIO_TDI_BIND, &b, sizeof(b),
			      &dev_data->psp_ret, dev_data);
}

int sev_tio_tdi_unbind(struct tsm_dsm_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		       bool force)
{
	struct sev_data_tio_tdi_unbind ub = {
		.length = sizeof(ub),
		.flags = force ? TIO_TDI_UNBIND_FLAG_FORCE : 0,
	};

	if (WARN_ON(!tdi_data || !dev_data))
		return 0;

	if (WARN_ON(!tdi_data->gctx_paddr))
		return -EFAULT;

	spdm_ctrl_init(&ub.spdm_ctrl, dev_data);
	ub.dev_ctx_sla = dev_data->dev_ctx;
	ub.tdi_ctx_sla = tdi_data->tdi_ctx;
	ub.gctx_paddr = tdi_data->gctx_paddr;

	return sev_tio_do_cmd(SEV_CMD_TIO_TDI_UNBIND, &ub, sizeof(ub),
			      &dev_data->psp_ret, dev_data);
}

int sev_tio_tdi_report(struct tsm_dsm_tio *dev_data, struct tsm_tdi_tio *tdi_data)
{
	struct sev_data_tio_tdi_report r = {
		.length = sizeof(r),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
		.gctx_paddr = tdi_data->gctx_paddr,
	};

	if (WARN_ON_ONCE(IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx)))
		return -EFAULT;

	spdm_ctrl_init(&r.spdm_ctrl, dev_data);

	return sev_tio_do_cmd(SEV_CMD_TIO_TDI_REPORT, &r, sizeof(r),
			      &dev_data->psp_ret, dev_data);
}

int sev_tio_asid_fence_clear(struct sla_addr_t dev_ctx, u64 gctx_paddr, int *psp_ret)
{
	struct sev_data_tio_asid_fence_clear c = {
		.length = sizeof(c),
		.dev_ctx_paddr = dev_ctx,
		.gctx_paddr = gctx_paddr,
	};

	return sev_do_cmd(SEV_CMD_TIO_ASID_FENCE_CLEAR, &c, psp_ret);
}

int sev_tio_asid_fence_status(struct tsm_dsm_tio *dev_data, u16 device_id, u8 segment_id,
			      u32 asid, bool *fenced)
{
	u64 *status = DATA_PG(u64, dev_data);
	struct sev_data_tio_asid_fence_status s = {
		.length = sizeof(s),
		.dev_ctx_paddr = dev_data->dev_ctx,
		.asid = asid,
		.status_pa = __psp_pa(status),
	};
	int ret;

	ret = sev_do_cmd(SEV_CMD_TIO_ASID_FENCE_STATUS, &s, &dev_data->psp_ret);

	if (ret == SEV_RET_SUCCESS) {
		u8 dma_status = FIELD_GET(TIO_FENCE_DMA_STATUS_MASK, *status);
		u8 mmio_status = FIELD_GET(TIO_FENCE_MMIO_STATUS_MASK, *status);

		switch (dma_status) {
		case TIO_FENCE_DMA_STATUS_NOT_FENCED:
			*fenced = false;
			break;
		case TIO_FENCE_DMA_STATUS_ERROR_FENCED:
		case TIO_FENCE_DMA_STATUS_DEFAULT_FENCED:
			*fenced = true;
			break;
		default:
			pr_err("%04x:%x:%x.%d: undefined DMA fence state %#llx\n",
			       segment_id, PCI_BUS_NUM(device_id),
			       PCI_SLOT(device_id), PCI_FUNC(device_id), *status);
			*fenced = true;
			break;
		}

		switch (mmio_status) {
		case TIO_FENCE_MMIO_STATUS_NOT_FENCED:
			*fenced = false;
			break;
		case TIO_FENCE_MMIO_STATUS_FENCED:
			*fenced = true;
			break;
		default:
			pr_err("%04x:%x:%x.%d: undefined MMIO fence state %#llx\n",
			       segment_id, PCI_BUS_NUM(device_id),
			       PCI_SLOT(device_id), PCI_FUNC(device_id), *status);
			*fenced = true;
			break;
		}
	}

	return ret;
}

int sev_tio_guest_request(struct tsm_dsm_tio *dev_data, struct tsm_tdi_tio *tdi_data,
			  void *req, void *res)
{
	struct sev_data_tio_guest_request gr = {
		.length = sizeof(gr),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
		.gctx_paddr = tdi_data->gctx_paddr,
		.req_paddr = __psp_pa(req),
		.res_paddr = __psp_pa(res),
	};

	if (WARN_ON(!tdi_data || !dev_data))
		return -EINVAL;

	spdm_ctrl_init(&gr.spdm_ctrl, dev_data);

	return sev_tio_do_cmd(SEV_CMD_TIO_GUEST_REQUEST, &gr, sizeof(gr),
			      &dev_data->psp_ret, dev_data);
}

#define SEV_TIO_TDI_INFO_P1_FLAG_MEAS_DIGEST_VALID		BIT(0)
#define SEV_TIO_TDI_INFO_P1_FLAG_MEAS_DIGEST_FRESH		BIT(1)
#define SEV_TIO_TDI_INFO_P1_TDI_STATUS_MASK		GENMASK(3, 2)
#define SEV_TIO_TDI_INFO_P1_TDI_STATUS_SHIFT		2
#define SEV_TIO_TDI_INFO_P2_FLAG_NO_FW_UPDATE		BIT(0)
#define SEV_TIO_TDI_INFO_P2_FLAG_CACHE_LINE_SIZE		BIT(1)
#define SEV_TIO_TDI_INFO_P2_FLAG_LOCK_MSIX		BIT(2)
#define SEV_TIO_TDI_INFO_P2_FLAG_BIND_P2P			BIT(3)
#define SEV_TIO_TDI_INFO_P2_FLAG_ALL_REQUEST_REDIRECT	BIT(4)

struct sev_tio_tdi_info_data {
	u32 length;
	struct tdisp_interface_id interface_id;
	u32 p1_flags; /* SEV_TIO_TDI_INFO_P1_FLAG_xxx and tdi_status in bits 3:2 */
	u32 p2_flags; /* SEV_TIO_TDI_INFO_P2_FLAG_xxx */
	u64 spdm_algos;
	u8 certs_digest[48];
	u8 meas_digest[48];
	u8 interface_report_digest[48];
	u64 intf_report_counter;
	u32 asid; /* ASID of the guest that this device is assigned to. Valid if CTX_STATE=1 */
	u8 reserved2[4];
} __packed;

struct sev_data_tio_tdi_info {
	u32 length;
	u32 reserved1;
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 status_paddr;
	u8 reserved2[16];
} __packed;

int sev_tio_tdi_info(struct tsm_dsm_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		     struct tsm_tdi_status *ts)
{
	struct sev_tio_tdi_info_data *data =
		DATA_PG(struct sev_tio_tdi_info_data, dev_data);
	struct sev_data_tio_tdi_info info = {
		.length = sizeof(info),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
		.status_paddr = __psp_pa(data),
	};
	int ret;

	if (IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx))
		return -ENXIO;

	ret = sev_do_cmd(SEV_CMD_TIO_TDI_INFO, &info, &dev_data->psp_ret);
	if (ret)
		return ret;

	print_hex_dump(KERN_INFO, "TDIINFO ", DUMP_PREFIX_OFFSET, 16, 1, data, data->length, false);

	ts->id = data->interface_id;
	ts->meas_digest_valid = !!(data->p1_flags & SEV_TIO_TDI_INFO_P1_FLAG_MEAS_DIGEST_VALID);
	ts->meas_digest_fresh = !!(data->p1_flags & SEV_TIO_TDI_INFO_P1_FLAG_MEAS_DIGEST_FRESH);
	ts->no_fw_update = !!(data->p2_flags & SEV_TIO_TDI_INFO_P2_FLAG_NO_FW_UPDATE);
	ts->cache_line_size = !!(data->p2_flags & SEV_TIO_TDI_INFO_P2_FLAG_CACHE_LINE_SIZE) ? 128 : 64;
	ts->lock_msix = !!(data->p2_flags & SEV_TIO_TDI_INFO_P2_FLAG_LOCK_MSIX);
	ts->bind_p2p = !!(data->p2_flags & SEV_TIO_TDI_INFO_P2_FLAG_BIND_P2P);
	ts->all_request_redirect = !!(data->p2_flags & SEV_TIO_TDI_INFO_P2_FLAG_ALL_REQUEST_REDIRECT);

#define __ALGO(x, n, y) \
	((((x) & (0xFFULL << (n))) == TIO_SPDM_ALGOS_##y) ? \
	 (1ULL << TSM_SPDM_ALGOS_##y) : 0)
	ts->spdm_algos =
		__ALGO(data->spdm_algos, 0, DHE_SECP256R1) |
		__ALGO(data->spdm_algos, 0, DHE_SECP384R1) |
		__ALGO(data->spdm_algos, 8, AEAD_AES_128_GCM) |
		__ALGO(data->spdm_algos, 8, AEAD_AES_256_GCM) |
		__ALGO(data->spdm_algos, 16, ASYM_TPM_ALG_RSASSA_3072) |
		__ALGO(data->spdm_algos, 16, ASYM_TPM_ALG_ECDSA_ECC_NIST_P256) |
		__ALGO(data->spdm_algos, 16, ASYM_TPM_ALG_ECDSA_ECC_NIST_P384) |
		__ALGO(data->spdm_algos, 24, HASH_TPM_ALG_SHA_256) |
		__ALGO(data->spdm_algos, 24, HASH_TPM_ALG_SHA_384) |
		__ALGO(data->spdm_algos, 32, KEY_SCHED_SPDM_KEY_SCHEDULE);
#undef __ALGO
	memcpy(ts->certs_digest, data->certs_digest, sizeof(ts->certs_digest));
	memcpy(ts->meas_digest, data->meas_digest, sizeof(ts->meas_digest));
	memcpy(ts->interface_report_digest, data->interface_report_digest,
	       sizeof(ts->interface_report_digest));
	ts->intf_report_counter = data->intf_report_counter;
	ts->valid = true;

	return 0;
}

/**
 * struct sev_tio_tdi_status_data - TDI status data returned by TIO_TDI_STATUS
 *
 * @length: Length of this status data structure
 * @tdisp_state: Current TDISP state of the TDI
 */
struct sev_tio_tdi_status_data {
	u32 length;
	u8 tdisp_state;
	u8 reserved1[0x10-0x5];
} __packed;

/**
 * struct sev_data_tio_tdi_status - TIO_TDI_STATUS command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2
 * @dev_ctx_sla: Scatter list address of device context
 * @tdi_ctx_sla: Scatter list address of TDI context
 * @status_paddr: System physical address where status will be written
 */
struct sev_data_tio_tdi_status {
	u32 length;
	u32 reserved1;
	struct spdm_ctrl spdm_ctrl;
	struct sla_addr_t dev_ctx_sla;
	struct sla_addr_t tdi_ctx_sla;
	u64 status_paddr;
} __packed;

int sev_tio_tdi_status(struct tsm_dsm_tio *dev_data, struct tsm_tdi_tio *tdi_data)
{
	struct sev_tio_tdi_status_data *data =
		DATA_PG(struct sev_tio_tdi_status_data, dev_data);
	struct sev_data_tio_tdi_status status = {
		.length = sizeof(status),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
		.status_paddr = __psp_pa(data),
	};

	if (IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx))
		return -ENXIO;

	spdm_ctrl_init(&status.spdm_ctrl, dev_data);

	return sev_tio_do_cmd(SEV_CMD_TIO_TDI_STATUS, &status, sizeof(status),
			      &dev_data->psp_ret, dev_data);
}

#define TIO_TDISP_STATE_CONFIG_UNLOCKED	0
#define TIO_TDISP_STATE_CONFIG_LOCKED	1
#define TIO_TDISP_STATE_RUN		2
#define TIO_TDISP_STATE_ERROR		3

int sev_tio_tdi_status_fin(struct tsm_dsm_tio *dev_data, struct tsm_tdi_tio *tdi_data,
			   enum tsm_tdisp_state *state)
{
	struct sev_tio_tdi_status_data *data = dev_data->data_pg;

	print_hex_dump(KERN_INFO, "TDISTATUS ", DUMP_PREFIX_OFFSET, 16, 1, data, data->length, false);

	switch (data->tdisp_state) {
#define __TDISP_STATE(y) case TIO_TDISP_STATE_##y: *state = TDISP_STATE_##y; pr_info(#y "\n"); break
	__TDISP_STATE(CONFIG_UNLOCKED);
	__TDISP_STATE(CONFIG_LOCKED);
	__TDISP_STATE(RUN);
	__TDISP_STATE(ERROR);
#undef __TDISP_STATE
	}

	return 0;
}

int sev_tio_cmd_buffer_len(int cmd)
{
	switch (cmd) {
	case SEV_CMD_TIO_STATUS:		return sizeof(struct sev_data_tio_status);
	case SEV_CMD_TIO_INIT:			return sizeof(struct sev_data_tio_init);
	case SEV_CMD_TIO_DEV_CREATE:		return sizeof(struct sev_data_tio_dev_create);
	case SEV_CMD_TIO_DEV_RECLAIM:		return sizeof(struct sev_data_tio_dev_reclaim);
	case SEV_CMD_TIO_DEV_CONNECT:		return sizeof(struct sev_data_tio_dev_connect);
	case SEV_CMD_TIO_DEV_DISCONNECT:	return sizeof(struct sev_data_tio_dev_disconnect);
	case SEV_CMD_TIO_DEV_STATUS:		return sizeof(struct sev_data_tio_dev_status);
	case SEV_CMD_TIO_DEV_MEASUREMENTS:	return sizeof(struct sev_data_tio_dev_meas);
	case SEV_CMD_TIO_DEV_CERTIFICATES:	return sizeof(struct sev_data_tio_dev_certs);
	case SEV_CMD_TIO_TDI_CREATE:		return sizeof(struct sev_data_tio_tdi_create);
	case SEV_CMD_TIO_TDI_RECLAIM:		return sizeof(struct sev_data_tio_tdi_reclaim);
	case SEV_CMD_TIO_TDI_BIND:		return sizeof(struct sev_data_tio_tdi_bind);
	case SEV_CMD_TIO_TDI_UNBIND:		return sizeof(struct sev_data_tio_tdi_unbind);
	case SEV_CMD_TIO_TDI_REPORT:		return sizeof(struct sev_data_tio_tdi_report);
	case SEV_CMD_TIO_TDI_STATUS:		return sizeof(struct sev_data_tio_tdi_status);
	case SEV_CMD_TIO_GUEST_REQUEST:		return sizeof(struct sev_data_tio_guest_request);
	case SEV_CMD_TIO_ASID_FENCE_CLEAR:	return sizeof(struct sev_data_tio_asid_fence_clear);
	case SEV_CMD_TIO_ASID_FENCE_STATUS: return sizeof(struct sev_data_tio_asid_fence_status);
	case SEV_CMD_TIO_TDI_INFO:		return sizeof(struct sev_data_tio_tdi_info);
	case SEV_CMD_TIO_ROLL_KEY:		return sizeof(struct sev_data_tio_roll_key);
	default:				return 0;
	}
}
