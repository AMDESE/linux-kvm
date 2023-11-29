// SPDX-License-Identifier: GPL-2.0-only

// Interface to PSP for CCP/SEV-TIO/SNP-VM

#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/tsm.h>
#include <linux/psp.h>
#include <linux/file.h>
#include <linux/vmalloc.h>

#include <asm/smp.h>
#include <asm/sev-common.h>
#include <asm/sev.h>
#include <asm/page.h>

#include "psp-dev.h"
#include "sev-dev.h"
#include "sev-dev-tio.h"

#define SLA_PAGE_TYPE_DATA	0
#define SLA_PAGE_TYPE_SCATTER	1
#define SLA_PAGE_SIZE_4K	0
#define SLA_PAGE_SIZE_2M	1
#define SLA_SZ(s)		((s).page_size == SLA_PAGE_SIZE_2M ? SZ_2M : SZ_4K)
#define SLA_SCATTER_LEN(s)	(SLA_SZ(s) / sizeof(sla_addr_t))
#define SLA_EOL			((sla_addr_t) { .pfn = 0xFFFFFFFFFFUL })
#define SLA_NULL		((sla_addr_t) { 0 })
#define IS_SLA_NULL(s)		((s).sla == SLA_NULL.sla)
#define IS_SLA_EOL(s)		((s).sla == SLA_EOL.sla)

// the BUFFER Structure
struct sla_buffer_hdr {
	u32 capacity_sz; // The capacity of the buffer in bytes.
	u32 payload_sz; // The size of BUFFER_PAYLOAD in bytes. Must be multiple of 32B.
	union {
		u32 flags; //  Bit 0: Indicates that this buffer is encrypted. Bit[31:1]: Reserved.
		struct {
			u32 encryption:1;
		};
	};
	u32 reserved1; // 31:0 – Reserved.
	u8 iv[16]; //  IV used for the encryption of this buffer.
	u8 authtag[16]; // Authentication tag for this buffer.
	u8 reserved2[16];
	// 40h – BUFFER_PAYLOAD BUFFER_SIZE bytes of data.
} __packed;

struct spdm_dobj_hdr {
	u32 id;// 0h 31:0 DOBJ_ID Data object type identifier.
	u32 length;// Length of the data object in bytes, INCLUDING THIS HEADER. Must be a multiple of 32B.
	union {
		u16 ver;
		struct { //  8h 15:0 DOBJ_VERSION Version of the data object structure.
			u8 minor; // Bit[7:0]: Minor version.
			u8 major; // Bit[15:8]: Major versionthe DATA_OBJECT_HEADER Structure
		} version;
	};
} __packed;

enum spdm_data_type_t {
	DOBJ_DATA_TYPE_SPDM = 0x1,
	DOBJ_DATA_TYPE_SECURE_SPDM = 0x2,
};

struct spdm_dobj_hdr_req {
	struct spdm_dobj_hdr hdr; // id == SPDM_DOBJ_ID_REQ
	u8 data_type; // spdm_data_type_t
	u8 reserved2[5];
} __packed;

struct spdm_dobj_hdr_resp {
	struct spdm_dobj_hdr hdr; // id == SPDM_DOBJ_ID_RESP
	u8 data_type; // spdm_data_type_t
	u8 reserved2[5];
} __packed;

struct spdm_dobj_hdr_cert {
	struct spdm_dobj_hdr hdr; // id == SPDM_DOBJ_ID_CERTIFICATE
	u8 reserved1[6];
	u16 device_id;
	u8 segment_id;
	u8 type; // 1h: SPDM certificate. 0h, 2h–FFh: Reserved.
	u8 reserved2[12];
} __packed;

struct spdm_dobj_hdr_meas {
	struct spdm_dobj_hdr hdr; // id == SPDM_DOBJ_ID_MEASUREMENT
	u8 reserved1[6];
	u16 device_id;
	u8 segment_id;
	u8 type; // 1h: SPDM measurement. 0h, 2h–FFh: Reserved.
	u8 reserved2[12];
} __packed;

struct spdm_dobj_hdr_report {
	struct spdm_dobj_hdr hdr; // id == SPDM_DOBJ_ID_REPORT
	u8 reserved1[6];
	u16 device_id;
	u8 segment_id;
	u8 type; // 1h: TDISP interface report. 0h, 2h–FFh: Reserved.
	u8 reserved2[12];
} __packed;

struct spdm_ctrl {
	sla_addr_t req;
	sla_addr_t resp;
	sla_addr_t scratch;
	sla_addr_t output;
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

	if (hdr && hdr->id == check_dobjid)
		return hdr;

	pr_err("! ERROR: expected %d, found %d\n", check_dobjid, hdr->id);
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

/**
 * struct sev_tio_info - TIO_INFO command's info_paddr buffer
 *
 * @length: Length of this structure in bytes
 * @tio_en: Indicates if SNP-IO feature is enabled.
 *	Controlled by SEV_INIT_FLAGS_SEV_TIO_EN parameter of SNP_INIT_EX.
*/
struct sev_tio_status {
	u32 length;
	union {
		u32 flags;
		struct {
			u32 tio_en:1;
			u32 tio_init_done:1;
		};
	};
	u32 spdm_req_size_min;
	u32 spdm_req_size_max;
	u32 spdm_scratch_size_min;
	u32 spdm_scratch_size_max;
	u32 spdm_out_size_min;
	u32 spdm_out_size_max;
	u32 spdm_rsp_size_min;
	u32 spdm_rsp_size_max;
	u32 devctx_size;
	u32 tdictx_size;
};

/**
 * struct sev_data_tio_status - SEV_CMD_TIO_STATUS command
 *
 * @length: Length of this command buffer in bytes
 * @info_length: Length of the buffer to write the sev_tio_info structure
 * @info_paddr: SPA of the buffer to write the sev_tio_info structure
*/
struct sev_data_tio_status {
	u32 length;			/* In */
	u32 reserved;			/* In */
	u64 status_paddr; 		/* In */
} __packed;

/* TIO_INIT */
struct sev_data_tio_init {
	u32 length;			/* In */
	u32 reserved[3];		/* In */
} __packed;

static struct sev_tio_status *tio_status;

void sev_tio_cleanup(void)
{
	kfree(tio_status);
	tio_status = NULL;
}

/**
 * struct sev_data_tio_dev_create - TIO_DEV_CREATE command
 */
struct sev_data_tio_dev_create {
	u32 length;			/* In */
	u32 reserved1;
	sla_addr_t dev_ctx_sla;		/* In */
	u16 device_id; // DEVICE_ID The PCIe Routing Identifier of the device to connect to.
	u16 root_port_id; // ROOT_PORT_ID The PCIe Routing Identifier of the root port of the device.
	u8 segment_id; // SEGMENT_ID The PCIe Segment Identifier of the device to connect to.
	u8 reserved2[11];
} __packed;

struct sev_data_tio_dev_connect {
	u32 length; // LENGTH Length in bytes of this command buffer.
	u32 reserved1; // 4h–7h – – Reserved.
	struct spdm_ctrl spdm_ctrl; // SPDM_CTRL SPDM control structure defined in Section 5.1.
	u8 reserved2[8];
	sla_addr_t dev_ctx_sla; // Scatter list address of the device context buffer.
	u8 tc_mask; // Bitmask of the traffic classes to initialize for SEV-TIO usage.
	u8 cert_slot; // Slot number of the certificate requested for constructing the SPDM session.
	u8 reserved3[6]; // 3Ah–3Fh – – Reserved
	u8 ide_stream_id[8]; // tc_mask says which IDs are valid
	u8 reserved4[8];
} __packed;

struct sev_data_tio_dev_disconnect {
	u32 length; // LENGTH Length in bytes of this command buffer.
	union {
		u32 flags;
		struct {
			u32 force:1;
		};
	};
	struct spdm_ctrl spdm_ctrl; // SPDM_CTRL SPDM control structure defined in Section 5.1.
	sla_addr_t dev_ctx_sla; // Scatter list address of the device context buffer.
} __packed;

/**
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure
 * @dev_ctx_paddr: SPA of page donated by hypervisor
 */
struct sev_data_tio_dev_meas {
	u32 length;				/* In */
	union {
		u32 flags;
		struct {
			u32 raw_bitstream:1;
		};
	};
	struct spdm_ctrl spdm_ctrl;		/* In */
	sla_addr_t dev_ctx_sla;			/* In */
} __packed;

struct sev_data_tio_dev_certs {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	sla_addr_t dev_ctx_sla;			/* In */
} __packed;

/**
 * struct sev_data_tio_dev_reclaim - TIO_DEV_RECLAIM command
 *
 * @length: Length in bytes of this command buffer
 * @dev_ctx_paddr: SPA of page donated by hypervisor
 */
struct sev_data_tio_dev_reclaim {
	u32 length;				/* In */
	u32 reserved;				/* In */
	sla_addr_t dev_ctx_sla;			/* In */
} __packed;

/**
 * struct sev_tio_dev_status - sev_data_tio_dev_status::status_paddr of
 * TIO_DEV_STATUS command
 *
 */
struct sev_tio_dev_status {
	u32 length;
	u8 ctx_state;
	u8 reserved1;
	union {
		u8 p1;
		struct {
			u8 request_pending:1;
			u8 request_pending_tdi:1;
		};
	};
	u8 certs_slot;
	u16 device_id;
	u8 segment_id;
	u8 tc_mask;
	u16 request_pending_command;
	u16 reserved2;
	struct tdisp_interface_id request_pending_interface_id;
	union {
		u8 p2;
		struct {
			u8 meas_digest_valid:1;
			u8 no_fw_update:1;
		};
	};
	u8 reserved3[3];
	u16 ide_stream_id[8];
	u8 reserved4[8];
	u8 certs_digest[48];
	u8 meas_digest[48];
} __packed;

/**
 * struct sev_data_tio_dev_status - TIO_DEV_STATUS command
 *
 * @length: Length in bytes of this command buffer
[FIXME: spec says here "Reserved. Should be zero."]
 * @dev_ctx_paddr: SPA of a device context page
 * @status_length: Length in bytes of the sev_tio_dev_status buffer
 * @status_paddr: SPA of the status buffer. See Table 16
*/
struct sev_data_tio_dev_status {
	u32 length;				/* In */
	u32 reserved;
	sla_addr_t dev_ctx_paddr;		/* In */
	u32 status_length;			/* In */
	u64 status_paddr;			/* In */
} __packed;

int sev_tio_dev_status(struct tsm_dev_tio *dev_data, struct tsm_dev_status *status);

/**
 * struct sev_data_tio_tdi_create - TIO_TDI_CREATE command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure
 * @dev_ctx_paddr: SPA of a device context page
 * @tdi_ctx_paddr: SPA of page donated by hypervisor
 * @interface_id: Interface ID of the TDI as defined by TDISP (host PCIID)
 */
struct sev_data_tio_tdi_create {
	u32 length;				/* In */
	u32 reserved;
	sla_addr_t dev_ctx_sla;			/* In */
	sla_addr_t tdi_ctx_sla;			/* In */
	struct tdisp_interface_id interface_id;	/* In */
	u8 reserved2[12];
} __packed;

struct sev_data_tio_tdi_reclaim {
	u32 length;				/* In */
	u32 reserved;
	sla_addr_t dev_ctx_sla;			/* In */
	sla_addr_t tdi_ctx_sla;			/* In */
	u64 reserved2;
} __packed;

/*
 * struct sev_data_tio_tdi_bind - TIO_TDI_BIND command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2.
 * @tdi_ctx_paddr: SPA of page donated by hypervisor
 * @guest_ctx_paddr: SPA of guest context page
 * @flags:
 *  4 ALL_REQUEST_REDIRECT Requires ATS translated requests to route through the root complex. Must be 1.
 *  3 BIND_P2P Enables direct P2P. Must be 0
 *  2 LOCK_MSIX Lock the MSI-X table and PBA.
 *  1 CACHE_LINE_SIZE Indicates the cache line size. 0 indicates 64B. 1 indicates 128B. Must be 0.
 *  0 NO_FW_UPDATE Indicates that no firmware updates are allowed while the interface is locked.
 * @mmio_reporting_offset: Offset added to the MMIO range addresses in the interface report.
 * @guest_interface_id: Hypervisor provided identifier used by the guest to identify the TDI in guest messages
 */
struct sev_data_tio_tdi_bind {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	sla_addr_t dev_ctx_sla;
	sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;
	u16 guest_device_id;
	union {
		u16 flags;
		// These are TDISP's LOCK_INTERFACE_REQUEST flags
		struct {
			u16 no_fw_update : 1;
			u16 reservedf1 : 1;
			u16 lock_msix : 1;
			u16 bind_p2p : 1;
			u16 all_request_redirect : 1;
		};
	} tdisp_lock_if;
	u16 reserved2;
} __packed;

/*
 * struct sev_data_tio_tdi_unbind - TIO_TDI_UNBIND command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2.
 * @tdi_ctx_paddr: SPA of page donated by hypervisor
 */
struct sev_data_tio_tdi_unbind {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	sla_addr_t dev_ctx_sla;
	sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;			/* In */
} __packed;

struct sev_data_tio_asid_fence_clear {
	u32 length;				/* In */
	u32 reserved1;
	u64 gctx_paddr;			/* In */
	u16 device_id;
	u8 segment_id;
	u8 reserved[13];
} __packed;

struct sev_data_tio_asid_fence_status {
	u32 length;				/* In */
	u32 asid;				/* In */
	u64 status_pa;
	u16 device_id;
	u8 segment_id;
	u8 reserved[13];
} __packed;

/**
 * struct sev_data_tio_guest_request - TIO_GUEST_REQUEST command
 *
 * @length: Length in bytes of this command buffer
 * @spdm_ctrl: SPDM control structure defined in Chapter 2.
 * @gctx_paddr: system physical address of guest context page
 * @tdi_ctx_paddr: SPA of page donated by hypervisor
 * @req_paddr: system physical address of request page
 * @res_paddr: system physical address of response page
 */
struct sev_data_tio_guest_request {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	sla_addr_t dev_ctx_sla;
	sla_addr_t tdi_ctx_sla;
	u64 gctx_paddr;
	u64 req_paddr;				/* In */
	u64 res_paddr;				/* In */
} __packed;

struct sev_data_tio_roll_key {
	u32 length;				/* In */
	u32 reserved;
	struct spdm_ctrl spdm_ctrl;		/* In */
	sla_addr_t dev_ctx_sla;			/* In */
} __packed;

static struct sla_buffer_hdr *sla_buffer_map(sla_addr_t sla)
{
	struct sla_buffer_hdr *buf;

	BUILD_BUG_ON(sizeof(struct sla_buffer_hdr) != 0x40);
	if (IS_SLA_NULL(sla))
		return NULL;

	if (sla.page_type == SLA_PAGE_TYPE_SCATTER) {
		sla_addr_t *scatter = __va(sla.pfn << PAGE_SHIFT);
		unsigned i, npages = 0;
		struct page **pp;

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

		pp = kmalloc(sizeof(pp[0]) * npages, GFP_KERNEL);
		if (!pp)
			return NULL;

		for (i = 0; i < npages; ++i) {
			pp[i] = pfn_to_page(scatter[i].pfn);
		}

		buf = vm_map_ram(pp, npages, 0);
		kfree(pp);
	} else {
		struct page *pg = pfn_to_page(sla.pfn);

		buf = vm_map_ram(&pg, 1, 0);
	}

	return buf;
}

static void sla_buffer_unmap(sla_addr_t sla, struct sla_buffer_hdr *buf)
{
	if (!buf)
		return;

	if (sla.page_type == SLA_PAGE_TYPE_SCATTER) {
		sla_addr_t *scatter = __va(sla.pfn << PAGE_SHIFT);
		unsigned i, npages = 0;

		for (i = 0; i < SLA_SCATTER_LEN(sla); ++i) {
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
	}
}

static void dobj_response_init(struct sla_buffer_hdr *buf)
{
	struct spdm_dobj_hdr *dobj = sla_to_dobj_hdr(buf);

	dobj->id = SPDM_DOBJ_ID_RESP;
	dobj->version.major = 0x1;
	dobj->version.minor = 0;
	dobj->length = 0;
	buf->payload_sz = sla_dobj_id_to_size(dobj->id) + dobj->length;
}

static sla_addr_t sla_alloc(size_t len, bool firmware_state)
{
	unsigned long i, npages = PAGE_ALIGN(len) >> PAGE_SHIFT;
	struct sla_buffer_hdr *buf;
	sla_addr_t *scatter = NULL;
	sla_addr_t ret = SLA_NULL;
	char tmp[256] = "";
	struct page *pg;

	if (npages == 0)
		return ret;

	BUG_ON(npages > ((PAGE_SIZE / sizeof(sla_addr_t)) + 1));
	BUILD_BUG_ON(PAGE_SIZE < SZ_4K);

	if (npages > 1) {
		pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!pg)
			return SLA_NULL;

		ret.pfn = page_to_pfn(pg);
		ret.page_size = SLA_PAGE_SIZE_4K;
		ret.page_type = SLA_PAGE_TYPE_SCATTER;

		scatter = page_to_virt(pg);
		for (i = 0; i < npages; ++i) {
			pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
			if (!pg)
				return SLA_NULL; // TODO: goto error_exit

			scatter[i].pfn = page_to_pfn(pg);
			scatter[i].page_type = SLA_PAGE_TYPE_DATA;
			scatter[i].page_size = SLA_PAGE_SIZE_4K;
		}
		scatter[i] = SLA_EOL;
	} else {
		pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!pg)
			return SLA_NULL;

		ret.pfn = page_to_pfn(pg);
		ret.page_size = SLA_PAGE_SIZE_4K;
		ret.page_type = SLA_PAGE_TYPE_DATA;
	}

	buf = sla_buffer_map(ret);
	buf->capacity_sz = (npages << PAGE_SHIFT);

	if (firmware_state) {
		if (scatter) {
			tmp[0] = 0;
			for (i = 0; i < npages; ++i) {
				snprintf(tmp + strlen(tmp), sizeof(tmp) - strlen(tmp), " %lx",
					(unsigned long) scatter[i].pfn << PAGE_SHIFT);
				if (rmp_make_private(scatter[i].pfn, 0, PG_LEVEL_4K, 0, true)) {
					pr_err("Unexpectedly reclaiming\n");
					for (unsigned j = 0; j < i; ++j)
						snp_reclaim_pages(scatter[j].pfn << PAGE_SHIFT,
								  1, true);
					ret = SLA_NULL;
					goto unmap_exit;
				}
			}
		} else {
			rmp_make_private(ret.pfn, 0, PG_LEVEL_4K, 0, true);
		}
	}

unmap_exit:
	sla_buffer_unmap(ret, buf);
	return ret;
}

static void sla_free(sla_addr_t sla, size_t len, bool firmware_state)
{
	unsigned int npages = PAGE_ALIGN(len) >> PAGE_SHIFT;
	sla_addr_t *scatter = NULL;
	int ret = 0, i;

	if (IS_SLA_NULL(sla))
		return;

	if (firmware_state) {
		if (sla.page_type == SLA_PAGE_TYPE_SCATTER) {
			sla_addr_t *scatter = __va(sla.pfn << PAGE_SHIFT);
			for (i = 0; i < npages; ++i) {
				if (IS_SLA_EOL(scatter[i]))
					break;
				ret = snp_reclaim_pages(scatter[i].pfn << PAGE_SHIFT, 1, false);
				if (ret)
					break;
			}
		} else {
			pr_err("Reclaiming %llx\n", (u64)sla.pfn << PAGE_SHIFT);
			ret = snp_reclaim_pages(sla.pfn << PAGE_SHIFT, 1, false);
		}
	}

	if (WARN_ON(ret))
		return;

	if (scatter) {
		for (i = 0; i < npages; ++i) {
			if (IS_SLA_EOL(scatter[i]))
				break;
			free_page((unsigned long)__va(scatter[i].pfn << PAGE_SHIFT));
		}
	}

	free_page((unsigned long)__va(sla.pfn << PAGE_SHIFT));
}

static void tio_blob_release(struct tsm_blob *b)
{
	memset(b->data, 0, b->len);
}

void tio_save_output(struct tsm_blob **blob, sla_addr_t sla, u32 check_dobjid)
{
	struct sla_buffer_hdr *buf;
	struct spdm_dobj_hdr *hdr;

	tsm_blob_put(*blob);
	*blob = NULL;

	buf = sla_buffer_map(sla);
	if (!buf)
		return;

	hdr = sla_to_dobj_hdr_check(buf, check_dobjid);
	if (hdr)
		*blob = tsm_blob_new(SPDM_DOBJ_DATA(hdr), hdr->length, tio_blob_release);

	sla_buffer_unmap(sla, buf);
}

static int sev_tio_do_cmd(int cmd, void *data, size_t data_len, int *psp_ret,
			  struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	int rc;

	*psp_ret = 0;
	rc = sev_do_cmd(cmd, data, psp_ret);

	if (WARN_ON(!spdm && !rc && *psp_ret == SEV_RET_SPDM_REQUEST))
		return -EIO;

	if (spdm && (rc == 0 || rc == -EIO) && *psp_ret == SEV_RET_SPDM_REQUEST) {
		struct spdm_dobj_hdr_resp *resp_hdr;
		struct spdm_dobj_hdr_req *req_hdr;

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
		case DOBJ_DATA_TYPE_SPDM: rc = PCI_DOE_PROTOCOL_CMA_SPDM; break;
		case DOBJ_DATA_TYPE_SECURE_SPDM: rc = PCI_DOE_PROTOCOL_SECURED_CMA_SPDM; break;
		default: rc = -EINVAL; return rc;
		}
		resp_hdr->data_type = req_hdr->data_type;
		spdm->req_len = req_hdr->hdr.length;
		spdm->rsp_len = tio_status->spdm_req_size_max -
			(sla_dobj_id_to_size(SPDM_DOBJ_ID_RESP) + sizeof(struct sla_buffer_hdr));
	} else if (dev_data && dev_data->cmd) {
		// For either error or success just stop the bouncing
		memset(dev_data->cmd_data, 0, sizeof(dev_data->cmd_data));
		dev_data->cmd = 0;
	}

	return rc;
}

int sev_tio_continue(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct spdm_dobj_hdr_resp *resp_hdr;
	int ret;

	if (!dev_data || !dev_data->cmd)
		return -EINVAL;

	resp_hdr = sla_to_dobj_resp_hdr(dev_data->respbuf);
	resp_hdr->hdr.length = ALIGN(sla_dobj_id_to_size(SPDM_DOBJ_ID_RESP) + spdm->rsp_len, 32);
	dev_data->respbuf->payload_sz = resp_hdr->hdr.length;

	ret = sev_tio_do_cmd(dev_data->cmd, dev_data->cmd_data, 0, &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

static int spdm_ctrl_init(struct tsm_spdm *spdm, struct spdm_ctrl *ctrl, struct tsm_dev_tio *dev_data)
{
	ctrl->req = dev_data->req;
	ctrl->resp = dev_data->resp;
	ctrl->scratch = dev_data->scratch;
	ctrl->output = dev_data->output;

	spdm->req = sla_to_data(dev_data->reqbuf, SPDM_DOBJ_ID_REQ);
	spdm->rsp = sla_to_data(dev_data->respbuf, SPDM_DOBJ_ID_RESP);
	if (!spdm->req || !spdm->rsp)
		return -EFAULT;

	return 0;
}

static void spdm_ctrl_free(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	size_t len = tio_status->spdm_req_size_max -
		(sla_dobj_id_to_size(SPDM_DOBJ_ID_RESP) +
		 sizeof(struct sla_buffer_hdr));

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

static int spdm_ctrl_alloc(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	int ret;

	dev_data->req = sla_alloc(tio_status->spdm_req_size_max, true);
	dev_data->resp = sla_alloc(tio_status->spdm_req_size_max, false);
	dev_data->scratch = sla_alloc(tio_status->spdm_scratch_size_max, true);
	dev_data->output = sla_alloc(tio_status->spdm_out_size_max, true);

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

	dobj_response_init(dev_data->respbuf);

	return 0;

free_spdm_exit:
	spdm_ctrl_free(dev_data, spdm);
	return ret;
}

int sev_tio_status(void)
{
	struct sev_data_tio_status data_status = {
		.length = sizeof(data_status),
	};
	int ret = 0, psp_ret = 0;

	if (!sev_version_greater_or_equal(1, 55))
		return -ENOTSUPP;

	WARN_ON(tio_status);

	tio_status = kzalloc(sizeof(*tio_status), GFP_KERNEL);
	// "8-byte aligned, and does not cross a page boundary"
	// BUG_ON(tio_status & ~PAGE_MASK > PAGE_SIZE - sizeof(*tio_status));

	if (!tio_status)
		return -ENOMEM;

	tio_status->length = sizeof(*tio_status);
	data_status.status_paddr = __psp_pa(tio_status);

	ret = sev_do_cmd(SEV_CMD_TIO_STATUS, &data_status, &psp_ret);
	if (ret)
		goto free_exit;

	if (tio_status->flags & 0xFFFFFF00) {
		ret = -EFAULT;
		goto free_exit;
	}

	if (!tio_status->tio_en && !tio_status->tio_init_done) {
		ret = -ENOTSUPP;
		goto free_exit;
	}

	if (tio_status->tio_en && !tio_status->tio_init_done) {
		struct sev_data_tio_init ti = { .length = sizeof(ti) };

		ret = sev_do_cmd(SEV_CMD_TIO_INIT, &ti, &psp_ret);
		if (ret)
			goto free_exit;

		ret = sev_do_cmd(SEV_CMD_TIO_STATUS, &data_status, &psp_ret);
		if (ret)
			goto free_exit;
	}

	pr_notice("SEV-TIO status: EN=%d INIT_DONE=%d "
		  "rq=%d..%d rs=%d..%d "
		  "scr=%d..%d out=%d..%d dev=%d tdi=%d\n",
		  tio_status->tio_en, tio_status->tio_init_done,
		  tio_status->spdm_req_size_min, tio_status->spdm_req_size_max,
		  tio_status->spdm_rsp_size_min, tio_status->spdm_rsp_size_max,
		  tio_status->spdm_scratch_size_min, tio_status->spdm_scratch_size_max,
		  tio_status->spdm_out_size_min, tio_status->spdm_out_size_max,
		  tio_status->devctx_size, tio_status->tdictx_size);

	return 0;

free_exit:
	pr_err("Failed to enable SEV-TIO: ret=%d en=%d initdone=%d SEV=%d\n",
	       ret, tio_status->tio_en, tio_status->tio_init_done,
	       boot_cpu_has(X86_FEATURE_SEV));
	pr_err("Check BIOS for: SMEE, SEV Control, SEV-ES ASID Space Limit=99,\n"
	       "SNP Memory (RMP Table) Coverage, RMP Coverage for 64Bit MMIO Ranges\n"
	       "SEV-SNP Support, SEV-TIO Support, PCIE IDE Capability\n");
	if (cc_platform_has(CC_ATTR_MEM_ENCRYPT))
		pr_err("mem_encrypt=on is currently broken\n");

	kfree(tio_status);
	return ret;
}

int sev_tio_dev_create(struct tsm_dev_tio *dev_data, u16 device_id,
		       u16 root_port_id, u8 segment_id)
{
	struct sev_data_tio_dev_create create = {
		.length = sizeof(create),
		.device_id = device_id,
		.root_port_id = root_port_id,
		.segment_id = segment_id,
	};

	dev_data->dev_ctx = sla_alloc(tio_status->devctx_size, true);
	if (IS_SLA_NULL(dev_data->dev_ctx))
		return -ENOMEM;

	create.dev_ctx_sla = dev_data->dev_ctx;
	return sev_tio_do_cmd(SEV_CMD_TIO_DEV_CREATE, &create, sizeof(create),
			      &dev_data->psp_ret, dev_data, NULL);
}

int sev_tio_dev_reclaim(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct sev_data_tio_dev_reclaim r = {
		.length = sizeof(r),
		.dev_ctx_sla = dev_data->dev_ctx,
	};
	int ret;

	if (IS_SLA_NULL(dev_data->dev_ctx))
		return 0;

	ret = sev_do_cmd(SEV_CMD_TIO_DEV_RECLAIM, &r, &dev_data->psp_ret);

	sla_free(dev_data->dev_ctx, tio_status->devctx_size, true);
	dev_data->dev_ctx = SLA_NULL;

	spdm_ctrl_free(dev_data, spdm);

	return ret;
}

int sev_tio_dev_connect(struct tsm_dev_tio *dev_data, u8 tc_mask, u8 cert_slot,
			struct tsm_spdm *spdm)
{
	struct sev_data_tio_dev_connect connect = {
		.length = sizeof(connect),
		.tc_mask = tc_mask,
		.cert_slot = cert_slot,
		.dev_ctx_sla = dev_data->dev_ctx,
		.ide_stream_id = { 0 },
	};
	int ret;

	if (WARN_ON(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;
	if (!(tc_mask & 1))
		return -EINVAL;

	ret = spdm_ctrl_alloc(dev_data, spdm);
	if (ret)
		return ret;
	ret = spdm_ctrl_init(spdm, &connect.spdm_ctrl, dev_data);
	if (ret)
		return ret;

	ret = sev_tio_do_cmd(SEV_CMD_TIO_DEV_CONNECT, &connect, sizeof(connect),
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

int sev_tio_dev_disconnect(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct sev_data_tio_dev_disconnect dc = {
		.length = sizeof(dc),
		.dev_ctx_sla = dev_data->dev_ctx,
	};
	int ret;

	BUG_ON(IS_SLA_NULL(dev_data->dev_ctx));

	ret = spdm_ctrl_init(spdm, &dc.spdm_ctrl, dev_data);
	if (ret)
		return ret;

	ret = sev_tio_do_cmd(SEV_CMD_TIO_DEV_DISCONNECT, &dc, sizeof(dc),
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

int sev_tio_dev_measurements(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct sev_data_tio_dev_meas meas = {
		.length = sizeof(meas),
		.raw_bitstream = 1,
	};
	int ret;

	if (WARN_ON(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;

	spdm_ctrl_init(spdm, &meas.spdm_ctrl, dev_data);
	meas.dev_ctx_sla = dev_data->dev_ctx;

	ret = sev_tio_do_cmd(SEV_CMD_TIO_DEV_MEASUREMENTS, &meas, sizeof(meas),
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

int sev_tio_dev_certificates(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct sev_data_tio_dev_certs c = {
		.length = sizeof(c),
	};
	int ret;

	if (WARN_ON(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;

	spdm_ctrl_init(spdm, &c.spdm_ctrl, dev_data);
	c.dev_ctx_sla = dev_data->dev_ctx;

	ret = sev_tio_do_cmd(SEV_CMD_TIO_DEV_CERTIFICATES, &c, sizeof(c),
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

int sev_tio_dev_status(struct tsm_dev_tio *dev_data, struct tsm_dev_status *s)
{
	struct sev_tio_dev_status *status = (struct sev_tio_dev_status *) dev_data->data;
	struct sev_data_tio_dev_status data_status = {
		.length = sizeof(data_status),
		.dev_ctx_paddr = dev_data->dev_ctx,
		.status_length = sizeof(*status),
		.status_paddr = __psp_pa(status),
	};
	int ret;

	if (!dev_data)
		return -ENODEV;

	if (IS_SLA_NULL(dev_data->dev_ctx))
		return -ENXIO;

	memset(status, 0, sizeof(*status));

	ret = sev_do_cmd(SEV_CMD_TIO_DEV_STATUS, &data_status, &dev_data->psp_ret);
	if (ret)
		return ret;

	s->ctx_state = status->ctx_state;
	s->device_id = status->device_id;
	s->tc_mask = status->tc_mask;
	memcpy(s->ide_stream_id, status->ide_stream_id, sizeof(status->ide_stream_id));
	s->certs_slot = status->certs_slot;
	s->no_fw_update = status->no_fw_update;

	return 0;
}

int sev_tio_ide_refresh(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm)
{
	struct sev_data_tio_roll_key rk = {
		.length = sizeof(rk),
		.dev_ctx_sla = dev_data->dev_ctx,
	};
	int ret;

	if (WARN_ON(IS_SLA_NULL(dev_data->dev_ctx)))
		return -EFAULT;

	ret = spdm_ctrl_init(spdm, &rk.spdm_ctrl, dev_data);
	if (ret)
		return ret;

	ret = sev_tio_do_cmd(SEV_CMD_TIO_ROLL_KEY, &rk, sizeof(rk),
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

int sev_tio_tdi_create(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, u16 dev_id,
		       u8 rseg, u8 rseg_valid)
{
	struct sev_data_tio_tdi_create c = {
		.length = sizeof(c),
	};
	int ret;

	if (!dev_data || !tdi_data) /* Device is not "connected" */
		return -EPERM;

	BUG_ON(IS_SLA_NULL(dev_data->dev_ctx));
	BUG_ON(!IS_SLA_NULL(tdi_data->tdi_ctx));

	tdi_data->tdi_ctx = sla_alloc(tio_status->tdictx_size, true);
	if (IS_SLA_NULL(tdi_data->tdi_ctx))
		return -ENOMEM;

	c.dev_ctx_sla = dev_data->dev_ctx;
	c.tdi_ctx_sla = tdi_data->tdi_ctx;
	c.interface_id.rid = dev_id;
	c.interface_id.rseg = rseg;
	c.interface_id.rseg_valid = rseg_valid;

	ret = sev_do_cmd(SEV_CMD_TIO_TDI_CREATE, &c, &dev_data->psp_ret);
	if (ret)
		goto free_exit;

	return 0;

free_exit:
	sla_free(tdi_data->tdi_ctx, tio_status->tdictx_size, true);
	tdi_data->tdi_ctx = SLA_NULL;
	return ret;
}

void sev_tio_tdi_reclaim(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data)
{
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

int sev_tio_tdi_bind(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		     __u32 guest_rid, u64 gctx_paddr, struct tsm_spdm *spdm)
{
	struct sev_data_tio_tdi_bind b = {
		.length = sizeof(b),
	};
	int ret;

	BUG_ON(IS_SLA_NULL(dev_data->dev_ctx));
	BUG_ON(IS_SLA_NULL(tdi_data->tdi_ctx));

	spdm_ctrl_init(spdm, &b.spdm_ctrl, dev_data);
	b.dev_ctx_sla = dev_data->dev_ctx;
	b.tdi_ctx_sla = tdi_data->tdi_ctx;
	b.guest_device_id = guest_rid;
	b.gctx_paddr = gctx_paddr;

	tdi_data->gctx_paddr = gctx_paddr;

	ret = sev_tio_do_cmd(SEV_CMD_TIO_TDI_BIND, &b, sizeof(b),
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

int sev_tio_tdi_unbind(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		       struct tsm_spdm *spdm)
{
	struct sev_data_tio_tdi_unbind ub = {
		.length = sizeof(ub),
	};
	int ret;

	if (WARN_ON(!tdi_data || !dev_data))
		return 0;
	BUG_ON(!tdi_data->gctx_paddr);

	spdm_ctrl_init(spdm, &ub.spdm_ctrl, dev_data);
	ub.dev_ctx_sla = dev_data->dev_ctx;
	ub.tdi_ctx_sla = tdi_data->tdi_ctx;
	ub.gctx_paddr = tdi_data->gctx_paddr;

	ret = sev_tio_do_cmd(SEV_CMD_TIO_TDI_UNBIND, &ub, sizeof(ub),
			     &dev_data->psp_ret, dev_data, spdm);
	return ret;
}

int sev_tio_asid_fence_clear(u16 device_id, u8 segment_id, u64 gctx_paddr, int *psp_ret)
{
	struct sev_data_tio_asid_fence_clear c = {
		.length = sizeof(c),
		.gctx_paddr = gctx_paddr,
		.device_id = device_id,
		.segment_id = segment_id,
	};
	int ret;

	ret = sev_do_cmd(SEV_CMD_TIO_ASID_FENCE_CLEAR, &c, psp_ret);

	return ret;
}

int sev_tio_asid_fence_status(struct tsm_dev_tio *dev_data, u16 device_id, u8 segment_id,
			      unsigned asid, bool *fenced)
{
	u64 *status = (u64 *) dev_data->data;
	struct sev_data_tio_asid_fence_status s = {
		.length = sizeof(s),
		.asid = asid,
		.status_pa = __psp_pa(status),
		.device_id = device_id,
		.segment_id = segment_id,
	};
	int ret;

	*status = 0;

	ret = sev_do_cmd(SEV_CMD_TIO_ASID_FENCE_STATUS, &s, &dev_data->psp_ret);

	if (ret == SEV_RET_SUCCESS) {
		switch (*status) {
		case 0: *fenced = false; break;
		case 1: *fenced = true; break;
		default:
			pr_err("%04x:%x:%x.%d: undefined fence state %#llx\n",
			       segment_id, PCI_BUS_NUM(device_id),
			       PCI_SLOT(device_id), PCI_FUNC(device_id), *status);
			*fenced = true;
			break;
		}
	}

	return ret;
}

int sev_tio_guest_request(void *data, u32 guest_rid, u64 gctx_paddr,
			  struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
			  struct tsm_spdm *spdm)
{
	struct tio_guest_request *tgr = data;
	struct sev_data_tio_guest_request gr = {
		.length = sizeof(gr),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
		.gctx_paddr = tgr->data.gctx_paddr,
		.req_paddr = tgr->data.req_paddr,
		.res_paddr = tgr->data.res_paddr,
	};
	int ret;

	if (WARN_ON(!tdi_data || !dev_data))
		return -EINVAL;

	spdm_ctrl_init(spdm, &gr.spdm_ctrl, dev_data);

	ret = sev_tio_do_cmd(SEV_CMD_TIO_GUEST_REQUEST, &gr, sizeof(gr),
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

struct sev_tio_tdi_info_data {
	u32 length;
	struct tdisp_interface_id interface_id;
	union {
		u32 p1;
		struct {
			u32 meas_digest_valid:1;
			u32 meas_digest_fresh:1;
		};
	};
	union {
		u32 p2;
		struct {
			u32 no_fw_update:1;
			u32 cache_line_size:1;
			u32 lock_msix:1;
			u32 bind_p2p:1;
			u32 all_request_redirect:1;
		};
	};
	u64 spdm_algos;
	u8 certs_digest[48];
	u8 meas_digest[48];
	u8 interface_report_digest[48];
	u8 guest_report_id[16];
} __packed;

struct sev_data_tio_tdi_info {
	u32 length;
	u32 reserved1;
	sla_addr_t dev_ctx_sla;
	sla_addr_t tdi_ctx_sla;
	u32 status_length;
	u32 reserved2;
	u64 status_paddr;
} __packed;

#define TIO_SPDM_ALGOS_DHE_SECP256R1 			0
#define TIO_SPDM_ALGOS_DHE_SECP384R1 			1
#define TIO_SPDM_ALGOS_AEAD_AES_128_GCM 		(0<<8)
#define TIO_SPDM_ALGOS_AEAD_AES_256_GCM			(1<<8)
#define TIO_SPDM_ALGOS_ASYM_TPM_ALG_RSASSA_3072		(0<<16)
#define TIO_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P256	(1<<16)
#define TIO_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P384	(2<<16)
#define TIO_SPDM_ALGOS_HASH_TPM_ALG_SHA_256		(0<<24)
#define TIO_SPDM_ALGOS_HASH_TPM_ALG_SHA_384		(1<<24)
#define TIO_SPDM_ALGOS_KEY_SCHED_SPDM_KEY_SCHEDULE	(0ULL<<32)

int sev_tio_tdi_info(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		     struct tsm_tdi_status *ts)
{
	struct sev_tio_tdi_info_data *data = (struct sev_tio_tdi_info_data *) dev_data->data;
	struct sev_data_tio_tdi_info info = {
		.length = sizeof(info),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
		.status_length = sizeof(*data),
		.status_paddr = __psp_pa(data),
	};
	int ret;

	if (IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx))
		return -ENXIO;

	memset(data, 0, sizeof(*data));

	ret = sev_do_cmd(SEV_CMD_TIO_TDI_INFO, &info, &dev_data->psp_ret);
	if (ret)
		return ret;

	ts->id = data->interface_id;
	ts->meas_digest_valid = data->meas_digest_valid;
	ts->meas_digest_fresh = data->meas_digest_fresh;
	ts->no_fw_update = data->no_fw_update;
	ts->cache_line_size = data->cache_line_size == 0 ? 64 : 128;
	ts->lock_msix = data->lock_msix;
	ts->bind_p2p = data->bind_p2p;
	ts->all_request_redirect = data->all_request_redirect;

#define __ALGO(x, n, y) \
	((((x) & (0xFFUL << (n))) == TIO_SPDM_ALGOS_##y) ? \
	 (1ULL << TSM_TDI_SPDM_ALGOS_##y) : 0)
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
	memcpy(ts->guest_report_id, data->guest_report_id, sizeof(ts->guest_report_id));
	ts->valid = true;

	return 0;
}

struct sev_tio_tdi_status_data {
	u32 length;
	u8 tdisp_state;
	u8 reserved1[3];
} __packed;

struct sev_data_tio_tdi_status {
	u32 length;
	u32 reserved1;
	struct spdm_ctrl spdm_ctrl;
	sla_addr_t dev_ctx_sla;
	sla_addr_t tdi_ctx_sla;
	u64 status_paddr;
} __packed;

#define TIO_TDISP_STATE_CONFIG_UNLOCKED 0
#define TIO_TDISP_STATE_CONFIG_LOCKED 1
#define TIO_TDISP_STATE_RUN 2
#define TIO_TDISP_STATE_ERROR 3

int sev_tio_tdi_status(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
		       struct tsm_spdm *spdm)
{
	struct sev_tio_tdi_status_data *data = (struct sev_tio_tdi_status_data *) dev_data->data;
	struct sev_data_tio_tdi_status status = {
		.length = sizeof(status),
		.dev_ctx_sla = dev_data->dev_ctx,
		.tdi_ctx_sla = tdi_data->tdi_ctx,
	};
	int ret;

	if (IS_SLA_NULL(dev_data->dev_ctx) || IS_SLA_NULL(tdi_data->tdi_ctx))
		return -ENXIO;

	memset(data, 0, sizeof(*data));

	spdm_ctrl_init(spdm, &status.spdm_ctrl, dev_data);
	status.status_paddr = __psp_pa(data);

	ret = sev_tio_do_cmd(SEV_CMD_TIO_TDI_STATUS, &status, sizeof(status),
			     &dev_data->psp_ret, dev_data, spdm);

	return ret;
}

int sev_tio_tdi_status_fin(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
			   enum tsm_tdisp_state *state)
{
	struct sev_tio_tdi_status_data *data = (struct sev_tio_tdi_status_data *) dev_data->data;

	switch (data->tdisp_state) {
#define __TDISP_STATE(y) case TIO_TDISP_STATE_##y: *state = TDISP_STATE_##y; break
	__TDISP_STATE(CONFIG_UNLOCKED);
	__TDISP_STATE(CONFIG_LOCKED);
	__TDISP_STATE(RUN);
	__TDISP_STATE(ERROR);
#undef __TDISP_STATE
	}
	memset(dev_data->data, 0, sizeof(dev_data->data));

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
//	case SEV_CMD_TIO_TDI_REPORT:		return sizeof(struct sev_data_tio_tdi_report);
	case SEV_CMD_TIO_TDI_STATUS:		return sizeof(struct sev_data_tio_tdi_status);
	case SEV_CMD_TIO_GUEST_REQUEST:		return sizeof(struct sev_data_tio_guest_request);
	case SEV_CMD_TIO_ASID_FENCE_CLEAR:	return sizeof(struct sev_data_tio_asid_fence_clear);
	case SEV_CMD_TIO_ASID_FENCE_STATUS:	return sizeof(struct sev_data_tio_asid_fence_status);
	case SEV_CMD_TIO_TDI_INFO:		return sizeof(struct sev_data_tio_tdi_info);
	case SEV_CMD_TIO_ROLL_KEY:		return sizeof(struct sev_data_tio_roll_key);
	default:				return 0;
	}
}
