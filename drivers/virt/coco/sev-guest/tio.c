// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bitops.h>
#include <linux/minmax.h>
#include <linux/pci.h>
#include <linux/psp-sev.h>
#include <linux/tsm.h>
#include <linux/pci-tsm.h>
#include <crypto/gcm.h>
#include <uapi/linux/sev-guest.h>

#include <asm/svm.h>
#include <asm/sev.h>

#include "sev-guest.h"

ulong tsm_vtom = (2ULL << 40);
module_param(tsm_vtom, ulong, 0644);
MODULE_PARM_DESC(tsm_vtom, "SEV TIO vTOM value");

#define tsm_dev_to_snp_dev(t)	((struct snp_guest_dev *)dev_get_drvdata((t)->dev.parent))
#define pdev_to_tdi(p)		container_of((p)->tsm, struct tio_guest_tdi, ds.base_tsm)
#define ghcb_tio_sbdfn(pdev)	((pci_domain_nr((pdev)->bus) << 16) | pci_dev_id(pdev))

#define TIO_DATA_PAGES	(SZ_32K >> PAGE_SHIFT)
#define SPDM_MEASUREMENTS_NONCE_LEN 32

static void sev_free_shared_pages(struct device *dev, void *buf,
				  unsigned long npages, dma_addr_t dma_handle)
{
	dma_free_coherent(dev, npages << PAGE_SHIFT, buf, dma_handle);
}

static void *sev_alloc_shared_pages(struct device *dev, unsigned long npages,
				    dma_addr_t *dma_handle)
{
	return dma_alloc_coherent(dev, npages << PAGE_SHIFT, dma_handle, GFP_KERNEL);
}

struct tio_guest_tdi {
	struct pci_tsm_devsec ds;
	struct snp_guest_dev *snp_dev;
	u64 tdi_id; /* Runtime FW generated TDI id */
};

static void device_evidence_object_clear(struct device_evidence_object *obj)
{
	if (!obj)
		return;

	kfree(obj->digest);
	kfree(obj->data);
	obj->data = NULL;
	obj->len = 0;
	obj->digest = NULL;
}

static int device_evidence_object_assign(struct device_evidence_object *obj,
					 const void *src, size_t len)
{
	void *copy;

	device_evidence_object_clear(obj);
	if (!len || !src)
		return 0;

	copy = kmemdup(src, len, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;

	obj->data = copy;
	obj->len = len;
	return 0;
}

static void device_evidence_release(struct device_evidence *evidence)
{
	unsigned int i;

	if (!evidence)
		return;

	for (i = 0; i <= DEVICE_EVIDENCE_TYPE_MAX; i++)
		device_evidence_object_clear(&evidence->obj[i]);
}

static int handle_tio_guest_request(struct snp_guest_dev *snp_dev, u8 type,
				    void *req_buf, size_t req_sz, void *resp_buf, u32 resp_sz,
				    void *pt, u64 *npages, u64 *bdfn, u64 *param, u64 *fw_err)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	struct snp_guest_req req = {
		.msg_version = 2,
		.msg_type = type,
		.vmpck_id = mdesc->vmpck_id,
		.req_buf = kmemdup(req_buf, req_sz, GFP_KERNEL),
		.req_sz = req_sz,
		.resp_buf = kmalloc(resp_sz, GFP_KERNEL),
		.resp_sz = resp_sz,
		.exit_code = SVM_VMGEXIT_SEV_TIO_GR,
		.input.guest_rid = 0,
		.input.param = 0,
	};
	int ret;

	if (!req.req_buf || !req.resp_buf) {
		ret = -ENOMEM;
		goto error_exit;
	}

	if (pt && npages) {
		req.certs_data = pt;
		req.input.data_npages = *npages;
	}
	if (bdfn) {
		req.input.guest_rid = *bdfn & 0xFFFFFFFF;
		req.input.npages = *bdfn >> 32;
	}
	req.input.param = *param;

	ret = snp_send_guest_request(mdesc, &req);

	memcpy(resp_buf, req.resp_buf, resp_sz);
	*param = req.input.param;
	*fw_err = req.exitinfo2;

error_exit:
	kfree(req.resp_buf);
	kfree(req.req_buf);

	return ret;
}

static int guest_request_tio_data(struct snp_guest_dev *snp_dev, u8 type,
				  void *req_buf, size_t req_sz, void *resp_buf, u32 resp_sz,
				  u64 bdfn, enum tsm_tdisp_state *state,
				  struct device_evidence_object *certs,
				  struct device_evidence_object *meas,
				  const char *nonce,
				  struct device_evidence_object *report,
				  u64 *fw_err)
{
	u64 npages = TIO_DATA_PAGES, param = 0;
	struct tio_blob_table_entry *pt;
	dma_addr_t dh = 0;
	int rc;

	pt = sev_alloc_shared_pages(snp_dev->dev, TIO_DATA_PAGES, &dh);
	if (!pt)
		return -ENOMEM;

	if (state)
		param |= SVM_VMGEXIT_SEV_TIO_GR_INFO_STATE;
	if (certs)
		param |= SVM_VMGEXIT_SEV_TIO_GR_INFO_CERTS;
	if (meas)
		param |= SVM_VMGEXIT_SEV_TIO_GR_INFO_MEAS;
	if (report)
		param |= SVM_VMGEXIT_SEV_TIO_GR_INFO_REPORT;
	if (meas && nonce)
		memcpy(pt, nonce, SPDM_MEASUREMENTS_NONCE_LEN);

	rc = handle_tio_guest_request(snp_dev, type, req_buf, req_sz, resp_buf, resp_sz,
				      pt, &npages, &bdfn, &param, fw_err);
	if (npages > TIO_DATA_PAGES) {
		sev_free_shared_pages(snp_dev->dev, pt, TIO_DATA_PAGES, dh);
		pt = sev_alloc_shared_pages(snp_dev->dev, npages, &dh);
		if (!pt)
			return -ENOMEM;

		if (meas && nonce)
			memcpy(pt, nonce, SPDM_MEASUREMENTS_NONCE_LEN);
		rc = handle_tio_guest_request(snp_dev, type, req_buf, req_sz, resp_buf, resp_sz,
					      pt, &npages, &bdfn, &param, fw_err);
	}
	if (rc)
		goto out_free_pt;

	if (meas)
		device_evidence_object_clear(meas);
	if (certs)
		device_evidence_object_clear(certs);
	if (report)
		device_evidence_object_clear(report);

	for (unsigned int i = 0; i < 3; ++i) {
		u8 *ptr = ((u8 *)pt) + pt[i].offset;
		size_t len = pt[i].length;

		if (guid_is_null(&pt[i].guid))
			break;

		if (!len)
			continue;

		if (guid_equal(&pt[i].guid, &TIO_GUID_REPORT) && report)
			rc = device_evidence_object_assign(report, ptr, len);
		else if (guid_equal(&pt[i].guid, &TIO_GUID_MEASUREMENTS) && meas)
			rc = device_evidence_object_assign(meas, ptr, len);
		else if (guid_equal(&pt[i].guid, &TIO_GUID_CERTIFICATES) && certs)
			rc = device_evidence_object_assign(certs, ptr, len);
		else
			continue;
		if (rc)
			goto out_clear_blobs;
	}
	sev_free_shared_pages(snp_dev->dev, pt, npages, dh);

	if (state)
		*state = param;

	return 0;

out_clear_blobs:
	if (meas)
		device_evidence_object_clear(meas);
	if (certs)
		device_evidence_object_clear(certs);
	if (report)
		device_evidence_object_clear(report);
out_free_pt:
	sev_free_shared_pages(snp_dev->dev, pt, npages, dh);
	return rc;
}

struct tio_msg_tdi_info_req {
	u64 tdi_id;
	u8 reserved[8];
} __packed;

enum {
	TIO_MSG_TDI_INFO_RSP_STATUS_BOUND = 0,
	TIO_MSG_TDI_INFO_RSP_STATUS_INVALID = 1,
	TIO_MSG_TDI_INFO_RSP_STATUS_UNBOUND = 2,
};

struct tio_msg_tdi_info_rsp {
	u64 tdi_id;
	u16 status; /* TIO_MSG_TDI_INFO_RSP_STATUS_xxx */
	u8 reserved1[6];

	u32 meas_digest_valid:1;
	u32 meas_digest_fresh:1;
	u32 reserved2:30;

	/* These are TDISP's LOCK_INTERFACE_REQUEST flags */
	u32 no_fw_update:1;
	u32 cache_line_size:1;
	u32 lock_msix:1;
	u32 bind_p2p:1;
	u32 all_request_redirect:1;
	u32 reserved3:27;

	u64 spdm_algos;
	u8 certs_digest[48];
	u8 meas_digest[48];
	u8 interface_report_digest[48];
	u64 tdi_report_count;
	u64 reserved4;
} __packed;

/* SPDM algorithms used for TDISP, used in TIO_MSG_TDI_INFO_REQ */
#define TIO_SPDM_ALGOS_DHE_SECP256R1			0
#define TIO_SPDM_ALGOS_DHE_SECP384R1			1
#define TIO_SPDM_ALGOS_AEAD_AES_128_GCM			(0<<8)
#define TIO_SPDM_ALGOS_AEAD_AES_256_GCM			(1<<8)
#define TIO_SPDM_ALGOS_ASYM_TPM_ALG_RSASSA_3072		(0<<16)
#define TIO_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P256	(1<<16)
#define TIO_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P384	(2<<16)
#define TIO_SPDM_ALGOS_HASH_TPM_ALG_SHA_256		(0<<24)
#define TIO_SPDM_ALGOS_HASH_TPM_ALG_SHA_384		(1<<24)
#define TIO_SPDM_ALGOS_KEY_SCHED_SPDM_KEY_SCHEDULE	(0ULL<<32)

static int tio_tdi_status(struct pci_dev *pdev, struct snp_guest_dev *snp_dev,
			  struct tsm_tdi_status *ts, uint64_t tdi_id,
			  struct device_evidence_object *certs,
			  struct device_evidence_object *meas, const char *nonce,
			  struct device_evidence_object *report)
{
	enum tsm_tdisp_state state = TDISP_STATE_CONFIG_UNLOCKED;
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_tdi_info_rsp) + mdesc->ctx->authsize;
	struct tio_msg_tdi_info_rsp *rsp __free(kfree_sensitive) = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_tdi_info_req req = {
		.tdi_id = tdi_id,
	};
	u64 fw_err = 0;
	int rc;

	pci_notice(pdev, "TDI info");
	if (!rsp)
		return -ENOMEM;

	rc = guest_request_tio_data(snp_dev, TIO_MSG_TDI_INFO_REQ, &req,
				    sizeof(req), rsp, resp_len,
				    ghcb_tio_sbdfn(pdev), &state,
				    certs, meas, nonce,
				    report, &fw_err);
	if (rc)
		return rc;

	ts->meas_digest_valid = rsp->meas_digest_valid;
	ts->meas_digest_fresh = rsp->meas_digest_fresh;
	ts->no_fw_update = rsp->no_fw_update;
	ts->cache_line_size = rsp->cache_line_size == 0 ? 64 : 128;
	ts->lock_msix = rsp->lock_msix;
	ts->bind_p2p = rsp->bind_p2p;
	ts->all_request_redirect = rsp->all_request_redirect;
#define __ALGO(x, n, y) \
	((((x) & (0xFFUL << (n))) == TIO_SPDM_ALGOS_##y) ? \
	 (1ULL << TSM_SPDM_ALGOS_##y) : 0)
	ts->spdm_algos =
		__ALGO(rsp->spdm_algos, 0, DHE_SECP256R1) |
		__ALGO(rsp->spdm_algos, 0, DHE_SECP384R1) |
		__ALGO(rsp->spdm_algos, 8, AEAD_AES_128_GCM) |
		__ALGO(rsp->spdm_algos, 8, AEAD_AES_256_GCM) |
		__ALGO(rsp->spdm_algos, 16, ASYM_TPM_ALG_RSASSA_3072) |
		__ALGO(rsp->spdm_algos, 16, ASYM_TPM_ALG_ECDSA_ECC_NIST_P256) |
		__ALGO(rsp->spdm_algos, 16, ASYM_TPM_ALG_ECDSA_ECC_NIST_P384) |
		__ALGO(rsp->spdm_algos, 24, HASH_TPM_ALG_SHA_256) |
		__ALGO(rsp->spdm_algos, 24, HASH_TPM_ALG_SHA_384) |
		__ALGO(rsp->spdm_algos, 32, KEY_SCHED_SPDM_KEY_SCHEDULE);
#undef __ALGO
	memcpy(ts->certs_digest, rsp->certs_digest, sizeof(ts->certs_digest));
	memcpy(ts->meas_digest, rsp->meas_digest, sizeof(ts->meas_digest));
	memcpy(ts->interface_report_digest, rsp->interface_report_digest,
	       sizeof(ts->interface_report_digest));
	ts->intf_report_counter = rsp->tdi_report_count;
	ts->tdi_id = rsp->tdi_id;

	switch (rsp->status) {
	case TIO_MSG_TDI_INFO_RSP_STATUS_BOUND:
		ts->status = TDISP_STATE_BOUND;
		break;
	case TIO_MSG_TDI_INFO_RSP_STATUS_UNBOUND:
		ts->status = TDISP_STATE_UNBOUND;
		break;
	default:
		ts->status = TDISP_STATE_INVALID;
		break;
	}
	ts->state = state;

	return 0;
}

struct tio_msg_mmio_validate_req {
	u64 tdi_id;
	u8 reserved2[8];
	u64 subrange_base;
	u32 subrange_page_count;
	u32 range_offset;

	u16 validated:1; /* Desired value to set RMP.Validated for the range */
	/*
	 * Force validated:
	 * 0: If subrange does not have RMP.Validated set uniformly, fail.
	 * 1: If subrange does not have RMP.Validated set uniformly, force
	 *    to requested value
	 */
	u16 force_validated:1;
	u16 reserved3:14;

	u16 range_id;
	u8 reserved4[12];
} __packed;

/* Status codes from TIO_MSG_MMIO_VALIDATE_REQ */
enum mmio_validate_status {
	MMIO_VALIDATE_SUCCESS = 0,
	MMIO_VALIDATE_INVALID_TDI = 1,
	MMIO_VALIDATE_TDI_UNBOUND = 2,
	MMIO_VALIDATE_NOT_ASSIGNED = 3, /* At least one page is not assigned to the guest */
	MMIO_VALIDATE_NOT_IO = 4,	/* At least one page is not an I/O page */
	MMIO_VALIDATE_NOT_UNIFORM = 5,  /* Validated bit is not uniformly set for range */
	MMIO_VALIDATE_NOT_IMMUTABLE = 6,/* >=1 page does not have immutable bit set */
	MMIO_VALIDATE_NOT_MAPPED = 7,   /* At least one page is not mapped to the expected GPA */
	MMIO_VALIDATE_NOT_REPORTED = 8, /* Range ID is not reported in TDI report */
	MMIO_VALIDATE_OUT_OF_RANGE = 9, /* Subrange is out the MMIO range in TDI report */
	MMIO_VALIDATE_NOT_4K = 10,	/* >=1 page is not 4K page size */
};

struct tio_msg_mmio_validate_rsp {
	u64 tdi_id;
	u16 status; /* MMIO_VALIDATE_xxx */
	u8 reserved1[6];
	u64 subrange_base;
	u32 subrange_page_count;
	u32 range_offset;

	u16 changed:1; /* Validated bit has changed due to this operation */
	u16 reserved2:15;

	u16 range_id;
	u8 reserved3[12];
} __packed;

static int mmio_validate_range(struct snp_guest_dev *snp_dev, struct pci_dev *pdev,
			       uint64_t tdi_id, unsigned int range_id,
			       resource_size_t start, resource_size_t size,
			       bool invalidate, u64 *fw_err, u16 *status)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_mmio_validate_rsp) + mdesc->ctx->authsize;
	struct tio_msg_mmio_validate_rsp *rsp __free(kfree_sensitive) =
			kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_mmio_validate_req req = {
		.tdi_id = tdi_id,
		.subrange_base = start >> 12,
		.subrange_page_count = size >> 12,
		.range_offset = 0,
		.validated = !invalidate, /* Desired value to set RMP.Validated for the range */
		.force_validated = 0,
		.range_id = range_id,
	};
	u64 num_bdfn = SVM_VMGEXIT_SEV_TIO_GR_MMIO_MK_NUM_BDFN(size >> 12, ghcb_tio_sbdfn(pdev));
	u64 mmio_val = SVM_VMGEXIT_SEV_TIO_GR_MMIO_MK_VALIDATE(start, !invalidate);
	int rc;

	if (!rsp)
		return -ENOMEM;

	rc = handle_tio_guest_request(snp_dev, TIO_MSG_MMIO_VALIDATE_REQ,
				      &req, sizeof(req), rsp, resp_len,
				      NULL, NULL, &num_bdfn, &mmio_val, fw_err);
	if (rc || *fw_err || rsp->status != MMIO_VALIDATE_SUCCESS) {
		pci_err(pdev, "MMIO validate failed with rc=%d, fwerr=0x%llx, status=%x\n",
			rc, *fw_err, rsp->status);
		if (!rc)
			return -EFAULT;
		return rc;
	}

	*status = rsp->status;

	return 0;
}

static void tio_tdi_mmio_invalidate(struct pci_dev *pdev, struct snp_guest_dev *snp_dev,
				    uint64_t tdi_id)
{
	struct pci_tsm *tsm = pdev->tsm;
	u16 mmio_status;
	u64 fw_err = 0;
	int i = 0, rc = 0;
	struct pci_tsm_devsec *devsec_tsm = to_pci_tsm_devsec(tsm);
	struct pci_tsm_mmio *mmio = devsec_tsm->mmio;

	if (!mmio)
		return;

	pci_notice(pdev, "MMIO invalidate");

	for (i = 0; i < mmio->nr; ++i) {
		struct pci_tsm_mmio_entry *entry = pci_tsm_mmio_entry(mmio, i);
		struct resource *res = &entry->res;
		unsigned int range_id = entry->range_id;

		if (range_id >= PCI_NUM_RESOURCES ||
		    !resource_contains(pci_resource_n(pdev, range_id), res)) {
			pci_info(pdev, "Skipping MMIO [%d] %pr: no BAR %u window\n",
				 i, res, range_id);
			continue;
		}

		mmio_status = 0;
		rc = mmio_validate_range(snp_dev, pdev, tdi_id, range_id,
					 res->start, resource_size(res), true, &fw_err,
					 &mmio_status);
		if (rc || fw_err != SEV_RET_SUCCESS || mmio_status != MMIO_VALIDATE_SUCCESS) {
			pci_err(pdev, "MMIO #%d %llx..%llx validation failed 0x%llx %d\n",
				range_id, res->start, res->end, fw_err, mmio_status);
			continue;
		}

		pci_notice(pdev, "MMIO #%d %llx..%llx invalidated\n",
			   range_id, res->start, res->end);
	}

	pci_tsm_mmio_teardown(devsec_tsm->mmio);
	kfree(devsec_tsm->mmio);
	devsec_tsm->mmio = NULL;
}

static int tio_tdi_mmio_validate(struct pci_dev *pdev, struct snp_guest_dev *snp_dev,
				 uint64_t tdi_id)
{
	struct pci_tsm *tsm = pdev->tsm;
	u16 mmio_status;
	u64 fw_err = 0;
	int i, rc = 0;
	struct pci_tsm_mmio *mmio __free(kfree) = pci_tsm_mmio_alloc(pdev, TDISP_OFFSET_BAR_ALIGN);

	if (!mmio)
		return -ENOMEM;

	pci_notice(pdev, "MMIO validate");

	for (i = 0; i < mmio->nr; ++i) {
		struct pci_tsm_mmio_entry *entry = pci_tsm_mmio_entry(mmio, i);
		struct resource *res = &entry->res;
		unsigned int range_id = entry->range_id;

		if (range_id >= PCI_NUM_RESOURCES ||
		    !resource_contains(pci_resource_n(pdev, range_id), res)) {
			pci_info(pdev,
				 "Skipping MMIO [%d] %pr: no BAR %u window\n",
				 i, res, range_id);
			continue;
		}

		mmio_status = 0;
		rc = mmio_validate_range(snp_dev, pdev, tdi_id, range_id, res->start,
					 resource_size(res), false, &fw_err, &mmio_status);
		if (rc || fw_err != SEV_RET_SUCCESS || mmio_status != MMIO_VALIDATE_SUCCESS) {
			pci_err(pdev, "MMIO #%d %llx..%llx validation failed 0x%llx %d\n",
				range_id, res->start, res->end, fw_err, mmio_status);
			continue;
		}

		pci_notice(pdev, "MMIO #%d %llx..%llx validated\n", range_id, res->start, res->end);
	}

	if (!rc) {
		rc = pci_tsm_mmio_setup(pdev, mmio);
		if (!rc) {
			struct pci_tsm_devsec *devsec_tsm = to_pci_tsm_devsec(tsm);

			devsec_tsm->mmio = no_free_ptr(mmio);
		}
	}

	if (rc)
		tio_tdi_mmio_invalidate(pdev, snp_dev, tdi_id);

	return rc;
}

struct sdte {
	u64 v                  : 1;
	u64 reserved           : 3;
	u64 cxlio              : 3;
	u64 reserved1          : 45;
	u64 ppr                : 1;
	u64 reserved2          : 1;
	u64 giov               : 1;
	u64 gv                 : 1;
	u64 glx                : 2;
	u64 gcr3_tbl_rp0       : 3;
	u64 ir                 : 1;
	u64 iw                 : 1;
	u64 reserved3          : 1;
	u16 domain_id;
	u16 gcr3_tbl_rp1;
	u32 interrupt          : 1;
	u32 reserved4          : 5;
	u32 ex                 : 1;
	u32 sd                 : 1;
	u32 reserved5          : 2;
	u32 sats               : 1;
	u32 gcr3_tbl_rp2       : 21;
	u64 giv                : 1;
	u64 gint_tbl_len       : 4;
	u64 reserved6          : 1;
	u64 gint_tbl           : 46;
	u64 reserved7          : 2;
	u64 gpm                : 2;
	u64 reserved8          : 3;
	u64 hpt_mode           : 1;
	u64 reserved9          : 4;
	u32 asid               : 12;
	u32 reserved10         : 3;
	u32 viommu_en          : 1;
	u32 guest_device_id    : 16;
	u32 guest_id           : 15;
	u32 guest_id_mbo       : 1;
	u32 reserved11         : 1;
	u32 vmpl               : 2;
	u32 reserved12         : 3;
	u32 attrv              : 1;
	u32 reserved13         : 1;
	u32 sa                 : 8;
	u8 ide_stream_id[8];
	u32 vtom_en            : 1;
	u32 vtom               : 31;
	u32 rp_id              : 5;
	u32 reserved14         : 27;
	u8  reserved15[0x40-0x30];
} __packed;

struct tio_msg_sdte_write_req {
	u64 tdi_id;
	u8 reserved[8];
	struct sdte sdte;
} __packed;

/*
 * Status codes from TIO_MSG_SDTE_WRITE_REQ
 */
enum sdte_write_status {
	SDTE_WRITE_SUCCESS = 0,
	SDTE_WRITE_INVALID_TDI = 1,
	SDTE_WRITE_TDI_NOT_BOUND = 2,
	SDTE_WRITE_RESERVED = 3,
};

struct tio_msg_sdte_write_rsp {
	u64 tdi_id;
	u16 status; /* SDTE_WRITE_xxx */
	u8 reserved[6];
} __packed;

static int tio_tdi_sdte_write(struct pci_dev *pdev, struct snp_guest_dev *snp_dev,
			      uint64_t tdi_id, bool invalidate)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_sdte_write_rsp) + mdesc->ctx->authsize;
	struct tio_msg_sdte_write_rsp *rsp __free(kfree_sensitive) = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_sdte_write_req req;
	u64 flags = tsm_vtom | (invalidate ? 0 : SVM_VMGEXIT_SEV_TIO_GR_SDTE_VALIDATE);
	u64 bdfn = ghcb_tio_sbdfn(pdev);
	u64 fw_err = 0;
	int rc;

	BUILD_BUG_ON(sizeof(struct sdte) * 8 != 512);

	pci_notice(pdev, "SDTE write vTOM=%llx", flags);

	if (!invalidate)
		req = (struct tio_msg_sdte_write_req) {
			.tdi_id = tdi_id,
			.sdte.vmpl = 0,
			.sdte.vtom = tsm_vtom >> 21,
			.sdte.vtom_en = 1,
			.sdte.iw = 1,
			.sdte.ir = 1,
			.sdte.v = 1,
		};
	else
		req = (struct tio_msg_sdte_write_req) {
			.tdi_id = tdi_id,
		};

	if (!rsp)
		return -ENOMEM;

	rc = handle_tio_guest_request(snp_dev, TIO_MSG_SDTE_WRITE_REQ,
				      &req, sizeof(req), rsp, resp_len,
				      NULL, NULL, &bdfn, &flags, &fw_err);
	if (rc || fw_err || rsp->status != SDTE_WRITE_SUCCESS) {
		pci_err(pdev, "SDTE write failed with rc=%d, fwerr=0x%llx, status=%x\n",
			rc, fw_err, rsp->status);
		if (!rc)
			return -EFAULT;
		return rc;
	}

	pdev->dev.archdata.cc_shared_dma_offset = invalidate ? 0 : tsm_vtom;

	return 0;
}

static int sev_guest_status(struct pci_dev *pdev, struct tsm_tdi_status *ts)
{
	struct tio_guest_tdi *gtdi = pdev_to_tdi(pdev);

	return tio_tdi_status(pdev, gtdi->snp_dev, ts, gtdi->tdi_id,
			      NULL, NULL, NULL, NULL);
}

static struct pci_tsm *sev_guest_lock(struct tsm_dev *tsmdev, struct pci_dev *pdev)
{
	struct tio_guest_tdi *gtdi __free(kfree) = kzalloc(sizeof(*gtdi), GFP_KERNEL);
	struct tsm_tdi_status ts = {};
	u64 fw_err = 0, tdi_id = 0;
	int rc;

	if (!gtdi)
		return ERR_PTR(-ENOMEM);

	/* Enabling device tells the HV to register MMIO as memory slots */
	rc = pci_enable_device_mem(pdev);
	if (rc)
		return ERR_PTR(rc);

	rc = pci_tsm_devsec_constructor(pdev, &gtdi->ds, tsmdev);
	if (rc)
		return ERR_PTR(rc);

	gtdi->snp_dev = tsm_dev_to_snp_dev(tsmdev);

	rc = sev_tio_op(ghcb_tio_sbdfn(pdev), SVM_VMGEXIT_SEV_TIO_OP_BIND, &fw_err, &tdi_id);
	if (rc) {
		pci_err(pdev, "TDI bind CONFIG_LOCKED failed rc=%d fw=0x%llx\n",
			rc, fw_err);
		return ERR_PTR(rc);
	}
	pci_dbg(pdev, "New TDI ID=%llx\n", tdi_id);

	struct device_evidence *ev = device_evidence_create(0, HASH_ALGO_SHA384);
	if (!ev)
		return ERR_PTR(-ENOMEM);

	rc = tio_tdi_status(pdev, gtdi->snp_dev, &ts, tdi_id,
			    &ev->obj[DEVICE_EVIDENCE_TYPE_CERT0],
			    NULL, NULL,
			    &ev->obj[DEVICE_EVIDENCE_TYPE_REPORT]);
	if (rc)
		return ERR_PTR(rc);

	if (!ev->obj[DEVICE_EVIDENCE_TYPE_REPORT].data) {
		device_evidence_release(ev);
		return ERR_PTR(-ENODEV);
	}

	gtdi->ds.base_tsm.evidence = ev;
	gtdi->tdi_id = tdi_id;

	return &no_free_ptr(gtdi)->ds.base_tsm;
}

static void sev_guest_unlock(struct pci_tsm *tsm)
{
	struct pci_dev *pdev = tsm->pdev;
	struct tio_guest_tdi *gtdi = pdev_to_tdi(pdev);
	struct snp_guest_dev *snp_dev = gtdi->snp_dev;
	u64 fw_err = 0;

	tio_tdi_mmio_invalidate(pdev, snp_dev, gtdi->tdi_id);

	/* Quiesce DMA */
	sev_tio_op(ghcb_tio_sbdfn(pdev), SVM_VMGEXIT_SEV_TIO_OP_STOP, &fw_err, NULL);

	/*
	 * Up until now the VMM has been blocking clearing of BME and the device may
	 * not be able to recover without BME going via 0, do it now.
	 * Note that the device reset is still needed, leave to the userspace to
	 * decide on that.
	 */
	pci_disable_device(pdev);

	sev_tio_op(ghcb_tio_sbdfn(pdev), SVM_VMGEXIT_SEV_TIO_OP_UNBIND, &fw_err, NULL);

	device_evidence_release(tsm->evidence);
	kvfree(tsm);
}

static int sev_guest_accept(struct pci_dev *pdev)
{
	struct tio_guest_tdi *gtdi = pdev_to_tdi(pdev);
	struct snp_guest_dev *snp_dev = gtdi->snp_dev;
	struct pci_tsm *tsm = pdev->tsm;
	u64 fw_err = 0;
	int ret;

	if (!tsm->evidence->obj[DEVICE_EVIDENCE_TYPE_REPORT].data) {
		pci_warn_once(pdev, "Cannot accept without the report");
		return -ENODEV;
	}

	ret = sev_tio_op(ghcb_tio_sbdfn(pdev), SVM_VMGEXIT_SEV_TIO_OP_RUN, &fw_err, NULL);
	if (ret)
		return ret;

	ret = tio_tdi_mmio_validate(pdev, snp_dev, gtdi->tdi_id);
	if (ret)
		goto stop_tdi;

	return 0;

stop_tdi:
	sev_tio_op(ghcb_tio_sbdfn(pdev), SVM_VMGEXIT_SEV_TIO_OP_STOP, &fw_err, NULL);
	return ret;
}

static int sev_guest_refresh_evidence(struct pci_tsm *tsm, const void *nonce,
				      size_t nonce_len)
{
	struct pci_dev *pdev = tsm->pdev;
	struct tio_guest_tdi *gtdi = pdev_to_tdi(pdev);
	struct snp_guest_dev *snp_dev = gtdi->snp_dev;
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_tdi_info_rsp) + mdesc->ctx->authsize;
	struct tio_msg_tdi_info_rsp *rsp __free(kfree_sensitive) = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_tdi_info_req req = {
		.tdi_id = gtdi->tdi_id,
	};
	u64 fw_err = 0;
	char nonce_buf[SPDM_MEASUREMENTS_NONCE_LEN] = {};

	if (!rsp)
		return -ENOMEM;

	if (nonce_len) {
		memset(nonce_buf, 0, sizeof(nonce_buf));
		memcpy(nonce_buf, nonce,
		       min(nonce_len, SPDM_MEASUREMENTS_NONCE_LEN));
	}

	pci_notice(pdev, "TDI measurements");

	struct device_evidence *ev = pdev->tsm->evidence;

	return guest_request_tio_data(snp_dev, TIO_MSG_TDI_INFO_REQ,
				      &req, sizeof(req), rsp, resp_len,
				      ghcb_tio_sbdfn(pdev), NULL, NULL,
				      &ev->obj[DEVICE_EVIDENCE_TYPE_MEASUREMENTS],
				      nonce_buf, NULL, &fw_err);
}

static int sev_guest_enable_dma(struct pci_dev *pdev)
{
	struct tio_guest_tdi *gtdi = pdev_to_tdi(pdev);
	struct snp_guest_dev *snp_dev = gtdi->snp_dev;
	int ret;

	ret = tio_tdi_sdte_write(pdev, snp_dev, gtdi->tdi_id, false);

	return ret;
}

static void sev_guest_disable_dma(struct pci_dev *pdev)
{
	struct tio_guest_tdi *gtdi = pdev_to_tdi(pdev);
	struct snp_guest_dev *snp_dev = gtdi->snp_dev;
	int rc;

	rc = tio_tdi_sdte_write(pdev, snp_dev, gtdi->tdi_id, true);
	if (rc)
		pr_err("SDTE_WRITE failed, ret=%d\n", rc);
}

struct pci_tsm_ops sev_guest_tsm_ops = {
	.lock = sev_guest_lock,
	.unlock = sev_guest_unlock,
	.run = sev_guest_accept,
	.enable_dma = sev_guest_enable_dma,
	.disable_dma = sev_guest_disable_dma,
	.tdi_status = sev_guest_status,
	.refresh_evidence = sev_guest_refresh_evidence,
};

void sev_guest_tsm_set_ops(bool set, struct snp_guest_dev *snp_dev)
{
	if (set) {
		struct tsm_dev *tsmdev;

		tsmdev = tsm_register(snp_dev->dev, &sev_guest_tsm_ops);
		if (!IS_ERR_OR_NULL(tsmdev))
			snp_dev->tsmdev = tsmdev;
		return;
	}

	if (snp_dev->tsmdev) {
		tsm_unregister(snp_dev->tsmdev);
		snp_dev->tsmdev = NULL;
	}
}
