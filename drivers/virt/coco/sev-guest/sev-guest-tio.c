// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bitfield.h>
#include <linux/pci.h>
#include <linux/psp-sev.h>
#include <linux/tsm.h>
#include <linux/pci-tsm.h>
#include <crypto/gcm.h>
#include <uapi/linux/sev-guest.h>
#include <uapi/linux/tsm.h>

#include <asm/svm.h>
#include <asm/sev.h>

#include "sev-guest.h"

#define TIO_MESSAGE_VERSION	1

ulong tsm_vtom = 0x7fffffff;
module_param(tsm_vtom, ulong, 0644);
MODULE_PARM_DESC(tsm_vtom, "SEV TIO vTOM value");

#define tsm_dev_to_snp_dev(t)	((struct snp_guest_dev *)dev_get_drvdata((t)->dev.parent))
#define pdev_to_tdi(p)		container_of((p)->tsm, struct tio_guest_tdi, ds.base_tsm)

struct tio_guest_tdi {
	struct pci_tsm_devsec ds;
	struct snp_guest_dev *snp_dev;
};

/*
 * Status codes from TIO_MSG_SDTE_WRITE_RSP
 */
enum sdte_write_status {
	SDTE_WRITE_SUCCESS = 0,
	SDTE_WRITE_INVALID_TDI = 1,
	SDTE_WRITE_TDI_NOT_BOUND = 2,
	SDTE_WRITE_RESERVED = 3,
};

/*
 * Status codes from TIO_MSG_MMIO_CONFIG_REQ
 */
enum mmio_config_status {
	MMIO_CONFIG_SUCCESS = 0,
	MMIO_CONFIG_INVALID_TDI = 1,
	MMIO_CONFIG_TDI_UNBOUND = 2,
	 /* The provided MMIO range ID is not reported in the interface report */
	MMIO_CONFIG_NOT_REPORTED = 3,
	/* One or more attributes could not be changed */
	MMIO_CONFIG_COULD_NOT_CHANGE = 4,
};

static int handle_tio_guest_request(struct snp_guest_dev *snp_dev, u8 type,
				   void *req_buf, size_t req_sz, void *resp_buf, u32 resp_sz,
				   void *pt, u64 *npages, u64 *bdfn, u64 *param, u64 *fw_err)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	struct snp_guest_req req = {
		.msg_version = TIO_MESSAGE_VERSION,
	};
	u64 exitinfo2 = 0;
	int ret;

	req.msg_type = type;
	req.vmpck_id = mdesc->vmpck_id;
	req.req_buf = kmemdup(req_buf, req_sz, GFP_KERNEL);
	req.req_sz = req_sz;
	req.resp_buf = kmalloc(resp_sz, GFP_KERNEL);
	req.resp_sz = resp_sz;
	req.exit_code = SVM_VMGEXIT_SEV_TIO_GUEST_REQUEST;

	req.input.guest_rid = 0;
	req.input.param = 0;

	if (pt && npages) {
		req.certs_data = pt;
		req.input.data_npages = *npages;
	}
	if (bdfn)
		req.input.guest_rid = *bdfn;
	if (param)
		req.input.param = *param;

	ret = snp_send_guest_request(mdesc, &req);

	memcpy(resp_buf, req.resp_buf, resp_sz);

	if (param)
		*param = req.input.param;

	*fw_err = exitinfo2;

	kfree(req.resp_buf);
	kfree(req.req_buf);

	return ret;
}

static void free_shared_pages(void *buf, size_t sz)
{
	unsigned int npages = PAGE_ALIGN(sz) >> PAGE_SHIFT;
	int ret;

	if (!buf)
		return;

	ret = set_memory_encrypted((unsigned long)buf, npages);
	if (ret) {
		WARN_ONCE(ret, "failed to restore encryption mask (leak it)\n");
		return;
	}

	__free_pages(virt_to_page(buf), get_order(sz));
}

static void *alloc_shared_pages(size_t sz)
{
	unsigned int npages = PAGE_ALIGN(sz) >> PAGE_SHIFT;
	struct page *page;
	int ret;

	page = alloc_pages(GFP_KERNEL_ACCOUNT, get_order(sz));
	if (!page)
		return NULL;

	ret = set_memory_decrypted((unsigned long)page_address(page), npages);
	if (ret) {
		pr_err("failed to mark page shared, ret=%d\n", ret);
		__free_pages(page, get_order(sz));
		return NULL;
	}

	return page_address(page);
}

static int guest_request_tio_data(struct snp_guest_dev *snp_dev, u8 type,
				  void *req_buf, size_t req_sz, void *resp_buf, u32 resp_sz,
				  u64 bdfn, enum tsm_tdisp_state *state,
				  struct tsm_blob **certs, struct tsm_blob **meas,
				  const char *nonce,
				  struct tsm_blob **report, u64 *fw_err)
{
#define TIO_DATA_PAGES	(SZ_32K >> PAGE_SHIFT)
	u64 npages = TIO_DATA_PAGES, param = 0;
	struct tio_blob_table_entry *pt;
	int rc;

	pt = alloc_shared_pages(TIO_DATA_PAGES << PAGE_SHIFT);
	if (!pt)
		return -ENOMEM;

	memcpy(pt, nonce, SPDM_MEASUREMENTS_NONCE_LEN);
	rc = handle_tio_guest_request(snp_dev, type, req_buf, req_sz, resp_buf, resp_sz,
				      pt, &npages, &bdfn, state ? &param : NULL, fw_err);
	if (npages > TIO_DATA_PAGES) {
		free_shared_pages(pt, TIO_DATA_PAGES << PAGE_SHIFT);
		pt = alloc_shared_pages(npages << PAGE_SHIFT);
		if (!pt)
			return -ENOMEM;

		memcpy(pt, nonce, SPDM_MEASUREMENTS_NONCE_LEN);
		rc = handle_tio_guest_request(snp_dev, type, req_buf, req_sz, resp_buf, resp_sz,
					      pt, &npages, &bdfn, state ? &param : NULL, fw_err);
	}
	if (rc)
		return rc;

	tsm_blob_free(*meas);
	tsm_blob_free(*certs);
	tsm_blob_free(*report);
	*meas = NULL;
	*certs = NULL;
	*report = NULL;

	for (unsigned int i = 0; i < 3; ++i) {
		u8 *ptr = ((u8 *) pt) + pt[i].offset;
		size_t len = pt[i].length;
		struct tsm_blob *b;

		if (guid_is_null(&pt[i].guid))
			break;

		if (!len)
			continue;

		b = tsm_blob_new(ptr, len);
		if (!b)
			break;

		if (guid_equal(&pt[i].guid, &TIO_GUID_REPORT))
			*report = b;
		else if (guid_equal(&pt[i].guid, &TIO_GUID_MEASUREMENTS))
			*meas = b;
		else if (guid_equal(&pt[i].guid, &TIO_GUID_CERTIFICATES))
			*certs = b;
	}
	free_shared_pages(pt, npages);

	if (state)
		*state = param;

	return 0;
}

struct tio_msg_tdi_info_req {
	__u16 guest_device_id;
	__u8 reserved[14];
} __packed;

struct tio_msg_tdi_info_rsp {
	__u16 guest_device_id;
	__u16 status;
	__u8 reserved1[12];
	union {
		u32 meas_flags;
		struct {
			u32 meas_digest_valid : 1;
			u32 meas_digest_fresh : 1;
		};
	};
	union {
		u32 tdisp_lock_flags;
		/* These are TDISP's LOCK_INTERFACE_REQUEST flags */
		struct {
			u32 no_fw_update : 1;
			u32 cache_line_size : 1;
			u32 lock_msix : 1;
			u32 bind_p2p : 1;
			u32 all_request_redirect : 1;
		};
	};
	__u64 spdm_algos;
	__u8 certs_digest[48];
	__u8 meas_digest[48];
	__u8 interface_report_digest[48];
	__u64 tdi_report_count;
	__u64 reserved2;
} __packed;

/* Passing pci_tsm explicitly as it may not be set in pci_dev just yet */
static int tio_tdi_status(struct pci_dev *pdev, struct pci_tsm *tsm,
			  struct snp_guest_dev *snp_dev,
			  struct tsm_tdi_status *ts, bool getreport)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_tdi_info_rsp) + mdesc->ctx->authsize;
	struct tio_msg_tdi_info_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_tdi_info_req req = {
		.guest_device_id = pci_dev_id(pdev),
	};
	u64 fw_err = 0;
	int rc;
	enum tsm_tdisp_state state = 0;

	pci_notice(pdev, "TDI info");
	if (!rsp)
		return -ENOMEM;

	if (getreport) {
		rc = guest_request_tio_data(snp_dev, TIO_MSG_TDI_INFO_REQ, &req,
					    sizeof(req), rsp, resp_len,
					    req.guest_device_id, &state,
					    &tsm->certs, &tsm->meas, tsm->nonce,
					    &tsm->report, &fw_err);
	} else {
		u64 bdfn = req.guest_device_id, state64 = 0;

		rc = handle_tio_guest_request(snp_dev, TIO_MSG_TDI_INFO_REQ, &req,
					      sizeof(req), rsp, resp_len,
					      NULL, NULL, &bdfn, &state64,
					      &fw_err);
		state = state64;
	}
	if (rc)
		goto free_exit;

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

	ts->valid = true;
	ts->state = state;
	/* The response buffer contains the sensitive data, explicitly clear it. */
free_exit:
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

struct tio_msg_mmio_validate_req {
	__u16 guest_device_id;
	__u16 reserved1;
	__u8 reserved2[12];
	__u64 subrange_base;
	__u32 subrange_page_count;
	__u32 range_offset;
	union {
		__u16 flags;
		struct {
			__u16 validated:1; /* Desired value to set RMP.Validated for the range */
			/*
			 * Force validated:
			 * 0: If subrange does not have RMP.Validated set uniformly, fail.
			 * 1: If subrange does not have RMP.Validated set uniformly, force
			 *    to requested value
			 */
			__u16 force_validated:1;
		};
	};
	__u16 range_id;
	__u8 reserved3[12];
} __packed;

struct tio_msg_mmio_validate_rsp {
	__u16 guest_interface_id;
	__u16 status; /* MMIO_VALIDATE_xxx */
	__u8 reserved1[12];
	__u64 subrange_base;
	__u32 subrange_page_count;
	__u32 range_offset;
	union {
		__u16 flags;
		struct {
			/* Validated bit has changed due to this operation */
			__u16 changed:1;
		};
	};
	__u16 range_id;
	__u8 reserved2[12];
} __packed;

static int mmio_validate_range(struct snp_guest_dev *snp_dev, struct pci_dev *pdev,
			       unsigned int range_id, resource_size_t start, resource_size_t size,
			       bool invalidate, u64 *fw_err, u16 *status)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_mmio_validate_rsp) + mdesc->ctx->authsize;
	struct tio_msg_mmio_validate_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_mmio_validate_req req = {
		.guest_device_id = pci_dev_id(pdev),
		.subrange_base = start,
		.subrange_page_count = size >> PAGE_SHIFT,
		.range_offset = 0,
		.validated = !invalidate, /* Desired value to set RMP.Validated for the range */
		.force_validated = 0,
		.range_id = range_id,
	};
	u64 bdfn = pci_dev_id(pdev);
	u64 mmio_val = MMIO_MK_VALIDATE(start, size, range_id, !invalidate);
	int rc;

	if (!rsp)
		return -ENOMEM;

	rc = handle_tio_guest_request(snp_dev, TIO_MSG_MMIO_VALIDATE_REQ,
			       &req, sizeof(req), rsp, resp_len,
			       NULL, NULL, &bdfn, &mmio_val, fw_err);
	if (rc)
		goto free_exit;

	*status = rsp->status;

free_exit:
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

#ifdef SEV_TIO_GUEST_TRY_MAKE_MMIO_SHARED
struct tio_msg_mmio_config_req {
	__u16 guest_device_id;
	__u16 reserved1;
	struct {
		__u32 reserved2:2;
		__u32 is_non_tee_mem:1;
		__u32 reserved3:13;
		__u32 range_id:16;
	};
	struct {
		__u32 write:1; /* 0: read; 1: Write configuration of range */
		__u32 reserved4:31;
	};
	__u8 reserved5[4];
} __packed;

struct tio_msg_mmio_config_rsp {
	__u16 guest_device_id;
	__u16 status; /* mmio_config_status */
	struct {
		__u32 msix_table:1;
		__u32 msix_pba:1;
		__u32 is_non_tee_mem:1;
		__u32 is_mem_attr_updateable:1;
		__u32 reserved1:12;
		__u32 range_id:16;
	};
	struct {
		__u32 write:1; /* 0: read; 1: Write configuration of range */
		__u32 reserved2:31;
	};
	__u8 reserved3[4];
} __packed;

static int mmio_config_get(struct snp_guest_dev *snp_dev, struct pci_dev *pdev,
			   unsigned int range_id, bool *updateable, bool *is_non_tee,
			   u64 *fw_err, u16 *status)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_mmio_config_rsp) + mdesc->ctx->authsize;
	struct tio_msg_mmio_config_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_mmio_config_req req = {
		.guest_device_id = pci_dev_id(pdev),
		.is_non_tee_mem = 0,
		.range_id = range_id,
		.write = 0,
	};
	u64 bdfn = pci_dev_id(pdev);
	int rc;

	if (!rsp)
		return -ENOMEM;

	rc = handle_tio_guest_request(snp_dev, TIO_MSG_MMIO_CONFIG_REQ,
			       &req, sizeof(req), rsp, resp_len,
			       NULL, NULL, &bdfn, NULL, fw_err);
	if (rc)
		goto free_exit;

	*status = rsp->status;
	*updateable = rsp->is_mem_attr_updateable;
	*is_non_tee = rsp->is_non_tee_mem;

free_exit:
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

static int mmio_config_range(struct snp_guest_dev *snp_dev, struct pci_dev *pdev,
			     unsigned int range_id, resource_size_t start, resource_size_t size,
			     bool tee, u64 *fw_err, u16 *status)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_mmio_config_rsp) + mdesc->ctx->authsize;
	struct tio_msg_mmio_config_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_mmio_config_req req = {
		.guest_device_id = pci_dev_id(pdev),
//		We kinda want these but the spec does not define them (yet?)
//		.subrange_base = start,
//		.subrange_page_count = size >> PAGE_SHIFT,
//		.range_offset = 0,
		.is_non_tee_mem = !tee,
		.range_id = range_id,
		.write = 1,
	};
	u64 bdfn = pci_dev_id(pdev);
	u64 mmio_val = MMIO_MK_VALIDATE(start, size, range_id, tee);
	int rc;

	if (!rsp)
		return -ENOMEM;

	if (tee)
		mmio_val |= MMIO_CONFIG_TEE;

	rc = handle_tio_guest_request(snp_dev, TIO_MSG_MMIO_CONFIG_REQ,
			       &req, sizeof(req), rsp, resp_len,
			       NULL, NULL, &bdfn, &mmio_val, fw_err);
	if (rc)
		goto free_exit;

	*status = rsp->status;

free_exit:
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}
#endif

static int tio_tdi_mmio_validate(struct pci_dev *pdev, struct snp_guest_dev *snp_dev)
{
	struct pci_tsm *tsm = pdev->tsm;
	struct tdi_report_mmio_range mr;
	unsigned int range_id;
	struct resource *r;
	u16 mmio_status;
	u64 fw_err = 0;
	int i = 0, rc = 0;
	struct pci_tsm_mmio *mmio __free(kfree) =
		kzalloc(struct_size(mmio, res, PCI_NUM_RESOURCES), GFP_KERNEL);

	if (!mmio)
		return -ENOMEM;

	if (WARN_ON_ONCE(!tsm || !tsm->report))
		return -ENODEV;

	pci_notice(pdev, "MMIO validate");

	for (i = 0; i < TDI_REPORT_MR_NUM(tsm->report); ++i) {
		mr = TDI_REPORT_MR(tsm->report, i);
		range_id = FIELD_GET(TSM_TDI_REPORT_MMIO_RANGE_ID, mr.range_attributes);
		r = pci_resource_n(pdev, range_id);

		if (r->end == r->start || ((r->end - r->start + 1) & ~PAGE_MASK) || !mr.num) {
			pci_warn(pdev, "Skipping broken range [%d] #%d %d pages, %llx..%llx\n",
				i, range_id, mr.num, r->start, r->end);
			continue;
		}

		if (FIELD_GET(TSM_TDI_REPORT_MMIO_IS_NON_TEE, mr.range_attributes)) {
			pci_info(pdev, "Skipping non-TEE range [%d] #%d %d pages, %llx..%llx\n",
				 i, range_id, mr.num, r->start, r->end);
			continue;
		}

		/* Currently not supported */
		if (FIELD_GET(TSM_TDI_REPORT_MMIO_MSIX_TABLE, mr.range_attributes) ||
		    FIELD_GET(TSM_TDI_REPORT_MMIO_PBA, mr.range_attributes)) {
			pci_info(pdev, "Skipping MSIX (%ld/%ld) range [%d] #%d %d pages, %llx..%llx\n",
				 FIELD_GET(TSM_TDI_REPORT_MMIO_MSIX_TABLE, mr.range_attributes),
				 FIELD_GET(TSM_TDI_REPORT_MMIO_PBA, mr.range_attributes),
				 i, range_id, mr.num, r->start, r->end);
			continue;
		}

		mmio_status = 0;
		rc = mmio_validate_range(snp_dev, pdev, range_id,
					 r->start, r->end - r->start + 1, false, &fw_err,
					 &mmio_status);
		if (rc || fw_err != SEV_RET_SUCCESS || mmio_status != MMIO_VALIDATE_SUCCESS) {
			pci_err(pdev, "MMIO #%d %llx..%llx validation failed 0x%llx %d\n",
				range_id, r->start, r->end, fw_err, mmio_status);
			continue;
		}

		mmio->res[mmio->nr] = DEFINE_RES_NAMED_DESC(pci_resource_start(pdev, range_id),
				r->end - r->start + 1, "PCI MMIO Encrypted",
				pci_resource_flags(pdev, range_id), IORES_DESC_ENCRYPTED);
		++mmio->nr;

		pci_notice(pdev, "MMIO #%d %llx..%llx validated\n",  range_id, r->start, r->end);
	}

	if (!rc) {
		rc = pci_tsm_mmio_setup(pdev, mmio);
		if (!rc) {
			struct pci_tsm_devsec *devsec_tsm = to_pci_tsm_devsec(tsm);

			devsec_tsm->mmio = no_free_ptr(mmio);
		}
	}

	return rc;
}

static void tio_tdi_mmio_invalidate(struct pci_dev *pdev, struct snp_guest_dev *snp_dev)
{
	struct pci_tsm *tsm = pdev->tsm;
	struct tdi_report_mmio_range mr;
	unsigned int range_id;
	struct resource *r;
	u16 mmio_status;
	u64 fw_err = 0;
	int i = 0, rc = 0;
	struct pci_tsm_devsec *devsec_tsm = to_pci_tsm_devsec(tsm);
	struct pci_tsm_mmio *mmio = devsec_tsm->mmio;

	if (!mmio)
		return;

	pci_notice(pdev, "MMIO invalidate");

	for (i = 0; i < TDI_REPORT_MR_NUM(tsm->report); ++i) {
		mr = TDI_REPORT_MR(tsm->report, i);
		range_id = FIELD_GET(TSM_TDI_REPORT_MMIO_RANGE_ID, mr.range_attributes);
		r = pci_resource_n(pdev, range_id);

		if (r->end == r->start || ((r->end - r->start + 1) & ~PAGE_MASK) || !mr.num) {
			pci_warn(pdev, "Skipping broken range [%d] #%d %d pages, %llx..%llx\n",
				i, range_id, mr.num, r->start, r->end);
			continue;
		}

		if (FIELD_GET(TSM_TDI_REPORT_MMIO_IS_NON_TEE, mr.range_attributes)) {
			pci_info(pdev, "Skipping non-TEE range [%d] #%d %d pages, %llx..%llx\n",
				 i, range_id, mr.num, r->start, r->end);
			continue;
		}

		/* Currently not supported */
		if (FIELD_GET(TSM_TDI_REPORT_MMIO_MSIX_TABLE, mr.range_attributes) ||
		    FIELD_GET(TSM_TDI_REPORT_MMIO_PBA, mr.range_attributes)) {
			pci_info(pdev, "Skipping MSIX (%ld/%ld) range [%d] #%d %d pages, %llx..%llx\n",
				 FIELD_GET(TSM_TDI_REPORT_MMIO_MSIX_TABLE, mr.range_attributes),
				 FIELD_GET(TSM_TDI_REPORT_MMIO_PBA, mr.range_attributes),
				 i, range_id, mr.num, r->start, r->end);
			continue;
		}

		mmio_status = 0;
		rc = mmio_validate_range(snp_dev, pdev, range_id,
					 r->start, r->end - r->start + 1, true, &fw_err,
					 &mmio_status);
		if (rc || fw_err != SEV_RET_SUCCESS || mmio_status != MMIO_VALIDATE_SUCCESS) {
			pci_err(pdev, "MMIO #%d %llx..%llx validation failed 0x%llx %d\n",
				range_id, r->start, r->end, fw_err, mmio_status);
			continue;
		}

#ifdef SEV_TIO_GUEST_TRY_MAKE_MMIO_SHARED
		bool updateable = false, is_non_tee = false;
		u16 status = 0;

		rc = mmio_config_get(snp_dev, pdev, range_id, &updateable,
				     &is_non_tee, &fw_err, &status);
		if (rc || fw_err) {
			pci_err(pdev, "MMIO #%d %llx..%llx failed to get config\n",
				range_id, r->start, r->end);
			continue;
		}

		pci_notice(pdev, "[%d] #%d: updateable=%d is_non_tee=%d\n",
			   i, range_id, updateable, is_non_tee);

		if (!updateable || is_non_tee)
			continue;

		rc = mmio_config_range(snp_dev, pdev, range_id,
				       r->start, r->end - r->start + 1,
				       false, &fw_err, &status);
		if (rc) {
			pci_err(pdev, "MMIO #%d %llx..%llx failed to set config\n",
				range_id, r->start, r->end);
			continue;
		}

		pci_notice(pdev, "[%d] #%d: setting config rc=%d status=%d\n",
			   i, range_id, rc, status);
#endif
		pci_notice(pdev, "MMIO #%d %llx..%llx invalidated\n",  range_id, r->start, r->end);
	}

	pci_tsm_mmio_teardown(devsec_tsm->mmio);
	kfree(devsec_tsm->mmio);
	devsec_tsm->mmio = NULL;
}

struct sdte {
	__u64 v                  : 1;
	__u64 reserved           : 3;
	__u64 cxlio              : 3;
	__u64 reserved1          : 45;
	__u64 ppr                : 1;
	__u64 reserved2          : 1;
	__u64 giov               : 1;
	__u64 gv                 : 1;
	__u64 glx                : 2;
	__u64 gcr3_tbl_rp0       : 3;
	__u64 ir                 : 1;
	__u64 iw                 : 1;
	__u64 reserved3          : 1;
	__u16 domain_id;
	__u16 gcr3_tbl_rp1;
	__u32 interrupt          : 1;
	__u32 reserved4          : 5;
	__u32 ex                 : 1;
	__u32 sd                 : 1;
	__u32 reserved5          : 2;
	__u32 sats               : 1;
	__u32 gcr3_tbl_rp2       : 21;
	__u64 giv                : 1;
	__u64 gint_tbl_len       : 4;
	__u64 reserved6          : 1;
	__u64 gint_tbl           : 46;
	__u64 reserved7          : 2;
	__u64 gpm                : 2;
	__u64 reserved8          : 3;
	__u64 hpt_mode           : 1;
	__u64 reserved9          : 4;
	__u32 asid               : 12;
	__u32 reserved10         : 3;
	__u32 viommu_en          : 1;
	__u32 guest_device_id    : 16;
	__u32 guest_id           : 15;
	__u32 guest_id_mbo       : 1;
	__u32 reserved11         : 1;
	__u32 vmpl               : 2;
	__u32 reserved12         : 3;
	__u32 attrv              : 1;
	__u32 reserved13         : 1;
	__u32 sa                 : 8;
	__u8 ide_stream_id[8];
	__u32 vtom_en            : 1;
	__u32 vtom               : 31;
	__u32 rp_id              : 5;
	__u32 reserved14         : 27;
	__u8  reserved15[0x40-0x30];
} __packed;

struct tio_msg_sdte_write_req {
	__u16 guest_device_id;
	__u8 reserved[14];
	struct sdte sdte;
} __packed;

struct tio_msg_sdte_write_rsp {
	__u16 guest_device_id;
	__u16 status; /* SDTE_WRITE_xxx */
	__u8 reserved[12];
} __packed;

static int tio_tdi_sdte_write(struct pci_dev *pdev, struct snp_guest_dev *snp_dev, bool invalidate)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_sdte_write_rsp) + mdesc->ctx->authsize;
	struct tio_msg_sdte_write_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_sdte_write_req req;
	u64 fw_err = 0;
	u64 bdfn = pci_dev_id(pdev);
	u64 flags = invalidate ? 0 : SDTE_VALIDATE;
	int rc;

	BUILD_BUG_ON(sizeof(struct sdte) * 8 != 512);

	if (!invalidate)
		req = (struct tio_msg_sdte_write_req) {
			.guest_device_id = bdfn,
			.sdte.vmpl = 0,
			.sdte.vtom = tsm_vtom,
			.sdte.vtom_en = 1,
			.sdte.iw = 1,
			.sdte.ir = 1,
			.sdte.v = 1,
		};
	else
		req = (struct tio_msg_sdte_write_req) {
			.guest_device_id = bdfn,
		};

	pci_notice(pdev, "SDTE write vTOM=%lx", (unsigned long) req.sdte.vtom << 21);

	if (!rsp)
		return -ENOMEM;

	rc = handle_tio_guest_request(snp_dev, TIO_MSG_SDTE_WRITE_REQ,
			       &req, sizeof(req), rsp, resp_len,
			       NULL, NULL, &bdfn, &flags, &fw_err);
	if (rc) {
		pci_err(pdev, "SDTE write failed with 0x%llx\n", fw_err);
		goto free_exit;
	}

free_exit:
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

static int sev_guest_status(struct pci_dev *pdev, struct tsm_tdi_status *ts)
{
	struct tio_guest_tdi *gtdi = pdev_to_tdi(pdev);

	return tio_tdi_status(pdev, pdev->tsm, gtdi->snp_dev, ts, true);
}

static struct pci_tsm *sev_guest_lock(struct tsm_dev *tsmdev, struct pci_dev *pdev)
{
	struct tio_guest_tdi *gtdi __free(kfree) = kzalloc(sizeof(*gtdi), GFP_KERNEL);
	struct tsm_tdi_status ts = {};
	int rc;

	if (!gtdi)
		return ERR_PTR(-ENOMEM);

	rc = pci_tsm_devsec_constructor(pdev, &gtdi->ds, tsmdev);
	if (rc)
		return ERR_PTR(rc);

	pci_dbg(pdev, "TSM enabled\n");

	gtdi->snp_dev = tsm_dev_to_snp_dev(tsmdev);

	// Cannot call this yet: rc = sev_guest_status(pdev, &ts);
	rc = tio_tdi_status(pdev, &gtdi->ds.base_tsm, gtdi->snp_dev, &ts, true);
	if (rc)
		return ERR_PTR(rc);

	return &no_free_ptr(gtdi)->ds.base_tsm;
}

static void sev_guest_unlock(struct pci_tsm *tsm)
{
	struct pci_dev *pdev = tsm->pdev;
	struct tio_guest_tdi *gtdi = pdev_to_tdi(pdev);
	struct snp_guest_dev *snp_dev = gtdi->snp_dev;

	/* Disabling DMA equals "unbind" */
	tio_tdi_sdte_write(pdev, snp_dev, true);

	tio_tdi_mmio_invalidate(pdev, snp_dev);

	tsm->pdev->tsm = NULL;
	kvfree(tsm);
}

static int sev_guest_accept(struct pci_dev *pdev)
{
	struct tio_guest_tdi *gtdi = pdev_to_tdi(pdev);
	struct snp_guest_dev *snp_dev = gtdi->snp_dev;
	struct tsm_tdi_status ts = {};
	struct pci_tsm *tsm = pdev->tsm;
	int ret;

	/* Lock the config first! */
	if (!tsm->report)
		pci_warn(pdev, "!!! Accepting without attestation !!!");

	ret = tio_tdi_status(pdev, tsm, snp_dev, &ts, !tsm->report);
	if (ret) {
		pci_err(pdev, "Error reading the state, ret = %d", ret);
		return ret;
	}

	if (ts.state != TDISP_STATE_CONFIG_LOCKED && ts.state != TDISP_STATE_RUN) {
		pci_err(pdev, "Not in CONFIG_LOCKED or RUN state, state=%d instead",
			ts.state);
		return -EIO;
	}

	cond_resched();

	/* MMIO validation result is stored as IORESOURCE_VALIDATED */
	ret = tio_tdi_mmio_validate(pdev, snp_dev);
	if (ret)
		return ret;

	ret = tio_tdi_sdte_write(pdev, snp_dev, false);
	if (ret)
		return ret;

	cond_resched();

	ret = tio_tdi_status(pdev, tsm, snp_dev, &ts, false);
	if (ret) {
		pci_err(pdev, "Error confirming RUN state = %d", ret);
		return ret;
	}
	if (ts.state != TDISP_STATE_RUN) {
		pci_err(pdev, "Not in RUN state, state=%d instead", ts.state);
		return -EIO;
	}

	return 0;
}

struct pci_tsm_ops sev_guest_tsm_ops = {
	.lock = sev_guest_lock,
	.unlock = sev_guest_unlock,
	.accept = sev_guest_accept,
	.status = sev_guest_status,
};

//static void tsm_remove(void *tsm_dev)
//{
//	tsm_unregister(tsm_dev);
//}

void sev_guest_tsm_set_ops(bool set, struct snp_guest_dev *snp_dev)
{
#if defined(CONFIG_PCI_TSM) || defined(CONFIG_PCI_TSM_MODULE)
	if (set) {
		struct tsm_dev *tsmdev;

		tsmdev = tsm_register(snp_dev->dev, &sev_guest_tsm_ops);
		if (IS_ERR(tsmdev))
			return;

//		int ret;
//		ret = devm_add_action_or_reset(snp_dev->dev, tsm_remove, tsmdev);
//		if (ret) {
//			tsm_unregister(tsmdev);
//			return;
//		}

		snp_dev->tsmdev = tsmdev;
		return;
	}

	if (snp_dev->tsmdev) {
		tsm_unregister(snp_dev->tsmdev);
		snp_dev->tsmdev = NULL;
	}
#endif
}
