// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/pci.h>
#include <linux/psp-sev.h>
#include <linux/tsm.h>
#include <linux/pci-tsm.h>
#include <crypto/gcm.h>
#include <uapi/linux/sev-guest.h>

#include <asm/svm.h>
#include <asm/sev.h>
#include <asm/sev-internal.h>

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
	u64 tdi_id; /* Runtime FW generated TDI id */
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
	req.input.param = *param;

	ret = snp_send_guest_request(mdesc, &req);

	memcpy(resp_buf, req.resp_buf, resp_sz);

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
				  struct tsm_blob **report, u64 *fw_err)
{
#define TIO_DATA_PAGES	(SZ_32K >> PAGE_SHIFT)
	u64 npages = TIO_DATA_PAGES, param = 0;
	struct tio_blob_table_entry *pt;
	int rc;

	pt = alloc_shared_pages(TIO_DATA_PAGES << PAGE_SHIFT);
	if (!pt)
		return -ENOMEM;

	if (state)
		param |= SVM_VMGEXIT_SEV_TIO_GUEST_REQUEST_PARAM_STATE;
	if (report)
		param |= SVM_VMGEXIT_SEV_TIO_GUEST_REQUEST_PARAM_REPORT;

	rc = handle_tio_guest_request(snp_dev, type, req_buf, req_sz, resp_buf, resp_sz,
				      pt, &npages, &bdfn, &param, fw_err);
	if (npages > TIO_DATA_PAGES) {
		free_shared_pages(pt, TIO_DATA_PAGES << PAGE_SHIFT);
		pt = alloc_shared_pages(npages << PAGE_SHIFT);
		if (!pt)
			return -ENOMEM;

		rc = handle_tio_guest_request(snp_dev, type, req_buf, req_sz, resp_buf, resp_sz,
					      pt, &npages, &bdfn, &param, fw_err);
	}
	if (rc)
		return rc;

	if (report) {
		tsm_blob_free(*report);
		*report = NULL;
	}

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

		if (guid_equal(&pt[i].guid, &TIO_GUID_REPORT) && report)
			*report = b;
	}
	free_shared_pages(pt, npages);

	if (state)
		*state = param;

	return 0;
}

struct tio_msg_tdi_info_req {
	u16 guest_device_id;
	u8 reserved[14];
} __packed;

enum {
	TIO_MSG_TDI_INFO_RSP_STATUS_BOUND = 0,
	TIO_MSG_TDI_INFO_RSP_STATUS_INVALID = 1,
	TIO_MSG_TDI_INFO_RSP_STATUS_UNBOUND = 2,
};

struct tio_msg_tdi_info_rsp {
	u16 guest_device_id;
	u16 status; /* TIO_MSG_TDI_INFO_RSP_STATUS_xxx */
	u8 reserved1[12];

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

/* Passing pci_tsm explicitly as it may not be set in pci_dev just yet */
static int tio_tdi_status(struct pci_dev *pdev, struct snp_guest_dev *snp_dev,
			  struct tsm_tdi_status *ts, struct tsm_blob **report)
{
	enum tsm_tdisp_state state = TDISP_STATE_CONFIG_UNLOCKED;
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_tdi_info_rsp) + mdesc->ctx->authsize;
	struct tio_msg_tdi_info_rsp *rsp __free(kfree_sensitive) = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_tdi_info_req req = {
		.guest_device_id = pci_dev_id(pdev),
	};
	u64 fw_err = 0;
	int rc;

	pci_notice(pdev, "TDI info");
	if (!rsp)
		return -ENOMEM;

	rc = guest_request_tio_data(snp_dev, TIO_MSG_TDI_INFO_REQ, &req,
				    sizeof(req), rsp, resp_len,
				    req.guest_device_id, &state,
				    report, &fw_err);
	if (rc)
		return rc;

	ts->no_fw_update = rsp->no_fw_update;
	ts->cache_line_size = rsp->cache_line_size == 0 ? 64 : 128;
	ts->lock_msix = rsp->lock_msix;
	ts->bind_p2p = rsp->bind_p2p;
	ts->all_request_redirect = rsp->all_request_redirect;
	memcpy(ts->interface_report_digest, rsp->interface_report_digest,
	       sizeof(ts->interface_report_digest));
	ts->intf_report_counter = rsp->tdi_report_count;

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
	u16 guest_device_id;
	u16 reserved1;
	u8 reserved2[12];
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

struct tio_msg_mmio_validate_rsp {
	u16 guest_interface_id;
	u16 status; /* MMIO_VALIDATE_xxx */
	u8 reserved1[12];
	u64 subrange_base;
	u32 subrange_page_count;
	u32 range_offset;

	u16 changed:1; /* Validated bit has changed due to this operation */
	u16 reserved2:15;

	u16 range_id;
	u8 reserved3[12];
} __packed;

static int mmio_validate_range(struct snp_guest_dev *snp_dev, struct pci_dev *pdev,
			       unsigned int range_id,
			       resource_size_t start, resource_size_t size,
			       bool invalidate, u64 *fw_err, u16 *status)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_mmio_validate_rsp) + mdesc->ctx->authsize;
	struct tio_msg_mmio_validate_rsp *rsp __free(kfree_sensitive) = kzalloc(resp_len, GFP_KERNEL);
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
		return rc;

	*status = rsp->status;

	return 0;
}

static bool get_range(struct pci_dev *pdev, struct tsm_blob *report, unsigned int index,
		      unsigned int *range_id, resource_size_t *start, resource_size_t *size)
{
	struct tdi_report_mmio_range mr = TDI_REPORT_MR(report, index);
	unsigned int rangeid = FIELD_GET(TSM_TDI_REPORT_MMIO_RANGE_ID, mr.range_attributes);
	struct resource *r = pci_resource_n(pdev, rangeid);
	u64 first, offset;
	unsigned int i;

	if (FIELD_GET(TSM_TDI_REPORT_MMIO_IS_NON_TEE, mr.range_attributes)) {
		pci_info(pdev, "Skipping non-TEE range [%d] #%d %d pages, %llx..%llx\n",
			 index, rangeid, mr.num, r->start, r->end);
		return false;
	}

	/* Currently not supported */
	if (FIELD_GET(TSM_TDI_REPORT_MMIO_MSIX_TABLE, mr.range_attributes) ||
	    FIELD_GET(TSM_TDI_REPORT_MMIO_PBA, mr.range_attributes)) {
		pci_info(pdev, "Skipping MSIX (%ld/%ld) range [%d] #%d %d pages, %llx..%llx\n",
			 FIELD_GET(TSM_TDI_REPORT_MMIO_MSIX_TABLE, mr.range_attributes),
			 FIELD_GET(TSM_TDI_REPORT_MMIO_PBA, mr.range_attributes),
			 index, rangeid, mr.num, r->start, r->end);
		return false;
	}

	/*
	 * First the first subregion of BAR, i.e. with the smallest .first_page.
	 * This assumes that the same MMIO_REPORTING_OFFSET is applied to all regions.
	 * */
	for (i = 0, first = mr.first_page; i < TDI_REPORT_MR_NUM(report); ++i) {
		struct tdi_report_mmio_range mrtmp = TDI_REPORT_MR(report, i);

		if (rangeid != FIELD_GET(TSM_TDI_REPORT_MMIO_RANGE_ID, mrtmp.range_attributes))
			continue;

		first = min(mrtmp.first_page, first);
	}

	offset = mr.first_page - first;
	if (((offset + mr.num) << PAGE_SHIFT) > (r->end - r->start + 1)) {
		pci_warn(pdev, "Skipping broken range [%d] BAR%d off=%llx %d pages, %llx..%llx %llx %llx\n",
			 index, rangeid, offset, mr.num, r->start, r->end, mr.first_page, first);
		return false;
	}

	*range_id = rangeid;
	*start = r->start + offset;
	*size = mr.num << PAGE_SHIFT;

	return true;
}

static int tio_tdi_mmio_validate(struct pci_dev *pdev, struct snp_guest_dev *snp_dev)
{
	struct pci_tsm *tsm = pdev->tsm;
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
		unsigned int range_id;
		resource_size_t start = 0, size = 0, end;

		if (!get_range(pdev, tsm->report, i, &range_id, &start, &size))
			continue;

		end = start + size - 1;
		mmio_status = 0;
		rc = mmio_validate_range(snp_dev, pdev, range_id, start, size,
					 false, &fw_err,
					 &mmio_status);
		if (rc || fw_err != SEV_RET_SUCCESS || mmio_status != MMIO_VALIDATE_SUCCESS) {
			pci_err(pdev, "MMIO #%d %llx..%llx validation failed 0x%llx %d\n",
				range_id, start, end, fw_err, mmio_status);
			continue;
		}

		mmio->res[mmio->nr] = DEFINE_RES_NAMED_DESC(start, size, "PCI MMIO Encrypted",
				pci_resource_flags(pdev, range_id), IORES_DESC_ENCRYPTED);
		++mmio->nr;

		pci_notice(pdev, "MMIO #%d %llx..%llx validated\n",range_id, start, end);
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
	u16 mmio_status;
	u64 fw_err = 0;
	int i = 0, rc = 0;
	struct pci_tsm_devsec *devsec_tsm = to_pci_tsm_devsec(tsm);
	struct pci_tsm_mmio *mmio = devsec_tsm->mmio;

	if (!mmio)
		return;

	pci_notice(pdev, "MMIO invalidate");

	for (i = 0; i < TDI_REPORT_MR_NUM(tsm->report); ++i) {
		unsigned int range_id;
		resource_size_t start = 0, size = 0, end;

		if (!get_range(pdev, tsm->report, i, &range_id, &start, &size))
			continue;

		end = start + size - 1;
		mmio_status = 0;
		rc = mmio_validate_range(snp_dev, pdev, range_id,
					 start, size, true, &fw_err,
					 &mmio_status);
		if (rc || fw_err != SEV_RET_SUCCESS || mmio_status != MMIO_VALIDATE_SUCCESS) {
			pci_err(pdev, "MMIO #%d %llx..%llx validation failed 0x%llx %d\n",
				range_id, start, end, fw_err, mmio_status);
			continue;
		}

		pci_notice(pdev, "MMIO #%d %llx..%llx invalidated\n",  range_id, start, end);
	}

	pci_tsm_mmio_teardown(devsec_tsm->mmio);
	kfree(devsec_tsm->mmio);
	devsec_tsm->mmio = NULL;
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
	u16 guest_device_id;
	u8 reserved[14];
	struct sdte sdte;
} __packed;

struct tio_msg_sdte_write_rsp {
	u16 guest_device_id;
	u16 status; /* SDTE_WRITE_xxx */
	u8 reserved[12];
} __packed;

static int tio_tdi_sdte_write(struct pci_dev *pdev, struct snp_guest_dev *snp_dev, bool invalidate)
{
	struct snp_msg_desc *mdesc = snp_dev->msg_desc;
	size_t resp_len = sizeof(struct tio_msg_sdte_write_rsp) + mdesc->ctx->authsize;
	struct tio_msg_sdte_write_rsp *rsp __free(kfree_sensitive) = kzalloc(resp_len, GFP_KERNEL);
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
		return rc;
	}

	return 0;
}

static struct pci_tsm *sev_guest_lock(struct tsm_dev *tsmdev, struct pci_dev *pdev)
{
	struct tio_guest_tdi *gtdi __free(kfree) = kzalloc(sizeof(*gtdi), GFP_KERNEL);
	struct tsm_blob *report = NULL;
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

	pci_dbg(pdev, "TSM enabled\n");

	gtdi->snp_dev = tsm_dev_to_snp_dev(tsmdev);

	rc = sev_tio_op(pci_dev_id(pdev), SVM_VMGEXIT_SEV_TIO_OP_BIND, &fw_err, &tdi_id);
	if (rc) {
		pci_err(pdev, "TDI bind CONFIG_LOCKED failed rc=%d fw=0x%llx\n",
			rc, fw_err);
		return ERR_PTR(rc);
	}
	pci_dbg(pdev, "New TDI ID=%llx\n", tdi_id);

	rc = tio_tdi_status(pdev, gtdi->snp_dev, &ts, &report);
	if (rc)
		return ERR_PTR(rc);
	if (!report)
		return ERR_PTR(-ENODEV);

	gtdi->tdi_id = tdi_id;
	gtdi->ds.base_tsm.report = report;

	return &no_free_ptr(gtdi)->ds.base_tsm;
}

static void sev_guest_unlock(struct pci_tsm *tsm)
{
	struct pci_dev *pdev = tsm->pdev;
	struct tio_guest_tdi *gtdi = pdev_to_tdi(pdev);
	struct snp_guest_dev *snp_dev = gtdi->snp_dev;
	u64 fw_err = 0;
	int rc;

	/* Quiesce DMA */
	sev_tio_op(pci_dev_id(pdev), SVM_VMGEXIT_SEV_TIO_OP_STOP, &fw_err, NULL);

	/* Disable encrypted DMA but the HV is unable to restart it as MMIO is still blocked for HV */
	rc = tio_tdi_sdte_write(pdev, snp_dev, true);
	if (rc || fw_err)
		pr_err("SDTE_WRITE did not go through, ret=%d fw=0x%llx\n", rc, fw_err);

	tio_tdi_mmio_invalidate(pdev, snp_dev);

	sev_tio_op(pci_dev_id(pdev), SVM_VMGEXIT_SEV_TIO_OP_UNBIND, &fw_err, NULL);

	tsm->pdev->tsm = NULL;
	kvfree(tsm);
}

static int sev_guest_accept(struct pci_dev *pdev)
{
	struct tio_guest_tdi *gtdi = pdev_to_tdi(pdev);
	struct snp_guest_dev *snp_dev = gtdi->snp_dev;
	struct pci_tsm *tsm = pdev->tsm;
	u64 fw_err = 0;
	int ret;

	if (!tsm->report) {
		pci_warn_once(pdev, "Cannot accept without the report");
		return -ENODEV;
	}

	ret = sev_tio_op(pci_dev_id(pdev), SVM_VMGEXIT_SEV_TIO_OP_RUN, &fw_err, NULL);
	if (ret)
		return ret;

	ret = tio_tdi_sdte_write(pdev, snp_dev, false);
	if (ret)
		return ret;

	ret = tio_tdi_mmio_validate(pdev, snp_dev);

	return ret;
}

struct pci_tsm_ops sev_guest_tsm_ops = {
	.lock = sev_guest_lock,
	.unlock = sev_guest_unlock,
	.accept = sev_guest_accept,
};

void sev_guest_tsm_set_ops(bool set, struct snp_guest_dev *snp_dev)
{
	if (set) {
		struct tsm_dev *tsmdev;

		tsmdev = tsm_register(snp_dev->dev, &sev_guest_tsm_ops);
		if (IS_ERR(tsmdev))
			return;

		snp_dev->tsmdev = tsmdev;
		return;
	}

	if (snp_dev->tsmdev) {
		tsm_unregister(snp_dev->tsmdev);
		snp_dev->tsmdev = NULL;
	}
}
