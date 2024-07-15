// SPDX-License-Identifier: GPL-2.0-only

#include <linux/pci.h>
#include <linux/psp-sev.h>
#include <linux/tsm.h>

#include <asm/svm.h>
#include <asm/sev.h>

#include "sev-guest.h"

#define TIO_MESSAGE_VERSION	1

ulong tsm_vtom = 0x7fffffff;
module_param(tsm_vtom, ulong, 0644);
MODULE_PARM_DESC(tsm_vtom, "SEV TIO vTOM value");

static void tio_guest_blob_free(struct tsm_blob *b)
{
	/* Repeating tio_blob_release() */
	memset(b->data, 0, b->len);
}

static int handle_tio_guest_request(struct snp_guest_dev *snp_dev, u8 type,
				   void *req_buf, size_t req_sz, void *resp_buf, u32 resp_sz,
				   u64 *pt_pa, u64 *npages, u64 *bdfn, u64 *param, u64 *fw_err)
{
	/* TODO: only these 2 fields actually matter so pass just these */
	struct snp_guest_request_ioctl rio = {
		.msg_version = TIO_MESSAGE_VERSION,
		.exitinfo2 = 0,
	};
	int ret;

	snp_dev->input.data_gpa = 0;
	snp_dev->input.data_npages = 0;
	snp_dev->input.guest_rid = 0;
	snp_dev->input.param = 0;

	if (pt_pa && npages) {
		snp_dev->input.data_gpa = *pt_pa;
		snp_dev->input.data_npages = *npages;
	}
	if (bdfn)
		snp_dev->input.guest_rid = *bdfn;
	if (param)
		snp_dev->input.param = *param;

	mutex_lock(&snp_cmd_mutex);
	ret = handle_guest_request(snp_dev, SVM_VMGEXIT_SEV_TIO_GUEST_REQUEST,
				   &rio, type, req_buf, req_sz, resp_buf, resp_sz);
	mutex_unlock(&snp_cmd_mutex);

	if (param)
		*param = snp_dev->input.param;

	*fw_err = rio.exitinfo2;

	return ret;
}

static int guest_request_tio_certs(struct snp_guest_dev *snp_dev, u8 type,
				   void *req_buf, size_t req_sz, void *resp_buf, u32 resp_sz,
				   u64 bdfn, enum tsm_tdisp_state *state,
				   struct tsm_blob **certs, struct tsm_blob **meas,
				   struct tsm_blob **report, u64 *fw_err)
{
	u64 certs_size = SZ_32K, c1 = 0, pt_pa, param = 0;
	struct tio_blob_table_entry *pt;
	int rc;

	pt = alloc_shared_pages(snp_dev->dev, certs_size);
	if (!pt)
		return -ENOMEM;

	pt_pa = __pa(pt);
	c1 = certs_size;
	rc = handle_tio_guest_request(snp_dev, type, req_buf, req_sz, resp_buf, resp_sz,
				     &pt_pa, &c1, &bdfn, state ? &param : NULL, fw_err);

	if (c1 > SZ_32K) {
		free_shared_pages(pt, certs_size);
		certs_size = c1;
		pt = alloc_shared_pages(snp_dev->dev, certs_size);
		if (!pt)
			return -ENOMEM;

		pt_pa = __pa(pt);
		rc = handle_tio_guest_request(snp_dev, type, req_buf, req_sz, resp_buf, resp_sz,
					     &pt_pa, &c1, &bdfn, state ? &param : NULL, fw_err);
	}

	if (rc)
		return rc;

	tsm_blob_put(*meas);
	tsm_blob_put(*certs);
	tsm_blob_put(*report);
	*meas = NULL;
	*certs = NULL;
	*report = NULL;

	for (unsigned i = 0; i < 3; ++i) {
		u8 *ptr = ((u8 *) pt) + pt[i].offset;
		size_t len = pt[i].length;
		struct tsm_blob *b;

		if (guid_is_null(&pt[i].guid))
			break;

		if (!len)
			continue;

		b = tsm_blob_new(ptr, len, tio_guest_blob_free);
		if (!b)
			break;

		if (guid_equal(&pt[i].guid, &TIO_GUID_MEASUREMENTS))
			*meas = b;
		else if (guid_equal(&pt[i].guid, &TIO_GUID_CERTIFICATES))
			*certs = b;
		else if (guid_equal(&pt[i].guid, &TIO_GUID_REPORT))
			*report = b;
	}
	free_shared_pages(pt, certs_size);

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
		// These are TDISP's LOCK_INTERFACE_REQUEST flags
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

static int tio_tdi_status(struct tsm_tdi *tdi, struct snp_guest_dev *snp_dev,
			  struct tsm_tdi_status *ts)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	size_t resp_len = sizeof(struct tio_msg_tdi_info_rsp) + crypto->a_len;
	struct tio_msg_tdi_info_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_tdi_info_req req = {
		.guest_device_id = pci_dev_id(tdi->pdev),
	};
	u64 fw_err = 0;
	int rc;
	enum tsm_tdisp_state state = 0;

	pci_notice(tdi->pdev, "TDI info");
	if (!rsp)
		return -ENOMEM;

	rc = guest_request_tio_certs(snp_dev, TIO_MSG_TDI_INFO_REQ, &req,
				     sizeof(req), rsp, resp_len,
				     pci_dev_id(tdi->pdev), &state,
				     &tdi->tdev->certs, &tdi->tdev->meas,
				     &tdi->report, &fw_err);

	ts->meas_digest_valid = rsp->meas_digest_valid;
	ts->meas_digest_fresh = rsp->meas_digest_fresh;
	ts->no_fw_update = rsp->no_fw_update;
	ts->cache_line_size = rsp->cache_line_size == 0 ? 64 : 128;
	ts->lock_msix = rsp->lock_msix;
	ts->bind_p2p = rsp->bind_p2p;
	ts->all_request_redirect = rsp->all_request_redirect;
#define __ALGO(x, n, y) \
	((((x) & (0xFFUL << (n))) == TIO_SPDM_ALGOS_##y) ? \
	 (1ULL << TSM_TDI_SPDM_ALGOS_##y) : 0)
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

	ts->valid = true;
	ts->state = state;
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

struct tio_msg_mmio_validate_req {
	__u16 guest_device_id; // Hypervisor provided identifier used by the guest to identify
			// the TDI in guest messages.
	__u16 reserved1;
	__u8 reserved2[12];
	__u64 subrange_base; // Guest physical address of the subrange.
	__u32 subrange_page_count;
	__u32 range_offset; // Offset of the subrange within the MMIO range.
	union {
		__u16 flags;
		struct {
			__u16 validated:1; // Desired value to set RMP.Validated for the range.
			// Force validated:
			// 0: If subrange does not have RMP.Validated set uniformly, fail.
			// 1: If subrange does not have RMP.Validated set uniformly, force
			// 	to requested value.
			__u16 force_validated:1;
		};
	};
	__u16 range_id; // RangeID of MMIO range.
	__u8 reserved3[12];
} __packed;

struct tio_msg_mmio_validate_rsp {
	__u16 guest_interface_id;
	__u16 status; // MMIO_VALIDATE_xxx
	__u8 reserved1[12];
	__u64 subrange_base; // Guest physical address of the subrange.
	__u32 subrange_page_count; // Length of the subrange in bytes.
	__u32 range_offset; // Offset of the subrange within the MMIO range.
	union {
		__u16 flags;
		struct {
			__u16 changed:1; // Indicates that the Validated bit has changed
					// due to this operation.
		};
	};
	__u16 range_id; // RangeID of MMIO range.
	__u8 reserved2[12];
} __packed;

static int mmio_validate_range(struct snp_guest_dev *snp_dev, struct pci_dev *pdev,
			       unsigned int range_id, resource_size_t start, resource_size_t size,
			       bool invalidate, u64 *fw_err)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	size_t resp_len = sizeof(struct tio_msg_mmio_validate_rsp) + crypto->a_len;
	struct tio_msg_mmio_validate_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_mmio_validate_req req = {
		.guest_device_id = pci_dev_id(pdev),
		.subrange_base = start, // Guest physical address of the subrange.
		.subrange_page_count = size >> PAGE_SHIFT,
		.range_offset = 0, // Offset of the subrange within the MMIO range.
		.validated = 1, // Desired value to set RMP.Validated for the range.
		.force_validated = 0,
		.range_id = range_id, // RangeID of MMIO range.
	};
	u64 bdfn = pci_dev_id(pdev);
	u64 mmio_val = MMIO_MK_VALIDATE(start, size, range_id);
	int rc;

	if (!rsp)
		return -ENOMEM;

	if (invalidate)
		memset(&req, 0, sizeof(req));

	rc = handle_tio_guest_request(snp_dev, TIO_MSG_MMIO_VALIDATE_REQ,
			       &req, sizeof(req), rsp, resp_len,
			       NULL, NULL, &bdfn, &mmio_val, fw_err);
	if (rc)
		goto free_exit;

	if (rsp->status)
		rc = -EBADR;

free_exit:
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

static int tio_tdi_mmio_validate(struct tsm_tdi *tdi, struct snp_guest_dev *snp_dev, bool invalidate)
{
	struct pci_dev *pdev = tdi->pdev;
	struct tdi_report_mmio_range mr;
	struct resource *r;
	u64 fw_err = 0;
	int i = 0, rc;

	pci_notice(tdi->pdev, "MMIO validate");

	if (WARN_ON_ONCE(!tdi->report || !tdi->report->data))
		return -EFAULT;

	for (i = 0; i < TDI_REPORT_MR_NUM(tdi->report); ++i) {
		mr = TDI_REPORT_MR(tdi->report, i);
		r = pci_resource_n(tdi->pdev, mr.range_id);

		if (r->end == r->start || ((r->end - r->start + 1) & ~PAGE_MASK) || !mr.num) {
			pci_warn(tdi->pdev, "Skipping broken range [%d] #%d %d pages, %llx..%llx\n",
				i, mr.range_id, mr.num, r->start, r->end);
			continue;
		}

		if (mr.is_non_tee_mem) {
			pci_info(tdi->pdev, "Skipping non-TEE range [%d] #%d %d pages, %llx..%llx\n",
				 i, mr.range_id, mr.num, r->start, r->end);
			continue;
		}

		rc = mmio_validate_range(snp_dev, pdev, mr.range_id,
					 r->start, r->end - r->start + 1, invalidate, &fw_err);
		if (rc) {
			pci_err(pdev, "MMIO #%d %llx..%llx validation failed 0x%llx\n",
				mr.range_id, r->start, r->end, fw_err);
			continue;
		}

		pci_notice(pdev, "MMIO #%d %llx..%llx validated\n",  mr.range_id, r->start, r->end);
	}

	return rc;
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

#define SDTE_WRITE_SUCCESS 0
#define SDTE_WRITE_INVALID_TDI 1
#define SDTE_WRITE_TDI_NOT_BOUND 2
#define SDTE_WRITE_RESERVED 3 // Reserved fields were not 0

struct tio_msg_sdte_write_rsp {
	__u16 guest_device_id;
	__u16 status; // SDTE_WRITE_xxx
	__u8 reserved[12];
} __packed;

extern ulong tsm_vtom; // 0x7fffffff by default

static int tio_tdi_sdte_write(struct tsm_tdi *tdi, struct snp_guest_dev *snp_dev, bool invalidate)
{
	struct snp_guest_crypto *crypto = snp_dev->crypto;
	size_t resp_len = sizeof(struct tio_msg_sdte_write_rsp) + crypto->a_len;
	struct tio_msg_sdte_write_rsp *rsp = kzalloc(resp_len, GFP_KERNEL);
	struct tio_msg_sdte_write_req req = {
		.guest_device_id = pci_dev_id(tdi->pdev),
		.sdte.vmpl = 0, // VMPL other than 0 require SVSM call but apitest uses "2"
		.sdte.vtom = tsm_vtom,
		.sdte.vtom_en = 1, // no vIOMMU support yet
		.sdte.iw = 1,
		.sdte.ir = 1,
		.sdte.v = 1, // valid
	};
	u64 fw_err = 0;
	u64 bdfn = pci_dev_id(tdi->pdev);
	int rc;

	BUILD_BUG_ON(sizeof(struct sdte) * 8 != 512);

	if (invalidate)
		memset(&req, 0, sizeof(req));

	pci_notice(tdi->pdev, "SDTE write vTOM=%lx", (unsigned long) req.sdte.vtom << 21);

	if (!rsp)
		return -ENOMEM;

	rc = handle_tio_guest_request(snp_dev, TIO_MSG_SDTE_WRITE_REQ,
			       &req, sizeof(req), rsp, resp_len,
			       NULL, NULL, &bdfn, NULL, &fw_err);
	if (rc) {
		pci_err(tdi->pdev, "SDTE write failed with 0x%llx\n", fw_err);
		goto free_exit;
	}

free_exit:
	/* The response buffer contains the sensitive data, explicitly clear it. */
	memzero_explicit(&rsp, sizeof(resp_len));
	kfree(rsp);
	return rc;
}

static int sev_guest_tdi_status(struct tsm_tdi *tdi, void *private_data, struct tsm_tdi_status *ts)
{
	struct snp_guest_dev *snp_dev = private_data;

	return tio_tdi_status(tdi, snp_dev, ts);
}

static int sev_guest_tdi_validate(struct tsm_tdi *tdi, bool invalidate, void *private_data)
{
	struct snp_guest_dev *snp_dev = private_data;
	struct tsm_tdi_status ts = { 0 };
	int ret;

	if (!tdi->report) {
		ret = tio_tdi_status(tdi, snp_dev, &ts);

		if (ret || !tdi->report) {
			pci_err(tdi->pdev, "No report available, ret=%d", ret);
			if (!ret && tdi->report)
				ret = -EIO;
			return ret;
		}

		if (ts.state != TDISP_STATE_RUN) {
			pci_err(tdi->pdev, "Not in RUN state, state=%d instead", ts.state);
			return -EIO;
		}
	}

	ret = tio_tdi_sdte_write(tdi, snp_dev, invalidate);
	if (ret)
		return ret;

	ret = tio_tdi_mmio_validate(tdi, snp_dev, invalidate);
	if (ret)
		return ret;

	return 0;
}

struct tsm_ops sev_guest_tsm_ops = {
	.tdi_validate = sev_guest_tdi_validate,
	.tdi_status = sev_guest_tdi_status,
};

void sev_guest_tsm_set_ops(bool set, struct snp_guest_dev *snp_dev)
{
	if (set)
		tsm_set_ops(&sev_guest_tsm_ops, snp_dev);
	else
		tsm_set_ops(NULL, NULL);
}
