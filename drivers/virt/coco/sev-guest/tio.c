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

struct tio_guest_tdi {
	struct pci_tsm_devsec ds;
	struct snp_guest_dev *snp_dev;
	u64 tdi_id; /* Runtime FW generated TDI id */
};

static int handle_tio_guest_request(struct snp_guest_dev *snp_dev, u8 type,
				    void *req_buf, size_t req_sz, void *resp_buf, u32 resp_sz,
				    u64 *bdfn, u64 *param, u64 *fw_err)
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
				      &bdfn, &flags, &fw_err);
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

static struct pci_tsm *sev_guest_lock(struct tsm_dev *tsmdev, struct pci_dev *pdev)
{
	struct tio_guest_tdi *gtdi __free(kfree) = kzalloc(sizeof(*gtdi), GFP_KERNEL);
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

	struct device_evidence *evidence = device_evidence_create(0, HASH_ALGO_SHA384);
	if (!evidence)
		return ERR_PTR(-ENOMEM);
	gtdi->ds.base_tsm.evidence = evidence;

	gtdi->tdi_id = tdi_id;

	return &no_free_ptr(gtdi)->ds.base_tsm;
}

static void sev_guest_unlock(struct pci_tsm *tsm)
{
	struct pci_dev *pdev = tsm->pdev;
	u64 fw_err = 0;

	sev_tio_op(ghcb_tio_sbdfn(pdev), SVM_VMGEXIT_SEV_TIO_OP_UNBIND, &fw_err, NULL);

	/* Quiesce DMA */
	sev_tio_op(ghcb_tio_sbdfn(pdev), SVM_VMGEXIT_SEV_TIO_OP_STOP, &fw_err, NULL);

	tsm->pdev->tsm = NULL;
	kvfree(tsm);
}

static int sev_guest_accept(struct pci_dev *pdev)
{
	struct pci_tsm *tsm = pdev->tsm;
	u64 fw_err = 0;

	if (!tsm->evidence->obj[DEVICE_EVIDENCE_TYPE_REPORT].data) {
		pci_warn_once(pdev, "Cannot accept without the report");
		return -ENODEV;
	}

	return sev_tio_op(ghcb_tio_sbdfn(pdev), SVM_VMGEXIT_SEV_TIO_OP_RUN, &fw_err, NULL);
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
