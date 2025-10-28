// SPDX-License-Identifier: GPL-2.0-only

// Interface to CCP/SEV-TIO for generic PCIe TDISP module

#include <linux/pci.h>
#include <linux/device.h>
#include <linux/tsm.h>
#include <linux/kvm_host.h>
#include <linux/iommu.h>
#include <linux/pci-doe.h>
#include <linux/bitfield.h>
#include <linux/module.h>

#include <asm/sev-common.h>
#include <asm/sev.h>
#include <asm/sev-kvm.h>

#include "psp-dev.h"
#include "sev-dev.h"
#include "sev-dev-tio.h"

MODULE_IMPORT_NS("PCI_IDE");

#define TIO_DEFAULT_NR_IDE_STREAMS	1

static uint nr_ide_streams = TIO_DEFAULT_NR_IDE_STREAMS;
module_param_named(ide_nr, nr_ide_streams, uint, 0644);
MODULE_PARM_DESC(ide_nr, "Set the maximum number of IDE streams per PHB");

static bool ide_read_only  = false;
module_param_named(ide_ro, ide_read_only, bool, 0644);
MODULE_PARM_DESC(ide_ro, "If true, skips on configuring PF#0 IDE stream, use setpci instead. Does not disable IDE teardown.");

#define dev_to_sp(dev)		((struct sp_device *)dev_get_drvdata(dev))
#define dev_to_psp(dev)		((struct psp_device *)(dev_to_sp(dev)->psp_data))
#define dev_to_sev(dev)		((struct sev_device *)(dev_to_psp(dev)->sev_data))
#define tsm_dev_to_sev(tsmdev)	dev_to_sev((tsmdev)->dev.parent)

#define pdev_to_tio_dsm(pdev)	(container_of((pdev)->tsm, struct tio_dsm, tsm.base_tsm))

static int sev_tio_spdm_cmd(struct tio_dsm *dsm, int ret)
{
	struct tsm_dsm_tio *dev_data = &dsm->data;
	struct tsm_spdm *spdm = &dev_data->spdm;

	/* Check the main command handler response before entering the loop */
	if (ret == 0 && dev_data->psp_ret != SEV_RET_SUCCESS)
		return -EINVAL;

	if (ret <= 0)
		return ret;

	/* ret > 0 means "SPDM requested" */
	while (ret == PCI_DOE_FEATURE_CMA || ret == PCI_DOE_FEATURE_SSESSION) {
		ret = pci_doe(dsm->tsm.doe_mb, PCI_VENDOR_ID_PCI_SIG, ret,
			      spdm->req, spdm->req_len, spdm->rsp, spdm->rsp_len);
		if (ret < 0)
			break;

		WARN_ON_ONCE(ret == 0); /* The response should never be empty */
		spdm->rsp_len = ret;
		ret = sev_tio_continue(dev_data);
	}

	return ret;
}

static int stream_enable(struct pci_ide *ide)
{
	struct pci_dev *rp = pcie_find_root_port(ide->pdev);
	int ret;

	if (ide_read_only) {
		pci_warn(ide->pdev, "Skipping %s for %s", __func__, pci_name(rp));
		return 0;
	}

	ret = pci_ide_stream_enable(rp, ide);
	if (ret)
		return ret;

	ret = pci_ide_stream_enable(ide->pdev, ide);
	if (ret)
		pci_ide_stream_disable(rp, ide);

	return ret;
}

static int streams_enable(struct pci_ide **ide)
{
	int ret = 0;

	for (int i = 0; i < TIO_IDE_MAX_TC; ++i) {
		if (ide[i]) {
			ret = stream_enable(ide[i]);
			if (ret)
				break;
		}
	}

	return ret;
}

static void stream_disable(struct pci_ide *ide)
{
	pci_ide_stream_disable(ide->pdev, ide);
	pci_ide_stream_disable(pcie_find_root_port(ide->pdev), ide);
}

static void streams_disable(struct pci_ide **ide)
{
	for (int i = 0; i < TIO_IDE_MAX_TC; ++i)
		if (ide[i])
			stream_disable(ide[i]);
}

static void stream_setup(struct pci_ide *ide)
{
	struct pci_dev *rp = pcie_find_root_port(ide->pdev);

	ide->partner[PCI_IDE_EP].rid_start = 0;
	ide->partner[PCI_IDE_EP].rid_end = 0xffff;
	ide->partner[PCI_IDE_RP].rid_start = 0;
	ide->partner[PCI_IDE_RP].rid_end = 0xffff;

	ide->pdev->ide_cfg = 0;
	ide->pdev->ide_tee_limit = 1;
	rp->ide_cfg = 1;
	rp->ide_tee_limit = 0;

	if (ide_read_only) {
		pci_warn(ide->pdev, "Skipping %s for %s", __func__, pci_name(rp));
		return;
	}

	pci_warn(ide->pdev, "Forcing CFG/TEE for %s", pci_name(rp));
	pci_ide_stream_setup(ide->pdev, ide);
	pci_ide_stream_setup(rp, ide);
}

static u8 streams_setup(struct pci_ide **ide, u8 *ids)
{
	bool def = false;
	u8 tc_mask = 0;
	int i;

	for (i = 0; i < TIO_IDE_MAX_TC; ++i) {
		if (!ide[i]) {
			ids[i] = 0xFF;
			continue;
		}

		tc_mask |= BIT(i);
		ids[i] = ide[i]->stream_id;

		if (!def) {
			struct pci_ide_partner *settings;

			settings = pci_ide_to_settings(ide[i]->pdev, ide[i]);
			settings->default_stream = 1;
			def = true;
		}

		stream_setup(ide[i]);
	}

	return tc_mask;
}

static int streams_register(struct pci_ide **ide)
{
	int ret = 0, i;

	for (i = 0; i < TIO_IDE_MAX_TC; ++i) {
		if (ide[i]) {
			ret = pci_ide_stream_register(ide[i]);
			if (ret)
				break;
		}
	}

	return ret;
}

static void streams_unregister(struct pci_ide **ide)
{
	for (int i = 0; i < TIO_IDE_MAX_TC; ++i)
		if (ide[i])
			pci_ide_stream_unregister(ide[i]);
}

static void stream_teardown(struct pci_ide *ide)
{
	pci_ide_stream_teardown(ide->pdev, ide);
	pci_ide_stream_teardown(pcie_find_root_port(ide->pdev), ide);
}

static void streams_teardown(struct pci_ide **ide)
{
	for (int i = 0; i < TIO_IDE_MAX_TC; ++i) {
		if (ide[i]) {
			stream_teardown(ide[i]);
			pci_ide_stream_free(ide[i]);
			ide[i] = NULL;
		}
	}
}

static int stream_alloc(struct pci_dev *pdev, struct pci_ide **ide,
			unsigned int tc)
{
	struct pci_dev *rp = pcie_find_root_port(pdev);
	struct pci_ide *ide1;

	if (ide[tc]) {
		pci_err(pdev, "Stream for class=%d already registered", tc);
		return -EBUSY;
	}

	/* FIXME: find a better way */
	if (nr_ide_streams != TIO_DEFAULT_NR_IDE_STREAMS)
		pci_notice(pdev, "Enable non-default %d streams", nr_ide_streams);
	pci_ide_set_nr_streams(to_pci_host_bridge(rp->bus->bridge), nr_ide_streams);

	ide1 = pci_ide_stream_alloc(pdev);
	if (!ide1)
		return -EFAULT;

	/* Blindly assign streamid=0 to TC=0, and so on */
	ide1->stream_id = tc;

	ide[tc] = ide1;

	return 0;
}

static struct pci_tsm *tio_pf0_probe(struct pci_dev *pdev, struct sev_device *sev)
{
	struct tio_dsm *dsm __free(kfree) = kzalloc(sizeof(*dsm), GFP_KERNEL);
	int rc;

	if (!dsm)
		return NULL;

	rc = pci_tsm_pf0_constructor(pdev, &dsm->tsm, sev->tsmdev);
	if (rc)
		return NULL;

	pci_dbg(pdev, "TSM enabled\n");
	dsm->sev = sev;
	return &no_free_ptr(dsm)->tsm.base_tsm;
}

static struct pci_tsm *tio_tdi_probe(struct pci_dev *pdev, struct sev_device *sev)
{
	struct pci_tsm *tsm __free(kfree) = kzalloc(sizeof(*tsm), GFP_KERNEL);
	int rc;

	if (!tsm)
		return NULL;

	rc = pci_tsm_link_constructor(pdev, tsm, sev->tsmdev);
	if (rc)
		return NULL;

	pci_dbg(pdev, "TSM (sub-function) enabled\n");
	return no_free_ptr(tsm);
}

static struct pci_tsm *dsm_probe(struct tsm_dev *tsmdev, struct pci_dev *pdev)
{
	struct sev_device *sev = tsm_dev_to_sev(tsmdev);

	if (is_pci_tsm_pf0(pdev))
		return tio_pf0_probe(pdev, sev);
	return tio_tdi_probe(pdev, sev);
}

static void dsm_remove(struct pci_tsm *tsm)
{
	struct pci_dev *pdev = tsm->pdev;

	pci_dbg(pdev, "TSM disabled\n");

	if (tsm->tdi)
		pci_err(pdev, "TDI not released\n");

	if (is_pci_tsm_pf0(pdev)) {
		struct tio_dsm *dsm = container_of(tsm, struct tio_dsm, tsm.base_tsm);

		pci_tsm_pf0_destructor(&dsm->tsm);
		kfree(dsm);
	}
}

static int dsm_create(struct tio_dsm *dsm)
{
	struct pci_dev *pdev = dsm->tsm.base_tsm.pdev;
	u8 segment_id = pdev->bus ? pci_domain_nr(pdev->bus) : 0;
	struct pci_dev *rootport = pcie_find_root_port(pdev);
	u16 device_id = pci_dev_id(pdev);
	struct page *req_page;
	u16 root_port_id;
	u32 lnkcap = 0;
	int ret;

	if (pci_read_config_dword(rootport, pci_pcie_cap(rootport) + PCI_EXP_LNKCAP,
				  &lnkcap))
		return -ENODEV;

	root_port_id = FIELD_GET(PCI_EXP_LNKCAP_PN, lnkcap);

	req_page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!req_page)
		return -ENOMEM;

	dsm->data.guest_req_buf = page_address(req_page);

	dsm->data.guest_resp_buf = snp_alloc_firmware_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!dsm->data.guest_resp_buf) {
		ret = -EIO;
		goto free_req_exit;
	}

	ret = sev_tio_dev_create(&dsm->data, device_id, root_port_id, segment_id);
	if (ret)
		goto free_resp_exit;

	return 0;

free_resp_exit:
	snp_free_firmware_page(dsm->data.guest_resp_buf);
free_req_exit:
	__free_page(req_page);
	return ret;
}

static int dsm_connect(struct pci_dev *pdev)
{
	struct tio_dsm *dsm = pdev_to_tio_dsm(pdev);
	struct tsm_dsm_tio *dev_data = &dsm->data;
	u8 ids[TIO_IDE_MAX_TC];
	u8 tc_mask;
	int ret;

	if (pci_find_doe_mailbox(pdev, PCI_VENDOR_ID_PCI_SIG,
				 PCI_DOE_FEATURE_SSESSION) != dsm->tsm.doe_mb) {
		pci_err(pdev, "CMA DOE MB must support SSESSION\n");
		return -EFAULT;
	}

	ret = stream_alloc(pdev, dev_data->ide, 0);
	if (ret)
		return ret;

	ret = dsm_create(dsm);
	if (ret)
		goto ide_free_exit;

	tc_mask = streams_setup(dev_data->ide, ids);

	ret = sev_tio_dev_connect(dev_data, tc_mask, ids, dev_data->cert_slot);
	ret = sev_tio_spdm_cmd(dsm, ret);
	if (ret)
		goto free_exit;

	streams_enable(dev_data->ide);

	ret = streams_register(dev_data->ide);
	if (ret)
		goto free_exit;

	return 0;

free_exit:
	sev_tio_dev_reclaim(dev_data);

	streams_disable(dev_data->ide);
ide_free_exit:

	streams_teardown(dev_data->ide);

	return ret;
}

static void dsm_disconnect(struct pci_dev *pdev)
{
	bool force = SYSTEM_HALT <= system_state && system_state <= SYSTEM_RESTART;
	struct tio_dsm *dsm = pdev_to_tio_dsm(pdev);
	struct tsm_dsm_tio *dev_data = &dsm->data;
	int ret;

	ret = sev_tio_dev_disconnect(dev_data, force);
	ret = sev_tio_spdm_cmd(dsm, ret);
	if (ret && !force) {
		ret = sev_tio_dev_disconnect(dev_data, true);
		sev_tio_spdm_cmd(dsm, ret);
	}

	sev_tio_dev_reclaim(dev_data);

	if (dev_data->guest_resp_buf)
		snp_free_firmware_page(dev_data->guest_resp_buf);

	if (dev_data->guest_req_buf)
		__free_page(virt_to_page(dev_data->guest_req_buf));

	dev_data->guest_req_buf = NULL;
	dev_data->guest_resp_buf = NULL;

	streams_disable(dev_data->ide);
	streams_unregister(dev_data->ide);
	streams_teardown(dev_data->ide);
}

static void tdi_unbind(struct pci_tdi *tdi)
{
	struct tio_tdi *ttdi = container_of(tdi, struct tio_tdi, tdi);
	struct pci_dev *pdev = tdi->pdev;
	struct tio_dsm *dsm = pdev_to_tio_dsm(pdev->tsm->dsm_dev);
	struct tsm_dsm_tio *dev_data = &dsm->data;
	struct tsm_tdi_tio *tdi_data = &ttdi->data;
	enum tsm_tdisp_state state = TDISP_STATE_CONFIG_UNLOCKED;
	int ret;

	if (tdi->kvm) {
		ret = sev_tio_tdi_unbind(dev_data, tdi_data, false);
		ret = sev_tio_spdm_cmd(dsm, ret);
		if (ret) {
			ret = sev_tio_tdi_unbind(dev_data, tdi_data, true);
			sev_tio_spdm_cmd(dsm, ret);
		}
	}

	/* The hunk to verify transitioning to CONFIG_UNLOCKED */
	ret = sev_tio_tdi_status(dev_data, tdi_data);
	ret = sev_tio_spdm_cmd(dsm, ret);

	if (ret)
		pr_err("TDI status failed to read, ret=%d\n", ret);
	else
		sev_tio_tdi_status_fin(dev_data, tdi_data, &state);

	struct pci_dev *pf0 = pdev->tsm->dsm_dev;
	struct pci_dev *rootport = pcie_find_root_port(pf0);
	u8 segment_id = pci_domain_nr(rootport->bus);
	u16 device_id = pci_dev_id(rootport);
	bool fenced = false;

	sev_tio_tdi_reclaim(dev_data, tdi_data);

	if (!sev_tio_asid_fence_status(dev_data, device_id, segment_id,
				       tdi_data->asid, &fenced)) {
		if (fenced) {
			ret = sev_tio_asid_fence_clear(dev_data->dev_ctx,
						       tdi_data->gctx_paddr,
						       &dev_data->psp_ret);
			pci_notice(rootport, "Unfenced VM=%llx ASID=%d ret=%d %d",
				   tdi_data->gctx_paddr, tdi_data->asid, ret,
				   dev_data->psp_ret);
		}
	}

	tsm_blob_free(pdev->tsm->report);
	pdev->tsm->report = NULL;

	/*
	 * This is here and not in IOMMU as soon this will require SNP page
	 * reclaim call into the PSP and it is in this module.
	 */
	struct resource *res;
	pci_dev_for_each_resource(pdev, res) {
		if (!res || (res->end - res->start == 0))
			continue;

		pci_notice(pdev, "Sharing %s %llx..%llx\n",
			   res->name ? res->name : "(null)", res->start, res->end);
		for (resource_size_t off = res->start; off < res->end; off += PAGE_SIZE)
			rmp_make_shared(off >> PAGE_SHIFT, PG_LEVEL_4K);
	}

	kfree(ttdi);
}

static struct pci_tdi *tdi_bind(struct pci_dev *pdev, struct kvm *kvm, u32 tdi_id)
{
	struct tio_tdi *ttdi = kzalloc(sizeof(*ttdi), GFP_KERNEL);
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	enum tsm_tdisp_state state = TDISP_STATE_CONFIG_UNLOCKED;
	struct tio_dsm *dsm = pdev_to_tio_dsm(pdev->tsm->dsm_dev);
	struct tsm_dsm_tio *dev_data = &dsm->data;
	struct tsm_tdi_tio *tdi_data = &ttdi->data;
	int dom = pci_domain_nr(pdev->bus);
	u64 gctx;
	u32 asid;
	int ret;

	if (!ttdi)
		return ERR_PTR(-ENOMEM);

	pci_tsm_tdi_constructor(pdev, &ttdi->tdi, kvm, tdi_id);

	if (!sev->es_active)
		return ERR_PTR(-ENOSYS);

	gctx = __psp_pa((u64) sev->snp_context);
	asid = sev->asid;

	ret = sev_tio_tdi_create(dev_data, tdi_data, pci_dev_id(pdev), dom);
	if (ret)
		return ERR_PTR(ret);

	ret = sev_tio_tdi_bind(dev_data, tdi_data, ttdi->tdi.tdi_id, gctx, asid, false);
	ret = sev_tio_spdm_cmd(dsm, ret);
	if (ret)
		goto error_exit;

	tio_save_output(&pdev->tsm->report, dev_data->output, SPDM_DOBJ_ID_REPORT, NULL);

	ret = sev_tio_tdi_status(dev_data, tdi_data);
	ret = sev_tio_spdm_cmd(dsm, ret);
	if (ret)
		goto error_exit;

	ret = sev_tio_tdi_status_fin(dev_data, tdi_data, &state);
	if (ret)
		goto error_exit;

	return &(ttdi->tdi);

error_exit:
	tdi_unbind(&ttdi->tdi);
	return ERR_PTR(ret);
}

static int tdi_run(struct tio_dsm *dsm, struct tio_tdi *ttdi)
{
	enum tsm_tdisp_state state = TDISP_STATE_CONFIG_UNLOCKED;
	struct kvm_sev_info *sev = &to_kvm_svm(ttdi->tdi.kvm)->sev_info;
	struct tsm_dsm_tio *dev_data = &dsm->data;
	struct tsm_tdi_tio *tdi_data = &ttdi->data;
	u64 gctx_paddr;
	u32 asid;
	int ret = 0;

	if (!sev->es_active)
		return -ENOSYS;

	gctx_paddr = __psp_pa((u64) sev->snp_context);
	asid = sev->asid;

	ret = sev_tio_tdi_status(dev_data, tdi_data);
	ret = sev_tio_spdm_cmd(dsm, ret);
	if (ret)
		return ret;

	ret = sev_tio_tdi_status_fin(dev_data, tdi_data, &state);
	if (ret)
		return ret;
	if (state == TDISP_STATE_RUN)
		return 0;

	if (state != TDISP_STATE_CONFIG_LOCKED)
		return -EFAULT;

	ret = sev_tio_tdi_bind(dev_data, tdi_data, ttdi->tdi.tdi_id,
			       gctx_paddr, sev->asid, true);
	ret = sev_tio_spdm_cmd(dsm, ret);
	if (ret)
		return ret;

	tio_save_output(&ttdi->tdi.pdev->tsm->report, dev_data->output,
			SPDM_DOBJ_ID_REPORT, NULL);

	return 0;
}

static ssize_t guest_request(struct pci_tdi *tdi, enum pci_tsm_req_scope scope,
			     sockptr_t req, size_t reqlen,
			     sockptr_t resp, size_t resplen,
			     u64 *fw_err)
{
	struct pci_dev *pdev = tdi->pdev;
	struct tio_tdi *ttdi = container_of(tdi, struct tio_tdi, tdi);
	struct tio_dsm *dsm = pdev_to_tio_dsm(pdev->tsm->dsm_dev);
	struct tsm_dsm_tio *dev_data = &dsm->data;
	struct tsm_tdi_tio *tdi_data = &ttdi->data;
	struct snp_guest_msg_hdr reqh;
	int ret;

	if (reqlen < sizeof(reqh) || copy_from_sockptr(&reqh, req, sizeof(reqh)))
		return -EINVAL;

	if (reqh.msg_type == TIO_MSG_MMIO_VALIDATE_REQ || reqh.msg_type == TIO_MSG_SDTE_WRITE_REQ) {
		ret = tdi_run(dsm, ttdi);
		if (ret)
			return ret;
	}

	ret = copy_from_sockptr(dev_data->guest_req_buf, req, reqlen);
	if (ret)
		return ret;

	ret = sev_tio_guest_request(dev_data, tdi_data, dev_data->guest_req_buf,
				    dev_data->guest_resp_buf);
	ret = sev_tio_spdm_cmd(dsm, ret);
	*fw_err = dev_data->psp_ret;
	if (ret)
		return ret;
	ret = copy_to_sockptr(resp, dev_data->guest_resp_buf, resplen);

	if (ret)
		return ret;

	return resplen;
}

static struct pci_tsm_ops sev_tsm_ops = {
	.probe = dsm_probe,
	.remove = dsm_remove,
	.connect = dsm_connect,
	.disconnect = dsm_disconnect,
	.bind = tdi_bind,
	.unbind = tdi_unbind,
	.guest_req = guest_request,
};

void sev_tsm_init_locked(struct sev_device *sev, void *tio_status_page)
{
	struct sev_tio_status *t = kzalloc(sizeof(*t), GFP_KERNEL);
	struct tsm_dev *tsmdev;
	int ret;

	WARN_ON(sev->tio_status);

	if (!t)
		return;

	ret = sev_tio_init_locked(tio_status_page);
	if (ret) {
		pr_warn("SEV-TIO STATUS failed with %d\n", ret);
		goto error_exit;
	}

	tsmdev = tsm_register(sev->dev, &sev_tsm_ops);
	if (IS_ERR(tsmdev))
		goto error_exit;

	memcpy(t, tio_status_page, sizeof(*t));

	pr_notice("SEV-TIO status: EN=%d INIT_DONE=%d rq=%d..%d rs=%d..%d "
		  "scr=%d..%d out=%d..%d dev=%d tdi=%d algos=%x\n",
		  t->tio_en, t->tio_init_done,
		  t->spdm_req_size_min, t->spdm_req_size_max,
		  t->spdm_rsp_size_min, t->spdm_rsp_size_max,
		  t->spdm_scratch_size_min, t->spdm_scratch_size_max,
		  t->spdm_out_size_min, t->spdm_out_size_max,
		  t->devctx_size, t->tdictx_size,
		  t->tio_crypto_alg);

	sev->tsmdev = tsmdev;
	sev->tio_status = t;

	return;

error_exit:
	kfree(t);
	pr_err("Failed to enable SEV-TIO: ret=%d en=%d initdone=%d SEV=%d\n",
	       ret, t->tio_en, t->tio_init_done, boot_cpu_has(X86_FEATURE_SEV));
}

void sev_tsm_uninit(struct sev_device *sev)
{
	if (sev->tsmdev)
		tsm_unregister(sev->tsmdev);

	sev->tsmdev = NULL;
}
