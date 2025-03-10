// SPDX-License-Identifier: GPL-2.0
/*
 * TDX host user interface driver
 *
 * Copyright (C) 2025 Intel Corporation
 */

#include <linux/bitfield.h>
#include <linux/dmar.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/pci-tsm.h>
#include <linux/tsm.h>
#include <linux/device/faux.h>
#include <asm/cpu_device_id.h>
#include <asm/tdx.h>
#include <asm/tdx_global_metadata.h>

static const struct x86_cpu_id tdx_host_ids[] = {
	X86_MATCH_FEATURE(X86_FEATURE_TDX_HOST_PLATFORM, NULL),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, tdx_host_ids);

/*
 * The scope of this pointer is for TDX Connect.
 * Every feature should evaluate how to get tdx_sysinfo. TDX Connect expects no
 * tdx_sysinfo change after TDX Module update so could cache it. TDX version
 * sysfs expects change so should call tdx_get_sysinfo() every time.
 *
 * Maybe move TDX Connect to a separate file makes thing clearer.
 */
static const struct tdx_sys_info *tdx_sysinfo;

struct tdx_link {
	struct pci_tsm_pf0 pci;
};

static struct tdx_link *to_tdx_link(struct pci_tsm *tsm)
{
	return container_of(tsm, struct tdx_link, pci.base_tsm);
}

#define PCI_DOE_DATA_OBJECT_HEADER_1_OFFSET	0
#define PCI_DOE_DATA_OBJECT_HEADER_2_OFFSET	4
#define PCI_DOE_DATA_OBJECT_HEADER_SIZE		8
#define PCI_DOE_DATA_OBJECT_PAYLOAD_OFFSET	PCI_DOE_DATA_OBJECT_HEADER_SIZE

#define PCI_DOE_PROTOCOL_SECURE_SPDM		2

static int __maybe_unused tdx_spdm_msg_exchange(struct tdx_link *tlink,
						void *request, size_t request_sz,
						void *response, size_t response_sz)
{
	struct pci_dev *pdev = tlink->pci.base_tsm.pdev;
	void *req_pl_addr, *resp_pl_addr;
	size_t req_pl_sz, resp_pl_sz;
	u32 data, len;
	u16 vendor;
	u8 type;
	int ret;

	/*
	 * pci_doe() accept DOE PAYLOAD only but request carries DOE HEADER so
	 * shift the buffers, skip DOE HEADER in request buffer, and fill DOE
	 * HEADER in response buffer manually.
	 */

	data = le32_to_cpu(*(__le32 *)(request + PCI_DOE_DATA_OBJECT_HEADER_1_OFFSET));
	vendor = FIELD_GET(PCI_DOE_DATA_OBJECT_HEADER_1_VID, data);
	type = FIELD_GET(PCI_DOE_DATA_OBJECT_HEADER_1_TYPE, data);

	data = le32_to_cpu(*(__le32 *)(request + PCI_DOE_DATA_OBJECT_HEADER_2_OFFSET));
	len = FIELD_GET(PCI_DOE_DATA_OBJECT_HEADER_2_LENGTH, data);

	req_pl_sz = len * sizeof(__le32) - PCI_DOE_DATA_OBJECT_HEADER_SIZE;
	resp_pl_sz = response_sz - PCI_DOE_DATA_OBJECT_HEADER_SIZE;
	req_pl_addr = request + PCI_DOE_DATA_OBJECT_HEADER_SIZE;
	resp_pl_addr = response + PCI_DOE_DATA_OBJECT_HEADER_SIZE;

	ret = pci_tsm_doe_transfer(pdev, type, req_pl_addr, req_pl_sz,
				   resp_pl_addr, resp_pl_sz);
	if (ret < 0) {
		pci_err(pdev, "spdm msg exchange fail %d\n", ret);
		return ret;
	}

	data = FIELD_PREP(PCI_DOE_DATA_OBJECT_HEADER_1_VID, vendor) |
	       FIELD_PREP(PCI_DOE_DATA_OBJECT_HEADER_1_TYPE, type);
	*(__le32 *)(response + PCI_DOE_DATA_OBJECT_HEADER_1_OFFSET) = cpu_to_le32(data);

	len = (ret + PCI_DOE_DATA_OBJECT_HEADER_SIZE) / sizeof(__le32);
	data = FIELD_PREP(PCI_DOE_DATA_OBJECT_HEADER_2_LENGTH, len);
	*(__le32 *)(response + PCI_DOE_DATA_OBJECT_HEADER_2_OFFSET) = cpu_to_le32(data);

	ret += PCI_DOE_DATA_OBJECT_HEADER_SIZE;

	pci_dbg(pdev, "%s complete: vendor 0x%x type 0x%x rsp_sz %d\n",
		__func__, vendor, type, ret);
	return ret;
}

static int tdx_link_connect(struct pci_dev *pdev)
{
	return -ENXIO;
}

static void tdx_link_disconnect(struct pci_dev *pdev)
{
}

static struct pci_tsm *tdx_link_pf0_probe(struct tsm_dev *tsm_dev,
					  struct pci_dev *pdev)
{
	int rc;

	struct tdx_link *tlink __free(kfree) =
		kzalloc(sizeof(*tlink), GFP_KERNEL);
	if (!tlink)
		return NULL;

	rc = pci_tsm_pf0_constructor(pdev, &tlink->pci, tsm_dev);
	if (rc)
		return NULL;

	return &no_free_ptr(tlink)->pci.base_tsm;
}

static void tdx_link_pf0_remove(struct pci_tsm *tsm)
{
	struct tdx_link *tlink = to_tdx_link(tsm);

	pci_tsm_pf0_destructor(&tlink->pci);
	kfree(tlink);
}

static struct pci_tsm *tdx_link_fn_probe(struct tsm_dev *tsm_dev,
					 struct pci_dev *pdev)
{
	int rc;

	struct pci_tsm *pci_tsm __free(kfree) =
		kzalloc(sizeof(*pci_tsm), GFP_KERNEL);
	if (!pci_tsm)
		return NULL;

	rc = pci_tsm_link_constructor(pdev, pci_tsm, tsm_dev);
	if (rc)
		return NULL;

	return no_free_ptr(pci_tsm);
}

static struct pci_tsm *tdx_link_probe(struct tsm_dev *tsm_dev, struct pci_dev *pdev)
{
	if (is_pci_tsm_pf0(pdev))
		return tdx_link_pf0_probe(tsm_dev, pdev);

	return tdx_link_fn_probe(tsm_dev, pdev);
}

static void tdx_link_remove(struct pci_tsm *tsm)
{
	if (is_pci_tsm_pf0(tsm->pdev)) {
		tdx_link_pf0_remove(tsm);
		return;
	}

	/* for sub-functions */
	kfree(tsm);
}

static struct pci_tsm_ops tdx_link_ops = {
	.probe = tdx_link_probe,
	.remove = tdx_link_remove,
	.connect = tdx_link_connect,
	.disconnect = tdx_link_disconnect,
};

static void unregister_link_tsm(void *link)
{
	tsm_unregister(link);
}

static DEFINE_XARRAY(tlink_iommu_xa);

static void tdx_iommu_clear(u64 iommu_id, struct tdx_page_array *iommu_mt)
{
	u64 r;

	r = tdh_iommu_clear(iommu_id, iommu_mt);
	if (r) {
		pr_err("%s fail to clear tdx iommu\n", __func__);
		goto leak;
	}

	if (tdx_page_array_ctrl_release(iommu_mt, iommu_mt->nr_pages,
					page_to_phys(iommu_mt->root))) {
		pr_err("%s fail to release metadata pages\n", __func__);
		goto leak;
	}

	return;

leak:
	tdx_page_array_ctrl_leak(iommu_mt);
}

static int tdx_iommu_enable_one(struct dmar_drhd_unit *drhd)
{
	unsigned int nr_pages = tdx_sysinfo->connect.iommu_mt_page_count;
	u64 r, iommu_id;
	int ret;

	struct tdx_page_array *iommu_mt __free(tdx_page_array_free) =
		tdx_page_array_create_iommu_mt(1, nr_pages);
	if (!iommu_mt)
		return -ENOMEM;

	r = tdh_iommu_setup(drhd->reg_base_addr, iommu_mt, &iommu_id);
	/* This drhd doesn't support tdx mode, skip. */
	if ((r & TDX_SEAMCALL_STATUS_MASK)  == TDX_OPERAND_INVALID)
		return 0;

	if (r) {
		pr_err("fail to enable tdx mode for DRHD[0x%llx]\n",
		       drhd->reg_base_addr);
		return -EFAULT;
	}

	ret = xa_insert(&tlink_iommu_xa, (unsigned long)iommu_id,
			no_free_ptr(iommu_mt), GFP_KERNEL);
	if (ret) {
		tdx_iommu_clear(iommu_id, iommu_mt);
		return ret;
	}

	return 0;
}

static void tdx_iommu_disable_all(void *data)
{
	struct tdx_page_array *iommu_mt;
	unsigned long iommu_id;

	xa_for_each(&tlink_iommu_xa, iommu_id, iommu_mt)
		tdx_iommu_clear(iommu_id, iommu_mt);
}

static int tdx_iommu_enable_all(void)
{
	int ret;

	ret = do_for_each_drhd_unit(tdx_iommu_enable_one);
	if (ret)
		tdx_iommu_disable_all(NULL);

	return ret;
}

static int __maybe_unused tdx_connect_init(struct device *dev)
{
	struct tsm_dev *link;
	int ret;

	if (!IS_ENABLED(CONFIG_TDX_CONNECT))
		return 0;

	/*
	 * With this errata, TDX should use movdir64b to clear private pages
	 * when reclaiming them. See tdx_clear_page().
	 *
	 * Don't expect this errata on any TDX Connect supported platform. TDX
	 * Connect will never call tdx_clear_page().
	 */
	if (boot_cpu_has_bug(X86_BUG_TDX_PW_MCE))
		return -ENXIO;

	tdx_sysinfo = tdx_get_sysinfo();
	if (!tdx_sysinfo)
		return -ENXIO;

	if (!(tdx_sysinfo->features.tdx_features0 & TDX_FEATURES0_TDXCONNECT))
		return 0;

	ret = tdx_enable_ext();
	if (ret)
		return dev_err_probe(dev, ret, "Enable extension failed\n");

	ret = tdx_iommu_enable_all();
	if (ret)
		return dev_err_probe(dev, ret, "Enable tdx iommu failed\n");

	ret = devm_add_action_or_reset(dev, tdx_iommu_disable_all, NULL);
	if (ret)
		return ret;

	link = tsm_register(dev, &tdx_link_ops);
	if (IS_ERR(link))
		return dev_err_probe(dev, PTR_ERR(link),
				     "failed to register TSM\n");

	return devm_add_action_or_reset(dev, unregister_link_tsm, link);
}

static int tdx_host_probe(struct faux_device *fdev)
{
	/*
	 * Only support TDX Connect now. More TDX features could be added here.
	 *
	 * TODO: do tdx_connect_init() when it is fully implemented.
	 */
	return 0;
}

static struct faux_device_ops tdx_host_ops = {
	.probe = tdx_host_probe,
};

static struct faux_device *fdev;

static int __init tdx_host_init(void)
{
	if (!x86_match_cpu(tdx_host_ids))
		return -ENODEV;

	fdev = faux_device_create(KBUILD_MODNAME, NULL, &tdx_host_ops);
	if (!fdev)
		return -ENODEV;

	return 0;
}
module_init(tdx_host_init);

static void __exit tdx_host_exit(void)
{
	faux_device_destroy(fdev);
}
module_exit(tdx_host_exit);

MODULE_DESCRIPTION("TDX Host Services");
MODULE_LICENSE("GPL");
