// SPDX-License-Identifier: GPL-2.0
/*
 * Integrity & Data Encryption (IDE)
 *	PCIe r6.0, sec 6.33 DOE
 *
 */

#define dev_fmt(fmt) "IDE: " fmt

#include <linux/pci.h>
#include <linux/pci-ide.h>
#include <linux/bitfield.h>
#include <linux/module.h>

#define DRIVER_VERSION	"0.1"
#define DRIVER_AUTHOR	"aik@amd.com"
#define DRIVER_DESC	"Integrity and Data Encryption driver"

/* Returns an offset of the specific IDE stream block */
static u16 sel_off(struct pci_dev *pdev, unsigned sel_index)
{
	u16 offset = pci_find_next_ext_capability(pdev, 0, PCI_EXT_CAP_ID_IDE);
	unsigned linknum = 0, selnum = 0, i;
	u16 seloff;
	u32 cap = 0;

	if (!offset)
		return 0;

	pci_read_config_dword(pdev, offset + PCI_IDE_CAP, &cap);
	if (cap & PCI_IDE_CAP_SELECTIVE_IDE_SUPP)
		selnum = PCI_IDE_CAP_SELECTIVE_STREAMS_NUM(cap) + 1;

	if (!selnum || sel_index >= selnum)
		return 0;

	if (cap & PCI_IDE_CAP_LINK_IDE_SUPP)
		linknum = PCI_IDE_CAP_LINK_TC_NUM(cap) + 1;

	seloff = offset + PCI_IDE_LINK_STREAM + linknum * 2 * 4;
	for (i = 0; i < sel_index; ++i) {
		u32 selcap = 0;
		pci_read_config_dword(pdev, seloff, &selcap);

		/* Selective Cap+Ctrl+Sta + Addr#*8 */
		seloff += 3 * 4 + PCI_IDE_SEL_CAP_BLOCKS_NUM(selcap) * 2 * 4;
	}

	return seloff;
}

static u16 sel_off_addr_block(struct pci_dev *pdev, u16 offset, unsigned blocknum)
{
	u32 selcap = 0;
	unsigned blocks;

	pci_read_config_dword(pdev, offset, &selcap);

	blocks = PCI_IDE_SEL_CAP_BLOCKS_NUM(selcap);
	if (!blocks)
		return 0;

	return offset + 3 * 4 + // Skip Cap, Ctl, Sta
		2 * 4 + // RID Association Register 1 and 2
		blocknum * 3 * 4; // Each block is Address Association Register 1, 2, 3
}

static int set_sel(struct pci_dev *pdev, unsigned sel_index, u32 value)
{
	u16 offset = sel_off(pdev, sel_index);
	u32 status = 0;

	if (!offset)
		return -EINVAL;

	pci_read_config_dword(pdev, offset + 8, &status);
	if (status & PCI_IDE_SEL_STS_RECVD_INTEGRITY_CHECK) {
		pci_warn(pdev, "[%x] Clearing \"Received integrity check\"\n", offset + 4);
		pci_write_config_dword(pdev, offset + 8,
				       status & ~PCI_IDE_SEL_STS_RECVD_INTEGRITY_CHECK);
	}

	/* Selective IDE Stream Control Register */
	pci_write_config_dword(pdev, offset + 4, value);
	pci_info(pdev, "[%x] Writing %x to sel#%d:Ctl\n", offset + 4, value, sel_index);
	return 0;
}

int pci_ide_set_sel(struct pci_dev *pdev, unsigned sel_index, unsigned streamid,
		    bool enable, bool def, bool tee_limited, bool ide_cfg)
{
	return set_sel(pdev, sel_index,
		       FIELD_PREP(PCI_IDE_LINK_CTL_ID_MASK, streamid) |
		       (def ? PCI_IDE_SEL_CTL_DEFAULT : 0) |
		       (enable ? PCI_IDE_SEL_CTL_EN : 0) |
		       (tee_limited ? PCI_IDE_SEL_CTL_TEE_LIMITED : 0) |
		       (ide_cfg ? PCI_IDE_SEL_CTL_CFG_EN : 0)
		      );
}
EXPORT_SYMBOL_GPL(pci_ide_set_sel);

int pci_ide_set_sel_rid_assoc(struct pci_dev *pdev, unsigned sel_index,
			      bool valid, u8 seg_base, u16 rid_base, u16 rid_limit)
{
	u16 offset = sel_off(pdev, sel_index);
	u32 rid1 = PCI_IDE_SEL_RID_1(rid_limit);
	u32 rid2 = PCI_IDE_SEL_RID_2(valid, rid_base, seg_base);
	u32 ctl = 0;

	if (!offset)
		return -EINVAL;

	pci_read_config_dword(pdev, offset + 4, &ctl);
	if (ctl & PCI_IDE_SEL_CTL_EN)
		pci_warn(pdev, "Setting RID when En=off triggers Integrity Check Fail Message");

	/* IDE RID Association Register 1 */
	pci_write_config_dword(pdev, offset + 0xC, rid1);
	pci_info(pdev, "[%x] Writing %x to sel#%d:RID1\n", offset + 0xC, rid1, sel_index);
	/* IDE RID Association Register 2 */
	pci_write_config_dword(pdev, offset + 0x10, rid2);
	pci_info(pdev, "[%x] Writing %x to sel#%d:RID2\n", offset + 0x10, rid2, sel_index);
	return 0;
}
EXPORT_SYMBOL_GPL(pci_ide_set_sel_rid_assoc);

int pci_ide_set_sel_addr_assoc(struct pci_dev *pdev, unsigned sel_index, unsigned blocknum,
			       bool valid, u64 base, u64 limit)
{
	u16 offset = sel_off(pdev, sel_index), offset_ab;
	u32 a1 = PCI_IDE_SEL_ADDR_1(1, base, limit);
	u32 a2 = PCI_IDE_SEL_ADDR_2(limit);
	u32 a3 = PCI_IDE_SEL_ADDR_3(base);

	if (!offset)
		return -EINVAL;

	offset_ab = sel_off_addr_block(pdev, offset, blocknum);
	if (!offset_ab || offset_ab <= offset)
		return -EINVAL;

	/* IDE Address Association Register 1 */
	pci_write_config_dword(pdev, offset_ab, a1);
	pci_info(pdev, "[%x] Writing %x to sel#%d:%d:A1\n", offset_ab, a1, sel_index, blocknum);
	/* IDE Address Association Register 2 */
	pci_write_config_dword(pdev, offset_ab + 4, a2);
	pci_info(pdev, "[%x] Writing %x to sel#%d:%d:A2\n", offset_ab + 4, a2, sel_index, blocknum);
	/* IDE Address Association Register 1 */
	pci_write_config_dword(pdev, offset_ab + 8, a3);
	pci_info(pdev, "[%x] Writing %x to sel#%d:%d:A3\n", offset_ab + 8, a3, sel_index, blocknum);
	return 0;
}
EXPORT_SYMBOL_GPL(pci_ide_set_sel_addr_assoc);

int pci_ide_get_sel_sta(struct pci_dev *pdev, unsigned sel_index, u32 *status)
{
	u16 offset = sel_off(pdev, sel_index);
	u32 s = 0;
	int ret;

	if (!offset)
		return -EINVAL;


	ret = pci_read_config_dword(pdev, offset + 8, &s);
	if (ret)
		return ret;

	*status = s;
	pci_info(pdev, "[%x] Status %x of sel#%d:Sta\n", offset + 8, *status, sel_index);
	return 0;
}
EXPORT_SYMBOL_GPL(pci_ide_get_sel_sta);

static int __init ide_init(void)
{
	int ret = 0;

	pr_info(DRIVER_DESC " version: " DRIVER_VERSION "\n");
	return ret;
}

static void __exit ide_cleanup(void)
{
}

module_init(ide_init);
module_exit(ide_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
