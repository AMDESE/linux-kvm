// SPDX-License-Identifier: GPL-2.0
/*
 * Integrity & Data Encryption (IDE)
 *	PCIe r6.0, sec 6.33 DOE
 */

#ifndef LINUX_PCI_IDE_H
#define LINUX_PCI_IDE_H

int pci_ide_set_sel(struct pci_dev *pdev, unsigned sel_index, unsigned streamid,
		    bool enable, bool def, bool tee_limited, bool ide_cfg);
int pci_ide_set_sel_rid_assoc(struct pci_dev *pdev, unsigned sel_index,
			      bool valid, u8 seg_base, u16 rid_base, u16 rid_limit);
int pci_ide_set_sel_addr_assoc(struct pci_dev *pdev, unsigned sel_index, unsigned blocknum,
			       bool valid, u64 base, u64 limit);
int pci_ide_get_sel_sta(struct pci_dev *pdev, unsigned sel_index, u32 *status);

#endif
