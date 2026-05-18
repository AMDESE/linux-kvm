/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_DEVICE_H
#define _ASM_X86_DEVICE_H

struct dev_archdata {
	dma_addr_t cc_shared_dma_offset;
	dma_addr_t cc_private_dma_offset;
};

struct pdev_archdata {
};

#endif /* _ASM_X86_DEVICE_H */
