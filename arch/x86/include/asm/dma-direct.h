/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ASM_X86_DMA_DIRECT_H
#define ASM_X86_DMA_DIRECT_H 1

#include <linux/pci-tsm.h>

static inline dma_addr_t __phys_to_dma(struct device *dev, phys_addr_t paddr)
{
	if (dev->dma_range_map)
		return translate_phys_to_dma(dev, paddr);
	return paddr;
}


static inline bool __device_cc_accepted(struct device *dev)
{
	if (!dev || !dev_is_pci(dev) || !to_pci_dev(dev)->tsm || !device_tcb_trusted(dev))
		return false;

	return test_bit(PCI_TSM_F_ACCEPT, &to_pci_dev(dev)->tsm->flags);
}

static inline dma_addr_t phys_to_dma(struct device *dev, phys_addr_t paddr, unsigned long attrs)
{
	if (__device_cc_accepted(dev)) {
		if (attrs & DMA_ATTR_CC_SHARED)
			return __phys_to_dma(dev, paddr) + dev->archdata.cc_shared_dma_offset;
		return __phys_to_dma(dev, paddr) + dev->archdata.cc_private_dma_offset;
	}

	return dma_addr_encrypted(__phys_to_dma(dev, paddr));
}

static inline phys_addr_t dma_to_phys(struct device *dev, dma_addr_t daddr)
{
	phys_addr_t paddr;

	if (__device_cc_accepted(dev)) {
		if (dev->archdata.cc_shared_dma_offset &&
		    daddr >= dev->archdata.cc_shared_dma_offset)
			return daddr - dev->archdata.cc_shared_dma_offset;
		if (dev->archdata.cc_private_dma_offset &&
		    daddr >= dev->archdata.cc_private_dma_offset)
			return daddr - dev->archdata.cc_private_dma_offset;
	}

	daddr = dma_addr_canonical(daddr);
	if (dev->dma_range_map)
		paddr = translate_dma_to_phys(dev, daddr);
	else
		paddr = daddr;

	return paddr;
}

static inline dma_addr_t phys_to_dma_unencrypted(struct device *dev, phys_addr_t paddr)
{
	if (__device_cc_accepted(dev))
		return __phys_to_dma(dev, paddr) + dev->archdata.cc_shared_dma_offset;
	return dma_addr_unencrypted(__phys_to_dma(dev, paddr));
}

static inline dma_addr_t phys_to_dma_encrypted(struct device *dev, phys_addr_t paddr)
{
	if (__device_cc_accepted(dev))
		return __phys_to_dma(dev, paddr) + dev->archdata.cc_private_dma_offset;
	return dma_addr_encrypted(__phys_to_dma(dev, paddr));
}

#define phys_to_dma_unencrypted phys_to_dma_unencrypted
#define phys_to_dma_encrypted phys_to_dma_encrypted

#endif /* ASM_X86_DMA_DIRECT_H */
