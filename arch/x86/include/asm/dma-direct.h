/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ASM_X86_DMA_DIRECT_H
#define ASM_X86_DMA_DIRECT_H 1

static inline dma_addr_t __phys_to_dma(struct device *dev, phys_addr_t paddr)
{
	if (dev->dma_range_map)
		return translate_phys_to_dma(dev, paddr);
	return paddr;
}

static inline dma_addr_t phys_to_dma(struct device *dev, phys_addr_t paddr)
{
	/*
	 * TDISP devices only work in CoCoVMs and rely on IOMMU to
	 * decide on the memory encryption.
	 * Stop leaking the SME mask in DMA handles and return
	 * the real address.
	 */
	if (device_cc_accepted(dev))
		return dma_addr_unencrypted(__phys_to_dma(dev, paddr));

	return dma_addr_encrypted(__phys_to_dma(dev, paddr));
}

static inline phys_addr_t dma_to_phys(struct device *dev, dma_addr_t daddr)
{
	return daddr;
}

static inline dma_addr_t phys_to_dma_unencrypted(struct device *dev,
						 phys_addr_t paddr)
{
	return dma_addr_unencrypted(__phys_to_dma(dev, paddr));
}

#define phys_to_dma_unencrypted phys_to_dma_unencrypted

#endif /* ASM_X86_DMA_DIRECT_H */
