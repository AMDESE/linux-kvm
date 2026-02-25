/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ASM_X86_DMA_DIRECT_H
#define ASM_X86_DMA_DIRECT_H 1

static inline dma_addr_t __phys_to_dma(struct device *dev, phys_addr_t paddr)
{
	if (dev->dma_range_map)
		return translate_phys_to_dma(dev, paddr);
	return paddr;
}

static inline dma_addr_t phys_to_dma(struct device *dev, phys_addr_t paddr, unsigned long attrs)
{
	if (device_cc_accepted(dev)) {
		if (attrs && DMA_ATTR_CC_DECRYPTED)
			return __phys_to_dma(dev, paddr) + dev->archdata.cc_shared_dma_offset;
		// FIXME: archdata.cc_private_dma_offset?
		return __phys_to_dma(dev, paddr);
	}

	return dma_addr_encrypted(__phys_to_dma(dev, paddr));
}

static inline phys_addr_t dma_to_phys(struct device *dev, dma_addr_t daddr)
{
	if (device_cc_accepted(dev) && daddr >= dev->archdata.cc_shared_dma_offset)
		return daddr - dev->archdata.cc_shared_dma_offset;
	return dma_addr_canonical(daddr);
}

static inline dma_addr_t phys_to_dma_unencrypted(struct device *dev,
						 phys_addr_t paddr)
{
	if (device_cc_accepted(dev))
		return __phys_to_dma(dev, paddr) + dev->archdata.cc_shared_dma_offset;
	return dma_addr_canonical(__phys_to_dma(dev, paddr));
}

#define phys_to_dma_unencrypted phys_to_dma_unencrypted

#endif /* ASM_X86_DMA_DIRECT_H */
