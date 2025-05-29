// SPDX-License-Identifier: GPL-2.0
#include <linux/dma-buf.h>
#include <linux/kvm_host.h>
#include <linux/vfio.h>

#include "kvm_mm.h"

MODULE_IMPORT_NS("DMA_BUF");

struct kvm_vfio_dmabuf {
	struct kvm *kvm;
	struct kvm_memory_slot *slot;
};

static void kv_dmabuf_move_notify(struct dma_buf_attachment *attach)
{
	struct kvm_vfio_dmabuf *kv_dmabuf = attach->importer_priv;
	struct kvm_memory_slot *slot = kv_dmabuf->slot;
	struct kvm *kvm = kv_dmabuf->kvm;
	bool flush = false;

	struct kvm_gfn_range gfn_range = {
		.start = slot->base_gfn,
		.end = slot->base_gfn + slot->npages,
		.slot = slot,
		.may_block = true,
		.attr_filter = KVM_FILTER_PRIVATE | KVM_FILTER_SHARED,
	};

	KVM_MMU_LOCK(kvm);
	kvm_mmu_invalidate_begin(kvm);
	flush |= kvm_mmu_unmap_gfn_range(kvm, &gfn_range);
	if (flush)
		kvm_flush_remote_tlbs(kvm);

	kvm_mmu_invalidate_end(kvm);
	KVM_MMU_UNLOCK(kvm);
}

static const struct dma_buf_attach_ops kv_dmabuf_attach_ops = {
	.allow_peer2peer = true,
	.move_notify = kv_dmabuf_move_notify,
};

int kvm_vfio_dmabuf_bind(struct kvm *kvm, struct kvm_memory_slot *slot,
			 unsigned int fd)
{
	size_t size = slot->npages << PAGE_SHIFT;
	struct dma_buf_attachment *attach;
	struct kvm_vfio_dmabuf *kv_dmabuf;
	struct dma_buf *dmabuf;
	int ret;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	if (size != dmabuf->size) {
		ret = -EINVAL;
		goto err_dmabuf;
	}

	kv_dmabuf = kzalloc(sizeof(*kv_dmabuf), GFP_KERNEL);
	if (!kv_dmabuf) {
		ret = -ENOMEM;
		goto err_dmabuf;
	}

	kv_dmabuf->kvm = kvm;
	kv_dmabuf->slot = slot;
	attach = dma_buf_dynamic_attach(dmabuf, NULL, &kv_dmabuf_attach_ops,
					kv_dmabuf);
	if (IS_ERR(attach)) {
		ret = PTR_ERR(attach);
		goto err_kv_dmabuf;
	}

	slot->dmabuf_attach = attach;

	return 0;

err_kv_dmabuf:
	kfree(kv_dmabuf);
err_dmabuf:
	dma_buf_put(dmabuf);
	return ret;
}

void kvm_vfio_dmabuf_unbind(struct kvm_memory_slot *slot)
{
	struct dma_buf_attachment *attach = slot->dmabuf_attach;
	struct kvm_vfio_dmabuf *kv_dmabuf;
	struct dma_buf *dmabuf;

	if (WARN_ON_ONCE(!attach))
		return;

	kv_dmabuf = attach->importer_priv;
	dmabuf = attach->dmabuf;
	dma_buf_detach(dmabuf, attach);
	kfree(kv_dmabuf);
	dma_buf_put(dmabuf);
}

/*
 * The return value matters. If return -EFAULT, userspace will try to do
 * page attribute (shared <-> private) conversion.
 */
int kvm_vfio_dmabuf_get_pfn(struct kvm *kvm, struct kvm_memory_slot *slot,
			    gfn_t gfn, kvm_pfn_t *pfn, int *max_order)
{
	struct dma_buf_attachment *attach = slot->dmabuf_attach;
	pgoff_t pgoff = gfn - slot->base_gfn;
	int ret;

	if (WARN_ON_ONCE(!attach))
		return -EFAULT;

	ret = dma_buf_get_pfn_unlocked(attach, pgoff, pfn, max_order);
	if (ret)
		return -EIO;

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_vfio_dmabuf_get_pfn);
