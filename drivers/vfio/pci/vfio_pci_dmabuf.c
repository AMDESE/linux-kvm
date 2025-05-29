// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES.
 */
#include <linux/dma-buf.h>
#include <linux/pci-p2pdma.h>
#include <linux/dma-resv.h>

#include "vfio_pci_priv.h"

MODULE_IMPORT_NS("DMA_BUF");

struct vfio_pci_dma_buf {
	struct vfio_dma_buf_data export_data;

	struct dma_buf *dmabuf;
	struct vfio_pci_core_device *vdev;
	struct list_head dmabufs_elm;
	unsigned int nr_ranges;
	struct vfio_region_dma_range *dma_ranges;
	unsigned int orig_nents;
	bool revoked;
};

static int vfio_pci_dma_buf_attach(struct dma_buf *dmabuf,
				   struct dma_buf_attachment *attachment)
{
	struct vfio_pci_dma_buf *priv = dmabuf->priv;
	int rc;

	rc = pci_p2pdma_distance_many(priv->vdev->pdev, &attachment->dev, 1,
				      true);
	if (rc < 0)
		attachment->peer2peer = false;
	return 0;
}

static void vfio_pci_dma_buf_unpin(struct dma_buf_attachment *attachment)
{
}

static int vfio_pci_dma_buf_pin(struct dma_buf_attachment *attachment)
{
	/*
	 * Uses the dynamic interface but must always allow for
	 * dma_buf_move_notify() to do revoke
	 */
	return -EINVAL;
}

static int populate_sgt(struct dma_buf_attachment *attachment,
			enum dma_data_direction dir,
			struct sg_table *sgt, size_t sgl_size)
{
	struct vfio_pci_dma_buf *priv = attachment->dmabuf->priv;
	struct vfio_region_dma_range *dma_ranges = priv->dma_ranges;
	size_t offset, chunk_size;
	struct scatterlist *sgl;
	dma_addr_t dma_addr;
	phys_addr_t phys;
	int i, j, ret;

	for_each_sgtable_sg(sgt, sgl, j)
		sgl->length = 0;

	sgl = sgt->sgl;
	for (i = 0; i < priv->nr_ranges; i++) {
		phys = pci_resource_start(priv->vdev->pdev,
					  dma_ranges[i].region_index);
		phys += dma_ranges[i].offset;

		/*
		 * Break the BAR's physical range up into max sized SGL's
		 * according to the device's requirement.
		 */
		for (offset = 0; offset != dma_ranges[i].length;) {
			chunk_size = min(dma_ranges[i].length - offset,
					 sgl_size);

			/*
			 * Since the memory being mapped is a device memory
			 * it could never be in CPU caches.
			 */
			dma_addr = dma_map_resource(attachment->dev,
						    phys + offset,
						    chunk_size, dir,
						    DMA_ATTR_SKIP_CPU_SYNC);
			ret = dma_mapping_error(attachment->dev, dma_addr);
			if (ret)
				goto err;

			sg_set_page(sgl, NULL, chunk_size, 0);
			sg_dma_address(sgl) = dma_addr;
			sg_dma_len(sgl) = chunk_size;
			sgl = sg_next(sgl);
			offset += chunk_size;
		}
	}

	return 0;
err:
	for_each_sgtable_sg(sgt, sgl, j) {
		if (!sg_dma_len(sgl))
			continue;

		dma_unmap_resource(attachment->dev, sg_dma_address(sgl),
				   sg_dma_len(sgl),
				   dir, DMA_ATTR_SKIP_CPU_SYNC);
	}

	return ret;
}

static struct sg_table *
vfio_pci_dma_buf_map(struct dma_buf_attachment *attachment,
		     enum dma_data_direction dir)
{
	size_t sgl_size = dma_get_max_seg_size(attachment->dev);
	struct vfio_pci_dma_buf *priv = attachment->dmabuf->priv;
	struct sg_table *sgt;
	unsigned int nents;
	int ret;

	dma_resv_assert_held(priv->dmabuf->resv);

	if (!attachment->peer2peer)
		return ERR_PTR(-EPERM);

	if (priv->revoked)
		return ERR_PTR(-ENODEV);

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	nents = DIV_ROUND_UP(priv->dmabuf->size, sgl_size);
	ret = sg_alloc_table(sgt, nents, GFP_KERNEL);
	if (ret)
		goto err_kfree_sgt;

	ret = populate_sgt(attachment, dir, sgt, sgl_size);
	if (ret)
		goto err_free_sgt;

	/*
	 * Because we are not going to include a CPU list we want to have some
	 * chance that other users will detect this by setting the orig_nents to
	 * 0 and using only nents (length of DMA list) when going over the sgl
	 */
	priv->orig_nents = sgt->orig_nents;
	sgt->orig_nents = 0;
	return sgt;

err_free_sgt:
	sg_free_table(sgt);
err_kfree_sgt:
	kfree(sgt);
	return ERR_PTR(ret);
}

static void vfio_pci_dma_buf_unmap(struct dma_buf_attachment *attachment,
				   struct sg_table *sgt,
				   enum dma_data_direction dir)
{
	struct vfio_pci_dma_buf *priv = attachment->dmabuf->priv;
	struct scatterlist *sgl;
	int i;

	for_each_sgtable_dma_sg(sgt, sgl, i)
		dma_unmap_resource(attachment->dev,
				   sg_dma_address(sgl),
				   sg_dma_len(sgl),
				   dir, DMA_ATTR_SKIP_CPU_SYNC);

	sgt->orig_nents = priv->orig_nents;
	sg_free_table(sgt);
	kfree(sgt);
}

static int vfio_pci_dma_buf_get_pfn(struct dma_buf_attachment *attachment,
				    pgoff_t pgoff, u64 *pfn, int *max_order)
{
	struct vfio_pci_dma_buf *priv = attachment->dmabuf->priv;
	struct vfio_region_dma_range *dma_ranges = priv->dma_ranges;
	u64 offset = pgoff << PAGE_SHIFT;
	int i;

	dma_resv_assert_held(priv->dmabuf->resv);

	if (priv->revoked)
		return -ENODEV;

	if (offset >= priv->dmabuf->size)
		return -EINVAL;

	for (i = 0; i < priv->nr_ranges; i++) {
		if (offset < dma_ranges[i].length)
			break;

		offset -= dma_ranges[i].length;
	}

	*pfn = PHYS_PFN(pci_resource_start(priv->vdev->pdev, dma_ranges[i].region_index) +
			dma_ranges[i].offset + offset);

	/* TODO: large page mapping is yet to be supported */
	if (max_order)
		*max_order = 0;

	return 0;
}

static void vfio_pci_dma_buf_release(struct dma_buf *dmabuf)
{
	struct vfio_pci_dma_buf *priv = dmabuf->priv;

	/*
	 * Either this or vfio_pci_dma_buf_cleanup() will remove from the list.
	 * The refcount prevents both.
	 */
	if (priv->vdev) {
		down_write(&priv->vdev->memory_lock);
		list_del_init(&priv->dmabufs_elm);
		up_write(&priv->vdev->memory_lock);
		vfio_device_put_registration(&priv->vdev->vdev);
	}
	kfree(priv);
}

static const struct dma_buf_ops vfio_pci_dmabuf_ops = {
	.attach = vfio_pci_dma_buf_attach,
	.map_dma_buf = vfio_pci_dma_buf_map,
	.pin = vfio_pci_dma_buf_pin,
	.unpin = vfio_pci_dma_buf_unpin,
	.release = vfio_pci_dma_buf_release,
	.unmap_dma_buf = vfio_pci_dma_buf_unmap,
	.get_pfn = vfio_pci_dma_buf_get_pfn,
};

static int check_dma_ranges(struct vfio_pci_dma_buf *priv,
			    uint64_t *dmabuf_size)
{
	struct vfio_region_dma_range *dma_ranges = priv->dma_ranges;
	struct pci_dev *pdev = priv->vdev->pdev;
	resource_size_t bar_size;
	int i;

	for (i = 0; i < priv->nr_ranges; i++) {
		/*
		 * For PCI the region_index is the BAR number like
		 * everything else.
		 */
		if (dma_ranges[i].region_index >= VFIO_PCI_ROM_REGION_INDEX)
			return -EINVAL;

		if (!PAGE_ALIGNED(dma_ranges[i].offset) ||
		    !PAGE_ALIGNED(dma_ranges[i].length))
			return -EINVAL;

		bar_size = pci_resource_len(pdev, dma_ranges[i].region_index);
		if (dma_ranges[i].offset > bar_size ||
		    dma_ranges[i].offset + dma_ranges[i].length > bar_size)
			return -EINVAL;

		*dmabuf_size += dma_ranges[i].length;
	}

	return 0;
}

int vfio_pci_core_feature_dma_buf(struct vfio_pci_core_device *vdev, u32 flags,
				  struct vfio_device_feature_dma_buf __user *arg,
				  size_t argsz)
{
	struct vfio_device_feature_dma_buf get_dma_buf;
	struct vfio_region_dma_range *dma_ranges;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct vfio_pci_dma_buf *priv;
	uint64_t dmabuf_size = 0;
	int ret;

	ret = vfio_check_feature(flags, argsz, VFIO_DEVICE_FEATURE_GET,
				 sizeof(get_dma_buf));
	if (ret != 1)
		return ret;

	if (copy_from_user(&get_dma_buf, arg, sizeof(get_dma_buf)))
		return -EFAULT;

	dma_ranges = memdup_array_user(&arg->dma_ranges,
				      get_dma_buf.nr_ranges,
				      sizeof(*dma_ranges));
	if (IS_ERR(dma_ranges))
		return PTR_ERR(dma_ranges);

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		kfree(dma_ranges);
		return -ENOMEM;
	}

	priv->vdev = vdev;
	priv->nr_ranges = get_dma_buf.nr_ranges;
	priv->dma_ranges = dma_ranges;

	priv->export_data.kvm = vdev->vdev.kvm;

	ret = check_dma_ranges(priv, &dmabuf_size);
	if (ret)
		goto err_free_priv;

	if (!vfio_device_try_get_registration(&vdev->vdev)) {
		ret = -ENODEV;
		goto err_free_priv;
	}

	exp_info.ops = &vfio_pci_dmabuf_ops;
	exp_info.size = dmabuf_size;
	exp_info.flags = get_dma_buf.open_flags;
	exp_info.priv = priv;

	priv->dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(priv->dmabuf)) {
		ret = PTR_ERR(priv->dmabuf);
		goto err_dev_put;
	}

	/* dma_buf_put() now frees priv */
	INIT_LIST_HEAD(&priv->dmabufs_elm);
	down_write(&vdev->memory_lock);
	dma_resv_lock(priv->dmabuf->resv, NULL);
	priv->revoked = !__vfio_pci_memory_enabled(vdev);
	list_add_tail(&priv->dmabufs_elm, &vdev->dmabufs);
	dma_resv_unlock(priv->dmabuf->resv);
	up_write(&vdev->memory_lock);

	/*
	 * dma_buf_fd() consumes the reference, when the file closes the dmabuf
	 * will be released.
	 */
	ret = dma_buf_fd(priv->dmabuf, get_dma_buf.open_flags);
	pci_err(vdev->pdev, "___K___ %s %u: %d ranges, region#%d, fd=%d\n", __func__, __LINE__,
		get_dma_buf.nr_ranges,
		get_dma_buf.nr_ranges >= 1 ? dma_ranges[0].region_index:-1, ret);
	return ret;

err_dev_put:
	vfio_device_put_registration(&vdev->vdev);
err_free_priv:
	kfree(dma_ranges);
	kfree(priv);
	return ret;
}

void vfio_pci_dma_buf_move(struct vfio_pci_core_device *vdev, bool revoked)
{
	struct vfio_pci_dma_buf *priv;
	struct vfio_pci_dma_buf *tmp;

	lockdep_assert_held_write(&vdev->memory_lock);

	list_for_each_entry_safe(priv, tmp, &vdev->dmabufs, dmabufs_elm) {
		/*
		 * Returns true if a reference was successfully obtained.
		 * The caller must interlock with the dmabuf's release
		 * function in some way, such as RCU, to ensure that this
		 * is not called on freed memory.
		 */
		if (!get_file_rcu(&priv->dmabuf->file))
			continue;

		if (priv->revoked != revoked) {
			dma_resv_lock(priv->dmabuf->resv, NULL);
			priv->revoked = revoked;
			dma_buf_move_notify(priv->dmabuf);
			dma_resv_unlock(priv->dmabuf->resv);
		}
		dma_buf_put(priv->dmabuf);
	}
}

void vfio_pci_dma_buf_cleanup(struct vfio_pci_core_device *vdev)
{
	struct vfio_pci_dma_buf *priv;
	struct vfio_pci_dma_buf *tmp;

	down_write(&vdev->memory_lock);
	list_for_each_entry_safe(priv, tmp, &vdev->dmabufs, dmabufs_elm) {
		if (!get_file_rcu(&priv->dmabuf->file))
			continue;

		dma_resv_lock(priv->dmabuf->resv, NULL);
		list_del_init(&priv->dmabufs_elm);
		priv->vdev = NULL;
		priv->revoked = true;
		dma_buf_move_notify(priv->dmabuf);
		dma_resv_unlock(priv->dmabuf->resv);
		vfio_device_put_registration(&vdev->vdev);
		dma_buf_put(priv->dmabuf);
	}
	up_write(&vdev->memory_lock);
}

/*
 * Only vfio/pci implements this, so put the helper here for now.
 */
struct vfio_dma_buf_data *vfio_dma_buf_get_data(struct dma_buf *dmabuf)
{
	struct vfio_pci_dma_buf *priv = dmabuf->priv;

	if (dmabuf->ops != &vfio_pci_dmabuf_ops)
		return ERR_PTR(-EINVAL);

	return &priv->export_data;
}
EXPORT_SYMBOL_GPL(vfio_dma_buf_get_data);
