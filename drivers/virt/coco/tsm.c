// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/pci-ide.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/tsm.h>
#include <linux/kvm_host.h>

#define DRIVER_VERSION	"0.1"
#define DRIVER_AUTHOR	"aik@amd.com"
#define DRIVER_DESC	"TSM TDISP driver"

static struct {
	struct tsm_ops *ops;
	void *private_data;

	uint tc_mask;
	uint cert_slot;
	bool physfn;
} tsm;

module_param_named(tc_mask, tsm.tc_mask, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(tc_mask, "Mask of traffic classes enabled in the device");

module_param_named(cert_slot, tsm.cert_slot, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cert_slot, "Slot number of the certificate requested for constructing the SPDM session");

module_param_named(physfn, tsm.physfn, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(physfn, "Allow TDI on SR IOV of a physical function");

struct tsm_blob *tsm_blob_new(void *data, u32 len, void (*release)(struct tsm_blob *b))
{
	struct tsm_blob *b;

	if (!len || !data)
		return NULL;

	b = kzalloc(sizeof(*b) + len, GFP_KERNEL);
	if (!b)
		return NULL;

	b->data = (void *)b + sizeof(*b);
	b->len = len;
	b->release = release;
	memcpy(b->data, data, len);
	kref_init(&b->kref);

	return b;
}
EXPORT_SYMBOL_GPL(tsm_blob_new);

static void tsm_blob_release(struct kref *kref)
{
	struct tsm_blob *b = container_of(kref, struct tsm_blob, kref);

	b->release(b);
	kfree(b);
}

struct tsm_blob *tsm_blob_get(struct tsm_blob *b)
{
	if (!b)
		return NULL;

	if (!kref_get_unless_zero(&b->kref))
		return NULL;

	return b;
}
EXPORT_SYMBOL_GPL(tsm_blob_get);

void tsm_blob_put(struct tsm_blob *b)
{
	if (!b)
		return;

	kref_put(&b->kref, tsm_blob_release);
}
EXPORT_SYMBOL_GPL(tsm_blob_put);

static struct tsm_dev *tsm_dev_get(struct device *dev)
{
	struct tsm_tdi *tdi = dev->tdi;

	if (!tdi || !tdi->tdev || !kref_get_unless_zero(&tdi->tdev->kref))
		return NULL;

	return tdi->tdev;
}

static void tsm_dev_free(struct kref *kref);
static void tsm_dev_put(struct tsm_dev *tdev)
{
	kref_put(&tdev->kref, tsm_dev_free);
}

struct tsm_tdi *tsm_tdi_get(struct device *dev)
{
	struct tsm_tdi *tdi = dev->tdi;

	return tdi;
}
EXPORT_SYMBOL_GPL(tsm_tdi_get);

static int spdm_forward(struct tsm_spdm *spdm, u8 type)
{
	struct pci_doe_mb *doe_mb;
	int rc;

	if (type == PCI_DOE_PROTOCOL_SECURED_CMA_SPDM)
		doe_mb = spdm->doe_mb_secured;
	else if (type == PCI_DOE_PROTOCOL_CMA_SPDM)
		doe_mb = spdm->doe_mb;
	else
		return -EINVAL;

	if (!doe_mb)
		return -EFAULT;

	rc = pci_doe(doe_mb, PCI_VENDOR_ID_PCI_SIG, type,
		     spdm->req, spdm->req_len, spdm->rsp, spdm->rsp_len);
	if (rc >= 0)
		spdm->rsp_len = rc;

	return rc;
}

/*
 * Enables IDE between the RC and the device.
 * TEE Limited, IDE Cfg space and other bits are hardcoded
 * as this is a sketch.
 */
static int tsm_set_sel_ide(struct tsm_dev *tdev)
{
	struct pci_dev *rootport;
	int ret = 0;
	unsigned i;
	bool printed = false;

	rootport = tdev->pdev->bus->self;
	for (i = 0; i < ARRAY_SIZE(tdev->selective_ide); ++i) {
		if (!tdev->selective_ide[i].enable)
			continue;

		if (!printed) {
			pci_info(rootport, "Configuring IDE with %s\n",
				 pci_name(tdev->pdev));
			printed = true;
		}
		WARN_ON_ONCE(tdev->selective_ide[i].enabled);

		ret = pci_ide_set_sel_rid_assoc(tdev->pdev, i, true, 0, 0, 0xFFFF);
		if (ret)
			pci_warn(tdev->pdev,
				 "Failed configuring SelectiveIDE#%d rid1 with %d\n",
				 i, ret);
		ret = pci_ide_set_sel_addr_assoc(tdev->pdev, i, 0/* RID# */, true,
						 0, 0xFFFFFFFFFFF00000ULL);
		if (ret)
			pci_warn(tdev->pdev,
				 "Failed configuring SelectiveIDE#%d RID#0 with %d\n",
				 i, ret);

		ret = pci_ide_set_sel(tdev->pdev, i,
				      tdev->selective_ide[i].id,
				      tdev->selective_ide[i].enable,
				      tdev->selective_ide[i].def,
				      tdev->selective_ide[i].dev_tee_limited,
				      tdev->selective_ide[i].dev_ide_cfg);
		if (ret) {
			pci_warn(tdev->pdev,
				 "Failed configuring SelectiveIDE#%d with %d\n",
				 i, ret);
			break;
		}

		ret = pci_ide_set_sel_rid_assoc(rootport, i, true, 0, 0, 0xFFFF);
		if (ret)
			pci_warn(rootport,
				 "Failed configuring SelectiveIDE#%d rid1 with %d\n",
				 i, ret);

		ret = pci_ide_set_sel(rootport, i,
				      tdev->selective_ide[i].id,
				      tdev->selective_ide[i].enable,
				      tdev->selective_ide[i].def,
				      tdev->selective_ide[i].rootport_tee_limited,
				      tdev->selective_ide[i].rootport_ide_cfg);
		if (ret)
			pci_warn(rootport,
				 "Failed configuring SelectiveIDE#%d with %d\n",
				 i, ret);

		tdev->selective_ide[i].enabled = 1;
	}

	return ret;
}

static void tsm_unset_sel_ide(struct tsm_dev *tdev)
{
	struct pci_dev *rootport = tdev->pdev->bus->self;
	bool printed = false;

	for (unsigned i = 0; i < ARRAY_SIZE(tdev->selective_ide); ++i) {
		if (!tdev->selective_ide[i].enabled)
			continue;

		if (!printed) {
			pci_info(rootport, "Deconfiguring IDE with %s\n", pci_name(tdev->pdev));
			printed = true;
		}

		pci_ide_set_sel(rootport, i, 0, 0, 0, false, false);
		pci_ide_set_sel(tdev->pdev, i, 0, 0, 0, false, false);
		tdev->selective_ide[i].enabled = 0;
	}
}

static int tsm_dev_connect(struct tsm_dev *tdev, void *private_data, unsigned val)
{
	int ret;

	if (WARN_ON(!tsm.ops->dev_connect))
		return -EPERM;

	tdev->ide_pre = val == 2;
	if (tdev->ide_pre)
		tsm_set_sel_ide(tdev);

	mutex_lock(&tdev->spdm_mutex);
	while (1) {
		ret = tsm.ops->dev_connect(tdev, tsm.private_data);
		if (ret <= 0)
			break;

		ret = spdm_forward(&tdev->spdm, ret);
		if (ret < 0)
			break;
	}
	mutex_unlock(&tdev->spdm_mutex);

	if (!tdev->ide_pre)
		ret = tsm_set_sel_ide(tdev);

	tdev->connected = (ret == 0);

	return ret;
}

static int tsm_dev_reclaim(struct tsm_dev *tdev, void *private_data)
{
	struct pci_dev *pdev = NULL;
	int ret;

	if (WARN_ON(!tsm.ops->dev_reclaim))
		return -ENOTSUPP;

	/* Do not disconnect with active TDIs */
	for_each_pci_dev(pdev) {
		struct tsm_tdi *tdi = tsm_tdi_get(&pdev->dev);

		if (tdi && tdi->tdev == tdev && tdi->data)
			return -EBUSY;
	}

	if (!tdev->ide_pre)
		tsm_unset_sel_ide(tdev);

	mutex_lock(&tdev->spdm_mutex);
	while (1) {
		ret = tsm.ops->dev_reclaim(tdev, private_data);
		if (ret <= 0)
			break;

		ret = spdm_forward(&tdev->spdm, ret);
		if (ret < 0)
			break;
	}
	mutex_unlock(&tdev->spdm_mutex);

	if (tdev->ide_pre)
		tsm_unset_sel_ide(tdev);

	if (!ret)
		tdev->connected = false;

	return ret;
}

static int tsm_dev_status(struct tsm_dev *tdev, void *private_data, struct tsm_dev_status *s)
{
	if (WARN_ON(!tsm.ops->dev_status))
		return -EPERM;

	return tsm.ops->dev_status(tdev, private_data, s);
}

static int tsm_ide_refresh(struct tsm_dev *tdev, void *private_data)
{
	int ret;

	if (!tsm.ops->ide_refresh)
		return -EPERM;

	mutex_lock(&tdev->spdm_mutex);
	while (1) {
		ret = tsm.ops->ide_refresh(tdev, private_data);
		if (ret <= 0)
			break;

		ret = spdm_forward(&tdev->spdm, ret);
		if (ret < 0)
			break;
	}
	mutex_unlock(&tdev->spdm_mutex);

	return ret;
}

static void tsm_tdi_reclaim(struct tsm_tdi *tdi, void *private_data)
{
	int ret;

	if (WARN_ON(!tsm.ops->tdi_reclaim))
		return;

	mutex_lock(&tdi->tdev->spdm_mutex);
	while (1) {
		ret = tsm.ops->tdi_reclaim(tdi, private_data);
		if (ret <= 0)
			break;

		ret = spdm_forward(&tdi->tdev->spdm, ret);
		if (ret < 0)
			break;
	}
	mutex_unlock(&tdi->tdev->spdm_mutex);
}

static int tsm_tdi_validate(struct tsm_tdi *tdi, bool invalidate, void *private_data)
{
	int ret;

	if (!tdi || !tsm.ops->tdi_validate)
		return -EPERM;

	ret = tsm.ops->tdi_validate(tdi, invalidate, private_data);
	if (ret) {
		pci_err(tdi->pdev, "Validation failed, ret=%d", ret);
		tdi->pdev->dev.tdi_enabled = false;
	}

	return ret;
}

/* In case BUS_NOTIFY_PCI_BUS_MASTER is no good, a driver can call pci_dev_tdi_validate() */
int pci_dev_tdi_validate(struct pci_dev *pdev)
{
	struct tsm_tdi *tdi = tsm_tdi_get(&pdev->dev);

	return tsm_tdi_validate(tdi, false, tsm.private_data);
}
EXPORT_SYMBOL_GPL(pci_dev_tdi_validate);

static int tsm_tdi_status(struct tsm_tdi *tdi, void *private_data, struct tsm_tdi_status *ts)
{
	struct tsm_tdi_status tstmp = { 0 };
	int ret;

	if (WARN_ON(!tsm.ops->tdi_status))
		return -EPERM;

	mutex_lock(&tdi->tdev->spdm_mutex);
	while (1) {
		ret = tsm.ops->tdi_status(tdi, private_data, &tstmp);
		if (ret <= 0)
			break;

		ret = spdm_forward(&tdi->tdev->spdm, ret);
		if (ret < 0)
			break;
	}
	mutex_unlock(&tdi->tdev->spdm_mutex);

	*ts = tstmp;

	return ret;
}

static ssize_t tsm_cert_slot_store(struct device *dev, struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	ssize_t ret = count;
	unsigned long val;

	if (kstrtoul(buf, 0, &val) < 0)
		ret = -EINVAL;
	else
		tdev->cert_slot = val;

	tsm_dev_put(tdev);

	return ret;
}

static ssize_t tsm_cert_slot_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	ssize_t ret = sysfs_emit(buf, "%u\n", tdev->cert_slot);

	tsm_dev_put(tdev);
	return ret;
}

static DEVICE_ATTR_RW(tsm_cert_slot);

static ssize_t tsm_tc_mask_store(struct device *dev, struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	ssize_t ret = count;
	unsigned long val;

	if (kstrtoul(buf, 0, &val) < 0)
		ret = -EINVAL;
	else
		tdev->tc_mask = val;
	tsm_dev_put(tdev);

	return ret;
}

static ssize_t tsm_tc_mask_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	ssize_t ret = sysfs_emit(buf, "%#x\n", tdev->tc_mask);

	tsm_dev_put(tdev);
	return ret;
}

static DEVICE_ATTR_RW(tsm_tc_mask);

static ssize_t tsm_dev_connect_store(struct device *dev, struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	unsigned long val;
	ssize_t ret = -EIO;

	if (kstrtoul(buf, 0, &val) < 0)
		ret = -EINVAL;
	else if (val && !tdev->connected)
		ret = tsm_dev_connect(tdev, tsm.private_data, val);
	else if (!val && tdev->connected)
		ret = tsm_dev_reclaim(tdev, tsm.private_data);

	if (!ret)
		ret = count;

	tsm_dev_put(tdev);

	return ret;
}

static ssize_t tsm_dev_connect_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	ssize_t ret = sysfs_emit(buf, "%u\n", tdev->connected);

	tsm_dev_put(tdev);
	return ret;
}

static DEVICE_ATTR_RW(tsm_dev_connect);

static ssize_t tsm_sel_stream_store(struct device *dev, struct device_attribute *attr,
				    const char *buf, size_t count)
{
	unsigned ide_dev = false, tee_dev = true, ide_rp = true, tee_rp = false;
	unsigned sel_index, id, def, en;
	struct tsm_dev *tdev;

	if (sscanf(buf, "%u %u %u %u %u %u %u %u", &sel_index, &id, &def, &en,
		   &ide_dev, &tee_dev, &ide_rp, &tee_rp) != 8) {
		if (sscanf(buf, "%u %u %u %u", &sel_index, &id, &def, &en) != 4)
			return -EINVAL;
	}

	if (sel_index >= ARRAY_SIZE(tdev->selective_ide) || id > 0x100)
		return -EINVAL;

	tdev = tsm_dev_get(dev);
	if (en) {
		tdev->selective_ide[sel_index].id = id;
		tdev->selective_ide[sel_index].def = def;
		tdev->selective_ide[sel_index].enable = 1;
		tdev->selective_ide[sel_index].enabled = 0;
		tdev->selective_ide[sel_index].dev_ide_cfg = ide_dev;
		tdev->selective_ide[sel_index].dev_tee_limited = tee_dev;
		tdev->selective_ide[sel_index].rootport_ide_cfg = ide_rp;
		tdev->selective_ide[sel_index].rootport_tee_limited = tee_rp;
	} else {
		memset(&tdev->selective_ide[sel_index], 0, sizeof(tdev->selective_ide[0]));
	}

	tsm_dev_put(tdev);
	return count;
}

static ssize_t tsm_sel_stream_show(struct device *dev, struct device_attribute *attr,
				   char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	struct pci_dev *rootport = tdev->pdev->bus->self;
	char *buf1;
	ssize_t ret = 0, sz = PAGE_SIZE;
	unsigned i;


	buf1 = kmalloc(sz, GFP_KERNEL);
	if (!buf1)
		return -ENOMEM;

	buf1[0] = 0;
	for (i = 0; i < ARRAY_SIZE(tdev->selective_ide); ++i) {
		if (!tdev->selective_ide[i].enable)
			continue;

		ret += snprintf(buf1 + ret, sz - ret - 1, "%u: %d%s",
				i,
				tdev->selective_ide[i].id,
				tdev->selective_ide[i].def ? " DEF" : "");
		if (tdev->selective_ide[i].enabled) {
			u32 devst = 0, rcst = 0;

			pci_ide_get_sel_sta(tdev->pdev, i, &devst);
			pci_ide_get_sel_sta(rootport, i, &rcst);
			ret += snprintf(buf1 + ret, sz - ret - 1,
				" %x%s %s%s<-> %x%s %s%s rootport:%s",
				devst,
				PCI_IDE_SEL_STS_STATUS(devst) == 2 ? "=SECURE" : "",
				tdev->selective_ide[i].dev_ide_cfg ? "IDECfg " : "",
				tdev->selective_ide[i].dev_tee_limited ? "TeeLim " : "",
				rcst,
				PCI_IDE_SEL_STS_STATUS(rcst) == 2 ? "=SECURE" : "",
				tdev->selective_ide[i].rootport_ide_cfg ? "IDECfg " : "",
				tdev->selective_ide[i].rootport_tee_limited ? "TeeLim " : "",
				pci_name(rootport)
			       );
		}
		ret += snprintf(buf1 + ret, sz - ret - 1, "\n");
	}
	tsm_dev_put(tdev);

	ret = sysfs_emit(buf, buf1);
	kfree(buf1);

	return ret;
}

static DEVICE_ATTR_RW(tsm_sel_stream);

static ssize_t tsm_ide_refresh_store(struct device *dev, struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	int ret;

	ret = tsm_ide_refresh(tdev, tsm.private_data);
	tsm_dev_put(tdev);
	if (ret)
		return ret;

	return count;
}

static DEVICE_ATTR_WO(tsm_ide_refresh);

static ssize_t blob_show(struct tsm_blob *blob, char *buf)
{
	unsigned n, m;

	if (!blob)
		return sysfs_emit(buf, "none\n");

	n = snprintf(buf, PAGE_SIZE, "%u %u\n", blob->len,
		     kref_read(&blob->kref));
	m = hex_dump_to_buffer(blob->data, blob->len, 32, 1,
			       buf + n, PAGE_SIZE - n, false);
	n += min(PAGE_SIZE - n, m);
	n += snprintf(buf + n, PAGE_SIZE - n, "...\n");
	return n;
}

static ssize_t tsm_certs_gen(struct tsm_blob *certs, char *buf, size_t len)
{
	unsigned n = 0, i, off;

	for (i = 0, off = 0; off < certs->len; ++i) {
		struct spdm_certchain_block_header *h;
		unsigned o2;
		u8 *p;

		h = (struct spdm_certchain_block_header *) ((u8 *)certs->data + off);

		if (WARN_ON_ONCE(h->length > certs->len - off))
			return 0;

		n += snprintf(buf + n, len - n, "[%d] len=%d:\n", i, h->length);

		for (o2 = 0, p = (u8 *)&h[1]; o2 < h->length; o2 += 32) {
			unsigned m = hex_dump_to_buffer(p + o2, h->length - o2, 32, 1,
							buf + n, len - n, true);

			n += min(len - n, m);
			n += snprintf(buf + n, len - n, "\n");
		}

		off += h->length; /* Includes the header */
	}

	return n;
}

static ssize_t tsm_certs_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	ssize_t n = 0;

	if (!tdev->certs) {
		n = sysfs_emit(buf, "none\n");
	} else {
		n = tsm_certs_gen(tdev->certs, buf, PAGE_SIZE);
		if (!n)
			n = blob_show(tdev->certs, buf);
	}

	tsm_dev_put(tdev);
	return n;
}

static DEVICE_ATTR_RO(tsm_certs);

static ssize_t tsm_meas_gen(struct tsm_blob *meas, char *buf, size_t len)
{
	static const char *whats[] = { "ImmuROM", "MutFW", "HWCfg", "FWCfg",
		"MeasMft", "DevDbg", "MutFWVer", "MutFWVerSec" };
	struct dmtf_measurement_block_device_mode *dm;
	struct spdm_measurement_block_header *mb;
	struct dmtf_measurement_block_header *h;
	unsigned n = 0, m, off, what;
	bool dmtf;

	for (off = 0; off < meas->len; ) {
		mb = (struct spdm_measurement_block_header *)(((u8 *) meas->data) + off);
		dmtf = mb->spec & 1;

		n += snprintf(buf + n, len - n, "#%d (%d) ", mb->index, mb->size);
		if (dmtf) {
			h = (void *) &mb[1];

			if (WARN_ON_ONCE(mb->size != (sizeof(*h) + h->size)))
				return -EINVAL;

			what = h->type & 0x7F;
			n += snprintf(buf + n, len - n, "%x=[%s %s]: ",
				h->type,
				h->type & 0x80 ? "digest" : "raw",
				what < ARRAY_SIZE(whats) ? whats[what] : "reserved");

			if (what == 5) {
				dm = (struct dmtf_measurement_block_device_mode *) &h[1];
				n += snprintf(buf + n, len - n, " %x %x %x %x",
					      dm->opmode_cap, dm->opmode_sta,
					      dm->devmode_cap, dm->devmode_sta);
			} else {
				m = hex_dump_to_buffer(&h[1], h->size, 32, 1,
						       buf + n, len - n, false);
				n += min(PAGE_SIZE - n, m);
			}
		} else {
			n += snprintf(buf + n, len - n, "spec=%x: ", mb->spec);
			m = hex_dump_to_buffer(&mb[1], min(len - off, mb->size),
					       32, 1, buf + n, len - n, false);
			n += min(PAGE_SIZE - n, m);
		}

		off += sizeof(*mb) + mb->size;
		n += snprintf(buf + n, PAGE_SIZE - n, "...\n");
	}

	return n;
}

static ssize_t tsm_meas_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	ssize_t n = 0;

	if (!tdev->meas) {
		n = sysfs_emit(buf, "none\n");
	} else {
		if (!n)
			n = tsm_meas_gen(tdev->meas, buf, PAGE_SIZE);
		if (!n)
			n = blob_show(tdev->meas, buf);
	}

	tsm_dev_put(tdev);
	return n;
}

static DEVICE_ATTR_RO(tsm_meas);

static ssize_t tsm_dev_status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_dev *tdev = tsm_dev_get(dev);
	struct tsm_dev_status s = { 0 };
	int ret = tsm_dev_status(tdev, tsm.private_data, &s);
	ssize_t ret1;

	ret1 = sysfs_emit(buf, "ret=%d\n"
			  "ctx_state=%x\n"
			  "tc_mask=%x\n"
			  "certs_slot=%x\n"
			  "device_id=%x\n"
			  "segment_id=%x\n"
			  "no_fw_update=%x\n",
			  ret,
			  s.ctx_state,
			  s.tc_mask,
			  s.certs_slot,
			  s.device_id,
			  s.segment_id,
			  s.no_fw_update);

	tsm_dev_put(tdev);
	return ret1;
}

static DEVICE_ATTR_RO(tsm_dev_status);

static struct attribute *host_dev_attrs[] = {
	&dev_attr_tsm_cert_slot.attr,
	&dev_attr_tsm_tc_mask.attr,
	&dev_attr_tsm_dev_connect.attr,
	&dev_attr_tsm_sel_stream.attr,
	&dev_attr_tsm_ide_refresh.attr,
	&dev_attr_tsm_certs.attr,
	&dev_attr_tsm_meas.attr,
	&dev_attr_tsm_dev_status.attr,
	NULL,
};
static const struct attribute_group host_dev_group = {
	.attrs = host_dev_attrs,
};

static struct attribute *guest_dev_attrs[] = {
	&dev_attr_tsm_certs.attr,
	&dev_attr_tsm_meas.attr,
	NULL,
};
static const struct attribute_group guest_dev_group = {
	.attrs = guest_dev_attrs,
};

static ssize_t tsm_tdi_bind_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = tsm_tdi_get(dev);

	if (!tdi->vmid)
		return sysfs_emit(buf, "not bound\n");

	return sysfs_emit(buf, "VM=%#llx ASID=%d BDFn=%x:%x.%d\n",
			  tdi->vmid, tdi->asid,
			  PCI_BUS_NUM(tdi->guest_rid), PCI_SLOT(tdi->guest_rid),
			  PCI_FUNC(tdi->guest_rid));
}

static DEVICE_ATTR_RO(tsm_tdi_bind);

static ssize_t tsm_tdi_validate_store(struct device *dev, struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct tsm_tdi *tdi = tsm_tdi_get(dev);
	unsigned long val;
	ssize_t ret;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val) {
		ret = tsm_tdi_validate(tdi, false, tsm.private_data);
		if (ret)
			return ret;
	} else {
		tsm_tdi_validate(tdi, true, tsm.private_data);
	}

	tdi->validated = val;

	return count;
}

static ssize_t tsm_tdi_validate_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = tsm_tdi_get(dev);
	return sysfs_emit(buf, "%u\n", tdi->validated);
}

static DEVICE_ATTR_RW(tsm_tdi_validate);

ssize_t tsm_report_gen(struct tsm_blob *report, char *buf, size_t len)
{
	struct tdi_report_header *h = TDI_REPORT_HDR(report);
	struct tdi_report_mmio_range *mr = TDI_REPORT_MR_OFF(report);
	struct tdi_report_footer *f = TDI_REPORT_FTR(report);
	unsigned n, m, i;

	n = snprintf(buf, len,
		     "no_fw_update=%u\ndma_no_pasid=%u\ndma_pasid=%u\nats=%u\nprs=%u\n",
		     h->no_fw_update, h->dma_no_pasid, h->dma_pasid, h->ats, h->prs);
	n += snprintf(buf + n, len - n,
		      "msi_x_message_control=%#04x\nlnr_control=%#04x\n",
		      h->msi_x_message_control, h->lnr_control);
	n += snprintf(buf + n, len - n, "tph_control=%#08x\n", h->tph_control);

	for (i = 0; i < h->mmio_range_count; ++i) {
		n += snprintf(buf + n, len - n,
			      "[%i] #%u %#016llx +%#lx MSIX%c PBA%c NonTEE%c Upd%c\n",
			      i, mr[i].range_id, mr[i].first_page << PAGE_SHIFT,
			      (unsigned long) mr[i].num << PAGE_SHIFT,
			      mr[i].msix_table ? '+':'-',
			      mr[i].msix_pba ? '+':'-',
			      mr[i].is_non_tee_mem ? '+':'-',
			      mr[i].is_mem_attr_updatable ? '+':'-');
		if (mr[i].reserved)
			n += snprintf(buf + n, len - n,
			      "[%i] WARN: reserved=%#x\n", i, mr[i].range_attributes);
	}

	if (f->device_specific_info_len) {
		unsigned num = report->len - ((u8 *)f->device_specific_info - (u8 *)h);

		num = min(num, f->device_specific_info_len);
		n += snprintf(buf + n, len - n, "DevSp len=%d%s",
			f->device_specific_info_len, num ? ": " : "");
		m = hex_dump_to_buffer(f->device_specific_info, num, 32, 1, buf + n, len - n, false);
		n += min(len - n, m);
		n += snprintf(buf + n, len - n, m? "\n" : "...\n");
	}

	return n;
}
EXPORT_SYMBOL_GPL(tsm_report_gen);

static ssize_t tsm_report_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = tsm_tdi_get(dev);
	ssize_t n = 0;

	if (!tdi->report) {
		n = sysfs_emit(buf, "none\n");
	} else {
		if (!n)
			n = tsm_report_gen(tdi->report, buf, PAGE_SIZE);
		if (!n)
			n = blob_show(tdi->report, buf);
	}

	return n;
}

static DEVICE_ATTR_RO(tsm_report);

static char *spdm_algos_to_str(u64 algos, char *buf, size_t len)
{
	size_t n = 0;

	buf[0] = 0;
#define __ALGO(x) if ((n < len) && (algos & (1ULL << (TSM_TDI_SPDM_ALGOS_##x)))) \
	n += snprintf(buf + n, len - n, #x" ")
	__ALGO(DHE_SECP256R1);
	__ALGO(DHE_SECP384R1);
	__ALGO(AEAD_AES_128_GCM);
	__ALGO(AEAD_AES_256_GCM);
	__ALGO(ASYM_TPM_ALG_RSASSA_3072);
	__ALGO(ASYM_TPM_ALG_ECDSA_ECC_NIST_P256);
	__ALGO(ASYM_TPM_ALG_ECDSA_ECC_NIST_P384);
	__ALGO(HASH_TPM_ALG_SHA_256);
	__ALGO(HASH_TPM_ALG_SHA_384);
	__ALGO(KEY_SCHED_SPDM_KEY_SCHEDULE);
#undef __ALGO
	return buf;
}

static const char *tdisp_state_to_str(enum tsm_tdisp_state state)
{
	switch (state) {
#define __ST(x) case TDISP_STATE_##x: return #x
	case TDISP_STATE_UNAVAIL: return "TDISP state unavailable";
	__ST(CONFIG_UNLOCKED);
	__ST(CONFIG_LOCKED);
	__ST(RUN);
	__ST(ERROR);
#undef __ST
	default: return "unknown";
	}
}

static ssize_t tsm_tdi_status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct tsm_tdi *tdi = tsm_tdi_get(dev);
	struct tsm_tdi_status ts = { 0 };
	char algos[256] = "";
	unsigned n, m;
	int ret;

	ret = tsm_tdi_status(tdi, tsm.private_data, &ts);
	if (ret < 0)
		return sysfs_emit(buf, "ret=%d\n\n", ret);

	if (!ts.valid)
		return sysfs_emit(buf, "ret=%d\nstate=%d:%s\n",
				  ret, ts.state, tdisp_state_to_str(ts.state));

	n = snprintf(buf, PAGE_SIZE,
		     "ret=%d\n"
		     "state=%d:%s\n"
		     "meas_digest_fresh=%x\n"
		     "meas_digest_valid=%x\n"
		     "all_request_redirect=%x\n"
		     "bind_p2p=%x\n"
		     "lock_msix=%x\n"
		     "no_fw_update=%x\n"
		     "cache_line_size=%d\n"
		     "algos=%#llx:%s\n"
		     ,
		     ret,
		     ts.state, tdisp_state_to_str(ts.state),
		     ts.meas_digest_fresh,
		     ts.meas_digest_valid,
		     ts.all_request_redirect,
		     ts.bind_p2p,
		     ts.lock_msix,
		     ts.no_fw_update,
		     ts.cache_line_size,
		     ts.spdm_algos, spdm_algos_to_str(ts.spdm_algos, algos, sizeof(algos) - 1));

	n += snprintf(buf + n, PAGE_SIZE - n, "Certs digest: ");
	m = hex_dump_to_buffer(ts.certs_digest, sizeof(ts.certs_digest), 32, 1,
			       buf + n, PAGE_SIZE - n, false);
	n += min(PAGE_SIZE - n, m);
	n += snprintf(buf + n, PAGE_SIZE - n, "...\nMeasurements digest: ");
	m = hex_dump_to_buffer(ts.meas_digest, sizeof(ts.meas_digest), 32, 1,
			       buf + n, PAGE_SIZE - n, false);
	n += min(PAGE_SIZE - n, m);
	n += snprintf(buf + n, PAGE_SIZE - n, "...\nInterface report digest: ");
	m = hex_dump_to_buffer(ts.interface_report_digest, sizeof(ts.interface_report_digest), 32, 1,
			       buf + n, PAGE_SIZE - n, false);
	n += min(PAGE_SIZE - n, m);
	n += snprintf(buf + n, PAGE_SIZE - n, "...\n");

	return n;
}

static DEVICE_ATTR_RO(tsm_tdi_status);

static struct attribute *host_tdi_attrs[] = {
	&dev_attr_tsm_tdi_bind.attr,
	&dev_attr_tsm_report.attr,
	&dev_attr_tsm_tdi_status.attr,
	NULL,
};

static const struct attribute_group host_tdi_group = {
	.attrs = host_tdi_attrs,
};

static struct attribute *guest_tdi_attrs[] = {
	&dev_attr_tsm_tdi_validate.attr,
	&dev_attr_tsm_report.attr,
	&dev_attr_tsm_tdi_status.attr,
	NULL,
};

static const struct attribute_group guest_tdi_group = {
	.attrs = guest_tdi_attrs,
};

static int tsm_tdi_init(struct tsm_dev *tdev, struct pci_dev *pdev)
{
	struct tsm_tdi *tdi;
	int ret = 0;

	dev_info(&pdev->dev, "Initializing tdi\n");
	if (!tdev)
		return -ENODEV;

	tdi = kzalloc(sizeof(*tdi), GFP_KERNEL);
	if (!tdi)
		return -ENOMEM;

	/* tsm_dev_get() requires pdev->dev.tdi which is set later */
	if (!kref_get_unless_zero(&tdev->kref)) {
		ret = -EPERM;
		goto free_exit;
	}

	if (tsm.ops->dev_connect)
		tdi->ag = &host_tdi_group;
	else
		tdi->ag = &guest_tdi_group;

	ret = sysfs_create_link(&pdev->dev.kobj, &tdev->pdev->dev.kobj, "tsm_dev");
	if (ret)
		goto free_exit;

	ret = device_add_group(&pdev->dev, tdi->ag);
	if (ret)
		goto sysfs_unlink_exit;

	tdi->tdev = tdev;
	tdi->pdev = pci_dev_get(pdev);

	pdev->dev.tdi_enabled = !pdev->is_physfn || tsm.physfn;
	pdev->dev.tdi = tdi;
	pci_info(pdev, "TDI enabled=%d\n", pdev->dev.tdi_enabled);

	return 0;

sysfs_unlink_exit:
	sysfs_remove_link(&pdev->dev.kobj, "tsm_dev");
free_exit:
	kfree(tdi);

	return ret;
}

static void tsm_tdi_free(struct tsm_tdi *tdi)
{
	tsm_dev_put(tdi->tdev);

	pci_dev_put(tdi->pdev);

	device_remove_group(&tdi->pdev->dev, tdi->ag);
	sysfs_remove_link(&tdi->pdev->dev.kobj, "tsm_dev");
	tdi->pdev->dev.tdi = NULL;
	tdi->pdev->dev.tdi_enabled = false;
	kfree(tdi);
}

static int tsm_dev_init(struct pci_dev *pdev, struct tsm_dev **ptdev)
{
	struct tsm_dev *tdev;
	int ret = 0;

	dev_info(&pdev->dev, "Initializing tdev\n");
	tdev = kzalloc(sizeof(*tdev), GFP_KERNEL);
	if (!tdev)
		return -ENOMEM;

	kref_init(&tdev->kref);
	tdev->tc_mask = tsm.tc_mask;
	tdev->cert_slot = tsm.cert_slot;
	tdev->pdev = pci_dev_get(pdev);
	mutex_init(&tdev->spdm_mutex);

	if (tsm.ops->dev_connect)
		tdev->ag = &host_dev_group;
	else
		tdev->ag = &guest_dev_group;

	ret = device_add_group(&pdev->dev, tdev->ag);
	if (ret)
		return ret;

	if (tsm.ops->dev_connect) {
		tdev->pdev = pci_dev_get(pdev);
		tdev->spdm.doe_mb = pci_find_doe_mailbox(tdev->pdev,
							 PCI_VENDOR_ID_PCI_SIG,
							 PCI_DOE_PROTOCOL_CMA_SPDM);
		if (!tdev->spdm.doe_mb)
			goto pci_dev_put_exit;

		tdev->spdm.doe_mb_secured = pci_find_doe_mailbox(tdev->pdev,
								 PCI_VENDOR_ID_PCI_SIG,
								 PCI_DOE_PROTOCOL_SECURED_CMA_SPDM);
		if (!tdev->spdm.doe_mb_secured)
			goto pci_dev_put_exit;
	}

	*ptdev = tdev;
	return 0;

pci_dev_put_exit:
	pci_dev_put(pdev);
	kfree(tdev);

	return ret;
}

static void tsm_dev_free(struct kref *kref)
{
	struct tsm_dev *tdev = container_of(kref, struct tsm_dev, kref);

	device_remove_group(&tdev->pdev->dev, tdev->ag);

	if (tdev->connected)
		tsm_dev_reclaim(tdev, tsm.private_data);

	dev_info(&tdev->pdev->dev, "Freeing TDEV\n");
	pci_dev_put(tdev->pdev);
	kfree(tdev);
}

static int tsm_alloc_device(struct pci_dev *pdev)
{
	int ret = 0;

	/* It is guest VM == TVM */
	if (!tsm.ops->dev_connect) {
		if (pdev->devcap & PCI_EXP_DEVCAP_TEE_IO) {
			struct tsm_dev *tdev = NULL;

			ret = tsm_dev_init(pdev, &tdev);
			if (ret)
				return ret;

			ret = tsm_tdi_init(tdev, pdev);
			tsm_dev_put(tdev);
			return ret;
		}
		return 0;
	}

	if (pdev->is_physfn && pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_IDE)) {
		struct tsm_dev *tdev = NULL;

		WARN_ON_ONCE(pdev->devfn & 7);

		ret = tsm_dev_init(pdev, &tdev);
		if (ret)
			return ret;

		ret = tsm_tdi_init(tdev, pdev);
		tsm_dev_put(tdev);
		return ret;
	}

	// TODO: we probably do not need this one as the next "if" should pick up these
	if (pdev->is_virtfn && pci_find_ext_capability(pdev->physfn, PCI_EXT_CAP_ID_IDE)) {
		struct tsm_dev *tdev = tsm_dev_get(&pdev->physfn->dev);
		ret = tsm_tdi_init(tdev, pdev);
		tsm_dev_put(tdev);
		return ret;
	}

	if (pdev->is_virtfn) {
		struct pci_dev *pf0 = pci_get_slot(pdev->physfn->bus, pdev->physfn->devfn & ~7);

		if (pf0 && pci_find_ext_capability(pf0, PCI_EXT_CAP_ID_IDE)) {
			struct tsm_dev *tdev = tsm_dev_get(&pf0->dev);
			ret = tsm_tdi_init(tdev, pdev);
			tsm_dev_put(tdev);
			return ret;
		}
	}

	return 0;
}

static void tsm_dev_freeice(struct device *dev)
{
	struct tsm_tdi *tdi = tsm_tdi_get(dev);

	if (!tdi)
		return;

	tsm_tdi_free(tdi);
}

static int tsm_pci_bus_notifier(struct notifier_block *nb, unsigned long action, void *data)
{
	switch (action) {
	case BUS_NOTIFY_ADD_DEVICE:
		tsm_alloc_device(to_pci_dev(data));
		break;
	case BUS_NOTIFY_DEL_DEVICE:
		tsm_dev_freeice(data);
		break;
	case BUS_NOTIFY_PCI_BUS_MASTER:
		/* Validating before the driver or after the driver just does not work so don't! */
		tsm_tdi_validate(tsm_tdi_get(data), false, tsm.private_data);
		break;
	case BUS_NOTIFY_UNBOUND_DRIVER:
		tsm_tdi_validate(tsm_tdi_get(data), true, tsm.private_data);
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block tsm_pci_bus_nb = {
	.notifier_call = tsm_pci_bus_notifier,
};

static int __init tsm_init(void)
{
	int ret = 0;

	pr_info(DRIVER_DESC " version: " DRIVER_VERSION "\n");
	return ret;
}

static void __exit tsm_cleanup(void)
{
}

void tsm_set_ops(struct tsm_ops *ops, void *private_data)
{
	struct pci_dev *pdev = NULL;
	int ret;

	if (!tsm.ops && ops) {
		tsm.ops = ops;
		tsm.private_data = private_data;

		for_each_pci_dev(pdev) {
			ret = tsm_alloc_device(pdev);
			if (ret)
				break;
		}
		bus_register_notifier(&pci_bus_type, &tsm_pci_bus_nb);
	} else {
		bus_unregister_notifier(&pci_bus_type, &tsm_pci_bus_nb);
		for_each_pci_dev(pdev)
			tsm_dev_freeice(&pdev->dev);
		tsm.ops = ops;
	}
}
EXPORT_SYMBOL_GPL(tsm_set_ops);

int tsm_tdi_bind(struct tsm_tdi *tdi, u32 guest_rid, u64 vmid, u32 asid)
{
	int ret;

	if (WARN_ON(!tsm.ops->tdi_bind))
		return -EPERM;

	tdi->guest_rid = guest_rid;
	tdi->vmid = vmid;
	tdi->asid = asid;

	mutex_lock(&tdi->tdev->spdm_mutex);
	while (1) {
		ret = tsm.ops->tdi_bind(tdi, guest_rid, vmid, asid, tsm.private_data);
		if (ret < 0)
			break;

		if (!ret)
			break;

		ret = spdm_forward(&tdi->tdev->spdm, ret);
		if (ret < 0)
			break;
	}
	mutex_unlock(&tdi->tdev->spdm_mutex);

	if (ret) {
		tsm_tdi_unbind(tdi);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tsm_tdi_bind);

void tsm_tdi_unbind(struct tsm_tdi *tdi)
{
	tsm_tdi_reclaim(tdi, tsm.private_data);
	tdi->vmid = 0;
	tdi->asid = 0;
	tdi->guest_rid = 0;
}
EXPORT_SYMBOL_GPL(tsm_tdi_unbind);

int tsm_guest_request(struct tsm_tdi *tdi, enum tsm_tdisp_state *state, void *req_data)
{
	int ret;

	if (!tsm.ops->guest_request)
		return -EPERM;

	mutex_lock(&tdi->tdev->spdm_mutex);
	while (1) {
		ret = tsm.ops->guest_request(tdi, tdi->guest_rid, tdi->vmid, req_data, state, tsm.private_data);
		if (ret <= 0)
			break;

		ret = spdm_forward(&tdi->tdev->spdm, ret);
		if (ret < 0)
			break;
	}
	mutex_unlock(&tdi->tdev->spdm_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(tsm_guest_request);

struct tsm_tdi *tsm_tdi_find(u32 guest_rid, u64 vmid)
{
	struct pci_dev *pdev = NULL;
	struct tsm_tdi *tdi;

	for_each_pci_dev(pdev) {
		tdi = tsm_tdi_get(&pdev->dev);
		if (!tdi)
			continue;

		if (tdi->vmid == vmid && tdi->guest_rid == guest_rid)
			return tdi;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(tsm_tdi_find);

module_init(tsm_init);
module_exit(tsm_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
