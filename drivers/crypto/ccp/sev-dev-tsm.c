// SPDX-License-Identifier: GPL-2.0-only

// Interface to CCP/SEV-TIO for generic PCIe TDISP module

#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/tsm.h>

#include <asm/smp.h>
#include <asm/sev-common.h>

#include "psp-dev.h"
#include "sev-dev.h"
#include "sev-dev-tio.h"

static int mkret(int ret, struct tsm_dev_tio *dev_data)
{
	if (ret)
		return ret;

	if (dev_data->psp_ret == SEV_RET_SUCCESS)
		return 0;

	pr_err("PSP returned an error %d\n", dev_data->psp_ret);
	return -EINVAL;
}

static int dev_connect(struct tsm_dev *tdev, void *private_data)
{
	u16 device_id = pci_dev_id(tdev->pdev);
	u16 root_port_id = 0; // FIXME: this is NOT PCI id, need to figure out how to calculate this
	u8 segment_id = tdev->pdev->bus ? pci_domain_nr(tdev->pdev->bus) : 0;
	struct tsm_dev_tio *dev_data = tdev->data;
	int ret;

	if (!dev_data) {
		dev_data = kzalloc(sizeof(*dev_data), GFP_KERNEL);
		if (!dev_data)
			return -ENOMEM;

		ret = sev_tio_dev_create(dev_data, device_id, root_port_id, segment_id);
		if (ret)
			goto free_exit;

		tdev->data = dev_data;
	}

	if (dev_data->cmd == 0) {
		ret = sev_tio_dev_connect(dev_data, tdev->tc_mask, tdev->cert_slot, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
		if (ret < 0)
			goto free_exit;

		tio_save_output(&tdev->certs, dev_data->output, SPDM_DOBJ_ID_CERTIFICATE);
	}

	if (dev_data->cmd == SEV_CMD_TIO_DEV_CONNECT) {
		ret = sev_tio_continue(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		tio_save_output(&tdev->certs, dev_data->output, SPDM_DOBJ_ID_CERTIFICATE);
	}

	if (dev_data->cmd == 0) {
		ret = sev_tio_dev_measurements(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		tio_save_output(&tdev->meas, dev_data->output, SPDM_DOBJ_ID_MEASUREMENT);
	}

	if (dev_data->cmd == SEV_CMD_TIO_DEV_MEASUREMENTS) {
		ret = sev_tio_continue(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		tio_save_output(&tdev->meas, dev_data->output, SPDM_DOBJ_ID_MEASUREMENT);
	}

	if (dev_data->cmd == 0) {
		ret = sev_tio_dev_certificates(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		tio_save_output(&tdev->certs, dev_data->output, SPDM_DOBJ_ID_CERTIFICATE);
	}

	if (dev_data->cmd == SEV_CMD_TIO_DEV_CERTIFICATES) {
		ret = sev_tio_continue(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		tio_save_output(&tdev->certs, dev_data->output, SPDM_DOBJ_ID_CERTIFICATE);
	}

	return 0;

free_exit:
	sev_tio_dev_reclaim(dev_data, &tdev->spdm);
	kfree(dev_data);

	return ret;
}

static int dev_reclaim(struct tsm_dev *tdev, void *private_data)
{
	struct tsm_dev_tio *dev_data = tdev->data;
	int ret;

	if (!dev_data)
		return -ENODEV;

	if (dev_data->cmd == 0) {
		ret = sev_tio_dev_disconnect(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;
	} else if (dev_data->cmd == SEV_CMD_TIO_DEV_DISCONNECT) {
		ret = sev_tio_continue(dev_data, &tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;
	} else {
		dev_err(&tdev->pdev->dev, "Wrong state, cmd 0x%x in flight\n",
			dev_data->cmd);
	}

	ret = sev_tio_dev_reclaim(dev_data, &tdev->spdm);
	ret = mkret(ret, dev_data);

	tsm_blob_put(tdev->meas);
	tdev->meas = NULL;
	tsm_blob_put(tdev->certs);
	tdev->certs = NULL;
	kfree(tdev->data);
	tdev->data = NULL;

	return ret;
}

static int dev_status(struct tsm_dev *tdev, void *private_data, struct tsm_dev_status *s)
{
	struct tsm_dev_tio *dev_data = tdev->data;
	int ret;

	if (!dev_data)
		return -ENODEV;

	ret = sev_tio_dev_status(dev_data, s);
	ret = mkret(ret, dev_data);
	if (!ret)
		WARN_ON(s->device_id != pci_dev_id(tdev->pdev));

	return ret;
}

static int ide_refresh(struct tsm_dev *tdev, void *private_data)
{
	struct tsm_dev_tio *dev_data = tdev->data;
	int ret;

	if (!dev_data)
		return -ENODEV;

	ret = sev_tio_ide_refresh(dev_data, &tdev->spdm);

	return ret;
}

static int tdi_reclaim(struct tsm_tdi *tdi, void *private_data)
{
	struct tsm_dev_tio *dev_data;
	int ret;

	if (!tdi->data)
		return -ENODEV;

	dev_data = tdi->tdev->data;
	if (tdi->vmid) {
		if (dev_data->cmd == 0) {
			ret = sev_tio_tdi_unbind(tdi->tdev->data, tdi->data, &tdi->tdev->spdm);
			ret = mkret(ret, dev_data);
			if (ret)
				return ret;
		} else if (dev_data->cmd == SEV_CMD_TIO_TDI_UNBIND) {
			ret = sev_tio_continue(dev_data, &tdi->tdev->spdm);
			ret = mkret(ret, dev_data);
			if (ret)
				return ret;
		}
	}

	/* Reclaim TDI if DEV is connected */
	if (tdi->tdev->data) {
		struct tsm_tdi_tio *tdi_data = tdi->data;
		struct tsm_dev *tdev = tdi->tdev;
		struct pci_dev *rootport = tdev->pdev->bus->self;
		u8 segment_id = pci_domain_nr(rootport->bus);
		u16 device_id = pci_dev_id(rootport);
		bool fenced = false;

		sev_tio_tdi_reclaim(tdi->tdev->data, tdi->data);

		if (!sev_tio_asid_fence_status(dev_data, device_id, segment_id, tdi_data->asid, &fenced)) {
			if (fenced) {
				ret = sev_tio_asid_fence_clear(device_id, segment_id, tdi_data->vmid, &dev_data->psp_ret);
				pci_notice(rootport, "Unfenced VM=%llx ASID=%d ret=%d %d",
					   tdi_data->vmid, tdi_data->asid, ret, dev_data->psp_ret);
			}
		}

		tsm_blob_put(tdi->report);
		tdi->report = NULL;
	}

	kfree(tdi->data);
	tdi->data = NULL;

	return 0;
}

static int tdi_create(struct tsm_tdi *tdi)
{
	struct tsm_tdi_tio *tdi_data = tdi->data;
	int ret;

	if (tdi_data)
		return -EBUSY;

	tdi_data = kzalloc(sizeof(*tdi_data), GFP_KERNEL);
	if (!tdi_data)
		return -ENOMEM;

	ret = sev_tio_tdi_create(tdi->tdev->data, tdi_data, pci_dev_id(tdi->pdev),
				 tdi->rseg, tdi->rseg_valid);
	if (ret)
		kfree(tdi_data);
	else
		tdi->data = tdi_data;

	return ret;
}

static int tdi_bind(struct tsm_tdi *tdi, u32 bdfn, u64 vmid, u32 asid, void *private_data)
{
	struct tsm_dev_tio *dev_data = tdi->tdev->data;
	struct tsm_tdi_tio *tdi_data;

	int ret;

	if (!tdi->data) {
		ret = tdi_create(tdi);
		if (ret)
			return ret;
	}

	if (dev_data->cmd == 0) {
		ret = sev_tio_tdi_bind(dev_data, tdi->data, bdfn, vmid, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		tio_save_output(&tdi->report, dev_data->output, SPDM_DOBJ_ID_REPORT);
	}

	if (dev_data->cmd == SEV_CMD_TIO_TDI_BIND) {
		ret = sev_tio_continue(dev_data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		tio_save_output(&tdi->report, dev_data->output, SPDM_DOBJ_ID_REPORT);
	}

	tdi_data = tdi->data;
	tdi_data->vmid = vmid;
	tdi_data->asid = asid;

	return 0;
}

static int guest_request(struct tsm_tdi *tdi, u32 guest_rid, u64 kvmid, void *req_data,
			 enum tsm_tdisp_state *state, void *private_data)
{
	struct tsm_dev_tio *dev_data = tdi->tdev->data;
	struct tio_guest_request *req = req_data;
	int ret;

	if (!tdi->data)
		return -EFAULT;

	if (dev_data->cmd == 0) {
		ret = sev_tio_guest_request(&req->data, guest_rid, kvmid,
					    dev_data, tdi->data, &tdi->tdev->spdm);
		req->fw_err = dev_data->psp_ret;
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
	} else if (dev_data->cmd == SEV_CMD_TIO_GUEST_REQUEST) {
		ret = sev_tio_continue(dev_data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
	}

	if (dev_data->cmd == 0 && state) {
		ret = sev_tio_tdi_status(tdi->tdev->data, tdi->data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;
	} else if (dev_data->cmd == SEV_CMD_TIO_TDI_STATUS) {
		ret = sev_tio_continue(dev_data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret > 0)
			return ret;

		ret = sev_tio_tdi_status_fin(tdi->tdev->data, tdi->data, state);
	}

	return ret;
}

static int tdi_status(struct tsm_tdi *tdi, void *private_data, struct tsm_tdi_status *ts)
{
	struct tsm_dev_tio *dev_data = tdi->tdev->data;
	int ret;

	if (!tdi->data)
		return -ENODEV;

	if (0) // Not implemented yet
	if (dev_data->cmd == 0) {
		ret = sev_tio_tdi_info(tdi->tdev->data, tdi->data, ts);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;
	}

	if (dev_data->cmd == 0) {
		ret = sev_tio_tdi_status(tdi->tdev->data, tdi->data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		ret = sev_tio_tdi_status_fin(tdi->tdev->data, tdi->data, &ts->state);
	} else if (dev_data->cmd == SEV_CMD_TIO_TDI_STATUS) {
		ret = sev_tio_continue(dev_data, &tdi->tdev->spdm);
		ret = mkret(ret, dev_data);
		if (ret)
			return ret;

		ret = sev_tio_tdi_status_fin(tdi->tdev->data, tdi->data, &ts->state);
	} else {
		pci_err(tdi->pdev, "Wrong state, cmd 0x%x in flight\n",
			dev_data->cmd);
	}

	return ret;
}

struct tsm_ops sev_tsm_ops = {
	.dev_connect = dev_connect,
	.dev_reclaim = dev_reclaim,
	.dev_status = dev_status,
	.ide_refresh = ide_refresh,
	.tdi_bind = tdi_bind,
	.tdi_reclaim = tdi_reclaim,
	.guest_request = guest_request,
	.tdi_status = tdi_status,
};

void sev_tsm_set_ops(bool set)
{
	if (set) {
		int ret = sev_tio_status();

		if (ret)
			pr_warn("SEV-TIO STATUS failed with %d\n", ret);
		else
			tsm_set_ops(&sev_tsm_ops, NULL);
	} else {
		tsm_set_ops(NULL, NULL);
		sev_tio_cleanup();
	}
}
