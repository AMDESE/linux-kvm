/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __SEV_GUEST_H__
#define __SEV_GUEST_H__

#include <linux/miscdevice.h>
#include <asm/sev.h>

struct snp_guest_dev {
	struct device *dev;
	struct miscdevice misc;

	struct snp_msg_desc *msg_desc;

#if defined(CONFIG_PCI_TSM) || defined(CONFIG_PCI_TSM_MODULE)
	struct tsm_dev *tsmdev;
#endif
};

#endif /* __SEV_GUEST_H__ */
