/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __SEV_GUEST_H__
#define __SEV_GUEST_H__

#include <linux/miscdevice.h>
#include <asm/sev.h>

struct snp_guest_dev {
	struct device *dev;
	struct miscdevice misc;

	struct snp_msg_desc *msg_desc;

	struct tsm_dev *tsmdev;
};

void sev_guest_tsm_set_ops(bool set, struct snp_guest_dev *snp_dev);

#endif /* __SEV_GUEST_H__ */
