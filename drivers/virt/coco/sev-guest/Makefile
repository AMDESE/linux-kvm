# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_SEV_GUEST) += core.o
ifeq ($(CONFIG_PCI_TSM),y)
obj-$(CONFIG_SEV_GUEST) += tio.o
endif
