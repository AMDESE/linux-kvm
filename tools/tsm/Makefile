# SPDX-License-Identifier: GPL-2.0-only
# Makefile for tsm tools
#
include ../scripts/Makefile.include

BUILD_TARGET = tsm_obj_read
INSTALL_TARGETS = $(BUILD_TARGETS)

CFLAGS += -D__EXPORTED_HEADERS__ -I../../include/uapi -I../../include

all: $(BUILD_TARGET)

%: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	$(RM) $(BUILD_TARGET)

sbindir ?= /usr/sbin

install: all
	install -d $(DESTDIR)$(sbindir)
	install -m 755 -p $(INSTALL_TARGETS) $(DESTDIR)$(sbindir)
