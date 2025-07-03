#!/bin/bash

DEVPATH=$(readlink /sys/bus/pci/devices/$1)
RP=$(echo $DEVPATH | sed -n 's#.*/\([0-9a-f]\{4\}:[0-9a-f]\{2\}:[0-9a-f]\{2\}\.[0-9]\)/.*#\1#p')

PCIUTILS=~/pciutils

if [ ! -f $PCIUTILS/lspci ] ; then
	git clone https://github.com/pciutils/pciutils.git $PCIUTILS && make -C $PCIUTILS
fi

function streams() {
	sudo $PCIUTILS/lspci -i $PCIUTILS/pci.ids -Dvvnns $1 | \
		grep -e "\($1\|Integrity & Data Encryption\|IDECap\|IDECtl\|$2 \)" | grep --color=always -E 'secure|insecure|$'
}

STREAMID=$2
if [ "$STREAMID" == "" ] ; then
	STREAMID="SelectiveIDE#0"
fi
streams $1 $STREAMID
streams $RP $STREAMID
