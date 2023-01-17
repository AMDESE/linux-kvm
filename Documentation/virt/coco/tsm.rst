.. SPDX-License-Identifier: GPL-2.0

What it is
==========

This is for PCI passthrough in confidential computing (CoCo: SEV-SNP, TDX, CoVE).
Currently passing through PCI devices to a CoCo VM uses SWIOTLB to pre-shared
memory buffers.

PCIe IDE (Integrity and Data Encryption) and TDISP (TEE Device Interface Security
Protocol) are protocols to enable encryption over PCIe link and DMA to encrypted
memory. This doc is focused to DMAing to encrypted VM, the encrypted host memory is
out of scope.


Protocols
=========

PCIe r6 DOE is a mailbox protocol to read/write object from/to device.
Objects are of plain SPDM or secure SPDM type. SPDM is responsible for authenticating
devices, creating a secure link between a device and TSM.
IDE_KM manages PCIe link encryption keys, it works on top of secure SPDM.
TDISP manages a passed through PCI function state, also works on top on secure SPDM.
Additionally, PCIe defines IDE capability which provides the host OS a way
to enable streams on the PCIe link.


TSM module
==========

This is common place to trigger device authentication and keys management.
It exposes certificates/measurenets/reports/status via sysfs and provides control
over the link (limited though by the TSM capabilities).
A platform is expected to register a specific set of hooks. The same module works
in host and guest OS, the set of requires platform hooks is quite different.


Flow
====

At the boot time the tsm.ko scans the PCI bus to find and setup TDISP-cabable
devices; it also listens to hotplug events. If setup was successful, tsm-prefixed
nodes will appear in sysfs.

Then, the user enables IDE by writing to /sys/bus/pci/devices/0000:e1:00.0/tsm_dev_connect
and this is how PCIe encryption is enabled.

To pass the device through, a modifined VMM is required.

In the VM, the same tsm.ko loads. In addition to the host's setup, the VM wants
to receive the report and enable secure DMA or/and secure MMIO, via some VM<->HV
protocol (such as AMD GHCB). Once this is done, a VM can access validated MMIO
with the Cbit set and the device can DMA to encrypted memory.


References
==========

[1] TEE Device Interface Security Protocol - TDISP - v2022-07-27
https://members.pcisig.com/wg/PCI-SIG/document/18268?downloadRevision=21500
[2] Security Protocol and Data Model (SPDM)
https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.2.1.pdf
