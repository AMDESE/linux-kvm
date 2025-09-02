/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Userspace interface for AMD SEV and SNP guest driver.
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * SEV API specification is available at: https://developer.amd.com/sev/
 */

#ifndef __UAPI_LINUX_SEV_GUEST_H_
#define __UAPI_LINUX_SEV_GUEST_H_

#include <linux/types.h>
#include <linux/uuid.h>

#define SNP_REPORT_USER_DATA_SIZE 64

struct snp_report_req {
	/* user data that should be included in the report */
	__u8 user_data[SNP_REPORT_USER_DATA_SIZE];

	/* The vmpl level to be included in the report */
	__u32 vmpl;

	/* Must be zero filled */
	__u8 rsvd[28];
};

struct snp_report_resp {
	/* response data, see SEV-SNP spec for the format */
	__u8 data[4000];
};

struct snp_derived_key_req {
	__u32 root_key_select;
	__u32 rsvd;
	__u64 guest_field_select;
	__u32 vmpl;
	__u32 guest_svn;
	__u64 tcb_version;
};

struct snp_derived_key_resp {
	/* response data, see SEV-SNP spec for the format */
	__u8 data[64];
};

struct snp_guest_request_ioctl {
	/* message version number (must be non-zero) */
	__u8 msg_version;

	/* Request and response structure address */
	__u64 req_data;
	__u64 resp_data;

	/* bits[63:32]: VMM error code, bits[31:0] firmware error code (see psp-sev.h) */
	union {
		__u64 exitinfo2;
		struct {
			__u32 fw_error;
			__u32 vmm_error;
		};
	};
};

struct snp_ext_report_req {
	struct snp_report_req data;

	/* where to copy the certificate blob */
	__u64 certs_address;

	/* length of the certificate blob */
	__u32 certs_len;
};

#define SNP_GUEST_REQ_IOC_TYPE	'S'

/* Get SNP attestation report */
#define SNP_GET_REPORT _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x0, struct snp_guest_request_ioctl)

/* Get a derived key from the root */
#define SNP_GET_DERIVED_KEY _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x1, struct snp_guest_request_ioctl)

/* Get SNP extended report as defined in the GHCB specification version 2. */
#define SNP_GET_EXT_REPORT _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x2, struct snp_guest_request_ioctl)

/* Guest message request EXIT_INFO_2 constants */
#define SNP_GUEST_FW_ERR_MASK		GENMASK_ULL(31, 0)
#define SNP_GUEST_VMM_ERR_SHIFT		32
#define SNP_GUEST_VMM_ERR(x)		(((u64)x) << SNP_GUEST_VMM_ERR_SHIFT)
#define SNP_GUEST_FW_ERR(x)		((x) & SNP_GUEST_FW_ERR_MASK)
#define SNP_GUEST_ERR(vmm_err, fw_err)	(SNP_GUEST_VMM_ERR(vmm_err) | \
					 SNP_GUEST_FW_ERR(fw_err))

#define SNP_GUEST_VMM_ERR_INVALID_LEN	1
#define SNP_GUEST_VMM_ERR_BUSY		2

/*
 * TIO_GUEST_REQUEST's TIO_MSG_MMIO_VALIDATE_REQ
 * encoding for MMIO in RDX:
 *
 * ........ ....GGGG GGGGGGGG GGGGGGGG GGGGGGGG GGGGGGGG GGGGOOOO OOOOTrrr
 * Where:
 *	G - guest physical address
 *	O - order of 4K pages
 *	T - TEE (valid for TIO_MSG_MMIO_CONFIG_REQ)
 *	r - range id == BAR
 */
#define MMIO_VALIDATE_GPA(r)      ((r) & 0x000FFFFFFFFFF000ULL)
#define MMIO_VALIDATE_LEN(r)      (1ULL << (12 + (((r) >> 4) & 0xFF)))
#define MMIO_VALIDATE_RANGEID(r)  ((r) & 0x7)
#define MMIO_VALIDATE_RESERVED(r) ((r) & 0xFFF0000000000000ULL)
#define MMIO_VALIDATE_PRIVATE(r)  (!!((r) & BIT(3)))

#define MMIO_MK_VALIDATE(start, size, range_id, private) \
	(MMIO_VALIDATE_GPA(start) | \
	(get_order(size) << 4) | \
	((private) ? BIT(3) : 0) | \
	((range_id) & 7) )

#define SDTE_VALIDATE		1

/* Optional Certificates/measurements/report data from TIO_GUEST_REQUEST */
struct tio_blob_table_entry {
	guid_t guid;
	__u32 offset;
	__u32 length;
} __packed;

/* Measurement’s blob: 5caa80c6-12ef-401a-b364-ec59a93abe3f */
#define TIO_GUID_MEASUREMENTS \
	GUID_INIT(0x5caa80c6, 0x12ef, 0x401a, 0xb3, 0x64, 0xec, 0x59, 0xa9, 0x3a, 0xbe, 0x3f)
/* Certificates blob: 078ccb75-2644-49e8-afe7-5686c5cf72f1 */
#define TIO_GUID_CERTIFICATES \
	GUID_INIT(0x078ccb75, 0x2644, 0x49e8, 0xaf, 0xe7, 0x56, 0x86, 0xc5, 0xcf, 0x72, 0xf1)
/* Attestation report: 70dc5b0e-0cc0-4cd5-97bb-ff0ba25bf320 */
#define TIO_GUID_REPORT \
	GUID_INIT(0x70dc5b0e, 0x0cc0, 0x4cd5, 0x97, 0xbb, 0xff, 0x0b, 0xa2, 0x5b, 0xf3, 0x20)

#endif /* __UAPI_LINUX_SEV_GUEST_H_ */
