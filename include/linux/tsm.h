/* SPDX-License-Identifier: GPL-2.0 */

#ifndef LINUX_TSM_H
#define LINUX_TSM_H

#include <linux/cdev.h>

/* SPDM control structure for DOE */
struct tsm_spdm {
	unsigned long req_len;
	void *req;
	unsigned long rsp_len;
	void *rsp;

	struct pci_doe_mb *doe_mb;
	struct pci_doe_mb *doe_mb_secured;
};

/* Data object for measurements/certificates/attestationreport */
struct tsm_blob {
	void *data;
	unsigned len;
	struct kref kref;
	void (*release)(struct tsm_blob *b);
};

struct tsm_blob *tsm_blob_new(void *data, u32 len, void (*release)(struct tsm_blob *b));
struct tsm_blob *tsm_blob_get(struct tsm_blob *b);
void tsm_blob_put(struct tsm_blob *b);

/**
 * struct tdisp_interface_id - TDISP INTERFACE_ID Definition
 *
 * @function_id: Identifies the function of the device hosting the TDI
 * 15:0: @rid: Requester ID
 * 23:16: @rseg: Requester Segment (Reserved if Requester Segment Valid is Clear)
 * 24: @rseg_valid: Requester Segment Valid
 * 31:25 – Reserved
 * 8B - Reserved
*/
struct tdisp_interface_id {
	union {
		struct {
			u32 function_id;
			u8 reserved[8];
		};
		struct {
			u16 rid;
			u8 rseg;
			u8 rseg_valid : 1;
		};
	};
} __packed;

/*
 * Measurement block as defined in SPDM DSP0274.
 */
struct spdm_measurement_block_header {
	u8 index;
	u8 spec; // MeasurementSpecification;
	u16 size;
} __packed;

struct dmtf_measurement_block_header {
	u8 type; // DMTFSpecMeasurementValueType;
	u16 size; // DMTFSpecMeasurementValueSize;
} __packed;

struct dmtf_measurement_block_device_mode {
	u32 opmode_cap; //OperationalModeCapabilties;
	u32 opmode_sta; // OperationalModeState;
	u32 devmode_cap; // DeviceModeCapabilties;
	u32 devmode_sta; // DeviceModeState;
} __packed;

struct spdm_certchain_block_header {
	u16 length;
	u16 reserved;
} __packed;

/*
 * TDI Report Structure as defined in TDISP.
 */
struct tdi_report_header {
	union {
		u16 interface_info;
		struct {
			u16 no_fw_update:1; // firmware updates not permitted in CONFIG_LOCKED or RUN.
			u16 dma_no_pasid:1; // TDI generates DMA requests without PASID
			u16 dma_pasid:1; // TDI generates DMA requests with PASID
			u16 ats:1; //  ATS supported and enabled for the TDI
			u16 prs:1; //  PRS supported and enabled for the TDI
			u16 reserved1:11;
		};
	};
	u16 reserved2;
	u16 msi_x_message_control;
	u16 lnr_control;
	u32 tph_control;
	u32 mmio_range_count;
} __packed;

// Each MMIO Range of the TDI is reported with the MMIO reporting offset added.
// Base and size in units of 4K pages
struct tdi_report_mmio_range {
	u64 first_page; // First 4K page with offset added
	u32 num; // Number of 4K pages in this range
	union {
		u32 range_attributes;
		struct {
			u32 msix_table:1;
			u32 msix_pba:1;
			u32 is_non_tee_mem:1;
			u32 is_mem_attr_updatable:1;
			u32 reserved:12;
			u32 range_id:16;
		};
	};
} __packed;

struct tdi_report_footer {
	u32 device_specific_info_len; // No idea how to deal with this
	u8 device_specific_info[];
} __packed;

#define TDI_REPORT_HDR(rep)		((struct tdi_report_header *) ((rep)->data))
#define TDI_REPORT_MR_NUM(rep)		(TDI_REPORT_HDR(rep)->mmio_range_count)
#define TDI_REPORT_MR_OFF(rep)		((struct tdi_report_mmio_range *) (TDI_REPORT_HDR(rep) + 1))
#define TDI_REPORT_MR(rep, rangeid)	TDI_REPORT_MR_OFF(rep)[rangeid]
#define TDI_REPORT_FTR(rep)		((struct tdi_report_footer *) &TDI_REPORT_MR((rep), TDI_REPORT_MR_NUM(rep)))

/* Physical device descriptor responsible for IDE/TDISP setup */
struct tsm_dev {
	struct kref kref;
	const struct attribute_group *ag;
	struct pci_dev *pdev; /* Physical PCI function #0 */
	struct tsm_spdm spdm;
	struct mutex spdm_mutex;

	u8 tc_mask;
	u8 cert_slot;
	u8 connected;
	struct {
		u8 enabled : 1;
		u8 enable : 1;
		u8 def : 1;
		u8 dev_ide_cfg : 1;
		u8 dev_tee_limited : 1;
		u8 rootport_ide_cfg : 1;
		u8 rootport_tee_limited : 1;
		u8 id;
	} selective_ide[256];
	bool ide_pre;

	struct tsm_blob *meas;
	struct tsm_blob *certs;

	void *data; /* Platform specific data */
};

/* PCI function for passing through, can be the same as tsm_dev::pdev */
struct tsm_tdi {
	const struct attribute_group *ag;
	struct pci_dev *pdev;
	struct tsm_dev *tdev;

	u8 rseg;
	u8 rseg_valid;
	bool validated;

	struct tsm_blob *report;

	void *data; /* Platform specific data */

	u64 vmid;
	u32 asid;
	u16 guest_rid; /* BDFn of PCI Fn in the VM */
};

struct tsm_dev_status {
	u8 ctx_state;
	u8 tc_mask;
	u8 certs_slot;
	u16 device_id;
	u16 segment_id;
	u8 no_fw_update;
	u16 ide_stream_id[8];
};

enum tsm_spdm_algos {
	TSM_TDI_SPDM_ALGOS_DHE_SECP256R1,
	TSM_TDI_SPDM_ALGOS_DHE_SECP384R1,
	TSM_TDI_SPDM_ALGOS_AEAD_AES_128_GCM,
	TSM_TDI_SPDM_ALGOS_AEAD_AES_256_GCM,
	TSM_TDI_SPDM_ALGOS_ASYM_TPM_ALG_RSASSA_3072,
	TSM_TDI_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P256,
	TSM_TDI_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P384,
	TSM_TDI_SPDM_ALGOS_HASH_TPM_ALG_SHA_256,
	TSM_TDI_SPDM_ALGOS_HASH_TPM_ALG_SHA_384,
	TSM_TDI_SPDM_ALGOS_KEY_SCHED_SPDM_KEY_SCHEDULE,
};

enum tsm_tdisp_state {
	TDISP_STATE_UNAVAIL,
	TDISP_STATE_CONFIG_UNLOCKED,
	TDISP_STATE_CONFIG_LOCKED,
	TDISP_STATE_RUN,
	TDISP_STATE_ERROR,
};

struct tsm_tdi_status {
	bool valid;
	u8 meas_digest_fresh:1;
	u8 meas_digest_valid:1;
	u8 all_request_redirect:1;
	u8 bind_p2p:1;
	u8 lock_msix:1;
	u8 no_fw_update:1;
	u16 cache_line_size;
	u64 spdm_algos; /* Bitmask of (1<<TSM_TDI_SPDM_ALGOS_xxx) */
	u8 certs_digest[48];
	u8 meas_digest[48];
	u8 interface_report_digest[48];

	/* HV only */
	struct tdisp_interface_id id;
	u8 guest_report_id[16];
	enum tsm_tdisp_state state;
};

struct tsm_ops {
	/* HV hooks */
	int (*dev_connect)(struct tsm_dev *tdev, void *private_data);
	int (*dev_reclaim)(struct tsm_dev *tdev, void *private_data);
	int (*dev_status)(struct tsm_dev *tdev, void *private_data, struct tsm_dev_status *s);
	int (*ide_refresh)(struct tsm_dev *tdev, void *private_data);
	int (*tdi_bind)(struct tsm_tdi *tdi, u32 bdfn, u64 vmid, u32 asid, void *private_data);
	int (*tdi_reclaim)(struct tsm_tdi *tdi, void *private_data);

	int (*guest_request)(struct tsm_tdi *tdi, u32 guest_rid, u64 vmid, void *req_data,
			     enum tsm_tdisp_state *state, void *private_data);

	/* VM hooks */
	int (*tdi_validate)(struct tsm_tdi *tdi, bool invalidate, void *private_data);

	/* HV and VM hooks */
	int (*tdi_status)(struct tsm_tdi *tdi, void *private_data, struct tsm_tdi_status *ts);
};

void tsm_set_ops(struct tsm_ops *ops, void *private_data);
struct tsm_tdi *tsm_tdi_get(struct device *dev);
int tsm_tdi_bind(struct tsm_tdi *tdi, u32 guest_rid, u64 vmid, u32 asid);
void tsm_tdi_unbind(struct tsm_tdi *tdi);
int tsm_guest_request(struct tsm_tdi *tdi, enum tsm_tdisp_state *state, void *req_data);
struct tsm_tdi *tsm_tdi_find(u32 guest_rid, u64 vmid);

int pci_dev_tdi_validate(struct pci_dev *pdev);
ssize_t tsm_report_gen(struct tsm_blob *report, char *b, size_t len);

#endif /* LINUX_TSM_H */
