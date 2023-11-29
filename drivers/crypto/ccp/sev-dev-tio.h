#ifndef __PSP_SEV_TIO_H__
#define __PSP_SEV_TIO_H__

#include <linux/tsm.h>
#include <uapi/linux/psp-sev.h>

#if defined(CONFIG_CRYPTO_DEV_SP_PSP) || defined(CONFIG_CRYPTO_DEV_SP_PSP_MODULE)

int sev_tio_cmd_buffer_len(int cmd);

typedef union {
	u64 sla;
	struct {
		u64 page_type : 1;
		u64 page_size : 1;
		u64 reserved1 : 10;
		u64 pfn : 40;
		u64 reserved2 : 12;
	};
} __packed sla_addr_t;

#define SEV_TIO_MAX_COMMAND_LENGTH	128
#define SEV_TIO_MAX_DATA_LENGTH		256

/* struct tsm_dev::data */
struct tsm_dev_tio {
	sla_addr_t dev_ctx;
	sla_addr_t req;
	sla_addr_t resp;
	sla_addr_t scratch;
	sla_addr_t output;
	struct sla_buffer_hdr *reqbuf; /* vmap'ed @req for DOE */
	struct sla_buffer_hdr *respbuf; /* vmap'ed @resp for DOE */

	int cmd;
	int psp_ret;
	u8 cmd_data[SEV_TIO_MAX_COMMAND_LENGTH];
	u8 data[SEV_TIO_MAX_DATA_LENGTH]; // Data page for SPDM-aware commands returning some data
};

/* struct tsm_tdi::data */
struct tsm_tdi_tio {
	sla_addr_t tdi_ctx;
	u64 gctx_paddr;

	u64 vmid;
	u32 asid;
};

#define SPDM_DOBJ_ID_NONE		0
#define SPDM_DOBJ_ID_REQ		1
#define SPDM_DOBJ_ID_RESP		2
/* SPDM_DOBJ_ID_SCRATCH			3  Cannot access this one at any time */
#define SPDM_DOBJ_ID_CERTIFICATE	4
#define SPDM_DOBJ_ID_MEASUREMENT	5
#define SPDM_DOBJ_ID_REPORT		6

void sev_tio_cleanup(void);

void tio_save_output(struct tsm_blob **blob, sla_addr_t sla, u32 dobjid);

int sev_tio_status(void);
int sev_tio_continue(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm);

int sev_tio_dev_measurements(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm);
int sev_tio_dev_certificates(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm);
int sev_tio_dev_create(struct tsm_dev_tio *dev_data, u16 device_id, u16 root_port_id, u8 segment_id);
int sev_tio_dev_connect(struct tsm_dev_tio *dev_data, u8 tc_mask, u8 cert_slot, struct tsm_spdm *spdm);
int sev_tio_dev_disconnect(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm);
int sev_tio_dev_reclaim(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm);
int sev_tio_dev_status(struct tsm_dev_tio *dev_data, struct tsm_dev_status *status);
int sev_tio_ide_refresh(struct tsm_dev_tio *dev_data, struct tsm_spdm *spdm);

int sev_tio_tdi_create(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, u16 dev_id,
		       u8 rseg, u8 rseg_valid);
void sev_tio_tdi_reclaim(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data);
int sev_tio_guest_request(void *data, u32 guest_rid, u64 gctx_paddr,
			  struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, struct tsm_spdm *spdm);

int sev_tio_tdi_bind(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, __u32 guest_rid, u64 gctx_paddr,
		struct tsm_spdm *spdm);
int sev_tio_tdi_unbind(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, struct tsm_spdm *spdm);

int sev_tio_asid_fence_clear(u16 device_id, u8 segment_id, u64 gctx_paddr, int *psp_ret);
int sev_tio_asid_fence_status(struct tsm_dev_tio *dev_data, u16 device_id, u8 segment_id, unsigned asid, bool *fenced);

int sev_tio_tdi_info(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, struct tsm_tdi_status *ts);
int sev_tio_tdi_status(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data, struct tsm_spdm *spdm);
int sev_tio_tdi_status_fin(struct tsm_dev_tio *dev_data, struct tsm_tdi_tio *tdi_data,
			   enum tsm_tdisp_state *state);

#endif	/* CONFIG_CRYPTO_DEV_SP_PSP */

#endif	/* __PSP_SEV_TIO_H__ */
