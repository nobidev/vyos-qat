/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2014 - 2023 Intel Corporation */
#ifndef ADF_ACCEL_DEVICES_H_
#define ADF_ACCEL_DEVICES_H_
#ifndef USER_SPACE
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/io.h>
#include <linux/ratelimit.h>
#include "adf_cfg_common.h"
#else
#include <stdbool.h>
#endif /* USER_SPACE */

#define NON_GPL_COMMON

#define ADF_DH895XCC_DEVICE_NAME "dh895xcc"
#define ADF_DH895XCCVF_DEVICE_NAME "dh895xccvf"
#define ADF_C62X_DEVICE_NAME "c6xx"
#define ADF_C62XVF_DEVICE_NAME "c6xxvf"
#define ADF_C3XXX_DEVICE_NAME "c3xxx"
#define ADF_C3XXXVF_DEVICE_NAME "c3xxxvf"
#define ADF_200XX_DEVICE_NAME "200xx"
#define ADF_200XXVF_DEVICE_NAME "200xxvf"
#define ADF_D15XX_DEVICE_NAME "d15xx"
#define ADF_D15XXVF_DEVICE_NAME "d15xxvf"
#define ADF_C4XXX_DEVICE_NAME "c4xxx"
#define ADF_C4XXXVF_DEVICE_NAME "c4xxxvf"
#define ADF_DH895XCC_PCI_DEVICE_ID 0x435
#define ADF_DH895XCCIOV_PCI_DEVICE_ID 0x443
#define ADF_C62X_PCI_DEVICE_ID 0x37c8
#define ADF_C62XIOV_PCI_DEVICE_ID 0x37c9
#define ADF_C3XXX_PCI_DEVICE_ID 0x19e2
#define ADF_C3XXXIOV_PCI_DEVICE_ID 0x19e3
#define ADF_200XX_PCI_DEVICE_ID 0x18ee
#define ADF_200XXIOV_PCI_DEVICE_ID 0x18ef
#define ADF_D15XX_PCI_DEVICE_ID 0x6f54
#define ADF_D15XXIOV_PCI_DEVICE_ID 0x6f55
#define ADF_C4XXX_PCI_DEVICE_ID 0x18a0
#define ADF_C4XXXIOV_PCI_DEVICE_ID 0x18a1

#define ADF_GEN3_WRKTHD2PARTMAP 0x82000
#define ADF_GEN3_WQM_SIZE 0x4
#define ADF_WRITE_CSR_WQM(csr_addr, csr_offset, index, value) \
	ADF_CSR_WR(csr_addr, \
	(csr_offset) + ((index) * \
	ADF_GEN3_WQM_SIZE), value)

static inline bool IS_QAT_GEN3(const unsigned int id)
{
	return (id == ADF_C4XXX_PCI_DEVICE_ID);
}

#if defined(CONFIG_PCI_IOV)
#define ADF_VF2PF_SET_SIZE 32
#define ADF_MAX_VF2PF_SET 4
#define ADF_VF2PF_SET_OFFSET(set_nr) ((set_nr) * ADF_VF2PF_SET_SIZE)
#define ADF_VF2PF_VFNR_TO_SET(vf_nr) ((vf_nr) / ADF_VF2PF_SET_SIZE)
#define ADF_VF2PF_VFNR_TO_MASK(vf_nr) \
	({ \
	u32 vf_nr_ = (vf_nr); \
	BIT((vf_nr_) - ADF_VF2PF_SET_SIZE * ADF_VF2PF_VFNR_TO_SET(vf_nr_)); \
	})
#endif

#define ADF_ADMINMSGUR_OFFSET (0x3A000 + 0x574)
#define ADF_ADMINMSGLR_OFFSET (0x3A000 + 0x578)
#define ADF_MAILBOX_BASE_OFFSET 0x20970
#define ADF_MAILBOX_STRIDE 0x1000
#define ADF_ADMINMSG_LEN 32
#define ADF_DEVICE_FUSECTL_OFFSET 0x40
#define ADF_DEVICE_LEGFUSE_OFFSET 0x4C
#define ADF_DEVICE_FUSECTL_MASK 0x80000000
#define ADF_PCI_MAX_BARS 3
#define ADF_DEVICE_NAME_LENGTH 32
#define ADF_ETR_MAX_RINGS_PER_BANK 16
#define ADF_MAX_MSIX_VECTOR_NAME 32
#define ADF_DEVICE_NAME_PREFIX "qat_"
#define ADF_STOP_RETRY 100
#define ADF_VF_SHUTDOWN_RETRY 100
#define ADF_PF_WAIT_RESTARTING_COMPLETE_DELAY 100
#define ADF_CFG_NUM_SERVICES 4
#define ADF_SRV_TYPE_BIT_LEN 3
#define ADF_SRV_TYPE_MASK 0x7
#define ADF_RINGS_PER_SRV_TYPE 2
#define ADF_THRD_ABILITY_BIT_LEN 4
#define ADF_THRD_ABILITY_MASK 0xf
#define ADF_VF_OFFSET 0x8
#define ADF_MAX_FUNC_PER_DEV 0x7
#define ADF_PCI_DEV_OFFSET 0x3

#define ADF_DEFAULT_RING_TO_SRV_MAP \
	(CRYPTO | CRYPTO << ADF_CFG_SERV_RING_PAIR_1_SHIFT | \
	NA << ADF_CFG_SERV_RING_PAIR_2_SHIFT | \
	COMP << ADF_CFG_SERV_RING_PAIR_3_SHIFT)

enum adf_accel_capabilities {
	ADF_ACCEL_CAPABILITIES_NULL = 0,
	ADF_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC = 1,
	ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC = 2,
	ADF_ACCEL_CAPABILITIES_CIPHER = 4,
	ADF_ACCEL_CAPABILITIES_AUTHENTICATION = 8,
	ADF_ACCEL_CAPABILITIES_COMPRESSION = 32,
	ADF_ACCEL_CAPABILITIES_DEPRECATED = 64,
	ADF_ACCEL_CAPABILITIES_RANDOM_NUMBER = 128
};

enum dev_sku_info {
	DEV_SKU_1 = 0,
	DEV_SKU_2,
	DEV_SKU_3,
	DEV_SKU_4,
	DEV_SKU_VF,
	DEV_SKU_1_SYM,
	DEV_SKU_2_SYM,
	DEV_SKU_3_SYM,
	DEV_SKU_UNKNOWN,
};

#ifndef USER_SPACE
struct adf_bar {
	resource_size_t base_addr;
	void __iomem *virt_addr;
	resource_size_t size;
};

struct adf_irq {
	bool enabled;
	char name[ADF_MAX_MSIX_VECTOR_NAME];
};

struct adf_accel_msix {
	struct msix_entry *entries;
	struct adf_irq *irqs;
	u32 num_entries;
};

struct adf_accel_pci {
	struct pci_dev *pci_dev;
	struct adf_accel_msix msix_entries;
	struct adf_bar pci_bars[ADF_PCI_MAX_BARS];
	enum dev_sku_info sku;
	u8 revid;
};
#endif /* USER_SPACE */

enum dev_state {
	DEV_DOWN = 0,
	DEV_UP
};

static inline const char *get_sku_info(enum dev_sku_info info)
{
	switch (info) {
	case DEV_SKU_1:
		return "SKU1";
	case DEV_SKU_1_SYM:
		return "SKU1SYM";
	case DEV_SKU_2:
		return "SKU2";
	case DEV_SKU_2_SYM:
		return "SKU2SYM";
	case DEV_SKU_3:
		return "SKU3";
	case DEV_SKU_3_SYM:
		return "SKU3SYM";
	case DEV_SKU_4:
		return "SKU4";
	case DEV_SKU_VF:
		return "SKUVF";
	case DEV_SKU_UNKNOWN:
	default:
		break;
	}
	return "Unknown SKU";
}

#ifndef USER_SPACE
struct adf_hw_aram_info {
	u32 reserved_0;
	u32 reserved_1;
	/* Initialise CY AE mask, "1" = AE is used for CY operations */
	u32 cy_ae_mask;
	/* Initialise DC AE mask, "1" = AE is used for DC operations */
	u32 dc_ae_mask;
	/* Number of long words used to define the ARAM regions */
	u32 num_aram_lw_entries;
	/* ARAM region definitions */
	u32 mmp_region_size;
	u32 mmp_region_offset;
	u32 skm_region_size;
	u32 skm_region_offset;
	/* Defines size and offset of compression intermediate buffers stored
	 * in ARAM (device's on-chip memory).
	 */
	u32 inter_buff_aram_region_size;
	u32 inter_buff_aram_region_offset;
	u32 sadb_region_size;
	u32 sadb_region_offset;
};

struct adf_hw_device_class {
	const char *name;
	const enum adf_device_type type;
	uint32_t instances;
};

struct adf_arb_info {
	u32 arbiter_offset;
	u32 wrk_thd_2_srv_arb_offset;
	u32 dbg_rst_arb_offset;
	u32 wrk_cfg_offset;
};

struct adf_admin_info {
	u32 admin_msg_ur;
	u32 admin_msg_lr;
	u32 mailbox_offset;
};

struct adf_cfg_device_data;
struct adf_accel_dev;
struct adf_etr_data;
struct adf_etr_ring_data;

struct sla_sku_dev {
	u32 ticks[ADF_MAX_SERVICES];
	u32 slau_supported[ADF_MAX_SERVICES];
	u8 svc_supported;
};

struct adf_dev_util_table {
	void *virt_addr;
	dma_addr_t dma_addr;
	u32 total_util;
};

struct adf_hw_device_data {
	struct adf_hw_device_class *dev_class;
	uint32_t (*get_accel_mask)(struct adf_accel_dev *accel_dev);
	uint32_t (*get_ae_mask)(struct adf_accel_dev *accel_dev);
	uint32_t (*get_sram_bar_id)(struct adf_hw_device_data *self);
	uint32_t (*get_misc_bar_id)(struct adf_hw_device_data *self);
	uint32_t (*get_etr_bar_id)(struct adf_hw_device_data *self);
	uint32_t (*get_num_aes)(struct adf_hw_device_data *self);
	uint32_t (*get_num_accels)(struct adf_hw_device_data *self);
	void (*notify_and_wait_ethernet)(struct adf_accel_dev *accel_dev);
	bool (*get_eth_doorbell_msg)(struct adf_accel_dev *accel_dev);
	uint32_t (*get_pf2vf_offset)(uint32_t i);
	uint32_t (*get_vintmsk_offset)(uint32_t i);
	u32 (*get_vintsou_offset)(void);
	void (*get_arb_info)(struct adf_arb_info *arb_csrs_info);
	void (*get_admin_info)(struct adf_admin_info *admin_csrs_info);
	int (*init_accel_units)(struct adf_accel_dev *accel_dev);
	void (*exit_accel_units)(struct adf_accel_dev *accel_dev);
	uint32_t (*get_clock_speed)(struct adf_hw_device_data *self);
	enum dev_sku_info (*get_sku)(struct adf_hw_device_data *self);
	u32 (*get_dc_ae_mask)(struct adf_accel_dev *accel_dev);
#if defined(CONFIG_PCI_IOV)
	void (*process_and_get_vf2pf_int)(void __iomem *pmisc_bar_addr,
					  u32 vf_int_mask[ADF_MAX_VF2PF_SET]);
	void (*enable_vf2pf_interrupts)(void __iomem *pmisc_bar_addr,
					u32 vf_mask_sets, u8 vf2pf_set);
	void (*disable_vf2pf_interrupts)(void __iomem *pmisc_bar_addr,
					 u32 vf_mask_sets, u8 vf2pf_set);
	int (*get_arbitrary_numvfs)(struct adf_accel_dev *accel_dev,
				    const int numvfs);
#endif
	int (*alloc_irq)(struct adf_accel_dev *accel_dev);
	void (*free_irq)(struct adf_accel_dev *accel_dev);
	void (*enable_error_correction)(struct adf_accel_dev *accel_dev);
	void (*disable_error_correction)(struct adf_accel_dev *accel_dev);
	int (*init_ras)(struct adf_accel_dev *accel_dev);
	void (*exit_ras)(struct adf_accel_dev *accel_dev);
	int (*check_uncorrectable_error)(struct adf_accel_dev *accel_dev);
	void (*print_err_registers)(struct adf_accel_dev *accel_dev);
	void (*disable_error_interrupts)(struct adf_accel_dev *accel_dev);
	bool (*ras_interrupts)(struct adf_accel_dev *accel_dev,
			       bool *reset_required);
	int (*init_admin_comms)(struct adf_accel_dev *accel_dev);
	void (*exit_admin_comms)(struct adf_accel_dev *accel_dev);
	int (*send_admin_init)(struct adf_accel_dev *accel_dev);
	int (*get_heartbeat_status)(struct adf_accel_dev *accel_dev);
	uint32_t (*get_ae_clock)(struct adf_hw_device_data *self);
	int (*fw_load)(struct adf_accel_dev *accel_dev);
	int (*get_ring_to_svc_map)(struct adf_accel_dev *accel_dev,
				   u16 *ring_to_svc_map);
	int (*get_fw_image_type)(struct adf_accel_dev *accel_dev,
				 enum adf_cfg_fw_image_type *fw_image_type);
	int (*get_fw_name)(struct adf_accel_dev *accel_dev, char *uof_name);
	void (*set_asym_rings_mask)(struct adf_accel_dev *accel_dev);
	int (*get_sla_units)(struct adf_accel_dev *accel_dev, u32 **sla_units);
	int (*calc_sla_units)(struct adf_accel_dev *accel_dev,
			      struct sla_sku_dev *sla_sku);
	u32 (*get_slices_for_svc)(struct adf_accel_dev *accel_dev,
				  enum adf_svc_type svc);
	int (*get_num_vfs)(struct adf_accel_dev *accel_dev);
	uint32_t (*get_accel_cap)(struct adf_accel_dev *accel_dev);
	int (*init_arb)(struct adf_accel_dev *accel_dev);
	void (*exit_arb)(struct adf_accel_dev *accel_dev);
	void (*disable_arb)(struct adf_accel_dev *accel_dev);
	void (*get_arb_mapping)(struct adf_accel_dev *accel_dev,
				const uint32_t **cfg);
	void (*disable_iov)(struct adf_accel_dev *accel_dev);
	void (*configure_iov_threads)(struct adf_accel_dev *accel_dev,
				      bool enable);
	void (*enable_ints)(struct adf_accel_dev *accel_dev);
	bool (*check_slice_hang)(struct adf_accel_dev *accel_dev);
	int (*set_ssm_wdtimer)(struct adf_accel_dev *accel_dev);
	int (*enable_vf2pf_comms)(struct adf_accel_dev *accel_dev);
	int (*disable_vf2pf_comms)(struct adf_accel_dev *accel_dev);
	void (*reset_device)(struct adf_accel_dev *accel_dev);
	void (*reset_hw_units)(struct adf_accel_dev *accel_dev);
	uint32_t (*set_default_frequency)(struct adf_accel_dev *accel_dev);
	int (*measure_clock)(struct adf_accel_dev *accel_dev);
	void (*pre_reset)(struct adf_accel_dev *accel_dev);
	void (*post_reset)(struct adf_accel_dev *accel_dev);
	int (*configure_accel_units)(struct adf_accel_dev *accel_dev);
	const char *fw_name;
	const char *fw_mmp_name;
	uint32_t fuses;
	uint32_t accel_capabilities_mask;
	uint32_t instance_id;
	u32 aerucm_mask;
	u32 service_mask;
	uint16_t tx_rings_mask;
	uint8_t tx_rx_gap;
	uint8_t num_banks;
	u8 num_rings_per_bank;
	uint8_t num_accel;
	uint8_t num_logical_accel;
	uint8_t num_engines;
	u32 extended_dc_capabilities;
	u32 clock_frequency;
	u16 ring_to_svc_map;
	u8 min_iov_compat_ver;
	bool reset_ack;
	unsigned long accel_mask;
	unsigned long ae_mask;
	u32 cipher_capabilities_mask;
	u32 hash_capabilities_mask;
	u32 asym_capabilities_mask;
	int (*config_device)(struct adf_accel_dev *accel_dev);
	u16 asym_rings_mask;
	bool is_du_supported;
	bool is_sla_supported;
};

/* helper enum for performing CSR operations */
enum operation {
	AND,
	OR,
};

/* CSR write macro */
#define ADF_CSR_WR(csr_base, csr_offset, val) \
	__raw_writel(val, (((u8 *)(csr_base)) + (csr_offset)))
/* 64-bit CSR write macro */
#define ADF_CSR_WR64(csr_base, csr_offset, val) \
	__raw_writeq(val, (((u8 *)(csr_base)) + (csr_offset)))

/* CSR read macro */
#define ADF_CSR_RD(csr_base, csr_offset) \
	__raw_readl(((u8 *)(csr_base)) + (csr_offset))

/* 64-bit CSR read macro */
#define ADF_CSR_RD64(csr_base, csr_offset) \
	__raw_readq(((u8 *)(csr_base)) + (csr_offset))

/* Macro applying a percentage to a value */
#define ADF_APPLY_PERCENTAGE(value, percentage) ((value * percentage) / 100)

/* Tolerance value in percent applied to both MIN and MAX AE frequencies
 * in clock frequency measurement
 */
#define ADF_AE_FREQ_TOLERANCE (1)

#define GET_DEV(accel_dev) ((accel_dev)->accel_pci_dev.pci_dev->dev)
#define GET_BARS(accel_dev) ((accel_dev)->accel_pci_dev.pci_bars)
#define GET_HW_DATA(accel_dev) (accel_dev->hw_device)
#define GET_MAX_BANKS(accel_dev) (GET_HW_DATA(accel_dev)->num_banks)
#define GET_DEV_SKU(accel_dev) (accel_dev->accel_pci_dev.sku)
#define GET_NUM_RINGS_PER_BANK(accel_dev) \
	(GET_HW_DATA(accel_dev)->num_rings_per_bank)
#define GET_MAX_ACCELENGINES(accel_dev) (GET_HW_DATA(accel_dev)->num_engines)
#define accel_to_pci_dev(accel_ptr) accel_ptr->accel_pci_dev.pci_dev
#define ADF_NUM_THREADS_PER_AE (8)
#define ADF_AE_ADMIN_THREAD (7)
#define ADF_NUM_PKE_STRAND (2)
#define ADF_AE_STRAND0_THREAD (8)
#define ADF_AE_STRAND1_THREAD (9)
#define ADF_NUM_HB_CNT_PER_AE (ADF_NUM_THREADS_PER_AE + ADF_NUM_PKE_STRAND)
#define GET_SRV_TYPE(ena_srv_mask, srv) \
	(((ena_srv_mask) >> (ADF_SRV_TYPE_BIT_LEN * (srv))) & ADF_SRV_TYPE_MASK)
#define GET_MAX_PROCESSES(accel_dev) \
	({ \
	typeof(accel_dev) dev = (accel_dev); \
	(GET_MAX_BANKS(dev) * (GET_NUM_RINGS_PER_BANK(dev) / 2)); \
	})
#define SET_ASYM_MASK(asym_mask, srv) \
	({ \
	typeof(srv) srv_ = (srv); \
	(asym_mask) |= \
	((1 << (srv_) * ADF_RINGS_PER_SRV_TYPE) | \
	 (1 << ((srv_) * ADF_RINGS_PER_SRV_TYPE + 1))); \
	})
#define GET_DU_TABLE(accel_dev) (accel_dev->du_table)

static inline void adf_csr_fetch_and_and(void __iomem *csr,
					 size_t offs, unsigned long mask)
{
	unsigned int val = ADF_CSR_RD(csr, offs);

	val &= mask;
	ADF_CSR_WR(csr, offs, val);
}

static inline void adf_csr_fetch_and_or(void __iomem *csr,
					size_t offs, unsigned long mask)
{
	unsigned int val = ADF_CSR_RD(csr, offs);

	val |= mask;
	ADF_CSR_WR(csr, offs, val);
}

static inline void
adf_csr_fetch_and_update(enum operation op, void __iomem *csr,
			 size_t offs, unsigned long mask)
{
	switch (op) {
	case AND:
		adf_csr_fetch_and_and(csr, offs, mask);
		break;
	case OR:
		adf_csr_fetch_and_or(csr, offs, mask);
		break;
	}
}

struct pfvf_stats {
	struct dentry *stats_file;
	/* Messages put in CSR */
	unsigned int tx;
	/* Messages read from CSR */
	unsigned int rx;
	/* Interrupt fired but int bit was clear */
	unsigned int spurious;
	/* Block messages sent */
	unsigned int blk_tx;
	/* Block messages received */
	unsigned int blk_rx;
	/* Blocks received with CRC errors */
	unsigned int crc_err;
	/* CSR in use by other side */
	unsigned int busy;
	/* Receiver did not acknowledge */
	unsigned int no_ack;
	/* Collision detected */
	unsigned int collision;
	/* Couldn't send a response */
	unsigned int tx_timeout;
	/* Didn't receive a response */
	unsigned int rx_timeout;
	/* Responses received */
	unsigned int rx_rsp;
	/* Messages re-transmitted */
	unsigned int retry;
	/* Event put timeout */
	unsigned int event_timeout;
};

#define NUM_PFVF_COUNTERS 14

struct adf_admin_comms {
	dma_addr_t phy_addr;
	dma_addr_t const_tbl_addr;
	dma_addr_t aram_map_phys_addr;
	dma_addr_t phy_hb_addr;
	void *virt_addr;
	void *virt_tbl_addr;
	void *virt_hb_addr;
	void __iomem *mailbox_addr;
	struct mutex lock;	/* protects adf_admin_comms struct */
};

struct icp_qat_fw_loader_handle;
struct adf_fw_loader_data {
	struct icp_qat_fw_loader_handle *fw_loader;
	const struct firmware *uof_fw;
	const struct firmware *mmp_fw;
};

struct adf_accel_vf_info {
	struct adf_accel_dev *accel_dev;
	struct mutex pf2vf_lock; /* protect CSR access for PF2VF messages */
	struct ratelimit_state vf2pf_ratelimit;
	u32 vf_nr;
	bool init;
	u8 compat_ver;
	struct pfvf_stats pfvf_counters;
#ifdef QAT_DBG
	struct dentry *debugfs_dir;
	struct qatd_dentry_config *qatd_config;
	u32 qatd_instance_id;
	struct adf_accel_dev *qatd_fake_dev;
#endif
};

struct adf_fw_versions {
	u8 fw_version_major;
	u8 fw_version_minor;
	u8 fw_version_patch;
	u8 mmp_version_major;
	u8 mmp_version_minor;
	u8 mmp_version_patch;
};

#define ADF_COMPAT_CHECKER_MAX 8
typedef int (*adf_iov_compat_checker_t)(struct adf_accel_dev *accel_dev,
					u8 vf_compat_ver);
struct adf_accel_compat_manager {
	u8 num_chker;
	adf_iov_compat_checker_t iov_compat_checkers[ADF_COMPAT_CHECKER_MAX];
};

struct adf_heartbeat;
struct adf_ver;
struct adf_uio_control_accel;
struct qat_uio_pci_dev;
struct adf_accel_dev {
	struct adf_hw_aram_info *aram_info;
	struct adf_accel_unit_info *au_info;
	struct adf_etr_data *transport;
	struct adf_hw_device_data *hw_device;
	struct adf_cfg_device_data *cfg;
	struct adf_fw_loader_data *fw_loader;
	struct adf_admin_comms *admin;
	struct adf_heartbeat *heartbeat;
	struct adf_ver *pver;
	unsigned int autoreset_on_error;
	atomic_t ref_count;
	struct list_head crypto_list;
	atomic_t *ras_counters;
	unsigned long status;
	struct dentry *debugfs_dir;
	struct dentry *clock_dbgfile;
	struct dentry *fw_cntr_dbgfile;
	struct dentry *cnvnr_dbgfile;
	struct dentry *pfvf_dbgdir;
	struct dentry *misc_error_dbgfile;
	struct dentry *pke_replay_dbgfile;
	struct dentry *debugfs_ae_config;
	struct list_head list;
	struct adf_accel_pci accel_pci_dev;
	struct module *owner;
	struct adf_accel_compat_manager *cm;
	u8 compat_ver;
	struct adf_fw_versions fw_versions;
	bool is_vf;
	union {
		struct {
			/* vf_info is non-zero when SR-IOV is init'ed */
			struct adf_accel_vf_info *vf_info;
			struct workqueue_struct *resp_wq;
		} pf;
		struct {
			struct workqueue_struct *pf2vf_wq;
			struct workqueue_struct *resp_wq;
			struct work_struct pf2vf_bh_wq;
			struct mutex vf2pf_lock; /* protect CSR access */
			struct completion iov_msg_completion;
			struct pfvf_stats pfvf_counters;
			struct completion err_notified;
			char *irq_name;
			bool irq_enabled;
			bool is_err_notified;
			uint8_t compatible;
			uint8_t pf_version;
			u8 pf2vf_block_byte;
			u8 pf2vf_block_resp_type;
		} vf;
	};
	u32 accel_id;
	spinlock_t vf2pf_csr_lock; /* protects VF2PF CSR access */
	void *lac_dev;
	struct adf_uio_control_accel *accel;
	struct qat_uio_pci_dev *uiodev;
	unsigned int num_ker_bundles;
	struct sla_sku_dev sla_sku;
	u32 *available_slau;
	u16 *sla_ids;
	struct adf_dev_util_table du_table;
	struct list_head sla_list;
#ifdef QAT_DBG
	struct qatd_dentry_config *qatd_config;
	struct qatd_instance *qatd_instance;
#endif /* QAT_DBG */
	bool is_user_bundle_dist_needed;
	bool is_drv_rm;
};
#endif
#endif
