/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2020 - 2021 Intel Corporation */

#ifndef ADF_C4XXX_ACCEL_UNITS_H_
#define ADF_C4XXX_ACCEL_UNITS_H_

#include <adf_accel_devices.h>

#define ADF_C4XXX_NUM_ACCEL_PER_AU 2
#define ADF_C4XXX_4_AE 4
#ifndef USER_SPACE
enum adf_accel_unit_services {
	ADF_ACCEL_SERVICE_NULL = 0,
	ADF_ACCEL_CRYPTO =  2,
	ADF_ACCEL_COMPRESSION =  4
};

struct adf_ae_info {
	u32 num_asym_thd;
	u32 num_sym_thd;
	u32 num_dc_thd;
};

struct adf_accel_unit {
	u8 au_mask;
	u32 accel_mask;
	u32 ae_mask;
	u32 comp_ae_mask;
	u32 num_ae;
	enum adf_accel_unit_services services;
};

struct adf_accel_unit_info {
	u32 sym_ae_msk;
	u32 asym_ae_msk;
	u32 num_pke_slices;
	u32 num_cipher_slices;
	u32 num_dc_slices;
	u32 dc_ae_msk;
	u8 num_cy_au;
	u8 num_dc_au;
	struct adf_accel_unit *au;
	const struct adf_ae_info *ae_info;
};
#endif

#define ADF_C4XXX_SKU1_MAX_DC_SLICES_FOR_RL (23)
#define ADF_C4XXX_SKU2_MAX_DC_SLICES_FOR_RL (15)
#define ADF_C4XXX_SKU3_MAX_DC_SLICES_FOR_RL (7)
#define ADF_C4XXX_SKU1_MAX_PKE_SLICES_FOR_RL (54)
#define ADF_C4XXX_SKU2_MAX_PKE_SLICES_FOR_RL (38)
#define ADF_C4XXX_SKU3_MAX_PKE_SLICES_FOR_RL (18)
#define ADF_C4XXX_SKU1_MAX_CIPHER_SLICES_FOR_RL (31)
#define ADF_C4XXX_SKU2_MAX_CIPHER_SLICES_FOR_RL (23)
#define ADF_C4XXX_SKU3_MAX_CIPHER_SLICES_FOR_RL (11)
#define ADF_C4XXX_DC_SLICES_PER_SSM (2)
#define ADF_C4XXX_PKE_SLICES_PER_SSM_4AE (4)
#define ADF_C4XXX_PKE_SLICES_PER_SSM_6AE (5)
#define ADF_C4XXX_PKE_SLICES_ADMIN (2)
#define ADF_C4XXX_ADMIN_ME (1)

#define ADF_C4XXX_LEGFUSE_BASE_SKU_MASK (BIT(2) | BIT(3))

/* Slice Hang enabling related registers  */
#define ADF_C4XXX_SHINTMASKSSM (0x1018)
#define ADF_C4XXX_SSMWDTL (0x54)
#define ADF_C4XXX_SSMWDTH (0x5C)
#define ADF_C4XXX_SSMWDTPKEL (0x58)
#define ADF_C4XXX_SSMWDTPKEH (0x60)
#define ADF_C4XXX_SHINTMASKSSM_VAL (0x00)

/* Return address of SHINTMASKSSM register for a given accelerator */
#define ADF_C4XXX_SHINTMASKSSM_OFFSET(accel) \
		(ADF_C4XXX_SHINTMASKSSM + ((accel) * 0x4000))

/* Set default value of Slice Hang watchdogs in clock cycles
 *
 * For symmetric cryptography and compression slices use 15 000 000 cycles
 */
#define ADF_C4XXX_SSM_WDT_64BIT_DEFAULT_VALUE 0xE4E1C0

/* For asymmetric cryptography slices use 51 000 000 cycles */
#define ADF_C4XXX_SSM_WDT_PKE_64BIT_DEFAULT_VALUE 0x30A32C0

/* Return address of SSMWDTL register for a given accelerator */
#define ADF_C4XXX_SSMWDTL_OFFSET(accel) \
		(ADF_C4XXX_SSMWDTL + ((accel) * 0x4000))

/* Return address of SSMWDTH register for a given accelerator */
#define ADF_C4XXX_SSMWDTH_OFFSET(accel) \
		(ADF_C4XXX_SSMWDTH + ((accel) * 0x4000))

/* Return address of SSMWDTPKEL register for a given accelerator */
#define ADF_C4XXX_SSMWDTPKEL_OFFSET(accel) \
		(ADF_C4XXX_SSMWDTPKEL + ((accel) * 0x4000))

/* Return address of SSMWDTPKEH register for a given accelerator */
#define ADF_C4XXX_SSMWDTPKEH_OFFSET(accel) \
		(ADF_C4XXX_SSMWDTPKEH + ((accel) * 0x4000))

int get_num_accel_units_c4xxx(struct adf_hw_device_data *self);
int adf_init_accel_units_c4xxx(struct adf_accel_dev *accel_dev);
void adf_exit_accel_units_c4xxx(struct adf_accel_dev *accel_dev);
int adf_configure_accel_units_c4xxx(struct adf_accel_dev *accel_dev);
void adf_enable_slice_hang_detection_c4xxx(struct adf_accel_dev *accel_dev);
int adf_set_ssm_wdtimer_c4xxx(struct adf_accel_dev *accel_dev);
int get_fw_image_type_c4xxx(struct adf_accel_dev *accel_dev,
			    enum adf_cfg_fw_image_type *fw_image_type);
u32 adf_get_slices_for_svc_c4xxx(struct adf_accel_dev *accel_dev,
				 enum adf_svc_type svc);
int adf_get_num_vfs_c4xxx(struct adf_accel_dev *accel_dev);
int adf_init_ae_config_c4xxx(struct adf_accel_dev *accel_dev);
void adf_exit_ae_config_c4xxx(struct adf_accel_dev *accel_dev);
#endif
