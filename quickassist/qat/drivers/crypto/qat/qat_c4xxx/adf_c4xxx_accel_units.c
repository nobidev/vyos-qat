// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2020 - 2021 Intel Corporation */

#include <linux/atomic.h>
#include <adf_accel_devices.h>
#include <adf_common_drv.h>
#include <adf_cfg.h>
#include <adf_gen3_hw_data.h>
#include "adf_c4xxx_hw_data.h"
#include "icp_qat_hw.h"
#include "adf_c4xxx_accel_units.h"
#include "adf_c4xxx_aram.h"
#include "adf_c4xxx_ras.h"
#include "adf_dev_err.h"
#include "adf_cfg_strings.h"
#include "adf_cfg_device.h"

/* accel unit information */
static struct adf_accel_unit adf_c4xxx_au_32_ae[] = {
	{0x1,  0x3,   0x3F,       0x1B,       6, ADF_ACCEL_SERVICE_NULL},
	{0x2,  0xC,   0xFC0,      0x6C0,      6, ADF_ACCEL_SERVICE_NULL},
	{0x4,  0x30,  0xF000,     0xF000,     4, ADF_ACCEL_SERVICE_NULL},
	{0x8,  0xC0,  0x3F0000,   0x1B0000,   6, ADF_ACCEL_SERVICE_NULL},
	{0x10, 0x300, 0xFC00000,  0x6C00000,  6, ADF_ACCEL_SERVICE_NULL},
	{0x20, 0xC00, 0xF0000000, 0xF0000000, 4, ADF_ACCEL_SERVICE_NULL}
};

static struct adf_accel_unit adf_c4xxx_au_24_ae[] = {
	{0x1,  0x3,   0x3F,       0x1B,       6, ADF_ACCEL_SERVICE_NULL},
	{0x2,  0xC,   0xFC0,      0x6C0,      6, ADF_ACCEL_SERVICE_NULL},
	{0x8,  0xC0,  0x3F0000,   0x1B0000,   6, ADF_ACCEL_SERVICE_NULL},
	{0x10, 0x300, 0xFC00000,  0x6C00000,  6, ADF_ACCEL_SERVICE_NULL},
};

static struct adf_accel_unit adf_c4xxx_au_12_ae[] = {
	{0x1,  0x3,   0x3F,       0x1B,       6, ADF_ACCEL_SERVICE_NULL},
	{0x8,  0xC0,  0x3F0000,   0x1B0000,   6, ADF_ACCEL_SERVICE_NULL},
};

/* Accel engine threads for each of the following services
 * <num_asym_thd> , <num_sym_thd> , <num_dc_thd>,
 */

/* Thread mapping for SKU capable of symmetric cryptography */
static const struct adf_ae_info adf_c4xxx_32_ae_sym[] = {
	{2, 6, 3}, {2, 6, 3}, {1, 7, 0}, {2, 6, 3},
	{2, 6, 3}, {1, 7, 0}, {2, 6, 3}, {2, 6, 3},
	{1, 7, 0}, {2, 6, 3}, {2, 6, 3}, {1, 7, 0},
	{2, 6, 3}, {2, 6, 3}, {2, 6, 3}, {2, 6, 3},
	{2, 6, 3}, {2, 6, 3}, {1, 7, 0}, {2, 6, 3},
	{2, 6, 3}, {1, 7, 0}, {2, 6, 3}, {2, 6, 3},
	{1, 7, 0}, {2, 6, 3}, {2, 6, 3}, {1, 7, 0},
	{2, 6, 3}, {2, 6, 3}, {2, 6, 3}, {2, 6, 3}
};

static const struct adf_ae_info adf_c4xxx_24_ae_sym[] = {
	{2, 6, 3}, {2, 6, 3}, {1, 7, 0}, {2, 6, 3},
	{2, 6, 3}, {1, 7, 0}, {2, 6, 3}, {2, 6, 3},
	{1, 7, 0}, {2, 6, 3}, {2, 6, 3}, {1, 7, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0},
	{2, 6, 3}, {2, 6, 3}, {1, 7, 0}, {2, 6, 3},
	{2, 6, 3}, {1, 7, 0}, {2, 6, 3}, {2, 6, 3},
	{1, 7, 0}, {2, 6, 3}, {2, 6, 3}, {1, 7, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}
};

static const struct adf_ae_info adf_c4xxx_12_ae_sym[] = {
	{2, 6, 3}, {2, 6, 3}, {1, 7, 0}, {2, 6, 3},
	{2, 6, 3}, {1, 7, 0}, {0, 0, 0}, {0, 0, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0},
	{2, 6, 3}, {2, 6, 3}, {1, 7, 0}, {2, 6, 3},
	{2, 6, 3}, {1, 7, 0}, {0, 0, 0}, {0, 0, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}
};

/* Thread mapping for SKU capable of asymmetric and symmetric cryptography */
static const struct adf_ae_info adf_c4xxx_32_ae[] = {
	{2, 5, 3}, {2, 5, 3}, {1, 6, 0}, {2, 5, 3},
	{2, 5, 3}, {1, 6, 0}, {2, 5, 3}, {2, 5, 3},
	{1, 6, 0}, {2, 5, 3}, {2, 5, 3}, {1, 6, 0},
	{2, 5, 3}, {2, 5, 3}, {2, 5, 3}, {2, 5, 3},
	{2, 5, 3}, {2, 5, 3}, {1, 6, 0}, {2, 5, 3},
	{2, 5, 3}, {1, 6, 0}, {2, 5, 3}, {2, 5, 3},
	{1, 6, 0}, {2, 5, 3}, {2, 5, 3}, {1, 6, 0},
	{2, 5, 3}, {2, 5, 3}, {2, 5, 3}, {2, 5, 3}
};

static const struct adf_ae_info adf_c4xxx_24_ae[] = {
	{2, 5, 3}, {2, 5, 3}, {1, 6, 0}, {2, 5, 3},
	{2, 5, 3}, {1, 6, 0}, {2, 5, 3}, {2, 5, 3},
	{1, 6, 0}, {2, 5, 3}, {2, 5, 3}, {1, 6, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0},
	{2, 5, 3}, {2, 5, 3}, {1, 6, 0}, {2, 5, 3},
	{2, 5, 3}, {1, 6, 0}, {2, 5, 3}, {2, 5, 3},
	{1, 6, 0}, {2, 5, 3}, {2, 5, 3}, {1, 6, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}
};

static const struct adf_ae_info adf_c4xxx_12_ae[] = {
	{2, 5, 3}, {2, 5, 3}, {1, 6, 0}, {2, 5, 3},
	{2, 5, 3}, {1, 6, 0}, {0, 0, 0}, {0, 0, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0},
	{2, 5, 3}, {2, 5, 3}, {1, 6, 0}, {2, 5, 3},
	{2, 5, 3}, {1, 6, 0}, {0, 0, 0}, {0, 0, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}
};

static const int sku_cy_au[] = ADF_C4XXX_NUM_CY_AU;
static const int sku_dc_au[] = ADF_C4XXX_NUM_DC_AU;

static void adf_update_hw_capability(struct adf_accel_dev *accel_dev)
{
	struct adf_accel_unit_info *au_info = accel_dev->au_info;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	u32 disabled_caps = 0;

	if (!au_info->asym_ae_msk)
		disabled_caps |= ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC
			| ICP_ACCEL_CAPABILITIES_ECEDMONT
			| ICP_ACCEL_CAPABILITIES_SM2;

	if (!au_info->sym_ae_msk)
		disabled_caps |= ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC
			| ICP_ACCEL_CAPABILITIES_CIPHER
			| ICP_ACCEL_CAPABILITIES_AUTHENTICATION
			| ICP_ACCEL_CAPABILITIES_ZUC
			| ICP_ACCEL_CAPABILITIES_CHACHA_POLY
			| ICP_ACCEL_CAPABILITIES_AESGCM_SPC
			| ICP_ACCEL_CAPABILITIES_SHA3_EXT
			| ICP_ACCEL_CAPABILITIES_SM3
			| ICP_ACCEL_CAPABILITIES_SM4;

	if (!au_info->dc_ae_msk) {
		disabled_caps |= ICP_ACCEL_CAPABILITIES_COMPRESSION
			| ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY;
		hw_device->extended_dc_capabilities = 0;
	}

	disabled_caps |= ICP_ACCEL_CAPABILITIES_INLINE;

	hw_device->accel_capabilities_mask =
		hw_device->accel_capabilities_mask & ~disabled_caps;
}

int get_num_accel_units_c4xxx(struct adf_hw_device_data *self)
{
	u32 i, num_accel = 0;
	unsigned long accel_mask = 0;

	if (!self || !self->accel_mask)
		return 0;

	accel_mask = self->accel_mask;

	for_each_set_bit(i, &accel_mask, ADF_C4XXX_MAX_ACCELERATORS) {
		num_accel++;
	}

	return num_accel / ADF_C4XXX_NUM_ACCEL_PER_AU;
}

static int get_accel_unit(struct adf_hw_device_data *self,
			  struct adf_accel_unit **accel_unit)
{
	enum dev_sku_info sku;

	sku = self->get_sku(self);

	switch (sku) {
	case DEV_SKU_1:
	case DEV_SKU_1_SYM:
		*accel_unit = adf_c4xxx_au_32_ae;
		break;
	case DEV_SKU_2:
	case DEV_SKU_2_SYM:
		*accel_unit = adf_c4xxx_au_24_ae;
		break;
	case DEV_SKU_3:
	case DEV_SKU_3_SYM:
		*accel_unit = adf_c4xxx_au_12_ae;
		break;
	default:
		*accel_unit = adf_c4xxx_au_12_ae;
		break;
	}
	return 0;
}

static int get_ae_info(struct adf_hw_device_data *self,
		       const struct adf_ae_info **ae_info)
{
	enum dev_sku_info sku;

	sku = self->get_sku(self);

	switch (sku) {
	case DEV_SKU_1:
		*ae_info = adf_c4xxx_32_ae;
		break;
	case DEV_SKU_1_SYM:
		*ae_info = adf_c4xxx_32_ae_sym;
		break;
	case DEV_SKU_2:
		*ae_info = adf_c4xxx_24_ae;
		break;
	case DEV_SKU_2_SYM:
		*ae_info = adf_c4xxx_24_ae_sym;
		break;
	case DEV_SKU_3:
		*ae_info = adf_c4xxx_12_ae;
		break;
	case DEV_SKU_3_SYM:
		*ae_info = adf_c4xxx_12_ae_sym;
		break;
	default:
		*ae_info = adf_c4xxx_12_ae;
		break;
	}

	return 0;
}

static int adf_check_svc_to_hw_capabilities(struct adf_accel_dev *accel_dev,
					    const char *svc_name,
					    enum icp_qat_capabilities_mask cap)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 hw_cap = hw_data->accel_capabilities_mask;

	hw_cap &= cap;
	if (hw_cap != cap) {
		dev_err(&GET_DEV(accel_dev),
			"Service not supported by accelerator: %s\n",
			svc_name);
		return -EFAULT;
	}

	return 0;
}

static int adf_check_accel_unit_config(struct adf_accel_dev *accel_dev,
				       u8 num_cy_au,
				       u8 num_dc_au)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES];
	u32 num_au = get_num_accel_units_c4xxx(hw_data);
	u32 service_mask = ADF_ACCEL_SERVICE_NULL;
	char *token, *cur_str;
	int ret = 0;

	/* Get the services enabled by user */
	snprintf(key, sizeof(key), ADF_SERVICES_ENABLED);
	if (adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC, key, val))
		return -EFAULT;
	cur_str = val;
	token = strsep(&cur_str, ADF_SERVICES_SEPARATOR);
	while (token) {
		if (!strncmp(token, ADF_CFG_CY,
			     strlen(ADF_CFG_CY))) {
			service_mask |= ADF_ACCEL_CRYPTO;
			ret |= adf_check_svc_to_hw_capabilities(accel_dev,
				token,
				ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC |
				ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC);
		}

		if (!strncmp(token, ADF_CFG_SYM,
			     strlen(ADF_CFG_SYM))) {
			service_mask |= ADF_ACCEL_CRYPTO;
			ret |= adf_check_svc_to_hw_capabilities(accel_dev,
				token,
				ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC);
		}

		if (!strncmp(token, ADF_CFG_ASYM,
			     strlen(ADF_CFG_ASYM))) {
				service_mask |= ADF_ACCEL_CRYPTO;

			ret |= adf_check_svc_to_hw_capabilities(accel_dev,
				token,
				ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC);
		}

		if (!strncmp(token, ADF_CFG_DC,
			     strlen(ADF_CFG_DC))) {
			service_mask |= ADF_ACCEL_COMPRESSION;
			ret |= adf_check_svc_to_hw_capabilities(accel_dev,
				token,
				ICP_ACCEL_CAPABILITIES_COMPRESSION);
		}
		token = strsep(&cur_str, ADF_SERVICES_SEPARATOR);
	}

	/* Ensure the user doesn't enable services that are not supported by
	 * accelerator.
	 */
	if (ret) {
		dev_err(&GET_DEV(accel_dev), "Invalid accelerator configuration.\n");
		return -EFAULT;
	}

	hw_data->service_mask = service_mask;
	/* Ensure the user doesn't allocate more than max accel units */
	if (num_au != (num_cy_au + num_dc_au)) {
		dev_err(&GET_DEV(accel_dev), "Invalid accel unit config.\n");
		dev_err(&GET_DEV(accel_dev), "Max accel units is %d\n", num_au);
		return -EFAULT;
	}

	/* Ensure user allocates hardware resources for enabled services */
	if (!num_cy_au && (service_mask & ADF_ACCEL_CRYPTO)) {
		dev_err(&GET_DEV(accel_dev), "Failed to enable cy service!\n");
		dev_err(&GET_DEV(accel_dev), "%s should not be 0\n",
			ADF_NUM_CY_ACCEL_UNITS);
		return -EFAULT;
	}
	if (!num_dc_au && (service_mask & ADF_ACCEL_COMPRESSION)) {
		dev_err(&GET_DEV(accel_dev), "Failed to enable dc service!\n");
		dev_err(&GET_DEV(accel_dev), "%s should not be 0\n",
			ADF_NUM_DC_ACCEL_UNITS);
			return -EFAULT;
	}
	return 0;
}

static int get_accel_unit_config(struct adf_accel_dev *accel_dev,
				 u8 *num_cy_au,
				 u8 *num_dc_au)
{
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES];

	*num_dc_au = 0;
	*num_cy_au = 0;

	/* Get the number of accel units allocated for each service */
	snprintf(key, sizeof(key), ADF_NUM_CY_ACCEL_UNITS);
	if (adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC, key, val))
		return -EFAULT;
	if (kstrtou8(val, 10, num_cy_au))
		return -EFAULT;

	snprintf(key, sizeof(key), ADF_NUM_DC_ACCEL_UNITS);
	if (adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC, key, val))
		return -EFAULT;
	if (kstrtou8(val, 10, num_dc_au))
		return -EFAULT;

	return 0;
}

static int adf_set_accel_unit_config(struct adf_accel_dev *accel_dev,
				     u8 num_cy_au, u8 num_dc_au)
{
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
	unsigned long val;

	snprintf(key, sizeof(key), ADF_NUM_CY_ACCEL_UNITS);
	val = num_cy_au;
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)&val, ADF_DEC))
		goto err;

	snprintf(key, sizeof(key), ADF_NUM_DC_ACCEL_UNITS);
	val = num_dc_au;
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)&val, ADF_DEC))
		goto err;


	dev_dbg(&GET_DEV(accel_dev),
		"Updated AU configuration to CY:%u, DC:%u\n",
		(unsigned int)num_cy_au, (unsigned int)num_dc_au);

	return 0;
err:
	dev_err(&GET_DEV(accel_dev), "Failed to configure accel units\n");
	return -EINVAL;
}

static int adf_set_ae_mask(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 num_au = get_num_accel_units_c4xxx(hw_data);
	struct adf_accel_unit_info *au_info = accel_dev->au_info;
	struct adf_accel_unit *accel_unit = accel_dev->au_info->au;
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES];
	char *token, *cur_str;
	bool asym_en = false, sym_en = false;
	u32 i;

	/* Get the services enabled by user */
	snprintf(key, sizeof(key), ADF_SERVICES_ENABLED);
	if (adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC, key, val))
		return -EFAULT;
	cur_str = val;
	token = strsep(&cur_str, ADF_SERVICES_SEPARATOR);
	while (token) {
		if (!strncmp(token, ADF_CFG_ASYM, strlen(ADF_CFG_ASYM)))
			asym_en = true;
		if (!strncmp(token, ADF_CFG_SYM, strlen(ADF_CFG_SYM)))
			sym_en = true;
		if (!strncmp(token, ADF_CFG_CY, strlen(ADF_CFG_CY))) {
			sym_en = true;
			asym_en = true;
		}
		token = strsep(&cur_str, ADF_SERVICES_SEPARATOR);
	}

	for (i = 0 ; i < num_au; i++) {
		if (accel_unit[i].services == ADF_ACCEL_CRYPTO) {
			/* AEs that support crypto can perform both
			 * symmetric and asymmetric crypto, however
			 * we only enable the threads if the relevant
			 * service is also enabled
			 */
			if (asym_en)
				au_info->asym_ae_msk |= accel_unit[i].ae_mask;
			if (sym_en)
				au_info->sym_ae_msk |= accel_unit[i].ae_mask;
		} else if (accel_unit[i].services == ADF_ACCEL_COMPRESSION) {
			au_info->dc_ae_msk |= accel_unit[i].comp_ae_mask;
		}
	}
	return 0;
}

static int adf_init_accel_unit_services(struct adf_accel_dev *accel_dev)
{
	u8 num_cy_au, num_dc_au;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 num_au = get_num_accel_units_c4xxx(hw_data);
	struct adf_accel_unit *accel_unit;
	const struct adf_ae_info *ae_info;
	int i;

	if (get_accel_unit_config(accel_dev, &num_cy_au, &num_dc_au)) {
		dev_err(&GET_DEV(accel_dev), "Invalid accel unit cfg\n");
		return -EFAULT;
	}

	if (adf_check_accel_unit_config(accel_dev, num_cy_au, num_dc_au))
		return -EFAULT;

	accel_dev->au_info = kzalloc(sizeof(*accel_dev->au_info), GFP_KERNEL);
	if (!accel_dev->au_info)
		return -ENOMEM;

	accel_dev->au_info->num_cy_au = num_cy_au;
	accel_dev->au_info->num_dc_au = num_dc_au;
	if (get_ae_info(hw_data, &ae_info)) {
		dev_err(&GET_DEV(accel_dev), "Failed to get ae info\n");
		goto err_au_info;
	}
	accel_dev->au_info->ae_info = ae_info;

	if (get_accel_unit(hw_data, &accel_unit)) {
		dev_err(&GET_DEV(accel_dev), "Failed to get accel unit\n");
		goto err_ae_info;
	}

	/* Enable compression accel units */
	/* Accel units with 4AEs are reserved for compression first */
	for (i = num_au - 1; i >= 0 && num_dc_au > 0; i--) {
		if (accel_unit[i].num_ae == ADF_C4XXX_4_AE) {
			accel_unit[i].services = ADF_ACCEL_COMPRESSION;
			num_dc_au--;
		}
	}
	for (i = num_au - 1; i >= 0 && num_dc_au > 0; i--) {
		if (accel_unit[i].services == ADF_ACCEL_SERVICE_NULL) {
			accel_unit[i].services = ADF_ACCEL_COMPRESSION;
			num_dc_au--;
		}
	}

	/* Enable crypto accel units */
	for (i = 0; i < num_au && num_cy_au > 0; i++) {
		if (accel_unit[i].services == ADF_ACCEL_SERVICE_NULL) {
			accel_unit[i].services = ADF_ACCEL_CRYPTO;
			num_cy_au--;
		}
	}

	for (i = 0; i < num_au; i++) {
		if (accel_unit[i].services == ADF_ACCEL_CRYPTO) {
			if (accel_unit[i].num_ae == ADF_C4XXX_4_AE)
				accel_dev->au_info->num_pke_slices +=
					ADF_C4XXX_PKE_SLICES_PER_SSM_4AE *
					ADF_C4XXX_NUM_ACCEL_PER_AU;
			else
				accel_dev->au_info->num_pke_slices +=
					ADF_C4XXX_PKE_SLICES_PER_SSM_6AE *
					ADF_C4XXX_NUM_ACCEL_PER_AU;
			accel_dev->au_info->num_cipher_slices +=
				accel_unit[i].num_ae;
		} else if (accel_unit[i].services == ADF_ACCEL_COMPRESSION) {
			accel_dev->au_info->num_dc_slices +=
				ADF_C4XXX_DC_SLICES_PER_SSM *
				ADF_C4XXX_NUM_ACCEL_PER_AU;
		}
	}
	accel_dev->au_info->au = accel_unit;
	return 0;

err_ae_info:
	accel_dev->au_info->ae_info = NULL;
err_au_info:
	kfree(accel_dev->au_info);
	accel_dev->au_info = NULL;
	return -EFAULT;
}

static void adf_exit_accel_unit_services(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 num_au = get_num_accel_units_c4xxx(hw_data);
	int i;

	if (!accel_dev->au_info) {
		return;
	}
	if (accel_dev->au_info->au) {
		for (i = 0; i < num_au; i++) {
			accel_dev->au_info->au[i].services =
				ADF_ACCEL_SERVICE_NULL;
		}
	}
	accel_dev->au_info->au = NULL;
	accel_dev->au_info->ae_info = NULL;
	kfree(accel_dev->au_info);
	accel_dev->au_info = NULL;
}

int adf_init_accel_units_c4xxx(struct adf_accel_dev *accel_dev)
{
	if (adf_init_accel_unit_services(accel_dev))
		return -EFAULT;

	/* Set cy and dc enabled AE masks */
	if (accel_dev->au_info->num_cy_au ||
	    accel_dev->au_info->num_dc_au) {
		if (adf_set_ae_mask(accel_dev)) {
			dev_err(&GET_DEV(accel_dev),
				"Failed to set ae masks\n");
			goto err_au;
		}
	}


	/* Define ARAM regions */
	if (adf_init_aram_config_c4xxx(accel_dev)) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to init aram config\n");
		goto err_au;
	}

	adf_update_hw_capability(accel_dev);

	/* Add Accel Unit configuration table to debugfs interface */
	if (adf_init_ae_config_c4xxx(accel_dev)) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to create entry for AE configuration\n");
		goto err_au;
	}

	return 0;

err_au:
	/* Free and clear accel unit data structures */
	adf_exit_accel_unit_services(accel_dev);
	return -EFAULT;
}

void adf_exit_accel_units_c4xxx(struct adf_accel_dev *accel_dev)
{
	adf_exit_accel_unit_services(accel_dev);
	/* Free aram mapping structure */
	adf_exit_aram_config_c4xxx(accel_dev);
	/* Remove Accel Unit configuration table from debugfs interface */
	adf_exit_ae_config_c4xxx(accel_dev);
}

int get_fw_image_type_c4xxx(struct adf_accel_dev *accel_dev,
			    enum adf_cfg_fw_image_type *fw_image_type)
{
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES];

	memcpy(val, ADF_SERVICES_DEFAULT_C4XXX,
	       sizeof(ADF_SERVICES_DEFAULT_C4XXX));
	dev_info(&GET_DEV(accel_dev),
		 "Enabling default configuration\n");
	adf_cfg_fw_string_to_id(val, accel_dev, &fw_image_type);

	return 0;
}
EXPORT_SYMBOL_GPL(get_fw_image_type_c4xxx);

static bool adf_check_sym_only_sku_c4xxx(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;
	u32 legfuse = 0;

	pci_read_config_dword(pdev, ADF_DEVICE_LEGFUSE_OFFSET,
			      &legfuse);

	if (legfuse & ADF_C4XXX_LEGFUSE_BASE_SKU_MASK)
		return true;
	else
		return false;
}

int adf_configure_accel_units_c4xxx(struct adf_accel_dev *accel_dev)
{
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES] = {0};
	char val_str[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	enum dev_sku_info sku = hw_data->get_sku(hw_data);
	u8 num_cy_au = 0, num_dc_au = 0;

	num_cy_au = sku_cy_au[sku];
	num_dc_au = sku_dc_au[sku];

	snprintf(key, sizeof(key), ADF_SERVICES_ENABLED);

	if (adf_cfg_section_add(accel_dev, ADF_GENERAL_SEC))
		goto err;

	/* Base station SKU supports symmetric cryptography only. */
	if (adf_check_sym_only_sku_c4xxx(accel_dev))
		snprintf(val_str, sizeof(val_str), ADF_CFG_SYM);
	else
		snprintf(val_str, sizeof(val_str), ADF_CFG_CY);

	if (num_dc_au) {
		strncat(val_str, ADF_SERVICES_SEPARATOR ADF_CFG_DC,
			ADF_CFG_MAX_VAL_LEN_IN_BYTES -
			strnlen(val_str, sizeof(val_str))
			- ADF_CFG_NULL_TERM_SIZE);
	}

	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)val_str, ADF_STR))
		goto err;

	if (adf_set_accel_unit_config(accel_dev, num_cy_au, num_dc_au))
		goto err;

	return 0;
err:
	dev_err(&GET_DEV(accel_dev), "Failed to configure accel units\n");
	return -EINVAL;
}

static inline void adf_unpack_ssm_wdtimer(u64 value, u32 *upper, u32 *lower)
{
	*lower = lower_32_bits(value);
	*upper = upper_32_bits(value);
}

/**
 * adf_set_ssm_wdtimer_c4xxx() - Initialize the slice hang watchdog timer.
 * @accel_dev: Structure holding accelerator data.
 *
 * @return 0 on success, error code otherwise.
 */
int adf_set_ssm_wdtimer_c4xxx(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	struct adf_bar *misc_bar =
		&GET_BARS(accel_dev)[hw_device->get_misc_bar_id(hw_device)];
	void __iomem *csr = misc_bar->virt_addr;
	unsigned long accel_mask = hw_device->accel_mask;
	u32 accel;
	u64 timer_val = ADF_C4XXX_SSM_WDT_64BIT_DEFAULT_VALUE;
	u64 timer_val_pke = ADF_C4XXX_SSM_WDT_PKE_64BIT_DEFAULT_VALUE;
	u32 ssm_wdt_low = 0, ssm_wdt_high = 0;
	u32 ssm_wdt_pke_low = 0, ssm_wdt_pke_high = 0;

	/* Convert 64bit Slice Hang watchdog value into 32bit values for
	 * mmio write to 32bit CSRs.
	 */
	adf_unpack_ssm_wdtimer(timer_val, &ssm_wdt_high, &ssm_wdt_low);
	adf_unpack_ssm_wdtimer(timer_val_pke, &ssm_wdt_pke_high,
			       &ssm_wdt_pke_low);

	/* Configures Slice Hang watchdogs */
	for_each_set_bit(accel, &accel_mask, ADF_C4XXX_MAX_ACCELERATORS) {
		ADF_CSR_WR(csr, ADF_C4XXX_SSMWDTL_OFFSET(accel),
			   ssm_wdt_low);
		ADF_CSR_WR(csr, ADF_C4XXX_SSMWDTH_OFFSET(accel),
			   ssm_wdt_high);
		ADF_CSR_WR(csr, ADF_C4XXX_SSMWDTPKEL_OFFSET(accel),
			   ssm_wdt_pke_low);
		ADF_CSR_WR(csr, ADF_C4XXX_SSMWDTPKEH_OFFSET(accel),
			   ssm_wdt_pke_high);
	}

	return 0;
}

void adf_enable_slice_hang_detection_c4xxx(struct adf_accel_dev *accel_dev)
{
	void __iomem *csr;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	u32 accel;
	unsigned long accel_mask;

	csr = (&GET_BARS(accel_dev)[ADF_C4XXX_PMISC_BAR])->virt_addr;
	accel_mask = hw_device->accel_mask;

	for_each_set_bit(accel, &accel_mask, ADF_C4XXX_MAX_ACCELERATORS) {
		/* Unmasks Slice Hang interrupts so they can be seen by IA. */
		ADF_CSR_WR(csr, ADF_C4XXX_SHINTMASKSSM_OFFSET(accel),
			   ADF_C4XXX_SHINTMASKSSM_VAL);
	}
}

u32 adf_get_slices_for_svc_c4xxx(struct adf_accel_dev *accel_dev,
				 enum adf_svc_type svc)
{
	if (svc == ADF_SVC_ASYM) {
		if (accel_dev->au_info->asym_ae_msk & 0x1)
			return accel_dev->au_info->num_pke_slices
				- ADF_C4XXX_PKE_SLICES_ADMIN;
		else
			return accel_dev->au_info->num_pke_slices;
	} else if (svc == ADF_SVC_SYM) {
		if (accel_dev->au_info->sym_ae_msk & 0x1)
			return accel_dev->au_info->num_cipher_slices
				- ADF_C4XXX_ADMIN_ME;
		else
			return accel_dev->au_info->num_cipher_slices;
	} else if (svc == ADF_SVC_DC) {
		if (accel_dev->au_info->dc_ae_msk & 0x1)
			return accel_dev->au_info->num_dc_slices
				- ADF_C4XXX_ADMIN_ME;
		else
			return accel_dev->au_info->num_dc_slices;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(adf_get_slices_for_svc_c4xxx);
