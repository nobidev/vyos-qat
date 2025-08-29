// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2023 Intel Corporation */

#include "adf_cfg.h"
#include "adf_common_drv.h"
#include "icp_qat_hw.h"
#include "adf_gen3_hw_data.h"

int get_arbitrary_numvfs(struct adf_accel_dev *accel_dev,
			 const int numvfs)
{
	int totalvfs = pci_sriov_get_totalvfs(accel_to_pci_dev(accel_dev));
	u32 capabilities = GET_HW_DATA(accel_dev)->accel_capabilities_mask;

	/* Number of VF's to be enabled is restricted to 32 in case of
	 * RL enabled in gen3 device due to F/W limitation
	 */
	if (capabilities & ICP_ACCEL_CAPABILITIES_RL)
		totalvfs = ADF_GEN3_MAX_RL_VFS;

	return numvfs > totalvfs ? totalvfs : numvfs;
}
EXPORT_SYMBOL_GPL(get_arbitrary_numvfs);

static int check_rl_capability_gen3(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	unsigned long rl_enabled = 0;
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES] = {'\0'};
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {'\0'};

	strlcpy(key, ADF_RL_FIRMWARE_ENABLED, sizeof(key));
	if (!adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC, key, val))
		if (kstrtoul(val, 0, &rl_enabled))
			return -EFAULT;

	/* Get the services enabled by user */
	snprintf(key, sizeof(key), ADF_SERVICES_ENABLED);
	if (adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC, key, val))
		return -EFAULT;

	if (rl_enabled)
		hw_device->accel_capabilities_mask |=
			ICP_ACCEL_CAPABILITIES_RL;

	return 0;
}

static int check_sym_only_capability_gen3(u32 capabilities)
{

	/* Check if SKU is capable only of symmetric cryptography
	 * via device capabilities.
	 */
	if ((capabilities & ADF_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC) &&
	    !(capabilities & ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC) &&
	    !(capabilities & ADF_ACCEL_CAPABILITIES_COMPRESSION))
		return true;
	else
		return false;
}
static int check_cipher_crc_capability_gen3(struct adf_accel_dev *accel_dev,
					    unsigned long crc_enabled)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES] = {'\0'};
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {'\0'};
	u32 capabilities = GET_HW_DATA(accel_dev)->accel_capabilities_mask;
	char *token, *cur_str;

	/* Check if SKU is capable only of symmetric cryptography */
	if (check_sym_only_capability_gen3(capabilities)) {
		dev_err(&GET_DEV(accel_dev),
			"Cipher CRC is not supported with this configuration\n");
		return 0;
	}

	/* Get other services enabled by user */
	snprintf(key, sizeof(key), ADF_SERVICES_ENABLED);
	if (adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC, key, val))
		return -EFAULT;

	cur_str = val;
	token = strsep(&cur_str, ADF_SERVICES_SEPARATOR);
	while (token) {
		if (strncmp(token, ADF_CFG_CY, strlen(ADF_CFG_CY))) {
			crc_enabled = 0;
		} else {
			crc_enabled = 1;
			break;
		}
		token = strsep(&cur_str, ADF_SERVICES_SEPARATOR);
	}
	if (!crc_enabled) {
		dev_err(&GET_DEV(accel_dev),
			"Cipher CRC is not supported with this configuration\n");
		return 0;
	}
	hw_device->accel_capabilities_mask |=
		ICP_ACCEL_CAPABILITIES_CIPHER_CRC;

	return 0;
}

int adf_config_device_gen3(struct adf_accel_dev *accel_dev)
{
	struct adf_accel_pci *accel_pci_dev = &accel_dev->accel_pci_dev;
	unsigned long crc_enabled = 0;
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES] = {'\0'};
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {'\0'};
	int ret = -ENOMEM;

	if (ADF_C4XXX_PCI_DEVICE_ID == accel_pci_dev->pci_dev->device){
		snprintf(key, sizeof(key), ADF_CIPHER_CRC_FIRMWARE_ENABLED);
		if (!adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC, key, val))
			if (kstrtoul(val, 0, &crc_enabled))
				return -EFAULT;
	}

	if (adf_config_device(accel_dev))
		return ret;

	if (check_rl_capability_gen3(accel_dev))
		return ret;

	/* If Cipher-CRC is enabled by user check if configuration
	 * supports it
	 */
	if (crc_enabled)
		if (check_cipher_crc_capability_gen3(accel_dev, crc_enabled))
			return ret;

	return 0;
}
EXPORT_SYMBOL_GPL(adf_config_device_gen3);
int get_max_numvfs(struct adf_accel_dev *accel_dev)
{
	u32 capabilities = GET_HW_DATA(accel_dev)->accel_capabilities_mask;

	/* Number of VF's to be enabled is restricted to 32 in case of
	 * RL enabled in c4xxx device due to F/W limitation
	 */
	if (capabilities & ICP_ACCEL_CAPABILITIES_RL)
		return ADF_GEN3_MAX_RL_VFS;
	else
		return ADF_GEN3_ETR_MAX_BANKS;
}
EXPORT_SYMBOL_GPL(get_max_numvfs);

