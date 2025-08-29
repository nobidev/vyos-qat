// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2020 - 2021 Intel Corporation */

#include <linux/firmware.h>
#include <linux/pci.h>
#include <linux/atomic.h>
#include "adf_accel_devices.h"
#include "adf_cfg.h"
#include "icp_qat_uclo.h"
#include "adf_common_drv.h"
#include "icp_qat_hw.h"
#include "adf_c4xxx_hw_data.h"
#include "adf_c4xxx_accel_units.h"

#define MMP_VERSION_LEN 4

/* Firmware Binary */
#define ADF_C4XXX_DC_OBJ "qat_c4xxx_dc.bin"
#define ADF_C4XXX_CY_OBJ "qat_c4xxx_cy.bin"
#define ADF_C4XXX_SYM_OBJ "qat_c4xxx_sym.bin"
#define ADF_C4XXX_DC_RL_OBJ "qat_c4xxx_dc_rl.bin"
#define ADF_C4XXX_CY_RL_OBJ "qat_c4xxx_cy_rl.bin"
#define ADF_C4XXX_SYM_RL_OBJ "qat_c4xxx_sym_rl.bin"
#define ADF_C4XXX_CY_CRC_OBJ "qat_c4xxx_cy_crc.bin"

/* Default accel firmware maximal object*/
#define ADF_C4XXX_MAX_OBJ 4

struct adf_mmp_version_s {
	u8 ver_val[MMP_VERSION_LEN];
};

static const char *get_obj_name(struct adf_accel_dev *accel_dev,
				enum adf_accel_unit_services service)
{
	u32 capabilities = GET_HW_DATA(accel_dev)->accel_capabilities_mask;
	bool sym_only_sku = false;
	bool rl_enabled = false;
	bool crc_enabled = false;

	if (capabilities & ICP_ACCEL_CAPABILITIES_RL)
		rl_enabled = true;

	if (capabilities & ICP_ACCEL_CAPABILITIES_CIPHER_CRC)
		crc_enabled = true;

	/* Check if SKU is capable only of symmetric cryptography
	 * via device capabilities.
	 */
	if ((capabilities & ADF_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC) &&
	    !(capabilities & ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC) &&
	    !(capabilities & ADF_ACCEL_CAPABILITIES_COMPRESSION))
		sym_only_sku = true;

	switch (service) {
	case ADF_ACCEL_CRYPTO:
		if (crc_enabled) {
			if (!rl_enabled)
				return ADF_C4XXX_CY_CRC_OBJ;
			dev_err(&GET_DEV(accel_dev), "Rate Limiting feature\t"
				"is not supported when Cipher-CRC is enabled\n");
			return NULL;
		}
		if (rl_enabled) {
			if (sym_only_sku)
				return ADF_C4XXX_SYM_RL_OBJ;
			else
				return ADF_C4XXX_CY_RL_OBJ;
		} else {
			if (sym_only_sku)
				return ADF_C4XXX_SYM_OBJ;
			return ADF_C4XXX_CY_OBJ;
		}
		break;
	case ADF_ACCEL_COMPRESSION:
		if (rl_enabled)
			return ADF_C4XXX_DC_RL_OBJ;
		return ADF_C4XXX_DC_OBJ;
	default:
		return NULL;
	}
}

static int32_t get_objs_num(struct adf_accel_dev *accel_dev)
{
	u32 srv;
	u32 max_srv_id = 0;
	unsigned long service_mask = accel_dev->hw_device->service_mask;

	/* The objects number corresponds to the number of services */
	for_each_set_bit(srv, &service_mask, ADF_C4XXX_MAX_OBJ) {
		max_srv_id = srv;
	}

	return (max_srv_id + 1);
}

static int32_t get_obj_cfg_ae_mask(struct adf_accel_dev *accel_dev,
				   enum adf_accel_unit_services service)
{
	u32 ae_mask = 0;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 num_au = get_num_accel_units_c4xxx(hw_data);
	struct adf_accel_unit *accel_unit = accel_dev->au_info->au;
	u32 i = 0;

	if (service == ADF_ACCEL_SERVICE_NULL)
		return 0;

	for (i = 0; i < num_au; i++) {
		if (accel_unit[i].services == service)
			ae_mask |= accel_unit[i].ae_mask;
	}
	return ae_mask;
}

int adf_ae_fw_load_c4xxx(struct adf_accel_dev *accel_dev)
{
	struct adf_fw_loader_data *loader_data = accel_dev->fw_loader;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	void *fw_addr, *mmp_addr;
	u32 fw_size, mmp_size;
	s32 i = 0;
	u32 max_objs = 1;
	char *obj_name = NULL;
	struct adf_mmp_version_s mmp_ver = { {0} };

	if (!hw_device->fw_name || !loader_data)
		return 0;

	if (request_firmware(&loader_data->mmp_fw, hw_device->fw_mmp_name,
			     &accel_dev->accel_pci_dev.pci_dev->dev)) {
		dev_err(&GET_DEV(accel_dev), "Failed to load MMP firmware %s\n",
			hw_device->fw_mmp_name);
		return -EFAULT;
	}
	if (request_firmware(&loader_data->uof_fw, hw_device->fw_name,
			     &accel_dev->accel_pci_dev.pci_dev->dev)) {
		dev_err(&GET_DEV(accel_dev), "Failed to load UOF firmware %s\n",
			hw_device->fw_name);
		goto out_err;
	}

	fw_size = loader_data->uof_fw->size;
	fw_addr = (void *)loader_data->uof_fw->data;
	mmp_size = loader_data->mmp_fw->size;
	mmp_addr = (void *)loader_data->mmp_fw->data;

	memcpy(&mmp_ver, mmp_addr, MMP_VERSION_LEN);

	accel_dev->fw_versions.mmp_version_major = mmp_ver.ver_val[0];
	accel_dev->fw_versions.mmp_version_minor = mmp_ver.ver_val[1];
	accel_dev->fw_versions.mmp_version_patch = mmp_ver.ver_val[2];

	if (hw_device->accel_capabilities_mask &
			ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC)
		if (qat_uclo_wr_mimage(loader_data->fw_loader, mmp_addr,
				       mmp_size)) {
			dev_err(&GET_DEV(accel_dev), "Failed to load MMP\n");
			goto out_err;
		}

	max_objs = get_objs_num(accel_dev);

	for (i = max_objs - 1; i >= 0; i--) {
		/* obj_name is used to indicate the firmware name in MOF,
		 * config unit0 must be loaded at end for authentication
		 */
		unsigned long service_mask = hw_device->service_mask;

		if (hw_device->service_mask &&
		    !(test_bit(i, &service_mask)))
			continue;
		obj_name = (char *)get_obj_name(accel_dev,
						BIT(i));
		if (!obj_name) {
			dev_err(&GET_DEV(accel_dev),
				"Invalid object (service = %lx)\n",
				BIT(i));
			goto out_err;
		}
		if (!get_obj_cfg_ae_mask(accel_dev, BIT(i)))
			continue;
		if (qat_uclo_set_cfg_ae_mask
			  (loader_data->fw_loader,
			   get_obj_cfg_ae_mask(accel_dev,
					       BIT(i)))) {
			dev_err(&GET_DEV(accel_dev),
				"Invalid config AE mask\n");
			goto out_err;
		}

		if (qat_uclo_map_obj(loader_data->fw_loader, fw_addr,
				     fw_size, obj_name)) {
			dev_err(&GET_DEV(accel_dev),
				"Failed to map UOF firmware\n");
			goto out_err;
		}
		if (qat_uclo_wr_all_uimage(loader_data->fw_loader)) {
			dev_err(&GET_DEV(accel_dev),
				"Failed to load UOF firmware\n");
			goto out_err;
		}
		qat_uclo_del_uof_obj(loader_data->fw_loader);
		obj_name = NULL;
	}

	return 0;

out_err:
	adf_ae_fw_release(accel_dev);
	return -EFAULT;
}
