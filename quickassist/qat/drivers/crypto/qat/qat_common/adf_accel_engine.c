// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2014 - 2017, 2019 - 2021 Intel Corporation */
#include <linux/firmware.h>
#include <linux/pci.h>
#include "adf_cfg.h"
#include "adf_accel_devices.h"
#include "adf_common_drv.h"
#include "icp_qat_uclo.h"
#include "icp_qat_hw.h"

void adf_ae_fw_release(struct adf_accel_dev *accel_dev)
{
	struct adf_fw_loader_data *loader_data = accel_dev->fw_loader;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;

	if (!hw_device->fw_name)
		return;

	qat_uclo_del_uof_obj(loader_data->fw_loader);
	qat_hal_deinit(loader_data->fw_loader);
	loader_data->fw_loader = NULL;

	if (loader_data->mmp_fw) {
		release_firmware(loader_data->mmp_fw);
		loader_data->mmp_fw = NULL;
	}

	if (loader_data->uof_fw) {
		release_firmware(loader_data->uof_fw);
		loader_data->uof_fw = NULL;
	}
}
EXPORT_SYMBOL_GPL(adf_ae_fw_release);

int adf_ae_start(struct adf_accel_dev *accel_dev)
{
	struct adf_fw_loader_data *loader_data = accel_dev->fw_loader;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 ae_ctr = 0, ae = 0, max_aes = GET_MAX_ACCELENGINES(accel_dev);

	if (!hw_data->fw_name)
		return 0;

	for_each_set_bit(ae, &hw_data->ae_mask, max_aes) {
		qat_hal_start(loader_data->fw_loader, ae, 0xFF);
		ae_ctr++;
	}
	dev_info(&GET_DEV(accel_dev),
		 "qat_dev%d started %d acceleration engines\n",
		 accel_dev->accel_id, ae_ctr);
	return 0;
}

int adf_ae_stop(struct adf_accel_dev *accel_dev)
{
	struct adf_fw_loader_data *loader_data = accel_dev->fw_loader;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 ae_ctr = 0, ae = 0, max_aes = GET_MAX_ACCELENGINES(accel_dev);

	if (!hw_data->fw_name)
		return 0;

	for_each_set_bit(ae, &hw_data->ae_mask, max_aes) {
		qat_hal_stop(loader_data->fw_loader, ae, 0xFF);
		ae_ctr++;
	}
	dev_info(&GET_DEV(accel_dev),
		 "qat_dev%d stopped %d acceleration engines\n",
		 accel_dev->accel_id, ae_ctr);
	return 0;
}

static int adf_ae_reset(struct adf_accel_dev *accel_dev, int ae)
{
	struct adf_fw_loader_data *loader_data = accel_dev->fw_loader;

	qat_hal_reset(loader_data->fw_loader);
	if (qat_hal_clr_reset(loader_data->fw_loader))
		return -EFAULT;

	return 0;
}

int adf_ae_init(struct adf_accel_dev *accel_dev)
{
	struct adf_fw_loader_data *loader_data;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;

	if (!hw_device->fw_name)
		return 0;

	loader_data = kzalloc(sizeof(*loader_data), GFP_KERNEL);
	if (!loader_data)
		return -ENOMEM;

	accel_dev->fw_loader = loader_data;
	if (qat_hal_init(accel_dev)) {
		dev_err(&GET_DEV(accel_dev), "Failed to init the AEs\n");
		kfree(loader_data);
		return -EFAULT;
	}
	if (adf_ae_reset(accel_dev, 0)) {
		dev_err(&GET_DEV(accel_dev), "Failed to reset the AEs\n");
		qat_hal_deinit(loader_data->fw_loader);
		kfree(loader_data);
		return -EFAULT;
	}
	return 0;
}

int adf_ae_shutdown(struct adf_accel_dev *accel_dev)
{
	struct adf_fw_loader_data *loader_data = accel_dev->fw_loader;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;

	if (!hw_device->fw_name)
		return 0;

	qat_hal_deinit(loader_data->fw_loader);
	kfree(accel_dev->fw_loader);
	accel_dev->fw_loader = NULL;
	return 0;
}
