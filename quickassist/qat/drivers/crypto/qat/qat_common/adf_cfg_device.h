/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2017 - 2021 Intel Corporation */
#ifndef ADF_CFG_DEVICE_H_
#define ADF_CFG_DEVICE_H_

#include "adf_cfg.h"
#include "adf_cfg_instance.h"
#include "adf_common_drv.h"

static inline void adf_cfg_fw_string_to_id(char *str,
					   struct adf_accel_dev *accel_dev,
					   enum adf_cfg_fw_image_type **fw)
{
	if (!strncmp(str, ADF_SERVICES_DEFAULT,
		     sizeof(ADF_SERVICES_DEFAULT)))
		**fw = ADF_FW_IMAGE_DEFAULT;
	else if (!strncmp(str, ADF_SERVICES_CRYPTO,
			  sizeof(ADF_SERVICES_CRYPTO)))
		**fw = ADF_FW_IMAGE_CRYPTO;
	else if (!strncmp(str, ADF_SERVICES_COMPRESSION,
			  sizeof(ADF_SERVICES_COMPRESSION)))
		**fw = ADF_FW_IMAGE_COMPRESSION;
	else if (!strncmp(str, ADF_SERVICES_CUSTOM1,
			  sizeof(ADF_SERVICES_CUSTOM1)))
		**fw = ADF_FW_IMAGE_CUSTOM1;
	else if (!strncmp(str, ADF_SERVICES_DEFAULT_C4XXX,
			  sizeof(ADF_SERVICES_DEFAULT_C4XXX)))
		**fw = ADF_FW_IMAGE_DEFAULT_C4XXX;
	else
	{
		**fw = ADF_FW_IMAGE_DEFAULT;
		dev_warn(&GET_DEV(accel_dev),
			 "Invalid ServicesProfile: %s," \
			 "Using DEFAULT image\n", str);
	}
}

struct adf_cfg_device {
	/* contains all the bundles info */
	struct adf_cfg_bundle **bundles;
	/* contains all the instances info */
	struct adf_cfg_instance **instances;
	int bundle_num;
	int instance_index;
	char name[ADF_CFG_MAX_STR_LEN];
	int dev_id;
	int max_kernel_bundle_nr;
	u16 total_num_inst;
	u16 bundles_free;
};

int adf_cfg_get_ring_pairs(struct adf_cfg_device *device,
			   struct adf_cfg_instance *inst,
			   const char *process_name,
			   struct adf_accel_dev *accel_dev);

int adf_cfg_device_init(struct adf_cfg_device *device,
			struct adf_accel_dev *accel_dev);

void adf_cfg_device_clear(struct adf_cfg_device *device,
			  struct adf_accel_dev *accel_dev);

int adf_cfg_get_services_enabled(struct adf_accel_dev *accel_dev,
				 u16 *serv_ena_mask);

#endif /* !ADF_CFG_DEVICE_H_ */
