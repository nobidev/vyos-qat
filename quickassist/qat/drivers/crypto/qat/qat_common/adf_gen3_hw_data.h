/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2023 Intel Corporation */

#ifndef ADF_GEN3_HW_DATA_H_
#define ADF_GEN3_HW_DATA_H_

#include "adf_accel_devices.h"

#define ADF_GEN3_MAX_RL_VFS 32
#define ADF_GEN3_ETR_MAX_BANKS 128

int get_arbitrary_numvfs(struct adf_accel_dev *accel_dev,
			 const int numvfs);
int get_max_numvfs(struct adf_accel_dev *accel_dev);

int adf_config_device_gen3(struct adf_accel_dev *accel_dev);
#endif
