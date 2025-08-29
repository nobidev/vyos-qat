/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2018, 2021 Intel Corporation */
#ifndef ADF_FW_COUNTERS_H_
#define ADF_FW_COUNTERS_H_

#include <linux/debugfs.h>
#include "adf_accel_devices.h"

int adf_fw_counters_add(struct adf_accel_dev *accel_dev);
void adf_fw_counters_remove(struct adf_accel_dev *accel_dev);

#endif
