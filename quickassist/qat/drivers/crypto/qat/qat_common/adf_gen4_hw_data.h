/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2020 - 2021 Intel Corporation */

#ifndef ADF_GEN4_HW_DATA_H_
#define ADF_GEN4_HW_DATA_H_

#include "adf_accel_devices.h"

struct adf_hw_csr_ops;
struct adf_pfvf_ops;

void adf_gen4_init_hw_csr_ops(struct adf_hw_csr_ops *csr_ops);
void adf_gen4_set_ssm_wdtimer(struct adf_accel_dev *accel_dev);
void adf_gen4_init_pf_pfvf_ops(struct adf_pfvf_ops *pfvf_ops);
int adf_gen4_ring_pair_reset(struct adf_accel_dev *accel_dev, u32 bank_number);
bool adf_gen4_handle_pm_interrupt(struct adf_accel_dev *accel_dev);
int adf_gen4_enable_pm(struct adf_accel_dev *accel_dev);
int adf_sysfs_init(struct adf_accel_dev *accel_dev);

#endif /* ADF_GEN4_HW_DATA_H_ */
