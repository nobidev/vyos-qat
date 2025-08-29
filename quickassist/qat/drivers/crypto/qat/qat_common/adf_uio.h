/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2015 - 2017, 2021 Intel Corporation */
#ifndef ADF_UIO_H
#define ADF_UIO_H
#include "adf_accel_devices.h"

struct qat_uio_bundle_dev {
	uint8_t hardware_bundle_number;
	struct adf_uio_control_bundle *bundle;
	struct adf_uio_control_accel *accel;
};

int adf_uio_register(struct adf_accel_dev *accel_dev);
void adf_uio_remove(struct adf_accel_dev *accel_dev);
int adf_uio_service_register(void);
int adf_uio_service_unregister(void);
int adf_ctl_ioctl_reserve_ring(unsigned long arg);
int adf_ctl_ioctl_release_ring(unsigned long arg);
int adf_ctl_ioctl_enable_ring(unsigned long arg);
int adf_ctl_ioctl_disable_ring(unsigned long arg);

#endif /* end of include guard: ADF_UIO_H */
