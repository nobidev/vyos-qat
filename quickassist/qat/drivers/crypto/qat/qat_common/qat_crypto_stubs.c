// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2017, 2019, 2021 Intel Corporation */
#include "adf_common_drv.h"

int qat_crypto_dev_config(struct adf_accel_dev *accel_dev)
{
	dev_info(&GET_DEV(accel_dev), "QAT registration with LKCF disabled\n");
	set_bit(ADF_STATUS_CONFIGURED, &accel_dev->status);
	return 0;
}
EXPORT_SYMBOL_GPL(qat_crypto_dev_config);

int qat_crypto_vf_dev_config(struct adf_accel_dev *accel_dev)
{
	dev_info(&GET_DEV(accel_dev),
		 "QAT registration with LKCF disabled in  VF\n");
	set_bit(ADF_STATUS_CONFIGURED, &accel_dev->status);
	return 0;
}
EXPORT_SYMBOL_GPL(qat_crypto_vf_dev_config);

int qat_crypto_register(void)
{
	return 0;
}

int qat_crypto_unregister(void)
{
	return 0;
}

int qat_algs_register(void)
{
	return 0;
}

void qat_algs_unregister(void)
{
}

int qat_asym_algs_register(void)
{
	return 0;
}

void qat_asym_algs_unregister(void)
{
}

