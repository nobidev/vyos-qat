// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2021 Intel Corporation */

#include <linux/module.h>
#include <linux/pci.h>

#include "adf_accel_devices.h"
#include "adf_gen4_hw_data.h"

const struct pci_error_handlers adf_err_handler = {
	/* do nothing */
};
EXPORT_SYMBOL_GPL(adf_err_handler);

void adf_gen4_init_hw_csr_ops(struct adf_hw_csr_ops *csr_ops)
{
	/* do nothing */
	asm volatile("nop");
}
EXPORT_SYMBOL_GPL(adf_gen4_init_hw_csr_ops);

void adf_gen4_set_ssm_wdtimer(struct adf_accel_dev *accel_dev)
{
	/* do nothing */
	asm volatile("nop");
}
EXPORT_SYMBOL_GPL(adf_gen4_set_ssm_wdtimer);

void adf_gen4_init_pf_pfvf_ops(struct adf_pfvf_ops *pfvf_ops)
{
	/* do nothing */
	asm volatile("nop");
}
EXPORT_SYMBOL_GPL(adf_gen4_init_pf_pfvf_ops);

int adf_gen4_ring_pair_reset(struct adf_accel_dev *accel_dev, u32 bank_number)
{
	/* do nothing */
	return 0;
}
EXPORT_SYMBOL_GPL(adf_gen4_ring_pair_reset);

bool adf_gen4_handle_pm_interrupt(struct adf_accel_dev *accel_dev)
{
	/* do nothing */
	return true;
}
EXPORT_SYMBOL_GPL(adf_gen4_handle_pm_interrupt);

int adf_gen4_enable_pm(struct adf_accel_dev *accel_dev)
{
	/*do nothing */
	return 0;
}
EXPORT_SYMBOL_GPL(adf_gen4_enable_pm);

int adf_sysfs_init(struct adf_accel_dev *accel_dev)
{
	/*do nothing */
	return 0;
}
EXPORT_SYMBOL_GPL(adf_sysfs_init);
