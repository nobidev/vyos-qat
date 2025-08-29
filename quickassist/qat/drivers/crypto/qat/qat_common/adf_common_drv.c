// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2022 Intel Corporation */

#include <linux/pci.h>
#include "adf_accel_devices.h"
#include "adf_common_drv.h"

/**
 * adf_unmap_pci_bars() - Unmap BARs for accelerator.
 * @accel_dev: Pointer to acceleration device.
 *
 * Unmaps all BARs for given device.
 */
void adf_unmap_pci_bars(struct adf_accel_dev *accel_dev)
{
	struct adf_accel_pci *accel_pci_dev = &accel_dev->accel_pci_dev;
	int i;

	for (i = 0; i < ADF_PCI_MAX_BARS; i++) {
		struct adf_bar *bar = &accel_pci_dev->pci_bars[i];

		if (bar->virt_addr) {
			pci_iounmap(accel_pci_dev->pci_dev, bar->virt_addr);
			bar->virt_addr = NULL;
		}
	}
}
EXPORT_SYMBOL_GPL(adf_unmap_pci_bars);

/**
 * adf_map_pci_bars() - Map BARs for accelerator.
 * @accel_dev: Pointer to acceleration device.
 *
 * Map all BARs for given device.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_map_pci_bars(struct adf_accel_dev *accel_dev)
{
	struct adf_accel_pci *accel_pci_dev = &accel_dev->accel_pci_dev;
	unsigned long bar_mask = 0;
	unsigned int bar_nr = 0;
	int ret = 0;

	bar_mask = pci_select_bars(accel_pci_dev->pci_dev, IORESOURCE_MEM);
	for_each_set_bit(bar_nr, &bar_mask, ADF_PCI_MAX_BARS * 2) {
		struct adf_bar *bar = &accel_pci_dev->pci_bars[bar_nr / 2];

		bar->base_addr =
			pci_resource_start(accel_pci_dev->pci_dev, bar_nr);
		bar->size = pci_resource_len(accel_pci_dev->pci_dev, bar_nr);
		if (!bar->base_addr || !bar->size)
			continue;
		bar->virt_addr = pci_iomap(accel_pci_dev->pci_dev, bar_nr, 0);
		if (!bar->virt_addr) {
			dev_err(&GET_DEV(accel_dev), "Failed to map BAR %d\n",
				bar_nr);
			ret = -EFAULT;
			adf_unmap_pci_bars(accel_dev);
			goto out;
		}
	}
out:
	return ret;
}
EXPORT_SYMBOL_GPL(adf_map_pci_bars);
