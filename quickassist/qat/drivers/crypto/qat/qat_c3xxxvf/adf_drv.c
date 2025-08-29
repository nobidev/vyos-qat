// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2015 - 2021 Intel Corporation */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/workqueue.h>
#include <linux/io.h>
#include <adf_accel_devices.h>
#include <adf_common_drv.h>
#include <adf_cfg.h>
#include "adf_c3xxxvf_hw_data.h"

#define ADF_SYSTEM_DEVICE(device_id) \
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, device_id)}

static const struct pci_device_id adf_pci_tbl[] = {
	ADF_SYSTEM_DEVICE(ADF_C3XXXIOV_PCI_DEVICE_ID),
	{0,}
};
MODULE_DEVICE_TABLE(pci, adf_pci_tbl);

static struct adf_cfg_depot_list adf_cfg_depot_lists[ADF_MAX_DEVICES];
static unsigned int adf_disconnect_status[ADF_MAX_DEVICES];
static int adf_probe(struct pci_dev *dev, const struct pci_device_id *ent);
static void adf_remove(struct pci_dev *dev);

static struct pci_driver adf_driver = {
	.id_table = adf_pci_tbl,
	.name = ADF_C3XXXVF_DEVICE_NAME,
	.probe = adf_probe,
	.remove = adf_remove,
};

static void adf_cleanup_pci_dev(struct adf_accel_dev *accel_dev)
{
	pci_release_regions(accel_dev->accel_pci_dev.pci_dev);
	pci_disable_device(accel_dev->accel_pci_dev.pci_dev);
}

static void adf_cleanup_accel(struct adf_accel_dev *accel_dev)
{
	struct adf_accel_pci *accel_pci_dev = &accel_dev->accel_pci_dev;
	struct adf_accel_dev *pf;

	adf_unmap_pci_bars(accel_dev);

	pf = adf_devmgr_pci_to_accel_dev(accel_pci_dev->pci_dev->physfn);
	adf_devmgr_rm_dev(accel_dev, pf);

	if (accel_dev->hw_device) {
		switch (accel_pci_dev->pci_dev->device) {
		case ADF_C3XXXIOV_PCI_DEVICE_ID:
			adf_clean_hw_data_c3xxxiov(accel_dev->hw_device);
			break;
		default:
			break;
		}
		kfree(accel_dev->hw_device);
		accel_dev->hw_device = NULL;
	}
	debugfs_remove_recursive(accel_dev->pfvf_dbgdir);
	adf_cfg_dev_remove(accel_dev);
	debugfs_remove(accel_dev->debugfs_dir);
}

static int adf_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct adf_accel_dev *accel_dev;
	struct adf_accel_dev *pf;
	struct adf_accel_pci *accel_pci_dev;
	struct adf_hw_device_data *hw_data;
	struct list_head *cfg_list;
	char name[ADF_DEVICE_NAME_LENGTH];
	int ret = 0;

	switch (ent->device) {
	case ADF_C3XXXIOV_PCI_DEVICE_ID:
		break;
	default:
		dev_err(&pdev->dev, "Invalid device 0x%x.\n", ent->device);
		return -ENODEV;
	}

	accel_dev = kzalloc_node(sizeof(*accel_dev), GFP_KERNEL,
				 dev_to_node(&pdev->dev));
	if (!accel_dev)
		return -ENOMEM;

	accel_dev->is_vf = true;
	pf = adf_devmgr_pci_to_accel_dev(pdev->physfn);
	accel_pci_dev = &accel_dev->accel_pci_dev;
	accel_pci_dev->pci_dev = pdev;

	/* Add accel device to accel table */
	if (adf_devmgr_add_dev(accel_dev, pf)) {
		dev_err(&pdev->dev, "Failed to add new accelerator device.\n");
		kfree(accel_dev);
		return -EFAULT;
	}
	INIT_LIST_HEAD(&accel_dev->crypto_list);

	accel_dev->owner = THIS_MODULE;
	/* Allocate and configure device configuration structure */
	hw_data = kzalloc_node(sizeof(*hw_data), GFP_KERNEL,
			       dev_to_node(&pdev->dev));
	if (!hw_data) {
		ret = -ENOMEM;
		goto out_err;
	}
	accel_dev->hw_device = hw_data;
	adf_init_hw_data_c3xxxiov(accel_dev->hw_device);
	pci_read_config_byte(pdev, PCI_REVISION_ID, &accel_pci_dev->revid);
	pci_read_config_dword(pdev, ADF_C3XXX_VFFUSECTL_OFFSET,
			      &hw_data->fuses);

	/* Get Accelerators and Accelerators Engines masks */
	hw_data->accel_mask = hw_data->get_accel_mask(accel_dev);
	hw_data->ae_mask = hw_data->get_ae_mask(accel_dev);
	accel_pci_dev->sku = hw_data->get_sku(hw_data);

	/* Create dev top level debugfs entry */
	snprintf(name, sizeof(name), "%s%s_" ADF_PCI_ADDR_FORMAT,
		 ADF_DEVICE_NAME_PREFIX, hw_data->dev_class->name,
		 pci_domain_nr(accel_to_pci_dev(accel_dev)->bus),
		 pdev->bus->number, PCI_SLOT(pdev->devfn),
		 PCI_FUNC(pdev->devfn));

	accel_dev->debugfs_dir = debugfs_create_dir(name, NULL);
	if (!accel_dev->debugfs_dir) {
		dev_err(&pdev->dev, "Could not create debugfs dir %s\n", name);
		ret = -EINVAL;
		goto out_err;
	}
	adf_pfvf_debugfs_add(accel_dev);

	/* Create device configuration table */
	ret = adf_cfg_dev_add(accel_dev);
	if (ret)
		goto out_err;

	/* enable PCI device */
	if (pci_enable_device(pdev)) {
		ret = -EFAULT;
		goto out_err;
	}

	/* set dma identifier */
	if (pci_set_dma_mask(pdev, DMA_BIT_MASK(48))) {
		if ((pci_set_dma_mask(pdev, DMA_BIT_MASK(32)))) {
			dev_err(&pdev->dev, "No usable DMA configuration\n");
			ret = -EFAULT;
			goto out_err_disable;
		} else {
			pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		}

	} else {
		pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	}

	if (pci_request_regions(pdev, ADF_C3XXXVF_DEVICE_NAME)) {
		ret = -EFAULT;
		goto out_err_disable;
	}

	if (hw_data->get_accel_cap) {
		hw_data->accel_capabilities_mask =
			hw_data->get_accel_cap(accel_dev);
	}

	/* Find and map all the device's BARS */
	ret = adf_map_pci_bars(accel_dev);
	if (ret)
		goto out_err_free_reg;

	pci_set_master(pdev);
	/* Completion for VF2PF request/response message exchange */
	init_completion(&accel_dev->vf.iov_msg_completion);
	/* Completion for error notifed to userspace */
	init_completion(&accel_dev->vf.err_notified);
	accel_dev->vf.is_err_notified = false;

	if (adf_disconnect_status[accel_dev->accel_id]) {
		dev_info(&GET_DEV(accel_dev), "Device attach\n");
		ret = adf_cfg_depot_restore_all(accel_dev, adf_cfg_depot_lists);
		if (ret)
			goto out_err_free_reg;
		adf_cfg_get_accel_algo_cap(accel_dev);
	} else {
		cfg_list = &adf_cfg_depot_lists[accel_dev->accel_id].sec_list;
		INIT_LIST_HEAD(cfg_list);
	}

	ret = adf_dev_init(accel_dev);
	if (ret)
		goto out_err_dev_shutdown;

	ret = adf_dev_start(accel_dev);
	if (ret)
		goto out_err_dev_stop;

	if (adf_disconnect_status[accel_dev->accel_id]) {
		adf_dev_restarted_notify(accel_dev);
		adf_disconnect_status[accel_dev->accel_id] = 0;
	}

	return ret;

out_err_dev_stop:
	adf_dev_stop(accel_dev);
out_err_dev_shutdown:
	adf_dev_shutdown(accel_dev);
out_err_free_reg:
	pci_release_regions(accel_pci_dev->pci_dev);
out_err_disable:
	pci_disable_device(accel_pci_dev->pci_dev);
out_err:
	adf_cleanup_accel(accel_dev);
	kfree(accel_dev);
	return ret;
}

static void adf_remove(struct pci_dev *pdev)
{
	struct adf_accel_dev *accel_dev = adf_devmgr_pci_to_accel_dev(pdev);
	struct list_head *cfg_list;

	if (!accel_dev) {
		pr_err("QAT: Driver removal failed\n");
		return;
	}
	cfg_list = &adf_cfg_depot_lists[accel_dev->accel_id].sec_list;
	adf_disable_pf2vf_interrupts(accel_dev);
	adf_flush_vf_wq();

	/*
	 * Don't return here to have a consistent behavior with
	 * other device drivers.
	 */
	if (!accel_dev->is_drv_rm) {
		dev_info(&GET_DEV(accel_dev), "Device removal\n");
		adf_disconnect_status[accel_dev->accel_id] = 1;
		adf_error_notifier((uintptr_t)accel_dev);

		if (adf_dev_restarting_notify_sync(accel_dev))
			adf_disconnect_status[accel_dev->accel_id] = 0;

		if (adf_cfg_depot_save_all(accel_dev, adf_cfg_depot_lists))
			dev_warn(&GET_DEV(accel_dev),
				 "Failed to save device configuration\n");
	} else {
		adf_cfg_depot_del_all(cfg_list);
	}
	clear_bit(ADF_STATUS_RESTARTING, &accel_dev->status);
	adf_dev_stop(accel_dev);
	adf_dev_shutdown(accel_dev);
	adf_cleanup_accel(accel_dev);
	adf_cleanup_pci_dev(accel_dev);
	kfree(accel_dev);
}

static int __init adfdrv_init(void)
{
	request_module("intel_qat");

	if (pci_register_driver(&adf_driver)) {
		pr_err("QAT: Driver initialization failed\n");
		return -EFAULT;
	}
	return 0;
}

static void __exit adfdrv_release(void)
{
	adf_devmgr_update_drv_rm(adf_driver.id_table->device);
	pci_unregister_driver(&adf_driver);
	adf_clean_vf_map(adf_driver.id_table->device);
}

module_init(adfdrv_init);
module_exit(adfdrv_release);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Intel");
MODULE_DESCRIPTION("Intel(R) QuickAssist Technology");
MODULE_VERSION(ADF_DRV_VERSION);
