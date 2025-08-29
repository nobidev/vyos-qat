// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2014 - 2021 Intel Corporation */
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include "adf_accel_devices.h"
#include "adf_common_drv.h"
#ifdef QAT_DBG
#include "qat_dbg.h"
#endif


static struct workqueue_struct *fatal_error_wq;

struct adf_fatal_error_data {
	struct adf_accel_dev *accel_dev;
	struct work_struct work;
};

static struct workqueue_struct *device_reset_wq;

static void adf_fatal_error_notify(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;

	if (hw_device->pre_reset) {
		dev_dbg(&GET_DEV(accel_dev), "Performing pre reset save\n");
		hw_device->pre_reset(accel_dev);
	}

	adf_error_notifier((uintptr_t)accel_dev);

	if (!accel_dev->is_vf) {
		if (accel_dev->pf.vf_info)
			adf_pf2vf_notify_fatal_error(accel_dev);
	}
}

static pci_ers_result_t adf_error_detected(struct pci_dev *pdev,
					   pci_channel_state_t state)
{
	struct adf_accel_dev *accel_dev = adf_devmgr_pci_to_accel_dev(pdev);

	dev_info(&pdev->dev, "Acceleration driver hardware error detected.\n");
	if (!accel_dev) {
		dev_err(&pdev->dev, "Can't find acceleration device\n");
		return PCI_ERS_RESULT_DISCONNECT;
	}

#ifdef QAT_DBG
	/* QAT_DBG - notify to prepare crash report */
	qat_dbg_fatal_error_handler(accel_dev);
#endif

	adf_fatal_error_notify(accel_dev);
	/* disable device as we may receive root port reset */
	if (!accel_dev->is_vf)
		pci_clear_master(pdev);

	if (state == pci_channel_io_perm_failure) {
		dev_err(&pdev->dev, "Can't recover from device error\n");
		return PCI_ERS_RESULT_DISCONNECT;
	}

	return PCI_ERS_RESULT_NEED_RESET;
}

/* reset dev data */
struct adf_reset_dev_data {
	int mode;
	struct adf_accel_dev *accel_dev;
	struct completion compl;
	struct work_struct reset_work;
};

void adf_reset_sbr(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);
	struct pci_dev *parent = pdev->bus->self;
	uint16_t bridge_ctl = 0;

	if (!parent)
		parent = pdev;

	if (!pci_wait_for_pending_transaction(pdev))
		dev_info(&GET_DEV(accel_dev),
			 "Transaction still in progress. Proceeding\n");

	dev_info(&GET_DEV(accel_dev), "Secondary bus reset\n");

	pci_ignore_hotplug(pdev);

	pci_cfg_access_lock(pdev);
	pci_read_config_word(parent, PCI_BRIDGE_CONTROL, &bridge_ctl);
	bridge_ctl |= PCI_BRIDGE_CTL_BUS_RESET;
	pci_write_config_word(parent, PCI_BRIDGE_CONTROL, bridge_ctl);
	msleep(100);
	bridge_ctl &= ~PCI_BRIDGE_CTL_BUS_RESET;
	pci_write_config_word(parent, PCI_BRIDGE_CONTROL, bridge_ctl);
	msleep(100);
	pci_cfg_access_unlock(pdev);
}
EXPORT_SYMBOL_GPL(adf_reset_sbr);

void adf_reset_flr(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);

	dev_info(&GET_DEV(accel_dev), "Function level reset\n");
	if (!pci_wait_for_pending_transaction(pdev)) {
		dev_info(&GET_DEV(accel_dev),
			 "Pending transactions, trying secondary bus reset\n");
		adf_reset_sbr(accel_dev);
		return;
	}

	pci_cfg_access_lock(pdev);
	__pci_reset_function_locked(pdev);
	pci_cfg_access_unlock(pdev);
}
EXPORT_SYMBOL_GPL(adf_reset_flr);

void adf_dev_pre_reset(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);
	u32 aer_offset, reg_val = 0;

	aer_offset = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ERR);

	pci_cfg_access_lock(pdev);
	pci_read_config_dword(pdev, aer_offset + PCI_ERR_UNCOR_MASK, &reg_val);
	reg_val |= ADF_PPAERUCM_MASK;
	pci_write_config_dword(pdev, aer_offset + PCI_ERR_UNCOR_MASK,
			       reg_val);
	pci_cfg_access_unlock(pdev);

	if (hw_device->disable_arb)
		hw_device->disable_arb(accel_dev);
}
EXPORT_SYMBOL_GPL(adf_dev_pre_reset);

void adf_dev_post_reset(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);
	u32 aer_offset;

	aer_offset = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ERR);

	pci_cfg_access_lock(pdev);
	pci_write_config_dword(pdev, aer_offset + PCI_ERR_UNCOR_MASK,
			       hw_device->aerucm_mask);
	pci_cfg_access_unlock(pdev);
}
EXPORT_SYMBOL_GPL(adf_dev_post_reset);

void adf_dev_restore(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);

	if (hw_device->pre_reset) {
		dev_dbg(&GET_DEV(accel_dev), "Performing pre reset save\n");
		hw_device->pre_reset(accel_dev);
	}

	if (!accel_dev->is_vf)
		pci_clear_master(pdev);

	if (hw_device->reset_device) {
		dev_info(&GET_DEV(accel_dev), "Resetting device qat_dev%d\n",
			 accel_dev->accel_id);
		hw_device->reset_device(accel_dev);
		pci_restore_state(pdev);
		pci_save_state(pdev);
	}

	if (hw_device->post_reset) {
		dev_dbg(&GET_DEV(accel_dev), "Performing post reset restore\n");
		hw_device->post_reset(accel_dev);
	}
}

static void adf_device_reset_worker(struct work_struct *work)
{
	struct adf_reset_dev_data *reset_data =
		  container_of(work, struct adf_reset_dev_data, reset_work);
	struct adf_accel_dev *accel_dev = reset_data->accel_dev;
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);

	if (adf_dev_restarting_notify_sync(accel_dev)) {
		if (!pdev->is_busmaster)
			pci_set_master(pdev);
		clear_bit(ADF_STATUS_RESTARTING, &accel_dev->status);
		return;
	}

	/*
	 * re-enable device to support pf/vf comms as it would be disabled
	 * in the detect function of aer driver
	 */
	if (!pdev->is_busmaster)
		pci_set_master(pdev);

	adf_dev_stop(accel_dev);
	adf_dev_shutdown(accel_dev);

	if (adf_dev_init(accel_dev) || adf_dev_start(accel_dev)) {
		/* The device hanged and we can't restart it */
		/* so stop here */
		dev_err(&GET_DEV(accel_dev),
			"Restart device failed. Device is unusable.\n");
		if (reset_data->mode == ADF_DEV_RESET_ASYNC)
			kfree(reset_data);
		return;
	}
#ifdef QAT_DBG
	if (qat_dbg_dev_restart_instance(accel_dev)) {
		return;
	}
#endif
	adf_dev_restarted_notify(accel_dev);
	clear_bit(ADF_STATUS_RESTARTING, &accel_dev->status);

	/* The dev is back alive. Notify the caller if in sync mode */
	if (reset_data->mode == ADF_DEV_RESET_SYNC)
		complete(&reset_data->compl);
	else
		kfree(reset_data);
}

int adf_dev_aer_schedule_reset(struct adf_accel_dev *accel_dev,
			       enum adf_dev_reset_mode mode)
{
	struct adf_reset_dev_data *reset_data;

	if (!adf_dev_started(accel_dev) ||
	    test_bit(ADF_STATUS_RESTARTING, &accel_dev->status))
		return 0;

	set_bit(ADF_STATUS_RESTARTING, &accel_dev->status);
	reset_data = kzalloc(sizeof(*reset_data), GFP_KERNEL);
	if (!reset_data)
		return -ENOMEM;
	reset_data->accel_dev = accel_dev;
	init_completion(&reset_data->compl);
	reset_data->mode = mode;
	INIT_WORK(&reset_data->reset_work, adf_device_reset_worker);
	queue_work(device_reset_wq, &reset_data->reset_work);

	/* If in sync mode wait for the result */
	if (mode == ADF_DEV_RESET_SYNC) {
		int ret = 0;
		/* Maximum device reset time is 10 seconds */
		unsigned long wait_jiffies = msecs_to_jiffies(10000);
		unsigned long timeout = wait_for_completion_timeout(
				   &reset_data->compl, wait_jiffies);
		if (!timeout) {
			dev_err(&GET_DEV(accel_dev),
				"Reset device timeout expired\n");
			ret = -EFAULT;
		}
		flush_workqueue(device_reset_wq);
		kfree(reset_data);
		return ret;
	}
	return 0;
}

int adf_dev_autoreset(struct adf_accel_dev *accel_dev,
		      enum adf_dev_reset_mode mode)
{
	if (accel_dev->autoreset_on_error)
		return adf_dev_reset(accel_dev, mode);

	return -EFAULT;
}

static int adf_fatal_error_work(struct adf_accel_dev *accel_dev,
				enum adf_dev_reset_mode mode)
{
	adf_fatal_error_notify(accel_dev);

	if (!accel_dev->is_vf)
		return adf_dev_autoreset(accel_dev, mode);
	return 0;
}

static pci_ers_result_t adf_slot_reset(struct pci_dev *pdev)
{
	struct adf_accel_dev *accel_dev = adf_devmgr_pci_to_accel_dev(pdev);

	if (!accel_dev) {
		pr_err("QAT: Can't find acceleration device\n");
		return PCI_ERS_RESULT_DISCONNECT;
	}
	pci_aer_clear_nonfatal_status(pdev);
	if (adf_dev_autoreset(accel_dev, ADF_DEV_RESET_SYNC))
		return PCI_ERS_RESULT_DISCONNECT;

	return PCI_ERS_RESULT_RECOVERED;
}

static void adf_resume(struct pci_dev *pdev)
{
	dev_info(&pdev->dev, "Acceleration driver reset completed\n");
	dev_info(&pdev->dev, "Device is up and running\n");
}

static const struct pci_error_handlers adf_err_handler = {
	.error_detected = adf_error_detected,
	.slot_reset = adf_slot_reset,
	.resume = adf_resume,
};

static void adf_notify_fatal_error_work(struct work_struct *work)
{
	struct adf_fatal_error_data *wq_data =
			container_of(work, struct adf_fatal_error_data, work);
	struct adf_accel_dev *accel_dev = wq_data->accel_dev;

#ifdef QAT_DBG
	/* QAT_DBG - notify to prepare crash report */
	qat_dbg_fatal_error_handler(accel_dev);
#endif
	adf_fatal_error_work(accel_dev, ADF_DEV_RESET_ASYNC);
	kfree(wq_data);
}

int adf_notify_fatal_error(struct adf_accel_dev *accel_dev)
{
	struct adf_fatal_error_data *wq_data;

	if (!adf_dev_started(accel_dev) ||
	    test_bit(ADF_STATUS_RESTARTING, &accel_dev->status))
		return 0;

	wq_data = kzalloc(sizeof(*wq_data), GFP_ATOMIC);
	if (!wq_data) {
		dev_err(&GET_DEV(accel_dev), "Failed to allocate memory\n");
		return -ENOMEM;
	}
	wq_data->accel_dev = accel_dev;

	INIT_WORK(&wq_data->work, adf_notify_fatal_error_work);
	queue_work(fatal_error_wq, &wq_data->work);

	return 0;
}

#ifdef QAT_DBG
/**
 * adf_notify_err_resp_work() - Notify about error response
 * @work: Pointer to work struct regarding acceleration device.
 *
 * Function Notifies about error response.
 */
static void adf_notify_err_resp_work(struct work_struct *work)
{
	struct adf_fatal_error_data *wq_data =
			container_of(work, struct adf_fatal_error_data, work);
	struct adf_accel_dev *accel_dev = wq_data->accel_dev;

	/* QAT_DBG - notify to prepare crash report */
	qat_dbg_err_resp_handler(accel_dev);

	kfree(wq_data);
}

/**
 * adf_notify_err_resp() - Initialize work on error response
 * @accel_dev: Pointer to acceleration device.
 *
 * Function requests handling error response notifier.
 *
 * Return: 0 on success, error code otherwise
 */
int adf_notify_err_resp(struct adf_accel_dev *accel_dev)
{
	struct adf_fatal_error_data *wq_data;

	wq_data = kzalloc(sizeof(*wq_data), GFP_ATOMIC);
	if (!wq_data)
		return -ENOMEM;

	wq_data->accel_dev = accel_dev;

	INIT_WORK(&wq_data->work, adf_notify_err_resp_work);
	queue_work(fatal_error_wq, &wq_data->work);

	return 0;
}

#endif
int __init adf_init_fatal_error_wq(void)
{
	fatal_error_wq = alloc_workqueue("qat_fatal_error_wq",
					 WQ_MEM_RECLAIM, 0);
	return !fatal_error_wq ? -EFAULT : 0;
}

void adf_exit_fatal_error_wq(void)
{
	if (fatal_error_wq)
		destroy_workqueue(fatal_error_wq);
	fatal_error_wq = NULL;
}

/**
 * adf_enable_aer() - Enable Advance Error Reporting for acceleration device
 * @accel_dev:  Pointer to acceleration device.
 * @adf:        PCI device driver owning the given acceleration device.
 *
 * Function enables PCI Advance Error Reporting for the
 * QAT acceleration device accel_dev.
 * To be used by QAT device specific drivers.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_enable_aer(struct adf_accel_dev *accel_dev, struct pci_driver *adf)
{
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);

	adf->err_handler = (struct pci_error_handlers *)(&adf_err_handler);
	pci_enable_pcie_error_reporting(pdev);
	return 0;
}
EXPORT_SYMBOL_GPL(adf_enable_aer);

/**
 * adf_disable_aer() - Enable Advance Error Reporting for acceleration device
 * @accel_dev:  Pointer to acceleration device.
 *
 * Function disables PCI Advance Error Reporting for the
 * QAT acceleration device accel_dev.
 * To be used by QAT device specific drivers.
 *
 * Return: void
 */
void adf_disable_aer(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);

	pci_disable_pcie_error_reporting(pdev);
}
EXPORT_SYMBOL_GPL(adf_disable_aer);

int adf_init_aer(void)
{
	device_reset_wq = alloc_workqueue("qat_device_reset_wq",
					  WQ_MEM_RECLAIM, 0);
	return !device_reset_wq ? -EFAULT : 0;
}

void adf_exit_aer(void)
{
	if (device_reset_wq)
		destroy_workqueue(device_reset_wq);
	device_reset_wq = NULL;
}
