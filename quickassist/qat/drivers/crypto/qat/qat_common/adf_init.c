// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2014 - 2021 Intel Corporation */
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include "adf_accel_devices.h"
#include "adf_cfg.h"
#include "adf_common_drv.h"
#include "adf_dev_err.h"
#include <linux/iommu.h>
#include "icp_qat_fw.h"
#include "adf_uio.h"
#include "adf_uio_control.h"

static LIST_HEAD(service_table);
static DEFINE_MUTEX(service_lock);

static void adf_service_add(struct service_hndl *service)
{
	mutex_lock(&service_lock);
	list_add(&service->list, &service_table);
	mutex_unlock(&service_lock);
}

int adf_service_register(struct service_hndl *service)
{
	memset(service->init_status, 0, sizeof(service->init_status));
	memset(service->start_status, 0, sizeof(service->start_status));
	adf_service_add(service);
	return 0;
}
EXPORT_SYMBOL_GPL(adf_service_register);

static void adf_service_remove(struct service_hndl *service)
{
	mutex_lock(&service_lock);
	list_del(&service->list);
	mutex_unlock(&service_lock);
}

int adf_service_unregister(struct service_hndl *service)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(service->init_status); i++) {
		if (service->init_status[i] || service->start_status[i]) {
			pr_err("QAT: Could not remove active service\n");
			return -EFAULT;
		}
	}
	adf_service_remove(service);
	return 0;
}
EXPORT_SYMBOL_GPL(adf_service_unregister);

static int adf_cfg_add_device_params(struct adf_accel_dev *accel_dev)
{
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
	char version[ADF_CFG_MAX_VAL_LEN_IN_BYTES];
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	unsigned long val;

	if (adf_cfg_section_add(accel_dev, ADF_GENERAL_SEC))
		goto err;

	snprintf(key, sizeof(key), ADF_DEV_MAX_BANKS);
	val = GET_MAX_BANKS(accel_dev);
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)&val, ADF_DEC))
		goto err;

	snprintf(key, sizeof(key), ADF_DEV_CAPABILITIES_MASK);
	val = hw_data->accel_capabilities_mask;
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)val, ADF_HEX))
		goto err;

	snprintf(key, sizeof(key), ADF_CIPHER_CAPABILITIES_MASK);
	val = hw_data->cipher_capabilities_mask;
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)val, ADF_HEX))
		goto err;

	snprintf(key, sizeof(key), ADF_HASH_CAPABILITIES_MASK);
	val = hw_data->hash_capabilities_mask;
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)val, ADF_HEX))
		goto err;

	snprintf(key, sizeof(key), ADF_ASYM_CAPABILITIES_MASK);
	val = hw_data->asym_capabilities_mask;
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)val, ADF_HEX))
		goto err;

	snprintf(key, sizeof(key), ADF_DEV_PKG_ID);
	val = accel_dev->accel_id;
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)&val, ADF_DEC))
		goto err;

	snprintf(key, sizeof(key), ADF_DEV_NODE_ID);
	val = dev_to_node(&GET_DEV(accel_dev));
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)&val, ADF_DEC))
		goto err;

	snprintf(key, sizeof(key), ADF_DEV_MAX_RINGS_PER_BANK);
	val = hw_data->num_rings_per_bank;
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)&val, ADF_DEC))
		goto err;

	snprintf(key, sizeof(key), ADF_UOF_VER_KEY);
	snprintf(version, ADF_CFG_MAX_VAL_LEN_IN_BYTES, "%d.%d.%d",
		 accel_dev->fw_versions.fw_version_major,
		 accel_dev->fw_versions.fw_version_minor,
		 accel_dev->fw_versions.fw_version_patch);
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)version, ADF_STR))
		goto err;

	snprintf(key, sizeof(key), ADF_HW_REV_ID_KEY);
	snprintf(version, ADF_CFG_MAX_VAL_LEN_IN_BYTES, "%d",
		 accel_dev->accel_pci_dev.revid);
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)version, ADF_STR))
		goto err;

	snprintf(key, sizeof(key), ADF_MMP_VER_KEY);
	snprintf(version, ADF_CFG_MAX_VAL_LEN_IN_BYTES, "%d.%d.%d",
		 accel_dev->fw_versions.mmp_version_major,
		 accel_dev->fw_versions.mmp_version_minor,
		 accel_dev->fw_versions.mmp_version_patch);
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)version, ADF_STR))
		goto err;

	return 0;
err:
	dev_err(&GET_DEV(accel_dev), "Failed to add internal values to accel_dev cfg\n");
	return -EINVAL;
}

static int adf_cfg_add_ext_params(struct adf_accel_dev *accel_dev)
{
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	unsigned long val;

	snprintf(key, sizeof(key), ADF_DC_EXTENDED_FEATURES);
	val = hw_data->extended_dc_capabilities;
	if (adf_cfg_add_key_value_param(accel_dev, ADF_GENERAL_SEC,
					key, (void *)val, ADF_HEX))
		return -EINVAL;

	return 0;
}


void adf_error_notifier(uintptr_t arg)
{
	struct adf_accel_dev *accel_dev = (struct adf_accel_dev *) arg;
	struct service_hndl *service;
	struct list_head *list_itr;

	list_for_each(list_itr, &service_table) {
		service = list_entry(list_itr, struct service_hndl, list);
		if (service->event_hld(accel_dev, ADF_EVENT_ERROR))
			dev_err(&GET_DEV(accel_dev),
				"Failed to send error event to %s.\n",
				service->name);
	}

	if (accel_dev->is_vf)
		complete(&accel_dev->vf.err_notified);
}
EXPORT_SYMBOL_GPL(adf_error_notifier);

/**
 * adf_set_ssm_wdtimer() - Initialize the slice hang watchdog timer.
 * @accel_dev: Pointer to adf_accel_dev structure
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_set_ssm_wdtimer(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_bar *misc_bar = &GET_BARS(accel_dev)[hw_data->
						get_misc_bar_id(hw_data)];
	void __iomem *csr = misc_bar->virt_addr;
	u32 i;
	u32 clk_per_sec = hw_data->get_clock_speed(hw_data);
	u32 timer_val = ADF_WDT_TIMER_SYM_COMP_MS * (clk_per_sec / 1000);
	u32 timer_val_pke = ADF_SSM_WDT_PKE_DEFAULT_VALUE;
	char timer_str[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};

	/* Get Watch Dog Timer for CySym+Comp from the configuration */
	if (!adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC,
				     ADF_DEV_SSM_WDT_BULK, (char *)timer_str)) {
		if (!kstrtouint((char *)timer_str, ADF_CFG_BASE_DEC,
				&timer_val))
			/* Convert msec to CPP clocks */
			timer_val = timer_val * (clk_per_sec / 1000);
	}
	/* Get Watch Dog Timer for CyAsym from the configuration */
	if (!adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC,
				     ADF_DEV_SSM_WDT_PKE, (char *)timer_str)) {
		if (!kstrtouint((char *)timer_str, ADF_CFG_BASE_DEC,
				&timer_val_pke))
			/* Convert msec to CPP clocks */
			timer_val_pke = timer_val_pke * (clk_per_sec / 1000);
	}

	 for_each_set_bit(i, &hw_data->accel_mask,
			  hw_data->num_accel) {
		/* Enable Watch Dog Timer for CySym + Comp */
		ADF_CSR_WR(csr, ADF_SSMWDT(i), timer_val);
		/* Enable Watch Dog Timer for CyAsym */
		ADF_CSR_WR(csr, ADF_SSMWDTPKE(i), timer_val_pke);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(adf_set_ssm_wdtimer);

/**
 * adf_dev_init() - Init data structures and services for the given accel device
 * @accel_dev: Pointer to acceleration device.
 *
 * Initialize the ring data structures and the admin comms and arbitration
 * services.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_dev_init(struct adf_accel_dev *accel_dev)
{
	struct service_hndl *service;
	struct list_head *list_itr;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;

	char value[ADF_CFG_MAX_VAL_LEN_IN_BYTES];
	int ret = 0;
	spin_lock_init(&accel_dev->vf2pf_csr_lock);

	if (!hw_data) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to init device - hw_data not set\n");
		return -EFAULT;
	}

	if (hw_data->reset_hw_units)
		hw_data->reset_hw_units(accel_dev);

	if (!test_bit(ADF_STATUS_CONFIGURED, &accel_dev->status) &&
	    !accel_dev->is_vf) {
		dev_err(&GET_DEV(accel_dev), "Device not configured\n");
		return -EFAULT;
	}

	if (adf_init_etr_data(accel_dev)) {
		dev_err(&GET_DEV(accel_dev), "Failed initialize etr\n");
		return -EFAULT;
	}

	if (hw_data->init_accel_units && hw_data->init_accel_units(accel_dev)) {
		dev_err(&GET_DEV(accel_dev), "Failed initialize accel_units\n");
		return -EFAULT;
	}

	if (hw_data->init_admin_comms && hw_data->init_admin_comms(accel_dev)) {
		dev_err(&GET_DEV(accel_dev), "Failed initialize admin comms\n");
		return -EFAULT;
	}

	if (hw_data->init_arb && hw_data->init_arb(accel_dev)) {
		dev_err(&GET_DEV(accel_dev), "Failed initialize hw arbiter\n");
		return -EFAULT;
	}

	if (hw_data->set_asym_rings_mask)
		hw_data->set_asym_rings_mask(accel_dev);
	/* Read autoreset on error parameter */
	ret = adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC,
				      ADF_AUTO_RESET_ON_ERROR, value);
	if (!ret) {
		if (kstrtouint(value, 10, &accel_dev->autoreset_on_error)) {
			dev_err(&GET_DEV(accel_dev),
				"Failed converting %s to a decimal value\n",
				ADF_AUTO_RESET_ON_ERROR);
			return -EFAULT;
		}
	}


	if (adf_ae_init(accel_dev)) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to initialise Acceleration Engine\n");
		return -EFAULT;
	}
	set_bit(ADF_STATUS_AE_INITIALISED, &accel_dev->status);
	if (hw_data->fw_load && hw_data->fw_load(accel_dev)) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to load acceleration FW\n");
		return -EFAULT;
	}
	set_bit(ADF_STATUS_AE_UCODE_LOADED, &accel_dev->status);

	/*
	 * There is no need to allocate the IRQ again here as the IRQs will
	 * not be freed for VFs in reset.
	 */
	if (!adf_devmgr_in_reset(accel_dev) || !accel_dev->is_vf) {
		if (hw_data->alloc_irq(accel_dev)) {
			dev_err(&GET_DEV(accel_dev), "Failed to allocate interrupts\n");
			return -EFAULT;
		}
	}
	set_bit(ADF_STATUS_IRQ_ALLOCATED, &accel_dev->status);
	if (hw_data->init_ras && hw_data->init_ras(accel_dev)) {
		dev_err(&GET_DEV(accel_dev), "Failed to init RAS\n");
		return -EFAULT;
	}

	hw_data->enable_ints(accel_dev);

	hw_data->enable_error_correction(accel_dev);

	if (!adf_devmgr_in_reset(accel_dev) || !accel_dev->is_vf) {
		if (hw_data->enable_vf2pf_comms &&
		    hw_data->enable_vf2pf_comms(accel_dev))
			return -EINVAL;
	}
#ifdef CONFIG_PCI_IOV
	if (!adf_devmgr_in_reset(accel_dev) || !accel_dev->is_vf) {
		if (adf_pf_vf_capabilities_init(accel_dev))
			return -EFAULT;
		if (adf_pf_vf_ring_to_svc_init(accel_dev))
			return -EFAULT;
	}
#endif

	if (!test_bit(ADF_STATUS_CONFIGURED, &accel_dev->status) &&
	    accel_dev->is_vf) {
		if (qat_crypto_vf_dev_config(accel_dev))
			return -EFAULT;
	}

	if (!test_bit(ADF_STATUS_RESTARTING, &accel_dev->status) &&
	    !test_bit(ADF_STATUS_SRIOV_RESTARTING, &accel_dev->status) &&
	    adf_cfg_add_device_params(accel_dev))
		return -EFAULT;
	/*
	 * Subservice initialisation is divided into two stages: init and start.
	 * This is to facilitate any ordering dependencies between services
	 * prior to starting any of the accelerators.
	 */
	list_for_each(list_itr, &service_table) {
		service = list_entry(list_itr, struct service_hndl, list);
		if (service->event_hld(accel_dev, ADF_EVENT_INIT)) {
			dev_err(&GET_DEV(accel_dev),
				"Failed to initialise service %s\n",
				service->name);
			return -EFAULT;
		}
		set_bit(accel_dev->accel_id, service->init_status);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(adf_dev_init);

/**
 * adf_dev_start() - Start acceleration service for the given accel device
 * @accel_dev:    Pointer to acceleration device.
 *
 * Function notifies all the registered services that the acceleration device
 * is ready to be used.
 * To be used by QAT device specific drivers.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_dev_start(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct service_hndl *service;
	struct list_head *list_itr;
	int status = 0;

	set_bit(ADF_STATUS_STARTING, &accel_dev->status);

	if (adf_ae_start(accel_dev)) {
		dev_err(&GET_DEV(accel_dev), "AE Start Failed\n");
		return -EFAULT;
	}
	set_bit(ADF_STATUS_AE_STARTED, &accel_dev->status);

	if (hw_data->send_admin_init(accel_dev)) {
		dev_err(&GET_DEV(accel_dev), "Failed to init fw\n");
		return -EFAULT;
	}

	if (hw_data->measure_clock)
		hw_data->measure_clock(accel_dev);

	/*
	 * Set ssm watch dog timer for slice hang detection
	 * Note! Not supported on devices older than C62x
	 */
	if (hw_data->set_ssm_wdtimer && hw_data->set_ssm_wdtimer(accel_dev)) {
		dev_err(&GET_DEV(accel_dev),
			"QAT: Failed to set ssm watch dog timer\n");
		return -EFAULT;
	}

	if (adf_rate_limiting_init(accel_dev)) {
		dev_err(&GET_DEV(accel_dev), "Failed to init RL\n");
		return -EFAULT;
	}
	list_for_each(list_itr, &service_table) {
		service = list_entry(list_itr, struct service_hndl, list);
		if (service->event_hld(accel_dev, ADF_EVENT_START)) {
			dev_err(&GET_DEV(accel_dev),
				"Failed to start service %s\n",
				service->name);
			return -EFAULT;
		}
		set_bit(accel_dev->accel_id, service->start_status);
	}

	if (!accel_dev->is_vf && !accel_dev->pf.vf_info &&
			iommu_present(&pci_bus_type))
		dev_err(&GET_DEV(accel_dev),
			"Cannot use PF with IOMMU enabled\n");

	if (accel_dev->is_vf || (!accel_dev->pf.vf_info &&
				!iommu_present(&pci_bus_type)))  {
		/* Create the UIO sysfs entries */
		if (adf_uio_sysfs_create(accel_dev)) {
			dev_err(&GET_DEV(accel_dev),
				"Failed to create the sysfs entry\n");
			set_bit(ADF_STATUS_STARTING, &accel_dev->status);
			clear_bit(ADF_STATUS_STARTED, &accel_dev->status);
			return -EFAULT;
		}

		/*Register UIO devices */
		if (adf_uio_register(accel_dev)) {
			adf_uio_remove(accel_dev);
			dev_err(&GET_DEV(accel_dev),
				"Failed to register UIO devices\n");
			set_bit(ADF_STATUS_STARTING, &accel_dev->status);
			clear_bit(ADF_STATUS_STARTED, &accel_dev->status);
			return -ENODEV;
		}
	}

	if (!test_bit(ADF_STATUS_RESTARTING, &accel_dev->status) &&
	    !test_bit(ADF_STATUS_SRIOV_RESTARTING, &accel_dev->status) &&
	    adf_cfg_add_ext_params(accel_dev))
		return -EFAULT;
	clear_bit(ADF_STATUS_STARTING, &accel_dev->status);
	set_bit(ADF_STATUS_STARTED, &accel_dev->status);

	if (!list_empty(&accel_dev->crypto_list)) {
		if (hw_data->accel_capabilities_mask &
				ADF_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC)
			status = qat_algs_register();

		if (hw_data->accel_capabilities_mask &
				ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC)
			status |= qat_asym_algs_register();

		if (status) {
			dev_err(&GET_DEV(accel_dev),
					"Failed to register crypto algs\n");
			set_bit(ADF_STATUS_STARTING, &accel_dev->status);
			clear_bit(ADF_STATUS_STARTED, &accel_dev->status);
			return -EFAULT;
		}
	}

	if (adf_cfg_dev_add_ext(accel_dev)) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to add config related debug file\n");
		set_bit(ADF_STATUS_STARTING, &accel_dev->status);
		clear_bit(ADF_STATUS_STARTED, &accel_dev->status);
		return -EFAULT;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(adf_dev_start);

/**
 * adf_dev_stop() - Stop acceleration service for the given accel device
 * @accel_dev:    Pointer to acceleration device.
 *
 * Function notifies all the registered services that the acceleration device
 * is shuting down.
 * To be used by QAT device specific drivers.
 *
 * Return: void
 */
void adf_dev_stop(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct service_hndl *service;
	struct list_head *list_itr;
	bool wait = false;
	int ret;
	int times;

	if (!adf_dev_started(accel_dev) &&
	    !test_bit(ADF_STATUS_STARTING, &accel_dev->status))
		return;

	clear_bit(ADF_STATUS_STARTING, &accel_dev->status);
	clear_bit(ADF_STATUS_STARTED, &accel_dev->status);

	if (!list_empty(&accel_dev->crypto_list)) {
		if (hw_data->accel_capabilities_mask &
				ADF_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC)
			qat_algs_unregister();
		if (hw_data->accel_capabilities_mask &
				ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC)
			qat_asym_algs_unregister();
	}

	adf_rate_limiting_exit(accel_dev);
	list_for_each(list_itr, &service_table) {
		service = list_entry(list_itr, struct service_hndl, list);
		if (!test_bit(accel_dev->accel_id, service->start_status))
			continue;
		ret = service->event_hld(accel_dev, ADF_EVENT_STOP);
		if (!ret) {
			clear_bit(accel_dev->accel_id, service->start_status);
		} else if (ret == -EAGAIN) {
			wait = true;
			clear_bit(accel_dev->accel_id, service->start_status);
		}
	}

	if (wait)
		msleep(100);

	for (times = 0; times < ADF_STOP_RETRY; times++) {
		if (!adf_dev_in_use(accel_dev))
			break;
		msleep(100);
	}

	if (test_bit(ADF_STATUS_AE_STARTED, &accel_dev->status)) {
		if (adf_ae_stop(accel_dev))
			dev_err(&GET_DEV(accel_dev), "failed to stop AE\n");
		else
			clear_bit(ADF_STATUS_AE_STARTED, &accel_dev->status);
	}

	adf_cfg_dev_remove_ext(accel_dev);
	if (accel_dev->is_vf || (!accel_dev->pf.vf_info &&
				 !iommu_present(&pci_bus_type))) {
		/* Remove UIO Devices */
		adf_uio_remove(accel_dev);
		/* Decrease a reference counter for the accel kobj. */
		adf_uio_sysfs_delete(accel_dev);
	}
}
EXPORT_SYMBOL_GPL(adf_dev_stop);

/**
 * adf_dev_shutdown() - shutdown acceleration services and data strucutures
 * @accel_dev: Pointer to acceleration device
 *
 * Cleanup the ring data structures and the admin comms and arbitration
 * services.
 */
void adf_dev_shutdown(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct service_hndl *service;
	struct list_head *list_itr;

	if (!hw_data) {
		dev_err(&GET_DEV(accel_dev),
			"QAT: Failed to shutdown device - hw_data not set\n");
		return;
	}

	if (test_bit(ADF_STATUS_AE_UCODE_LOADED, &accel_dev->status)) {
		adf_ae_fw_release(accel_dev);
		clear_bit(ADF_STATUS_AE_UCODE_LOADED, &accel_dev->status);
	}

	if (test_bit(ADF_STATUS_AE_INITIALISED, &accel_dev->status)) {
		if (adf_ae_shutdown(accel_dev))
			dev_err(&GET_DEV(accel_dev),
				"Failed to shutdown Accel Engine\n");
		else
			clear_bit(ADF_STATUS_AE_INITIALISED,
				  &accel_dev->status);
	}

	list_for_each(list_itr, &service_table) {
		service = list_entry(list_itr, struct service_hndl, list);
		if (!test_bit(accel_dev->accel_id, service->init_status))
			continue;
		if (service->event_hld(accel_dev, ADF_EVENT_SHUTDOWN))
			dev_err(&GET_DEV(accel_dev),
				"Failed to shutdown service %s\n",
				service->name);
		else
			clear_bit(accel_dev->accel_id, service->init_status);
	}

	if (hw_data->disable_iov)
		hw_data->disable_iov(accel_dev);


	/*
	 * When encountering VFs, the PF/VF communication and IRQs are kept as
	 * the PF driver will restore the settings for VFs and send the
	 * RESTARTED messages through PF/VF communications during reset
	 * to notify the VFs to restart itself. Considering Linux as the Host
	 * OS, the PF driver will disable SRIOV and these resources would
	 * be released in the adf_remove() function.
	 */
	if (!adf_devmgr_in_reset(accel_dev) || !accel_dev->is_vf) {
		if (hw_data->disable_vf2pf_comms)
			hw_data->disable_vf2pf_comms(accel_dev);
		if (test_bit(ADF_STATUS_IRQ_ALLOCATED, &accel_dev->status)) {
			hw_data->free_irq(accel_dev);
			clear_bit(ADF_STATUS_IRQ_ALLOCATED, &accel_dev->status);
		}
	}


	/* Delete configuration only if not restarting */
	if (!test_bit(ADF_STATUS_RESTARTING, &accel_dev->status))
		adf_cfg_del_all(accel_dev);

	if (hw_data->disable_error_correction)
		hw_data->disable_error_correction(accel_dev);

	if (hw_data->exit_ras)
		hw_data->exit_ras(accel_dev);

	if (hw_data->exit_arb)
		hw_data->exit_arb(accel_dev);

	if (hw_data->exit_accel_units)
		hw_data->exit_accel_units(accel_dev);

	adf_cleanup_etr_data(accel_dev);
	adf_dev_restore(accel_dev);

	if (hw_data->exit_admin_comms)
		hw_data->exit_admin_comms(accel_dev);
}
EXPORT_SYMBOL_GPL(adf_dev_shutdown);

/**
 * adf_dev_reset() - Reset acceleration service for the given accel device
 * @accel_dev:    Pointer to acceleration device.
 * @mode:     Synchronous or asynchronous mode for reset
 *
 * Function notifies all the registered services that the acceleration device
 * is resetting.
 * To be used by QAT device specific drivers.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_dev_reset(struct adf_accel_dev *accel_dev, enum adf_dev_reset_mode mode)
{
	return adf_dev_aer_schedule_reset(accel_dev, mode);
}
EXPORT_SYMBOL_GPL(adf_dev_reset);

int adf_dev_restarting_notify(struct adf_accel_dev *accel_dev)
{
	struct service_hndl *service;
	struct list_head *list_itr;

	list_for_each(list_itr, &service_table) {
		service = list_entry(list_itr, struct service_hndl, list);
		if (service->event_hld(accel_dev, ADF_EVENT_RESTARTING))
			dev_err(&GET_DEV(accel_dev),
				"Failed to restart service %s.\n",
				service->name);
	}
	return 0;
}

int adf_dev_restarted_notify(struct adf_accel_dev *accel_dev)
{
	struct service_hndl *service;
	struct list_head *list_itr;

	list_for_each(list_itr, &service_table) {
		service = list_entry(list_itr, struct service_hndl, list);
		if (service->event_hld(accel_dev, ADF_EVENT_RESTARTED))
			dev_err(&GET_DEV(accel_dev),
				"Failed to restart service %s.\n",
				service->name);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(adf_dev_restarted_notify);

int adf_dev_restarting_notify_sync(struct adf_accel_dev *accel_dev)
{
	int times;

	adf_dev_restarting_notify(accel_dev);
	for (times = 0; times < ADF_STOP_RETRY; times++) {
		if (!adf_dev_in_use(accel_dev))
			break;
		dev_dbg(&GET_DEV(accel_dev), "retry times=%d\n", times);
		msleep(100);
	}
	if (adf_dev_in_use(accel_dev)) {
		dev_warn(&GET_DEV(accel_dev),
			 "Device is still in use, can't be stopped.\n");
		return -EBUSY;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(adf_dev_restarting_notify_sync);

#ifdef QAT_DBG
/**
 * adf_dev_proc_crash_notify() - Notify about process crash
 * @accel_dev: Pointer to acceleration device.
 *
 * Function notifies registered services that process crash occured.
 */
int adf_dev_proc_crash_notify(struct adf_accel_dev *accel_dev)
{
	struct service_hndl *service;
	struct list_head *list_itr;

	list_for_each(list_itr, &service_table) {
		service = list_entry(list_itr, struct service_hndl, list);
		if (service->event_hld(accel_dev, ADF_EVENT_PROC_CRASH))
			dev_err(&GET_DEV(accel_dev),
				"Failed to send buffer sync notification %s.\n",
				service->name);
	}
	return 0;
}

/**
 * adf_dev_manual_dump_notify() - Notify about manual dump
 * @accel_dev: Pointer to acceleration device.
 *
 * Function notifies registered services on manual dump request.
 */
int adf_dev_manual_dump_notify(struct adf_accel_dev *accel_dev)
{
	struct service_hndl *service;
	struct list_head *list_itr;

	list_for_each(list_itr, &service_table) {
		service = list_entry(list_itr, struct service_hndl, list);
		if (service->event_hld(accel_dev, ADF_EVENT_MANUAL_DUMP))
			dev_err(&GET_DEV(accel_dev),
				"Failed to send manual dump notification %s.\n",
				service->name);
	}
	return 0;
}

/**
 * adf_dev_err_resp_notify() - Notify about error response
 * @accel_dev: Pointer to acceleration device.
 *
 * Function notifies registered services about error response.
 */
int adf_dev_err_resp_notify(struct adf_accel_dev *accel_dev)
{
	struct service_hndl *service;
	struct list_head *list_itr;

	list_for_each(list_itr, &service_table) {
		service = list_entry(list_itr, struct service_hndl, list);
		if (service->event_hld(accel_dev, ADF_EVENT_ERR_RESP))
			dev_err(&GET_DEV(accel_dev),
				"Failed to send error response "
				"notification %s.\n",
				service->name);
	}
	return 0;
}

/**
 * adf_dev_dbg_shutdown_notify() - Notify about debuggability shutdown
 * @accel_dev: Pointer to acceleration device.
 *
 * Function notifies about shutting debuggability down.
 */
int adf_dev_dbg_shutdown_notify(struct adf_accel_dev *accel_dev)
{
	struct service_hndl *service;
	struct list_head *list_itr;

	list_for_each(list_itr, &service_table) {
		service = list_entry(list_itr, struct service_hndl, list);
		if (service->event_hld(accel_dev, ADF_EVENT_DBG_SHUTDOWN))
			dev_err(&GET_DEV(accel_dev),
				"Failed to send debug shutdown "
				"notification %s.\n",
				service->name);
	}
	return 0;
}

#endif /* QAT_DBG */
