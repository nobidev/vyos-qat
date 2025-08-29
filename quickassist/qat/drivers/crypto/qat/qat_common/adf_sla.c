// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2019 - 2021 Intel Corporation */

#include "adf_cfg_common.h"
#include "adf_common_drv.h"
#include "adf_sla.h"
#include "adf_cfg_strings.h"
#include "adf_cfg.h"
#include "icp_qat_hw.h"

#define CYCLES_PER_TICK 16
#define INTERVALS_PER_SECOND 1000

static int sla_mgr_get_dev_caps(struct adf_accel_dev *accel_dev,
				struct sla_sku_dev *sla_sku)
{
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);
	u32 i = 0, slices = 0, num_aes = hw_data->get_num_aes(hw_data);
	u32 ticks_per_interval = CYCLES_PER_TICK * INTERVALS_PER_SECOND;
	u32 *sla_units = NULL;
	u32 capabilities = hw_data->accel_capabilities_mask;

	if (!num_aes)
		return 0;
	if (!hw_data->get_sla_units ||
	    hw_data->get_sla_units(accel_dev, &sla_units)) {
		dev_err(&GET_DEV(accel_dev),
			"Sla units not defined for device\n");
		return -EFAULT;
	}

	if (capabilities & ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC)
		sla_sku->slau_supported[ADF_SVC_ASYM] = sla_units[ADF_SVC_ASYM];
	if (capabilities & ADF_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC)
		sla_sku->slau_supported[ADF_SVC_SYM] = sla_units[ADF_SVC_SYM];
	if (capabilities & ADF_ACCEL_CAPABILITIES_COMPRESSION)
		sla_sku->slau_supported[ADF_SVC_DC] = sla_units[ADF_SVC_DC];

	/* Calculate sla units based on number of AES and it's not
	 * required for GEN3 device where sla calculation is done based
	 * on number of slices are used for services configured in config
	 * files.
	 */
	if (hw_data->calc_sla_units) {
		if (hw_data->calc_sla_units(accel_dev, sla_sku)) {
			dev_err(&GET_DEV(accel_dev),
				"Failed to calculate the number of sla\t"
				"units\n");
			return -EFAULT;
		}
	}

	slices = hw_data->get_slices_for_svc(accel_dev, ADF_SVC_ASYM);
	sla_sku->ticks[ADF_SVC_ASYM] = slices *
			(hw_data->clock_frequency / ticks_per_interval);
	slices = hw_data->get_slices_for_svc(accel_dev, ADF_SVC_SYM);
	sla_sku->ticks[ADF_SVC_SYM] = slices *
			(hw_data->clock_frequency / ticks_per_interval);
	slices = hw_data->get_slices_for_svc(accel_dev, ADF_SVC_DC);
	sla_sku->ticks[ADF_SVC_DC] = slices *
			(hw_data->clock_frequency / ticks_per_interval);

	for (i = 0; i < ADF_MAX_SERVICES; i++)
		if (sla_sku->slau_supported[i])
			sla_sku->svc_supported |= (BIT(i));

	return 0;
}

static int sla_mgr_get_new_sla_id(struct adf_accel_dev *accel_dev, u16 *id)
{
	u16 i = 0, max_slas = 0;
	unsigned long svc_supported = accel_dev->sla_sku.svc_supported;
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);
	u8 num_banks = GET_MAX_BANKS(accel_dev);

	if (hw_data->get_num_vfs)
		num_banks = hw_data->get_num_vfs(accel_dev);

	for_each_set_bit(i, &svc_supported, ADF_MAX_SERVICES)
		max_slas += num_banks;

	for (i = 0; i < max_slas && accel_dev->sla_ids[i]; i++)
		;

	if (accel_dev->sla_ids[i])
		return -EFAULT;

	*id = i;
	accel_dev->sla_ids[*id] = 1;

	return 0;
}

static int sla_mgr_add(struct adf_accel_dev *accel_dev,
		       struct adf_user_sla *sla)
{
	struct adf_slas *new_sla = kmalloc_node(sizeof(*new_sla), GFP_KERNEL,
		dev_to_node(&GET_DEV(accel_dev)));
	if (!new_sla)
		return -ENOMEM;

	memcpy(&new_sla->sla, sla, sizeof(*sla));
	list_add_tail(&new_sla->list, &accel_dev->sla_list);

	return 0;
}

static void sla_mgr_del(struct adf_accel_dev *accel_dev,
			struct adf_user_sla *sla)
{
	struct adf_slas *cur_sla = NULL, *tmp = NULL;

	list_for_each_entry_safe(cur_sla, tmp, &accel_dev->sla_list, list) {
		if (cur_sla->sla.sla_id == sla->sla_id) {
			list_del(&cur_sla->list);
			kfree(cur_sla);
			break;
		}
	}
}

static void sla_mgr_update(struct adf_accel_dev *accel_dev,
			   struct adf_user_sla *sla)
{
	struct adf_slas *cur_sla = NULL;

	list_for_each_entry(cur_sla, &accel_dev->sla_list, list) {
		if (cur_sla->sla.sla_id == sla->sla_id) {
			cur_sla->sla.rate_in_slau = sla->rate_in_slau;
			break;
		}
	}
}

static bool sla_mgr_svc_exists(struct adf_accel_dev *accel_dev,
			       struct adf_pci_address *addr,
			       enum adf_svc_type svc)
{
	struct adf_slas *cur_sla = NULL;
	struct adf_pci_address *tmp = NULL;

	list_for_each_entry(cur_sla, &accel_dev->sla_list, list) {
		tmp = &cur_sla->sla.pci_addr;
		if (adf_is_bdf_equal(addr, tmp) && cur_sla->sla.svc_type == svc)
			return true;
	}

	return false;
}

static int sla_mgr_get_sla(struct adf_accel_dev *accel_dev, u16 id,
			   struct adf_user_sla *sla)
{
	struct adf_slas *cur_sla = NULL;

	list_for_each_entry(cur_sla, &accel_dev->sla_list, list) {
		if (cur_sla->sla.sla_id == id) {
			memcpy(sla, &cur_sla->sla, sizeof(cur_sla->sla));
			return 0;
		}
	}

	return -EINVAL;
}

static void sla_mgr_get_slas(struct adf_accel_dev *accel_dev,
			     struct adf_user_slas *slas)
{
	struct adf_slas *cur_sla = NULL;

	slas->used_slas = 0;
	memset(&slas->slas, 0, sizeof(slas->slas));

	list_for_each_entry(cur_sla, &accel_dev->sla_list, list) {
		memcpy(&slas->slas[slas->used_slas],
		       &cur_sla->sla, sizeof(cur_sla->sla));
		slas->used_slas++;
	}
}

static int sla_mgr_update_caps(struct adf_accel_dev *accel_dev,
			       struct adf_user_sla_caps *caps)
{
	struct adf_slas *cur_sla = NULL;
	u8 i = 0;

	for (i = 0; i < ADF_MAX_SERVICES; i++)
		caps->services[i].avail_svc_rate_in_slau
			= caps->services[i].max_svc_rate_in_slau;

	caps->used_slas = 0;
	list_for_each_entry(cur_sla, &accel_dev->sla_list, list) {
		i = cur_sla->sla.svc_type;
		if (i >= ADF_MAX_SERVICES)
			return -EINVAL;
		caps->services[i].svc_type = cur_sla->sla.svc_type;
		caps->services[i].avail_svc_rate_in_slau -=
			cur_sla->sla.rate_in_slau;
		caps->used_slas++;
	}

	caps->avail_slas = caps->max_slas - caps->used_slas;

	return 0;
}

static int sla_set(struct adf_accel_dev *accel_dev,
		   struct adf_user_sla *sla, u32 sla_ticks)
{
	int vf_nr = 0;
	int ret = 0;

	ret = adf_get_vf_nr(&sla->pci_addr, &vf_nr);
	if (ret) {
		dev_err(&GET_DEV(accel_dev), "QAT: Get VF number failed.\n");
		return -EINVAL;
	}

	if (adf_is_vf_nr_valid(accel_dev, vf_nr) < 0) {
		dev_err(&GET_DEV(accel_dev), "Invalid VF address\n");
		return -EINVAL;
	}
	if (adf_send_set_sla(accel_dev, vf_nr, sla->svc_type, sla_ticks) < 0) {
		dev_err(&GET_DEV(accel_dev), "SLA send failed\n");
		return -EFAULT;
	}

	return ret;
}

static int sla_create(struct adf_accel_dev *accel_dev,
		      struct adf_user_sla *sla)
{
	u64 sla_ticks = 0;
	u16 sla_id = 0;
	int ret = -EINVAL;

	if (sla->rate_in_slau > accel_dev->available_slau[sla->svc_type]) {
		dev_err(&GET_DEV(accel_dev),
			"No SLA bandwidth left. requested=%d left=%d\n",
			sla->rate_in_slau,
			accel_dev->available_slau[sla->svc_type]);
		return ret;
	}

	sla_ticks = (u64)accel_dev->sla_sku.ticks[sla->svc_type] *
		sla->rate_in_slau;
	do_div(sla_ticks, accel_dev->sla_sku.slau_supported[sla->svc_type]);

	ret = sla_mgr_get_new_sla_id(accel_dev, &sla_id);
	if (ret < 0) {
		dev_err(&GET_DEV(accel_dev), "Get new SLA ID failed\n");
		return ret;
	}

	ret = sla_set(accel_dev, sla, (u32)sla_ticks);
	if (ret < 0) {
		accel_dev->sla_ids[sla_id] = 0;
		return ret;
	}

	accel_dev->available_slau[sla->svc_type] -= sla->rate_in_slau;
	sla->sla_id = sla_id;

	return ret;
}

static int sla_update(struct adf_accel_dev *accel_dev, struct adf_user_sla *sla,
		      u16 previous_rate)
{
	u64 sla_ticks = 0;
	int ret = -EINVAL;

	if (sla->rate_in_slau >
	    (accel_dev->available_slau[sla->svc_type] + previous_rate)) {
		dev_err(&GET_DEV(accel_dev),
			"Requested rate exceeds total bandwidth!\n");
		return ret;
	}

	sla_ticks = (u64)accel_dev->sla_sku.ticks[sla->svc_type] *
		sla->rate_in_slau;
	do_div(sla_ticks, accel_dev->sla_sku.slau_supported[sla->svc_type]);

	ret = sla_set(accel_dev, sla, (u32)sla_ticks);
	if (ret < 0)
		return ret;

	accel_dev->available_slau[sla->svc_type] -= sla->rate_in_slau;
	accel_dev->available_slau[sla->svc_type] += previous_rate;

	return ret;
}

static int sla_delete(struct adf_accel_dev *accel_dev,
		      struct adf_user_sla *sla)
{
	if (sla_set(accel_dev, sla, 0) < 0)
		return -EFAULT;

	accel_dev->available_slau[sla->svc_type] += sla->rate_in_slau;
	accel_dev->sla_ids[sla->sla_id] = 0;

	return 0;
}

static int sla_get_caps(struct adf_accel_dev *accel_dev,
			struct adf_user_sla_caps *caps)
{
	u8 i = 0;
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);
	u8 num_banks = GET_MAX_BANKS(accel_dev);

	if (hw_data->get_num_vfs)
		num_banks = hw_data->get_num_vfs(accel_dev);

	caps->max_slas = 0;
	for (i = 0; i < ADF_MAX_SERVICES; i++) {
		if (BIT(i) & accel_dev->sla_sku.svc_supported)
			caps->max_slas += num_banks;
		caps->services[i].svc_type = (enum adf_svc_type)i;
		caps->services[i].max_svc_rate_in_slau =
			accel_dev->sla_sku.slau_supported[i];
	}

	return 0;
}

static bool is_sla_supported(struct adf_accel_dev *accel_dev)
{
	if (!accel_dev->hw_device->is_sla_supported) {
		dev_err(&GET_DEV(accel_dev), "SLA not supported\n");
		return false;
	}

	return true;
}

int adf_sla_create(struct adf_user_sla *sla)
{
	int ret = 0;
	struct adf_accel_dev *accel_dev = NULL;

	accel_dev = adf_devmgr_get_dev_by_pci_domain_bus(&sla->pci_addr);
	if (!accel_dev) {
		pr_err("QAT: Physical Device dbdf:%.4x:%.2x:%.2x.%x not found\n",
		       sla->pci_addr.domain_nr,
		       sla->pci_addr.bus,
		       sla->pci_addr.dev,
		       sla->pci_addr.func);
		return -ENODEV;
	}
	if (!is_sla_supported(accel_dev)) {
		adf_dev_put(accel_dev);
		return -EFAULT;
	}

	if (!(accel_dev->sla_sku.svc_supported & BIT(sla->svc_type))) {
		dev_err(&GET_DEV(accel_dev),
			"Service is not enabled %d\n",
			sla->svc_type);
		adf_dev_put(accel_dev);
		return -EFAULT;
	}

	/* Do not allow more than one SLA for the same service */
	if (sla_mgr_svc_exists(accel_dev, &sla->pci_addr, sla->svc_type)) {
		dev_err(&GET_DEV(accel_dev),
			"SLA for the same service already in place\n");
		adf_dev_put(accel_dev);
		return -EFAULT;
	}

	/* Round SLA to nearest K */
	sla->rate_in_slau = roundup(sla->rate_in_slau, AU_ROUNDOFF);
	/* Allocate sla id and set it to sla */
	if (sla_create(accel_dev, sla)) {
		dev_err(&GET_DEV(accel_dev), "Failed to create SLA\n");
		adf_dev_put(accel_dev);
		return -EFAULT;
	}
	ret = sla_mgr_add(accel_dev, sla);
	if (ret)
		goto err;

	adf_dev_put(accel_dev);

	return ret;
err:
	sla_delete(accel_dev, sla);
	dev_err(&GET_DEV(accel_dev), "Failed to create SLA\n");
	adf_dev_put(accel_dev);

	return ret;
}

int adf_sla_update(struct adf_user_sla *sla)
{
	struct adf_accel_dev *accel_dev = NULL;
	struct adf_user_sla tmp;
	u32 previous_rate = 0;

	accel_dev = adf_devmgr_get_dev_by_bdf(&sla->pci_addr);
	if (!accel_dev) {
		pr_err("QAT: Physical Device dbdf=%.4x:%.2x:%.2x.%x not found\n",
		       sla->pci_addr.domain_nr,
		       sla->pci_addr.bus,
		       sla->pci_addr.dev,
		       sla->pci_addr.func);
		return -ENODEV;
	}

	if (!is_sla_supported(accel_dev)) {
		adf_dev_put(accel_dev);
		return -EFAULT;
	}

	if (sla_mgr_get_sla(accel_dev, sla->sla_id, &tmp) < 0) {
		dev_err(&GET_DEV(accel_dev), "SLA id=%d not found!\n",
			sla->sla_id);
		adf_dev_put(accel_dev);
		return -EINVAL;
	}

	previous_rate = tmp.rate_in_slau;
	/* Round SLA to nearest K */
	tmp.rate_in_slau = roundup(sla->rate_in_slau, AU_ROUNDOFF);

	if (sla_update(accel_dev, &tmp, previous_rate)) {
		dev_err(&GET_DEV(accel_dev), "Failed to update SLA\n");
		adf_dev_put(accel_dev);
		return -EFAULT;
	}

	sla_mgr_update(accel_dev, &tmp);
	adf_dev_put(accel_dev);

	return 0;
}

int adf_sla_delete(struct adf_user_sla *sla)
{
	struct adf_accel_dev *accel_dev = NULL;
	struct adf_user_sla tmp;

	accel_dev = adf_devmgr_get_dev_by_bdf(&sla->pci_addr);
	if (!accel_dev) {
		pr_err("QAT: Physical Device dbdf=%.4x:%.2x:%.2x.%x not found\n",
		       sla->pci_addr.domain_nr,
		       sla->pci_addr.bus,
		       sla->pci_addr.dev,
		       sla->pci_addr.func);
		return -ENODEV;
	}

	if (!is_sla_supported(accel_dev)) {
		adf_dev_put(accel_dev);
		return -EFAULT;
	}

	if (sla_mgr_get_sla(accel_dev, sla->sla_id, &tmp) < 0) {
		dev_err(&GET_DEV(accel_dev), "SLA id=%d not found!\n",
			sla->sla_id);
		adf_dev_put(accel_dev);
		return -EINVAL;
	}

	if (sla_delete(accel_dev, &tmp)) {
		dev_err(&GET_DEV(accel_dev), "Failed to delete SLA\n");
		adf_dev_put(accel_dev);
		return -EFAULT;
	}

	sla_mgr_del(accel_dev, sla);
	adf_dev_put(accel_dev);

	return 0;
}

int adf_sla_get_caps(struct adf_user_sla_caps *sla_caps)
{
	struct adf_accel_dev *accel_dev = NULL;
	int ret = -EFAULT;

	accel_dev = adf_devmgr_get_dev_by_bdf(&sla_caps->pf_addr);
	if (!accel_dev) {
		pr_err("QAT: Device dbdf:%.4x:%.2x:%.2x.%x not found\n",
		       sla_caps->pf_addr.domain_nr,
		       sla_caps->pf_addr.bus,
		       sla_caps->pf_addr.dev,
		       sla_caps->pf_addr.func);
		return -ENODEV;
	}

	if (!is_sla_supported(accel_dev)) {
		adf_dev_put(accel_dev);
		return ret;
	}

	if (sla_get_caps(accel_dev, sla_caps)) {
		dev_err(&GET_DEV(accel_dev), "Failed to get SLA capability\n");
		adf_dev_put(accel_dev);
		return ret;
	}

	ret = sla_mgr_update_caps(accel_dev, sla_caps);
	if (ret) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to update SLA capability\n");
		adf_dev_put(accel_dev);
		return ret;
	}

	adf_dev_put(accel_dev);

	return 0;
}

int adf_sla_get_list(struct adf_user_slas *slas)
{
	struct adf_accel_dev *accel_dev = NULL;
	int ret = -EFAULT;

	accel_dev = adf_devmgr_get_dev_by_bdf(&slas->pf_addr);
	if (!accel_dev) {
		pr_err("QAT: Device dbdf:%.4x:%.2x:%.2x.%x not found\n",
		       slas->pf_addr.domain_nr,
		       slas->pf_addr.bus,
		       slas->pf_addr.dev,
		       slas->pf_addr.func);
		return -ENODEV;
	}

	if (!is_sla_supported(accel_dev)) {
		adf_dev_put(accel_dev);
		return ret;
	}

	sla_mgr_get_slas(accel_dev, slas);

	adf_dev_put(accel_dev);

	return 0;
}

static u32 adf_get_period(struct adf_accel_dev *accel_dev)
{
	u32 ticks_per_interval = CYCLES_PER_TICK * INTERVALS_PER_SECOND;

	return GET_HW_DATA(accel_dev)->clock_frequency / ticks_per_interval;
}

int adf_sla_mgr_init(struct adf_accel_dev *accel_dev)
{
	u8 nr_svc = 0;
	u8 i = 0;
	struct sla_sku_dev sla_sku = { {0, 0, 0}, {0, 0, 0}, 0 };
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	unsigned long svc_supported = 0;
	u8 num_banks = GET_MAX_BANKS(accel_dev);

	if (hw_data->get_num_vfs)
		num_banks = hw_data->get_num_vfs(accel_dev);

	if (sla_mgr_get_dev_caps(accel_dev, &sla_sku))
		return -EFAULT;

	if (!sla_sku.svc_supported) {
		dev_err(&GET_DEV(accel_dev), "SLA not supported on %s\n",
			get_sku_info(GET_DEV_SKU(accel_dev)));
		return -EFAULT;
	}

	accel_dev->available_slau = kcalloc(ADF_MAX_SERVICES,
					    sizeof(*accel_dev->available_slau),
					    GFP_KERNEL);
	if (!accel_dev->available_slau)
		return -ENOMEM;

	svc_supported = sla_sku.svc_supported;

	for_each_set_bit(i, &svc_supported, ADF_MAX_SERVICES) {
		accel_dev->available_slau[i] = sla_sku.slau_supported[i];
		++nr_svc;
	}

	accel_dev->sla_ids = kcalloc(num_banks * nr_svc,
				     sizeof(*accel_dev->sla_ids),
				     GFP_KERNEL);
	if (!accel_dev->sla_ids) {
		dev_err(&GET_DEV(accel_dev), "Failed to init SLA.\n");
		kfree(accel_dev->available_slau);
		return -ENOMEM;
	}
	accel_dev->sla_sku = sla_sku;
	hw_data->is_sla_supported = true;

	return 0;
}

static void adf_sla_mgr_exit(struct adf_accel_dev *accel_dev)
{
	struct adf_slas *cur_sla = NULL, *tmp = NULL;
	bool *is_sla_supported = &GET_HW_DATA(accel_dev)->is_sla_supported;

	if (!(*is_sla_supported))
		return;

	list_for_each_entry_safe(cur_sla, tmp, &accel_dev->sla_list, list) {
		sla_delete(accel_dev, &cur_sla->sla);
		sla_mgr_del(accel_dev, &cur_sla->sla);
	}
	kfree(accel_dev->available_slau);
	kfree(accel_dev->sla_ids);
	*is_sla_supported = false;
}

/*
 * adf_rate_limiting_init() - Start rate limit gathering and init
 * sla data structure
 * @accel_dev:    Pointer to acceleration device.
 *
 * Function checks if rate limiting feature is enabled for the device.
 * Starts rate limit gathering and initializes sla data structures for devices
 * that supports rate limiting.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_rate_limiting_init(struct adf_accel_dev *accel_dev)
{
	u32 period = 0;
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);

	/* If accel dev is VF, return 0 */
	if (accel_dev->is_vf)
		return 0;

	/* If rate limiting is not supported, return 0 */
	if (!(hw_data->accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_RL))
		return 0;

	INIT_LIST_HEAD(&accel_dev->sla_list);

	period = adf_get_period(accel_dev);
	if (adf_send_rl_init(accel_dev, period,
			     hw_data->get_num_aes(hw_data))) {
		dev_err(&GET_DEV(accel_dev), "Failed to init gathering\n");
		return -EFAULT;
	}
	if (adf_du_init(accel_dev))
		return -EFAULT;

	return adf_sla_mgr_init(accel_dev);
}

/*
 * adf_rate_limiting_exit() - Delete the SLA entries and exit
 * @accel_dev:    Pointer to acceleration device.
 *
 * Function checks and deletes the entries of SLA and DU.
 *
 */
void adf_rate_limiting_exit(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	if (accel_dev->is_vf)
		return;

	/* send admin message to firmware to disable rate limiting */
	if ((hw_data->accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_RL) &&
	    (adf_send_rl_exit(accel_dev))) {
		dev_err(&GET_DEV(accel_dev), "Failed to send rl exit\n");
	}

	adf_sla_mgr_exit(accel_dev);
	adf_du_exit(accel_dev);
}
