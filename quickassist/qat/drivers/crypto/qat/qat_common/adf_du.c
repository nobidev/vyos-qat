// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2019 - 2021 Intel Corporation */
#include "adf_common_drv.h"
#include "adf_sla.h"
#include "adf_du.h"
#include "adf_du_user.h"
#include "icp_qat_fw_init_admin.h"

static int adf_du_get_active_dev(struct adf_accel_dev **accel_dev,
				 struct adf_pci_address *pci_addr)
{
	*accel_dev = adf_devmgr_get_dev_by_bdf(pci_addr);
	if (!*accel_dev) {
		pr_err("QAT: Device dbdf:%.4x:%.2x:%.2x:%x not found\n",
		       pci_addr->domain_nr, pci_addr->bus, pci_addr->dev,
		       pci_addr->func);
		return -EINVAL;
	}
	if (!adf_dev_started(*accel_dev)) {
		dev_err(&GET_DEV(*accel_dev), "Device not yet started.\n");
		goto exit;
	}

	return 0;

exit:
	adf_dev_put(*accel_dev);

	return -EFAULT;
}

static u32 adf_du_calc_util(struct adf_accel_dev *accel_dev,
			    u32 curr_util,
			    enum adf_svc_type svc_type)
{
	struct adf_dev_util_table *du_table = &(GET_DU_TABLE(accel_dev));
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);
	u32 slices = 0;
	u64 ticks_per_svc = 0, slau_per_svc = 0;

	/* Converting ticks to slau
	 * 1. get slices_per_svc
	 *    slices_per_svc = (no. of slices per service per AE pair) *
	 *                     (total AE pairs)
	 * 2. reference_ticks to ticks_per_svc
	 *    ticks_per_svc = reference_ticks * slices_per_svc
	 * 3. calculate utilization percentage per svc
	 *    percent_util_per_svc = total_ticks_per_svc / ticks_per_svc
	 * 4. convert utilization to slau
	 *    slau_per_svc = percent_util_per_svc * max_slau_per_svc
	 * NOTES:
	 *    slices_per_svc           = total slices per service
	 *    reference_ticks          = du_table->total_util(value of AE
	 *                               ticks measured between issuing
	 *                               DU Start and DU Stop)
	 *    total_ticks_per_svc      = curr_util(for PF, sum of all VF
	 *                               values returned by DU per service.
	 *                               For VF, value returned by DU per
	 *                               service for the VF)
	 *    max_slau_per_svc         = max device capacity in slau(
	 *                               accel_dev->sla_sku.slau_supported[svc])
	 */
	slices = hw_data->get_slices_for_svc(accel_dev, svc_type);
	ticks_per_svc = (u64)du_table->total_util * slices;
	if (ticks_per_svc) {
		slau_per_svc =
		(u64)accel_dev->sla_sku.slau_supported[svc_type] *
		curr_util;
		do_div(slau_per_svc, ticks_per_svc);
	}

	/* return device utilization in sla units */
	return (u32)slau_per_svc;
}

static u32 adf_du_get_vf_slau(struct adf_accel_dev *accel_dev,
			      struct adf_user_du *du)
{
	struct adf_slas *cur_sla = NULL, *tmp = NULL;

	list_for_each_entry_safe(cur_sla, tmp, &accel_dev->sla_list, list) {
		if (adf_is_bdf_equal(&cur_sla->sla.pci_addr, &du->vf_addr) &&
		    cur_sla->sla.svc_type == du->svc_type)
			return cur_sla->sla.rate_in_slau;
	}

	return 0;
}

static void adf_du_get_dev_util
	    (struct adf_accel_dev *accel_dev,
	     struct adf_user_du *du,
	     u32 vf_nr)
{
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);
	u32 current_util = 0;
	u32 max_slau_caps = accel_dev->sla_sku.slau_supported[du->svc_type];
	u8 num_banks = GET_MAX_BANKS(accel_dev), i = 0;
	u32 *dptr = NULL,
	    *du_entries = (u32 *)(GET_DU_TABLE(accel_dev).virt_addr);

	if (hw_data->get_num_vfs)
		num_banks = hw_data->get_num_vfs(accel_dev);

	du->slau_util_percent = 0;
	du->slau_supported = 0;
	dptr = du_entries + (du->svc_type * num_banks);

	if (vf_nr == ALL_VF_DU) {
		du->slau_supported = max_slau_caps;
		for (i = 0; i < num_banks; i++)
			current_util += dptr[i];
	} else if (vf_nr < num_banks) {
		current_util = dptr[vf_nr];
		du->slau_supported = adf_du_get_vf_slau(accel_dev, du);
	}

	du->slau_utilized = adf_du_calc_util(accel_dev, current_util,
					     du->svc_type);

	if (max_slau_caps)
		du->slau_util_percent =
			(du->slau_utilized * 100) / max_slau_caps;
}

static int adf_du_query_for_pf(struct adf_accel_dev *accel_dev,
			       struct adf_user_du *query)
{
	if (!(GET_HW_DATA(accel_dev)->is_du_supported)) {
		dev_err(&GET_DEV(accel_dev), "DU Query is not supported.\n");
		return -EINVAL;
	}

	if (!(accel_dev->sla_sku.svc_supported & BIT(query->svc_type))) {
		dev_err(&GET_DEV(accel_dev),
			"Service is not enabled %d\n",
		query->svc_type);
		return -EINVAL;
	}

	adf_du_get_dev_util(accel_dev, query, ALL_VF_DU);

	return 0;
}

static int adf_du_query_for_vf(struct adf_accel_dev *accel_dev,
			       struct adf_user_du *query)
{
	int vf_nr = 0;
	int ret = 0;

	if (!(GET_HW_DATA(accel_dev)->is_du_supported)) {
		dev_err(&GET_DEV(accel_dev), "DU Query is not supported by VF driver.\n");
		return -EINVAL;
	}

	if (!(accel_dev->sla_sku.svc_supported & BIT(query->svc_type))) {
		dev_err(&GET_DEV(accel_dev),
			"Service is not enabled %d\n",
			query->svc_type);
		return -EINVAL;
	}

	ret = adf_get_vf_nr(&query->vf_addr, &vf_nr);
	if (ret) {
		dev_err(&GET_DEV(accel_dev), "Get VF number failed.\n");
		return -EINVAL;
	}

	if (adf_is_vf_nr_valid(accel_dev, vf_nr) < 0) {
		dev_err(&GET_DEV(accel_dev), "BDF not found for DU Query.\n");
		return -EINVAL;
	}

	adf_du_get_dev_util(accel_dev, query, vf_nr);

	return ret;
}

int adf_du_start(struct adf_pci_address *pci_addr)
{
	struct adf_accel_dev *accel_dev = NULL;
	int ret = 0;

	ret = adf_du_get_active_dev(&accel_dev, pci_addr);
	if (ret)
		return ret;

	if ((accel_dev)->is_vf ||
	    !(GET_HW_DATA((accel_dev))->is_du_supported)) {
		dev_err(&GET_DEV(accel_dev),
			"DU Start is not supported\n");
		adf_dev_put(accel_dev);
		return -EINVAL;
	}

	ret = adf_send_du_start(accel_dev);
	adf_dev_put(accel_dev);

	return ret;
}

int adf_du_stop(struct adf_pci_address *pci_addr)
{
	struct adf_accel_dev *accel_dev = NULL;
	int ret = 0;

	ret = adf_du_get_active_dev(&accel_dev, pci_addr);
	if (ret)
		return ret;

	if ((accel_dev)->is_vf ||
	    !(GET_HW_DATA((accel_dev))->is_du_supported)) {
		dev_err(&GET_DEV(accel_dev),
			"DU Stop is not supported\n");
		adf_dev_put(accel_dev);
		return -EINVAL;
	}

	ret = adf_send_du_stop(accel_dev);
	adf_dev_put(accel_dev);

	return ret;
}

int adf_du_query(struct adf_user_du *du)
{
	struct adf_accel_dev *accel_dev = NULL;
	int ret = 0;

	if (du->svc_type >= ADF_MAX_SERVICES) {
		pr_err("QAT: Invalid svc type\n");
		return -EINVAL;
	}

	ret = adf_du_get_active_dev(&accel_dev, &du->pf_addr);
	if (ret)
		return ret;

	ret = adf_du_query_for_pf(accel_dev, du);
	if (ret)
		dev_err(&GET_DEV(accel_dev), "Failed to query du: %d\n", ret);

	adf_dev_put(accel_dev);

	return ret;
}

int adf_du_query_vf(struct adf_user_du *du)
{
	struct adf_accel_dev *accel_dev = NULL;
	int ret = 0;

	if (du->svc_type >= ADF_MAX_SERVICES) {
		pr_err("QAT: Invalid svc type\n");
		return -EINVAL;
	}

	if (du->pf_addr.bus != du->vf_addr.bus) {
		pr_err("QAT: VF doesn't belong to PF.\n");
		return -EINVAL;
	}

	ret = adf_du_get_active_dev(&accel_dev, &du->pf_addr);
	if (ret)
		return ret;

	ret = adf_du_query_for_vf(accel_dev, du);
	if (ret) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to query du VF: %d\n", ret);
	}

	adf_dev_put(accel_dev);

	return ret;
}

int adf_du_init(struct adf_accel_dev *accel_dev)
{
	struct adf_dev_util_table du_table = {0};
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);
	u8 num_banks = GET_MAX_BANKS(accel_dev);
	u32 size = 0;

	if (hw_data->get_num_vfs)
		num_banks = hw_data->get_num_vfs(accel_dev);

	size = ADF_MAX_SERVICES * num_banks;

	du_table.virt_addr = dma_alloc_coherent(&GET_DEV(accel_dev),
						size * sizeof(u32),
						&du_table.dma_addr,
						GFP_KERNEL);
	if (!du_table.virt_addr) {
		dev_err(&GET_DEV(accel_dev), "DU table memory allocation failed\n");
		return -ENOMEM;
	}
	accel_dev->du_table = du_table;
	GET_HW_DATA(accel_dev)->is_du_supported = true;

	return 0;
}

int adf_du_exit(struct adf_accel_dev *accel_dev)
{
	bool *is_du_supported = &GET_HW_DATA(accel_dev)->is_du_supported;
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);
	u8 num_banks = GET_MAX_BANKS(accel_dev);
	u32 size = 0;

	if (hw_data->get_num_vfs)
		num_banks = hw_data->get_num_vfs(accel_dev);

	size = ADF_MAX_SERVICES * num_banks;

	if (!(*is_du_supported))
		return 0;
	dma_free_coherent(&GET_DEV(accel_dev),
			  size,
			  GET_DU_TABLE(accel_dev).virt_addr,
			  accel_dev->du_table.dma_addr);
	*is_du_supported = false;

	return 0;
}
