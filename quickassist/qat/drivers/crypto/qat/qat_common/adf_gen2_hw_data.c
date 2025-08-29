// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2020 - 2021 Intel Corporation */

#include <linux/firmware.h>
#include <linux/pci.h>
#include "adf_gen2_hw_data.h"
#include "adf_cfg.h"
#include "adf_common_drv.h"
#include "icp_qat_uclo.h"
#include "icp_qat_hw.h"

#define MMP_VERSION_LEN 4

struct adf_mmp_version_s {
	u8 ver_val[MMP_VERSION_LEN];
};

void get_gen2_arb_info(struct adf_arb_info *arb_csrs_info)
{
	arb_csrs_info->arbiter_offset = ADF_ARB_OFFSET;
	arb_csrs_info->wrk_thd_2_srv_arb_offset =
			ADF_ARB_WRK_2_SER_MAP_OFFSET;
	arb_csrs_info->dbg_rst_arb_offset = ADF_ARB_DBG_RST_ARB_OFFSET;
}
EXPORT_SYMBOL_GPL(get_gen2_arb_info);

void get_gen2_admin_info(struct adf_admin_info *admin_csrs_info)
{
	admin_csrs_info->mailbox_offset = ADF_MAILBOX_BASE_OFFSET;
	admin_csrs_info->admin_msg_ur = ADF_ADMINMSGUR_OFFSET;
	admin_csrs_info->admin_msg_lr = ADF_ADMINMSGLR_OFFSET;
}
EXPORT_SYMBOL_GPL(get_gen2_admin_info);

int adf_gen2_init_arb(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_arb_info info;
	void __iomem *csr = accel_dev->transport->banks[0].csr_addr;
	u32 i;
	const u32 *thd_2_arb_cfg;

	/* invoke common adf_init_arb */
	adf_init_arb(accel_dev);

	info.arbiter_offset = ADF_ARB_OFFSET;
	info.wrk_thd_2_srv_arb_offset =
			ADF_ARB_WRK_2_SER_MAP_OFFSET;

	if (!hw_data->get_arb_mapping)
		return -1;

	/* Map worker threads to service arbiters */
	hw_data->get_arb_mapping(accel_dev, &thd_2_arb_cfg);
	if (!thd_2_arb_cfg)
		return -EFAULT;

	for (i = 0; i < hw_data->num_engines; i++)
		WRITE_CSR_ARB_WRK_2_SER_MAP(csr,
					    info.arbiter_offset,
					    info.wrk_thd_2_srv_arb_offset,
					    i, *(thd_2_arb_cfg + i));
	return 0;
}
EXPORT_SYMBOL_GPL(adf_gen2_init_arb);

void adf_gen2_exit_arb(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_arb_info info;
	void __iomem *csr;
	unsigned int i;

	if (!accel_dev->transport)
		return;

	csr = accel_dev->transport->banks[0].csr_addr;

	/* invoke common adf_exit_arb */
	adf_exit_arb(accel_dev);

	info.arbiter_offset = ADF_ARB_OFFSET;
	info.wrk_thd_2_srv_arb_offset =
			ADF_ARB_WRK_2_SER_MAP_OFFSET;

	if (!hw_data->get_arb_mapping)
		return;

	/* Unmap worker threads to service arbiters */
	for (i = 0; i < hw_data->num_engines; i++)
		WRITE_CSR_ARB_WRK_2_SER_MAP(csr,
					    info.arbiter_offset,
					    info.wrk_thd_2_srv_arb_offset,
					    i, 0);

	/* Disable arbitration on all rings */
	for (i = 0; i < GET_MAX_BANKS(accel_dev); i++)
		WRITE_CSR_ARB_RINGSRVARBEN(csr, i, 0);
}
EXPORT_SYMBOL_GPL(adf_gen2_exit_arb);

int adf_gen2_ae_fw_load(struct adf_accel_dev *accel_dev)
{
	struct adf_fw_loader_data *loader_data = accel_dev->fw_loader;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	void *uof_addr, *mmp_addr;
	u32 uof_size, mmp_size;
	char uofname[ADF_CFG_MAX_VAL_LEN_IN_BYTES];
	struct adf_accel_pci *pci_info = &accel_dev->accel_pci_dev;
	struct adf_mmp_version_s mmp_ver = { {0} };

	if (!hw_device->fw_name)
		return 0;

	if (request_firmware(&loader_data->mmp_fw, hw_device->fw_mmp_name,
			     &accel_dev->accel_pci_dev.pci_dev->dev)) {
		dev_err(&GET_DEV(accel_dev), "Failed to load MMP firmware %s\n",
			hw_device->fw_mmp_name);
		return -EFAULT;
	}
	if (request_firmware(&loader_data->uof_fw, hw_device->fw_name,
			     &accel_dev->accel_pci_dev.pci_dev->dev)) {
		dev_err(&GET_DEV(accel_dev), "Failed to load UOF firmware %s\n",
			hw_device->fw_name);
		goto out_err;
	}

	uof_size = loader_data->uof_fw->size;
	uof_addr = (void *)loader_data->uof_fw->data;
	mmp_size = loader_data->mmp_fw->size;
	mmp_addr = (void *)loader_data->mmp_fw->data;

	memcpy(&mmp_ver, mmp_addr, MMP_VERSION_LEN);

	accel_dev->fw_versions.mmp_version_major = mmp_ver.ver_val[0];
	accel_dev->fw_versions.mmp_version_minor = mmp_ver.ver_val[1];
	accel_dev->fw_versions.mmp_version_patch = mmp_ver.ver_val[2];

	if (pci_info->pci_dev->device == ADF_DH895XCC_PCI_DEVICE_ID) {
		strlcpy(uofname, ADF_DH895XCC_AE_FW_NAME,
			sizeof(uofname));
	} else {
		strlcpy(uofname, ADF_CXXX_AE_FW_NAME, sizeof(uofname));
	}

	if (hw_device->accel_capabilities_mask &
			ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC)
		if (qat_uclo_wr_mimage(loader_data->fw_loader, mmp_addr,
				       mmp_size)) {
			dev_err(&GET_DEV(accel_dev), "Failed to load MMP\n");
			goto out_err;
		}

	if (hw_device->get_fw_name(accel_dev, uofname)) {
		dev_err(&GET_DEV(accel_dev), "Failed to get UOF name\n");
		goto out_err;
	}
	if (qat_uclo_map_obj(loader_data->fw_loader, uof_addr,
			     uof_size, uofname)) {
		dev_err(&GET_DEV(accel_dev), "Failed to map FW\n");
		goto out_err;
	}

	if (qat_uclo_wr_all_uimage(loader_data->fw_loader)) {
		dev_err(&GET_DEV(accel_dev), "Failed to load UOF\n");
		goto out_err;
	}
	return 0;

out_err:
	adf_ae_fw_release(accel_dev);
	return -EFAULT;
}
EXPORT_SYMBOL_GPL(adf_gen2_ae_fw_load);

u32 get_gen2_vintsou_offset(void)
{
	return ADF_IOV_VINTSOU_OFFSET;
}
EXPORT_SYMBOL_GPL(get_gen2_vintsou_offset);

u32 adf_gen2_get_dc_ae_mask(struct adf_accel_dev *accel_dev)
{
	if (!(accel_dev->hw_device->accel_capabilities_mask &
	    ICP_ACCEL_CAPABILITIES_COMPRESSION))
		return 0;

	return accel_dev->hw_device->ae_mask;
}
EXPORT_SYMBOL_GPL(adf_gen2_get_dc_ae_mask);

u32 adf_gen2_get_slices_for_svc(struct adf_accel_dev *accel_dev,
				enum adf_svc_type svc)
{
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);
	u32 num_aes = hw_data->get_num_aes(hw_data);

	if (svc == ADF_SVC_ASYM)
		return ((num_aes / ADF_AE_PAIR) * ADF_ASYM_SLICES_PER_AE_PAIR);
	else if (svc == ADF_SVC_SYM)
		return num_aes;
	else if (svc == ADF_SVC_DC)
		return num_aes;

	return 0;
}
EXPORT_SYMBOL_GPL(adf_gen2_get_slices_for_svc);

int adf_gen2_calc_sla_units(struct adf_accel_dev *accel_dev,
			    struct sla_sku_dev *sla_sku)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 i = 0, num_aes = hw_data->get_num_aes(hw_data);
	u32 max_aes = hw_data->num_engines;

	if (!max_aes)
		return -EFAULT;
	for (i = 0; i < ADF_MAX_SERVICES; i++) {
		sla_sku->slau_supported[i] =
			(sla_sku->slau_supported[i] * num_aes) / max_aes;
		/* Round SLA to nearest K */
		sla_sku->slau_supported[i] =
			roundup(sla_sku->slau_supported[i], AU_ROUNDOFF);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(adf_gen2_calc_sla_units);
