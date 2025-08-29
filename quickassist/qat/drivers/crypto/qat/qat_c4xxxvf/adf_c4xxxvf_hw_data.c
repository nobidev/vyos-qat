// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2016 - 2021 Intel Corporation */

#include <adf_accel_devices.h>
#include <adf_pf2vf_msg.h>
#include <adf_common_drv.h>
#include "adf_c4xxxvf_hw_data.h"
#include "icp_qat_hw.h"

static struct adf_hw_device_class c4xxxiov_class = {
	.name = ADF_C4XXXVF_DEVICE_NAME,
	.type = DEV_C4XXXVF,
	.instances = 0
};

static u32 get_accel_mask(struct adf_accel_dev *accel_dev)
{
	return ADF_C4XXXIOV_ACCELERATORS_MASK;
}

static u32 get_ae_mask(struct adf_accel_dev *accel_dev)
{
	return ADF_C4XXXIOV_ACCELENGINES_MASK;
}

static u32 get_num_accels(struct adf_hw_device_data *self)
{
	return ADF_C4XXXIOV_MAX_ACCELERATORS;
}

static u32 get_num_aes(struct adf_hw_device_data *self)
{
	return ADF_C4XXXIOV_MAX_ACCELENGINES;
}

static u32 get_misc_bar_id(struct adf_hw_device_data *self)
{
	return ADF_C4XXXIOV_PMISC_BAR;
}

static u32 get_etr_bar_id(struct adf_hw_device_data *self)
{
	return ADF_C4XXXIOV_ETR_BAR;
}

static enum dev_sku_info get_sku(struct adf_hw_device_data *self)
{
	return DEV_SKU_VF;
}

static u32 get_pf2vf_offset(u32 i)
{
	return ADF_C4XXXIOV_PF2VF_OFFSET;
}

static u32 get_vintmsk_offset(u32 i)
{
	return ADF_C4XXXIOV_VINTMSK_OFFSET;
}

static u32 get_vintsou_offset(void)
{
	return ADF_C4XXXIOV_VINTSOU_OFFSET;
}

static int adf_vf_int_noop(struct adf_accel_dev *accel_dev)
{
	return 0;
}

static void adf_vf_void_noop(struct adf_accel_dev *accel_dev)
{
}

static u32 c4xxxvf_get_hw_cap(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;
	u32 vflegfuses;
	u32 capabilities;

	/* Read accelerator capabilities mask */
	pci_read_config_dword(pdev, ADF_C4XXXIOV_VFLEGFUSES_OFFSET,
			      &vflegfuses);
	capabilities =
		ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC |
		ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC |
		ICP_ACCEL_CAPABILITIES_CIPHER |
		ICP_ACCEL_CAPABILITIES_AUTHENTICATION |
		ICP_ACCEL_CAPABILITIES_COMPRESSION |
		ICP_ACCEL_CAPABILITIES_ZUC |
		ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY |
		ICP_ACCEL_CAPABILITIES_SHA3_EXT |
		ICP_ACCEL_CAPABILITIES_CHACHA_POLY |
		ICP_ACCEL_CAPABILITIES_AESGCM_SPC |
		ICP_ACCEL_CAPABILITIES_SM3 |
		ICP_ACCEL_CAPABILITIES_SM4 |
		ICP_ACCEL_CAPABILITIES_SM2;
	if (vflegfuses & ICP_ACCEL_MASK_CIPHER_SLICE) {
		capabilities &= ~ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC;
		capabilities &= ~ICP_ACCEL_CAPABILITIES_CIPHER;
	}
	if (vflegfuses & ICP_ACCEL_MASK_AUTH_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_AUTHENTICATION;
	if (vflegfuses & ICP_ACCEL_MASK_PKE_SLICE) {
		capabilities &= ~ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC;
		capabilities &= ~ICP_ACCEL_CAPABILITIES_SM2;
	}
	if (vflegfuses & ICP_ACCEL_MASK_COMPRESS_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_COMPRESSION;
	if (vflegfuses & ICP_ACCEL_MASK_EIA3_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_ZUC;
	if (vflegfuses & ICP_ACCEL_MASK_SM3_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_SM3;
	if (vflegfuses & ICP_ACCEL_MASK_SM4_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_SM4;

	capabilities &= ~ICP_ACCEL_CAPABILITIES_INLINE;

	return capabilities;
}

static void adf_set_asym_rings_mask(struct adf_accel_dev *accel_dev)
{
	int service;
	u16 ena_srv_mask;
	u16 service_type;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;

	accel_dev->hw_device->asym_rings_mask = 0;
	ena_srv_mask = hw_data->ring_to_svc_map;

	/* parse the service */
	for (service = 0;
		service < ADF_CFG_MAX_SERVICES;
		service++) {
		service_type =
			GET_SRV_TYPE(ena_srv_mask, service);
		switch (service_type) {
		case CRYPTO:
		case ASYM:
			accel_dev->hw_device->asym_rings_mask =
		ADF_C4XXX_DEF_ASYM_MASK;
			break;
		}
	}
}

static u32 get_clock_speed(struct adf_hw_device_data *self)
{
	/* CPP clock is half high-speed clock */
	return self->clock_frequency / 2;
}

void adf_init_hw_data_c4xxxiov(struct adf_hw_device_data *hw_data)
{
	hw_data->dev_class = &c4xxxiov_class;
	hw_data->num_banks = ADF_C4XXXIOV_ETR_MAX_BANKS;
	hw_data->num_rings_per_bank = ADF_C4XXXIOV_NUM_RINGS_PER_BANK;
	hw_data->num_accel = ADF_C4XXXIOV_MAX_ACCELERATORS;
	hw_data->num_logical_accel = 1;
	hw_data->num_engines = ADF_C4XXXIOV_MAX_ACCELENGINES;
	hw_data->tx_rx_gap = ADF_C4XXXIOV_RX_RINGS_OFFSET;
	hw_data->tx_rings_mask = ADF_C4XXXIOV_TX_RINGS_MASK;
	hw_data->alloc_irq = adf_vf_isr_resource_alloc;
	hw_data->free_irq = adf_vf_isr_resource_free;
	hw_data->enable_error_correction = adf_vf_void_noop;
	hw_data->init_admin_comms = adf_vf_int_noop;
	hw_data->exit_admin_comms = adf_vf_void_noop;
	hw_data->send_admin_init = adf_vf2pf_init;
	hw_data->init_arb = adf_vf_int_noop;
	hw_data->exit_arb = adf_vf_void_noop;
	hw_data->disable_iov = adf_vf2pf_shutdown;
	hw_data->get_accel_mask = get_accel_mask;
	hw_data->get_ae_mask = get_ae_mask;
	hw_data->get_num_accels = get_num_accels;
	hw_data->get_num_aes = get_num_aes;
	hw_data->get_etr_bar_id = get_etr_bar_id;
	hw_data->get_misc_bar_id = get_misc_bar_id;
	hw_data->get_pf2vf_offset = get_pf2vf_offset;
	hw_data->get_vintmsk_offset = get_vintmsk_offset;
	hw_data->get_clock_speed = get_clock_speed;
	hw_data->get_vintsou_offset = get_vintsou_offset;
	hw_data->get_sku = get_sku;
	hw_data->enable_ints = adf_vf_void_noop;
	hw_data->enable_vf2pf_comms = adf_enable_vf2pf_comms;
	hw_data->disable_vf2pf_comms = adf_disable_vf2pf_comms;
	hw_data->min_iov_compat_ver = ADF_PFVF_COMPATIBILITY_VERSION;
	hw_data->clock_frequency = ADF_C4XXX_AE_FREQ;
	hw_data->ring_to_svc_map = ADF_DEFAULT_RING_TO_SRV_MAP;
	hw_data->get_accel_cap = c4xxxvf_get_hw_cap;
	hw_data->config_device = adf_config_device;
	hw_data->set_asym_rings_mask = adf_set_asym_rings_mask;
	hw_data->dev_class->instances++;
	adf_devmgr_update_class_index(hw_data);
}

void adf_clean_hw_data_c4xxxiov(struct adf_hw_device_data *hw_data)
{
	hw_data->dev_class->instances--;
	adf_devmgr_update_class_index(hw_data);
}
