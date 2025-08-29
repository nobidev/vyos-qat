// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2020 - 2021 Intel Corporation */
#include <adf_accel_devices.h>
#include <adf_pf2vf_msg.h>
#include <adf_common_drv.h>
#include "adf_200xxvf_hw_data.h"
#include "adf_gen2_hw_data.h"
#include "icp_qat_hw.h"
#include "adf_cfg.h"

static struct adf_hw_device_class adf_200xxiov_class = {
	.name = ADF_200XXVF_DEVICE_NAME,
	.type = DEV_200XXVF,
	.instances = 0
};

static u32 get_accel_mask(struct adf_accel_dev *accel_dev)
{
	return ADF_200XXIOV_ACCELERATORS_MASK;
}

static u32 get_ae_mask(struct adf_accel_dev *accel_dev)
{
	return ADF_200XXIOV_ACCELENGINES_MASK;
}

static u32 get_num_accels(struct adf_hw_device_data *self)
{
	return ADF_200XXIOV_MAX_ACCELERATORS;
}

static u32 get_num_aes(struct adf_hw_device_data *self)
{
	return ADF_200XXIOV_MAX_ACCELENGINES;
}

static u32 get_misc_bar_id(struct adf_hw_device_data *self)
{
	return ADF_200XXIOV_PMISC_BAR;
}

static u32 get_etr_bar_id(struct adf_hw_device_data *self)
{
	return ADF_200XXIOV_ETR_BAR;
}

static enum dev_sku_info get_sku(struct adf_hw_device_data *self)
{
	return DEV_SKU_VF;
}

static u32 get_pf2vf_offset(u32 i)
{
	return ADF_200XXIOV_PF2VF_OFFSET;
}

static u32 get_vintmsk_offset(u32 i)
{
	return ADF_200XXIOV_VINTMSK_OFFSET;
}

static int adf_vf_int_noop(struct adf_accel_dev *accel_dev)
{
	return 0;
}

static void adf_vf_void_noop(struct adf_accel_dev *accel_dev)
{
}

static u32 adf_200xxvf_get_hw_cap(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;
	u32 legfuses;
	u32 capabilities;

	/* Read accelerator capabilities mask */
	pci_read_config_dword(pdev, ADF_200XX_VFLEGFUSE_OFFSET,
			      &legfuses);
	capabilities =
		ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC +
		ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC +
		ICP_ACCEL_CAPABILITIES_CIPHER +
		ICP_ACCEL_CAPABILITIES_AUTHENTICATION +
		ICP_ACCEL_CAPABILITIES_COMPRESSION +
		ICP_ACCEL_CAPABILITIES_ZUC +
		ICP_ACCEL_CAPABILITIES_SHA3;
	if (legfuses & ICP_ACCEL_MASK_CIPHER_SLICE) {
		capabilities &= ~ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC;
		capabilities &= ~ICP_ACCEL_CAPABILITIES_CIPHER;
	}
	if (legfuses & ICP_ACCEL_MASK_AUTH_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_AUTHENTICATION;
	if (legfuses & ICP_ACCEL_MASK_PKE_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC;
	if (legfuses & ICP_ACCEL_MASK_COMPRESS_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_COMPRESSION;
	if (legfuses & ICP_ACCEL_MASK_EIA3_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_ZUC;
	if (legfuses & ICP_ACCEL_MASK_SHA3_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_SHA3;

	return capabilities;
}

static u32 get_clock_speed(struct adf_hw_device_data *self)
{
	/* CPP clock is half high-speed clock */
	return self->clock_frequency / 2;
}

void adf_init_hw_data_200xxiov(struct adf_hw_device_data *hw_data)
{
	hw_data->dev_class = &adf_200xxiov_class;
	hw_data->num_banks = ADF_200XXIOV_ETR_MAX_BANKS;
	hw_data->num_rings_per_bank = ADF_ETR_MAX_RINGS_PER_BANK;
	hw_data->num_accel = ADF_200XXIOV_MAX_ACCELERATORS;
	hw_data->num_logical_accel = 1;
	hw_data->num_engines = ADF_200XXIOV_MAX_ACCELENGINES;
	hw_data->tx_rx_gap = ADF_200XXIOV_RX_RINGS_OFFSET;
	hw_data->tx_rings_mask = ADF_200XXIOV_TX_RINGS_MASK;
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
	hw_data->get_vintsou_offset = get_gen2_vintsou_offset;
	hw_data->get_sku = get_sku;
	hw_data->enable_ints = adf_vf_void_noop;
	hw_data->enable_vf2pf_comms = adf_enable_vf2pf_comms;
	hw_data->disable_vf2pf_comms = adf_disable_vf2pf_comms;
	hw_data->min_iov_compat_ver = ADF_PFVF_COMPATIBILITY_VERSION;
	hw_data->clock_frequency = ADF_200XX_AE_FREQ;
	hw_data->get_accel_cap = adf_200xxvf_get_hw_cap;
	hw_data->ring_to_svc_map = ADF_DEFAULT_RING_TO_SRV_MAP;
	hw_data->config_device = adf_config_device;
	hw_data->set_asym_rings_mask = adf_cfg_set_asym_rings_mask;
	hw_data->dev_class->instances++;
	adf_devmgr_update_class_index(hw_data);
}

void adf_clean_hw_data_200xxiov(struct adf_hw_device_data *hw_data)
{
	hw_data->dev_class->instances--;
	adf_devmgr_update_class_index(hw_data);
}
