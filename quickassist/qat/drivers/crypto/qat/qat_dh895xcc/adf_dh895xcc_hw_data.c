// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2014 - 2021 Intel Corporation */
#include <adf_accel_devices.h>
#include <adf_pf2vf_msg.h>
#include <adf_common_drv.h>
#include <adf_dev_err.h>
#include <adf_gen2_hw_data.h>
#include "adf_dh895xcc_hw_data.h"
#include "adf_heartbeat.h"
#include "icp_qat_hw.h"
#include "adf_cfg.h"

/* Worker thread to service arbiter mappings based on dev SKUs */
static const u32 thrd_to_arb_map_sku4[] = {
	0x12222AAA, 0x11666666, 0x12222AAA, 0x11666666,
	0x12222AAA, 0x11222222, 0x12222AAA, 0x11222222,
	0x00000000, 0x00000000, 0x00000000, 0x00000000
};

static const u32 thrd_to_arb_map_sku6[] = {
	0x12222AAA, 0x11666666, 0x12222AAA, 0x11666666,
	0x12222AAA, 0x11222222, 0x12222AAA, 0x11222222,
	0x12222AAA, 0x11222222, 0x12222AAA, 0x11222222
};

static const u32 thrd_to_arb_map_sku3[] = {
	0x00000888, 0x00000000, 0x00000888, 0x00000000,
	0x00000888, 0x00000000, 0x00000888, 0x00000000,
	0x00000888, 0x00000000, 0x00000888, 0x00000000
};

static u32 thrd_to_arb_map_gen[ADF_DH895XCC_MAX_ACCELENGINES] = {0};

static struct adf_slau_cfg slau_cfg[] = {
	{ADF_FW_IMAGE_CRYPTO,
		{
			/* SKU1 */
			{21000, 28000, 0},
			/* SKU2 */
			{41000, 41000, 0},
			/* SKU3 */
			{0, 0, 0},
			/* SKU4 */
			{35000, 40000, 0}
		}
	},
	{ADF_FW_IMAGE_COMPRESSION,
		{
			/* SKU1 */
			{0, 28000, 12000},
			/* SKU2 */
			{0, 41000, 23000},
			/* SKU3 */
			{0, 0, 0},
			/* SKU4 */
			{0, 40000, 20000}
		}
	},
	{ADF_FW_IMAGE_CUSTOM1,
		{
			/* SKU1 */
			{21000, 28000, 12000},
			/* SKU2 */
			{41000, 41000, 23000},
			/* SKU3 */
			{0, 0, 0},
			/* SKU4 */
			{35000, 40000, 20000}
		}
	}
};

static struct adf_hw_device_class dh895xcc_class = {
	.name = ADF_DH895XCC_DEVICE_NAME,
	.type = DEV_DH895XCC,
	.instances = 0
};

static u32 get_accel_mask(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;
	u32 fuse;

	pci_read_config_dword(pdev, ADF_DEVICE_FUSECTL_OFFSET,
			      &fuse);

	return (~fuse) >> ADF_DH895XCC_ACCELERATORS_REG_OFFSET &
		ADF_DH895XCC_ACCELERATORS_MASK;
}

static u32 get_ae_mask(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;
	u32 fuse;

	pci_read_config_dword(pdev, ADF_DEVICE_FUSECTL_OFFSET,
			      &fuse);

	return (~fuse) & ADF_DH895XCC_ACCELENGINES_MASK;
}

static uint32_t get_num_accels(struct adf_hw_device_data *self)
{
	uint32_t i, ctr = 0;

	if (!self || !self->accel_mask)
		return 0;

	for_each_set_bit(i, &self->accel_mask, ADF_DH895XCC_MAX_ACCELERATORS)
		ctr++;
	return ctr;
}

static uint32_t get_num_aes(struct adf_hw_device_data *self)
{
	uint32_t i, ctr = 0;

	if (!self || !self->ae_mask)
		return 0;

	for_each_set_bit(i, &self->ae_mask, ADF_DH895XCC_MAX_ACCELENGINES)
		ctr++;
	return ctr;
}

static uint32_t get_misc_bar_id(struct adf_hw_device_data *self)
{
	return ADF_DH895XCC_PMISC_BAR;
}

static uint32_t get_etr_bar_id(struct adf_hw_device_data *self)
{
	return ADF_DH895XCC_ETR_BAR;
}

static uint32_t get_sram_bar_id(struct adf_hw_device_data *self)
{
	return ADF_DH895XCC_SRAM_BAR;
}

static enum dev_sku_info get_sku(struct adf_hw_device_data *self)
{
	int sku = (self->fuses & ADF_DH895XCC_FUSECTL_SKU_MASK)
	    >> ADF_DH895XCC_FUSECTL_SKU_SHIFT;

	switch (sku) {
	case ADF_DH895XCC_FUSECTL_SKU_1:
		return DEV_SKU_1;
	case ADF_DH895XCC_FUSECTL_SKU_2:
		return DEV_SKU_2;
	case ADF_DH895XCC_FUSECTL_SKU_3:
		return DEV_SKU_3;
	case ADF_DH895XCC_FUSECTL_SKU_4:
		return DEV_SKU_4;
	default:
		return DEV_SKU_UNKNOWN;
	}
	return DEV_SKU_UNKNOWN;
}

#if defined(CONFIG_PCI_IOV)
static void process_and_get_vf2pf_int(void __iomem *pmisc_bar,
				      u32 vf_int_mask_sets[ADF_MAX_VF2PF_SET])
{
	u32 errsou3, errsou5, errmsk3, errmsk5;
	u32 sources, disabled, non_vf2pf_errmsk3, non_vf2pf_errmsk5;

	/* Get the interrupt sources triggered by VFs */
	errsou3 = ADF_CSR_RD(pmisc_bar, ADF_ERRSOU3);
	errsou5 = ADF_CSR_RD(pmisc_bar, ADF_ERRSOU5);
	sources = ADF_DH895XCC_ERR_REG_VF2PF_L(errsou3)
			  | ADF_DH895XCC_ERR_REG_VF2PF_U(errsou5);

	/* Get the already disabled interrupts */
	errmsk3 = ADF_CSR_RD(pmisc_bar, ADF_ERRMSK3);
	errmsk5 = ADF_CSR_RD(pmisc_bar, ADF_ERRMSK5);
	non_vf2pf_errmsk3 = errmsk3 & ADF_DH895XCC_ERRMSK3_NON_VF2PF;
	non_vf2pf_errmsk5 = errmsk5 & ADF_DH895XCC_ERRMSK5_NON_VF2PF;
	disabled = ADF_DH895XCC_ERR_REG_VF2PF_L(errmsk3)
			   | ADF_DH895XCC_ERR_REG_VF2PF_U(errmsk5);

	/*
	 * To avoid adding duplicate entries to work queue, clear
	 * source interrupt bits that are already masked in ERRMSK register.
	 */
	vf_int_mask_sets[0] = sources & ~disabled;
	vf_int_mask_sets[1] = 0;
	vf_int_mask_sets[2] = 0;
	vf_int_mask_sets[3] = 0;

	/*
	 * Due to HW limitations, when disabling the interrupts, we can't
	 * just disable the requested sources, as this would lead to missed
	 * interrupts if sources change just before writing to ERRMSK3 and
	 * ERRMSK5. To resolve this, disable all interrupts and re-enable only
	 * the sources that are not currently being serviced and the sources
	 * that were not already disabled. Re-enabling will trigger a new
	 * interrupt for the sources that have changed in the meantime, if any.
	 */
	errmsk3 |= ADF_DH895XCC_ERRMSK3_VF2PF_L(ADF_VF2PF_REG_MASK);
	errmsk5 |= ADF_DH895XCC_ERRMSK5_VF2PF_U(ADF_VF2PF_REG_MASK);
	ADF_CSR_WR(pmisc_bar, ADF_ERRMSK3, errmsk3);
	ADF_CSR_WR(pmisc_bar, ADF_ERRMSK5, errmsk5);

	errmsk3 = non_vf2pf_errmsk3 |
		  ADF_DH895XCC_ERRMSK3_VF2PF_L(sources | disabled);
	errmsk5 = non_vf2pf_errmsk5 |
		  ADF_DH895XCC_ERRMSK5_VF2PF_U(sources | disabled);
	ADF_CSR_WR(pmisc_bar, ADF_ERRMSK3, errmsk3);
	ADF_CSR_WR(pmisc_bar, ADF_ERRMSK5, errmsk5);
}

static void enable_vf2pf_interrupts(void __iomem *pmisc_addr,
				    u32 vf_mask, u8 vf2pf_set)
{
	if (vf2pf_set)
		return;

	/* Enable VF2PF Messaging Ints - VFs 1 through 16 per vf_mask[15:0] */
	if (vf_mask & 0xFFFF)
		adf_csr_fetch_and_and(pmisc_addr,
				      ADF_ERRMSK3,
				      ~ADF_DH895XCC_ERRMSK3_VF2PF_L(vf_mask));

	/* Enable VF2PF Messaging Ints - VFs 17 through 32 per vf_mask[31:16] */
	if (vf_mask >> 16) {
		adf_csr_fetch_and_and(pmisc_addr,
				      ADF_ERRMSK5,
				      ~ADF_DH895XCC_ERRMSK5_VF2PF_U(vf_mask));
	}
}

static void disable_vf2pf_interrupts(void __iomem *pmisc_addr,
				     u32 vf_mask, u8 vf2pf_set)
{
	if (vf2pf_set)
		return;

	/* Disable VF2PF interrupts for VFs 1 through 16 per vf_mask[15:0] */
	if (vf_mask & 0xFFFF)
		adf_csr_fetch_and_or(pmisc_addr,
				     ADF_ERRMSK3,
				     ADF_DH895XCC_ERRMSK3_VF2PF_L(vf_mask));

	/* Disable VF2PF interrupts for VFs 17 through 32 per vf_mask[31:16] */
	if (vf_mask >> 16)
		adf_csr_fetch_and_or(pmisc_addr,
				     ADF_ERRMSK5,
				     ADF_DH895XCC_ERRMSK5_VF2PF_U(vf_mask));
}
#endif /* CONFIG_PCI_IOV */

static void adf_get_arbiter_mapping(struct adf_accel_dev *accel_dev,
				    u32 const **arb_map_config)
{
	switch (accel_dev->accel_pci_dev.sku) {
	case DEV_SKU_1:
		adf_cfg_gen_dispatch_arbiter(accel_dev,
					     thrd_to_arb_map_sku4,
					     thrd_to_arb_map_gen,
					     ADF_DH895XCC_MAX_ACCELENGINES);
		*arb_map_config = thrd_to_arb_map_gen;
		break;

	case DEV_SKU_2:
	case DEV_SKU_4:
		adf_cfg_gen_dispatch_arbiter(accel_dev,
					     thrd_to_arb_map_sku6,
					     thrd_to_arb_map_gen,
					     ADF_DH895XCC_MAX_ACCELENGINES);
		*arb_map_config = thrd_to_arb_map_gen;
		break;

	case DEV_SKU_3:
		adf_cfg_gen_dispatch_arbiter(accel_dev,
					     thrd_to_arb_map_sku3,
					     thrd_to_arb_map_gen,
					     ADF_DH895XCC_MAX_ACCELENGINES);
		*arb_map_config = thrd_to_arb_map_gen;

		break;

	default:
		dev_err(&GET_DEV(accel_dev),
			"The configuration doesn't match any SKU\n");
		*arb_map_config = NULL;
	}
}

static uint32_t get_pf2vf_offset(uint32_t i)
{
	return ADF_DH895XCC_PF2VF_OFFSET(i);
}

static uint32_t get_vintmsk_offset(uint32_t i)
{
	return ADF_DH895XCC_VINTMSK_OFFSET(i);
}

static u32 get_clock_speed(struct adf_hw_device_data *self)
{
	/* CPP clock is half high-speed clock */
	return self->clock_frequency / 2;
}

static void adf_enable_error_interrupts(void __iomem *csr)
{
	ADF_CSR_WR(csr, ADF_ERRMSK0, ADF_DH895XCC_ERRMSK0_CERR); /* ME0-ME3  */
	ADF_CSR_WR(csr, ADF_ERRMSK1, ADF_DH895XCC_ERRMSK1_CERR); /* ME4-ME7  */
	ADF_CSR_WR(csr, ADF_ERRMSK4, ADF_DH895XCC_ERRMSK4_CERR); /* ME8-ME11 */

	/* Reset everything except VFtoPF1_16 */
	adf_csr_fetch_and_and(csr, ADF_ERRMSK3, ADF_DH895XCC_VF2PF1_16);

	/* Disable Secure RAM correctable error interrupt */
	adf_csr_fetch_and_or(csr, ADF_ERRMSK3, ADF_DH895XCC_ERRMSK3_CERR);

	/* Reset everything except VFtoPF17_32 */
	adf_csr_fetch_and_and(csr, ADF_ERRMSK5, ADF_DH895XCC_VF2PF17_32);

	/* RI CPP bus interface error detection and reporting. */
	ADF_CSR_WR(csr, ADF_DH895XCC_RICPPINTCTL, ADF_DH895XCC_RICPP_EN);

	/* TI CPP bus interface error detection and reporting. */
	ADF_CSR_WR(csr, ADF_DH895XCC_TICPPINTCTL, ADF_DH895XCC_TICPP_EN);

	/* Enable CFC Error interrupts and logging */
	ADF_CSR_WR(csr, ADF_DH895XCC_CPP_SHAC_ERR_CTRL,
		   ADF_DH895XCC_CPP_SHAC_UE);

	/* Enable SecureRAM to fix and log Correctable errors */
	ADF_CSR_WR(csr, ADF_DH895XCC_ESRAMCERR, ADF_DH895XCC_ESRAM_CERR);

	/* Enable SecureRAM Uncorrectable error interrupts and logging */
	ADF_CSR_WR(csr, ADF_DH895XCC_ESRAMUERR, ADF_DH895XCC_ESRAM_UERR);

	/* Enable Push/Pull Misc Uncorrectable error interrupts and logging */
	ADF_CSR_WR(csr, ADF_CPPMEMTGTERR, ADF_DH895XCC_TGT_UERR);
}

static void adf_disable_error_interrupts(struct adf_accel_dev *accel_dev)
{
	struct adf_bar *misc_bar = &GET_BARS(accel_dev)[ADF_DH895XCC_PMISC_BAR];
	void __iomem *csr = misc_bar->virt_addr;

	/* ME0-ME3 */
	ADF_CSR_WR(csr, ADF_ERRMSK0, ADF_DH895XCC_ERRMSK0_UERR |
		   ADF_DH895XCC_ERRMSK0_CERR);
	/* ME4-ME7 */
	ADF_CSR_WR(csr, ADF_ERRMSK1, ADF_DH895XCC_ERRMSK1_UERR |
		   ADF_DH895XCC_ERRMSK1_CERR);
	/* CPP Push Pull, RI, TI, CPM0-CPM1, CFC */
	ADF_CSR_WR(csr, ADF_ERRMSK3, ADF_DH895XCC_ERRMSK3_UERR |
		   ADF_DH895XCC_ERRMSK3_CERR);
	/* ME8-ME11 */
	ADF_CSR_WR(csr, ADF_ERRMSK4, ADF_DH895XCC_ERRMSK4_UERR |
		   ADF_DH895XCC_ERRMSK4_CERR);
	/* CPM2-CPM5 */
	ADF_CSR_WR(csr, ADF_ERRMSK5, ADF_DH895XCC_ERRMSK5_UERR |
		   ADF_DH895XCC_ERRMSK5_CERR);
}

static int adf_check_uncorrectable_error(struct adf_accel_dev *accel_dev)
{
	struct adf_bar *misc_bar = &GET_BARS(accel_dev)[ADF_DH895XCC_PMISC_BAR];
	void __iomem *csr = misc_bar->virt_addr;

	u32 errsou0 = ADF_CSR_RD(csr, ADF_ERRSOU0) & ADF_DH895XCC_ERRMSK0_UERR;
	u32 errsou1 = ADF_CSR_RD(csr, ADF_ERRSOU1) & ADF_DH895XCC_ERRMSK1_UERR;
	u32 errsou3 = ADF_CSR_RD(csr, ADF_ERRSOU3) & ADF_DH895XCC_ERRMSK3_UERR;
	u32 errsou4 = ADF_CSR_RD(csr, ADF_ERRSOU4) & ADF_DH895XCC_ERRMSK4_UERR;
	u32 errsou5 = ADF_CSR_RD(csr, ADF_ERRSOU5) & ADF_DH895XCC_ERRMSK5_UERR;

	return (errsou0 | errsou1 | errsou3 | errsou4 | errsou5);
}

static void adf_enable_mmps(void __iomem *csr,
			    unsigned int dev)
{
	unsigned int mmp;

	for (mmp = 0; mmp < ADF_MAX_MMP; ++mmp) {
		/*
		 * The device supports PKE,
		 * so enable error reporting from MMP memory
		 */
		adf_csr_fetch_and_or(csr, ADF_UERRSSMMMP(dev, mmp),
				     ADF_DH895XCC_UERRSSMMMP_EN);
		/*
		 * The device supports PKE,
		 * so enable error correction from MMP memory
		 */
		adf_csr_fetch_and_or(csr, ADF_CERRSSMMMP(dev, mmp),
				     ADF_DH895XCC_CERRSSMMMP_EN);
	}
}

static void adf_disable_mmps(void __iomem *csr,
			     unsigned int dev)
{
	unsigned int mmp;

	for (mmp = 0; mmp < ADF_MAX_MMP; ++mmp) {
		/*
		 * The device doesn't support PKE,
		 * so disable error reporting from MMP memory
		 */
		adf_csr_fetch_and_and(csr, ADF_UERRSSMMMP(dev, mmp),
				      ~ADF_DH895XCC_UERRSSMMMP_EN);
		/*
		 * The device doesn't support PKE,
		 * so disable error correction from MMP memory
		 */
		adf_csr_fetch_and_and(csr, ADF_CERRSSMMMP(dev, mmp),
				      ~ADF_DH895XCC_CERRSSMMMP_EN);
	}			}

static void adf_enable_mmp_error_correction(void __iomem *csr,
					    struct adf_hw_device_data *hw_data)
{
	unsigned int dev;

	/* Enable MMP Logging */
	for_each_set_bit(dev, &hw_data->accel_mask,
			 ADF_DH895XCC_MAX_ACCELERATORS) {
		/* Set power-up */
		adf_csr_fetch_and_and(csr, ADF_DH895XCC_SLICEPWRDOWN(dev),
				      ~ADF_DH895XCC_MMP_PWR_UP_MSK);

		if (hw_data->accel_capabilities_mask &
		    ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC)
			adf_enable_mmps(csr, dev);
		else
			adf_disable_mmps(csr, dev);

		/* Restore power-down value */
		adf_csr_fetch_and_or(csr, ADF_DH895XCC_SLICEPWRDOWN(dev),
				     ADF_DH895XCC_MMP_PWR_UP_MSK);

		/* Disabling correctable error interrupts. */
		ADF_CSR_WR(csr, ADF_DH895XCC_INTMASKSSM(dev),
			   ADF_DH895XCC_INTMASKSSM_UERR);
	}
}
static void adf_enable_error_correction(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	struct adf_bar *misc_bar = &GET_BARS(accel_dev)[ADF_DH895XCC_PMISC_BAR];
	void __iomem *csr = misc_bar->virt_addr;
	unsigned int i;

	/* Enable Accel Engine error detection & correction */
	for_each_set_bit(i, &hw_device->ae_mask,
			 ADF_DH895XCC_MAX_ACCELENGINES) {
		adf_csr_fetch_and_or(csr, ADF_DH895XCC_AE_CTX_ENABLES(i),
				     ADF_DH895XCC_ENABLE_AE_ECC_ERR);
		adf_csr_fetch_and_or(csr, ADF_DH895XCC_AE_MISC_CONTROL(i),
				     ADF_DH895XCC_ENABLE_AE_ECC_PARITY_CORR);
	}

	/* Enable shared memory error detection & correction */
	for_each_set_bit(i, &hw_device->accel_mask,
			 ADF_DH895XCC_MAX_ACCELERATORS) {
		adf_csr_fetch_and_or(csr, ADF_UERRSSMSH(i),
				     ADF_DH895XCC_ERRSSMSH_EN);
		adf_csr_fetch_and_or(csr, ADF_CERRSSMSH(i),
				     ADF_DH895XCC_ERRSSMSH_EN);
		adf_csr_fetch_and_or(csr, ADF_PPERR(i),
				     ADF_DH895XCC_PPERR_EN);
	}

	adf_enable_error_interrupts(csr);
	adf_enable_mmp_error_correction(csr, hw_device);
}

static void adf_enable_ints(struct adf_accel_dev *accel_dev)
{
	void __iomem *addr;

	addr = (&GET_BARS(accel_dev)[ADF_DH895XCC_PMISC_BAR])->virt_addr;

	/* Enable bundle and misc interrupts */
	ADF_CSR_WR(addr, ADF_DH895XCC_SMIAPF0_MASK_OFFSET,
		   accel_dev->pf.vf_info ? 0 :
			GENMASK_ULL(GET_MAX_BANKS(accel_dev) - 1, 0));
	ADF_CSR_WR(addr, ADF_DH895XCC_SMIAPF1_MASK_OFFSET,
		   ADF_DH895XCC_SMIA1_MASK);
}

static u32 get_ae_clock(struct adf_hw_device_data *self)
{
	/*
	 * Clock update interval is <16> ticks for dh895xcc.
	 */
	return self->clock_frequency / 16;
}

static u32 dh895xcc_get_hw_cap(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;
	u32 legfuses;
	u32 capabilities;

	/* Read accelerator capabilities mask */
	pci_read_config_dword(pdev, ADF_DEVICE_LEGFUSE_OFFSET,
			      &legfuses);
	capabilities =
		ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC +
		ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC +
		ICP_ACCEL_CAPABILITIES_CIPHER +
		ICP_ACCEL_CAPABILITIES_AUTHENTICATION +
#ifndef QAT_XEN_PLATFORM
		ICP_ACCEL_CAPABILITIES_COMPRESSION +
#endif
		ICP_ACCEL_CAPABILITIES_ECEDMONT +
		ICP_ACCEL_CAPABILITIES_EXT_ALGCHAIN;

	if (legfuses & ICP_ACCEL_MASK_CIPHER_SLICE)
		capabilities &= ~(ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC |
				  ICP_ACCEL_CAPABILITIES_CIPHER |
				  ICP_ACCEL_CAPABILITIES_EXT_ALGCHAIN);
	if (legfuses & ICP_ACCEL_MASK_AUTH_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_AUTHENTICATION;
	if (legfuses & ICP_ACCEL_MASK_PKE_SLICE)
		capabilities &= ~(ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC |
				  ICP_ACCEL_CAPABILITIES_ECEDMONT);
	if (legfuses & ICP_ACCEL_MASK_COMPRESS_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_COMPRESSION;

	return capabilities;
}

static int get_sla_units(struct adf_accel_dev *accel_dev, u32 **sla_units)
{
	u8 i = 0;
	enum adf_cfg_fw_image_type fw_image_type = ADF_FW_IMAGE_DEFAULT;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u8 sku = GET_DEV_SKU(accel_dev);

	if ((GET_DEV_SKU(accel_dev)) == DEV_SKU_UNKNOWN)
		return -EFAULT;

	if (hw_data->get_fw_image_type(accel_dev, &fw_image_type))
		return -EFAULT;

	for (i = 0; i < ARRAY_SIZE(slau_cfg); i++) {
		if (fw_image_type == slau_cfg[i].fw_image_type)
			*sla_units = slau_cfg[i].slau_supported[sku];
	}

	return 0;
}

static int get_fw_name(struct adf_accel_dev *accel_dev, char *uof_name)
{
	enum adf_cfg_fw_image_type fw_image_type = ADF_FW_IMAGE_DEFAULT;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;

	if (hw_data->get_fw_image_type(accel_dev, &fw_image_type))
		return -EFAULT;

	switch (fw_image_type) {
	case ADF_FW_IMAGE_DEFAULT:
		strlcpy(uof_name, ADF_DH895XCC_AE_FW_NAME,
			ADF_CFG_MAX_VAL_LEN_IN_BYTES);
		break;
	case ADF_FW_IMAGE_CRYPTO:
		strlcpy(uof_name, ADF_DH895XCC_AE_FW_NAME_CRYPTO,
			ADF_CFG_MAX_VAL_LEN_IN_BYTES);
		break;
	case ADF_FW_IMAGE_COMPRESSION:
		strlcpy(uof_name, ADF_DH895XCC_AE_FW_NAME_COMPRESSION,
			ADF_CFG_MAX_VAL_LEN_IN_BYTES);
		break;
	case ADF_FW_IMAGE_CUSTOM1:
		strlcpy(uof_name, ADF_DH895XCC_AE_FW_NAME_CUSTOM1,
			ADF_CFG_MAX_VAL_LEN_IN_BYTES);
		break;
	default:
		dev_err(&GET_DEV(accel_dev),
			"invalid ServicesProfile.\n");

		return -EFAULT;
	}

	return 0;
}

static u32 get_slices_for_svc(struct adf_accel_dev *accel_dev,
			      enum adf_svc_type svc)
{
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);
	u32 num_aes = hw_data->get_num_aes(hw_data);

	if (svc == ADF_SVC_ASYM)
		return ((num_aes / ADF_AE_PAIR) * ADF_ASYM_SLICES_PER_AE_PAIR);
	else if (svc == ADF_SVC_SYM)
		return num_aes;
	else if (svc == ADF_SVC_DC)
		return (num_aes / ADF_AE_PAIR) - ADF_RL_DC_ADMIN_SLICE;

	return 0;
}

void adf_init_hw_data_dh895xcc(struct adf_hw_device_data *hw_data)
{
	hw_data->dev_class = &dh895xcc_class;
	hw_data->instance_id = dh895xcc_class.instances++;
	hw_data->num_banks = ADF_DH895XCC_ETR_MAX_BANKS;
	hw_data->num_rings_per_bank = ADF_ETR_MAX_RINGS_PER_BANK;
	hw_data->num_accel = ADF_DH895XCC_MAX_ACCELERATORS;
	hw_data->num_logical_accel = 1;
	hw_data->num_engines = ADF_DH895XCC_MAX_ACCELENGINES;
	hw_data->tx_rx_gap = ADF_DH895XCC_RX_RINGS_OFFSET;
	hw_data->tx_rings_mask = ADF_DH895XCC_TX_RINGS_MASK;
	hw_data->alloc_irq = adf_isr_resource_alloc;
	hw_data->free_irq = adf_isr_resource_free;
	hw_data->enable_error_correction = adf_enable_error_correction;
	hw_data->check_uncorrectable_error = adf_check_uncorrectable_error;
	hw_data->print_err_registers = adf_print_err_registers;
	hw_data->disable_error_interrupts = adf_disable_error_interrupts;
	hw_data->get_accel_mask = get_accel_mask;
	hw_data->get_ae_mask = get_ae_mask;
	hw_data->get_num_accels = get_num_accels;
	hw_data->get_num_aes = get_num_aes;
	hw_data->get_etr_bar_id = get_etr_bar_id;
	hw_data->get_misc_bar_id = get_misc_bar_id;
	hw_data->get_pf2vf_offset = get_pf2vf_offset;
	hw_data->get_vintmsk_offset = get_vintmsk_offset;
	hw_data->get_arb_info = get_gen2_arb_info;
	hw_data->get_admin_info = get_gen2_admin_info;
	hw_data->get_clock_speed = get_clock_speed;
	hw_data->get_sram_bar_id = get_sram_bar_id;
	hw_data->get_sku = get_sku;
#if defined(CONFIG_PCI_IOV)
	hw_data->process_and_get_vf2pf_int = process_and_get_vf2pf_int;
	hw_data->enable_vf2pf_interrupts = enable_vf2pf_interrupts;
	hw_data->disable_vf2pf_interrupts = disable_vf2pf_interrupts;
#endif
	hw_data->fw_name = ADF_DH895XCC_FW;
	hw_data->fw_mmp_name = ADF_DH895XCC_MMP;
	hw_data->init_admin_comms = adf_init_admin_comms;
	hw_data->exit_admin_comms = adf_exit_admin_comms;
	hw_data->configure_iov_threads = adf_configure_iov_threads;
	hw_data->disable_iov = adf_disable_sriov;
	hw_data->send_admin_init = adf_send_admin_init;
	hw_data->init_arb = adf_gen2_init_arb;
	hw_data->exit_arb = adf_gen2_exit_arb;
	hw_data->disable_arb = adf_disable_arb;
	hw_data->get_arb_mapping = adf_get_arbiter_mapping;
	hw_data->enable_ints = adf_enable_ints;
	hw_data->enable_vf2pf_comms = adf_pf_enable_vf2pf_comms;
	hw_data->disable_vf2pf_comms = adf_pf_disable_vf2pf_comms;
	hw_data->reset_device = adf_reset_sbr;
	hw_data->min_iov_compat_ver = ADF_PFVF_COMPATIBILITY_VERSION;
	hw_data->get_heartbeat_status = adf_get_heartbeat_status;
	hw_data->get_ae_clock = get_ae_clock;
	hw_data->clock_frequency = ADF_DH895XCC_AE_FREQ;
	hw_data->get_accel_cap = dh895xcc_get_hw_cap;
	hw_data->ring_to_svc_map = ADF_DEFAULT_RING_TO_SRV_MAP;
	hw_data->pre_reset = adf_dev_pre_reset;
	hw_data->post_reset = adf_dev_post_reset;
	hw_data->fw_load = adf_gen2_ae_fw_load;
	hw_data->get_ring_to_svc_map = adf_get_services_enabled;
	hw_data->extended_dc_capabilities = 0;
	hw_data->config_device = adf_config_device;
	hw_data->set_asym_rings_mask = adf_cfg_set_asym_rings_mask;
	hw_data->get_sla_units = get_sla_units;
	hw_data->get_slices_for_svc = get_slices_for_svc;
	hw_data->calc_sla_units = adf_gen2_calc_sla_units;
	hw_data->get_fw_image_type = adf_cfg_get_fw_image_type;
	hw_data->get_fw_name = get_fw_name;
	hw_data->get_dc_ae_mask = adf_gen2_get_dc_ae_mask;
}

void adf_clean_hw_data_dh895xcc(struct adf_hw_device_data *hw_data)
{
	hw_data->dev_class->instances--;
}
