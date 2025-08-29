// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2015 - 2021 Intel Corporation */
#include <adf_accel_devices.h>
#include <adf_common_drv.h>
#include <adf_pf2vf_msg.h>
#include <adf_dev_err.h>
#include <adf_gen2_hw_data.h>
#include "adf_c62x_hw_data.h"
#include "adf_heartbeat.h"
#include "icp_qat_hw.h"
#include "adf_cfg.h"

/* Worker thread to service arbiter mappings */
static const u32 thrd_to_arb_map[ADF_C62X_MAX_ACCELENGINES] = {
	0x12222AAA, 0x11222AAA, 0x12222AAA, 0x11222AAA, 0x12222AAA,
	0x11222AAA, 0x12222AAA, 0x11222AAA, 0x12222AAA, 0x11222AAA
};

static u32 thrd_to_arb_map_gen[ADF_C62X_MAX_ACCELENGINES] = {0};

struct adf_slau_cfg_c62x {
	enum adf_cfg_fw_image_type fw_image_type;
	u32 slau_supported[ADF_MAX_SKUS][ADF_C62X_FREQ_SKUS][ADF_MAX_SERVICES];
};

static struct adf_slau_cfg_c62x slau_cfg[] = {
	{ADF_FW_IMAGE_CRYPTO,
		{
			/* (3x8) */
			{
				/* C62X_SKU */
				{33000, 15000, 0},
				/* C62X_SKU (800MHz) */
				{0, 15000, 0}
			},
			/* (3x16) */
			{
				/* C62X_SKU */
				{33000, 29000, 0},
				/* C62X_SKU (800MHz) */
				{0, 29000, 0}
			},
			/* (2x16 + 1x8) */
			{
				/* C62X_SKU */
				{33000, 37000, 0},
				/* C62X_SKU (800MHz) */
				{0, 37000, 0}
			}
		}
	},
	{ADF_FW_IMAGE_COMPRESSION,
		{
			/* (3x8) */
			{
				/* C62X_SKU */
				{0, 15000, 12000},
				/* C62X_SKU (800MHz) */
				{0, 15000, 24000}
			},
			/* (3x16) */
			{
				/* C62X_SKU */
				{0, 29000, 12000},
				/* C62X_SKU (800MHz) */
				{0, 29000, 24000}
			},
			/* (2x16 + 1x8) */
			{
				/* C62X_SKU */
				{0, 37000, 22000},
				/* C62X_SKU (800MHz) */
				{0, 37000, 25000}
			}
		}
	},
	{ADF_FW_IMAGE_CUSTOM1,
		{
			/* (3x8) */
			{
				/* C62X_SKU */
				{33000, 15000, 12000},
				/* C62X_SKU (800MHz) */
				{0, 15000, 24000}
			},
			/* (3x16) */
			{
				/* C62X_SKU */
				{33000, 29000, 12000},
				/* C62X_SKU (800MHz) */
				{0, 29000, 24000}
			},
			/* (2x16 + 1x8) */
			{
				/* C62X_SKU */
				{33000, 37000, 22000},
				/* C62X_SKU (800MHz) */
				{0, 37000, 25000}
			}
		}
	}
};

static struct adf_hw_device_class c62x_class = {
	.name = ADF_C62X_DEVICE_NAME,
	.type = DEV_C62X,
	.instances = 0
};

static u32 get_accel_mask(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;
	u32 fuse;
	u32 straps;

	pci_read_config_dword(pdev, ADF_DEVICE_FUSECTL_OFFSET,
			      &fuse);
	pci_read_config_dword(pdev, ADF_C62X_SOFTSTRAP_CSR_OFFSET,
			      &straps);

	return (~(fuse | straps)) >> ADF_C62X_ACCELERATORS_REG_OFFSET &
		ADF_C62X_ACCELERATORS_MASK;
}

static u32 get_ae_mask(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;
	u32 fuse;
	u32 me_straps;
	u32 me_disable;
	u32 ssms_disabled;

	pci_read_config_dword(pdev, ADF_DEVICE_FUSECTL_OFFSET,
			      &fuse);
	pci_read_config_dword(pdev, ADF_C62X_SOFTSTRAP_CSR_OFFSET,
			      &me_straps);

	/* If SSMs are disabled, then disable the corresponding MEs */
	ssms_disabled = (~get_accel_mask(accel_dev)) &
		ADF_C62X_ACCELERATORS_MASK;
	me_disable = 0x3;
	while (ssms_disabled) {
		if (ssms_disabled & 1)
			me_straps |= me_disable;
		ssms_disabled >>= 1;
		me_disable <<= 2;
	}

	return (~(fuse | me_straps)) & ADF_C62X_ACCELENGINES_MASK;
}

static u32 get_num_accels(struct adf_hw_device_data *self)
{
	u32 i, ctr = 0;

	if (!self || !self->accel_mask)
		return 0;

	for_each_set_bit(i, &self->accel_mask, ADF_C62X_MAX_ACCELERATORS)
		ctr++;
	return ctr;
}

static u32 get_num_aes(struct adf_hw_device_data *self)
{
	u32 i, ctr = 0;

	if (!self || !self->ae_mask)
		return 0;

	for_each_set_bit(i, &self->ae_mask, ADF_C62X_MAX_ACCELENGINES)
		ctr++;
	return ctr;
}

static u32 get_misc_bar_id(struct adf_hw_device_data *self)
{
	return ADF_C62X_PMISC_BAR;
}

static u32 get_etr_bar_id(struct adf_hw_device_data *self)
{
	return ADF_C62X_ETR_BAR;
}

static u32 get_sram_bar_id(struct adf_hw_device_data *self)
{
	return ADF_C62X_SRAM_BAR;
}

static enum dev_sku_info get_sku(struct adf_hw_device_data *self)
{
	int aes = get_num_aes(self);

	if (aes == 8)
		return DEV_SKU_2;
	else if (aes == 10)
		return DEV_SKU_4;

	return DEV_SKU_UNKNOWN;
}

#if defined(CONFIG_PCI_IOV)
static void process_and_get_vf2pf_int(void __iomem *pmisc_addr,
				      u32 vf_int_mask_sets[ADF_MAX_VF2PF_SET])
{
	u32 errsou3, errmsk3;
	u32 sources, disabled, non_vf2pf_errmsk3;

	/* Get the interrupt sources triggered by VFs */
	errsou3 = ADF_CSR_RD(pmisc_addr, ADF_ERRSOU3);
	sources = ADF_C62X_ERR_REG_VF2PF(errsou3);

	/* Get the already disabled interrupts */
	errmsk3 = ADF_CSR_RD(pmisc_addr, ADF_ERRMSK3);
	non_vf2pf_errmsk3 = errmsk3 & ADF_C62X_ERRMSK3_NON_VF2PF;
	disabled = ADF_C62X_ERR_REG_VF2PF(errmsk3);

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
	 * interrupts if sources change just before writing to ERRMSK3.
	 * To resolve this, disable all interrupts and re-enable only the
	 * sources that are not currently being serviced and the sources that
	 * were not already disabled. Re-enabling will trigger a new interrupt
	 * for the sources that have changed in the meantime, if any.
	 */
	errmsk3 |= ADF_C62X_ERRMSK3_VF2PF(ADF_VF2PF_INT_MASK);
	ADF_CSR_WR(pmisc_addr, ADF_ERRMSK3, errmsk3);

	errmsk3 =
		non_vf2pf_errmsk3 | ADF_C62X_ERRMSK3_VF2PF(sources | disabled);
	ADF_CSR_WR(pmisc_addr, ADF_ERRMSK3, errmsk3);
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
				      ~ADF_C62X_ERRMSK3_VF2PF(vf_mask));
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
				     ADF_C62X_ERRMSK3_VF2PF(vf_mask));
}
#endif /* CONFIG_PCI_IOV */

static void adf_get_arbiter_mapping(struct adf_accel_dev *accel_dev,
				    u32 const **arb_map_config)
{
	int i;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;

	for_each_set_bit(i, &hw_device->ae_mask, ADF_C62X_MAX_ACCELENGINES)
		thrd_to_arb_map_gen[i] = thrd_to_arb_map[i];
	adf_cfg_gen_dispatch_arbiter(accel_dev,
				     thrd_to_arb_map,
				     thrd_to_arb_map_gen,
				     ADF_C62X_MAX_ACCELENGINES);
	*arb_map_config = thrd_to_arb_map_gen;
}

static u32 get_pf2vf_offset(u32 i)
{
	return ADF_C62X_PF2VF_OFFSET(i);
}

static u32 get_vintmsk_offset(u32 i)
{
	return ADF_C62X_VINTMSK_OFFSET(i);
}

static u32 get_clock_speed(struct adf_hw_device_data *self)
{
	/* CPP clock is half high-speed clock */
	return self->clock_frequency / 2;
}

static void adf_enable_error_interrupts(void __iomem *csr)
{
	ADF_CSR_WR(csr, ADF_ERRMSK0, ADF_C62X_ERRMSK0_CERR); /* ME0-ME3  */
	ADF_CSR_WR(csr, ADF_ERRMSK1, ADF_C62X_ERRMSK1_CERR); /* ME4-ME7  */
	ADF_CSR_WR(csr, ADF_ERRMSK4, ADF_C62X_ERRMSK4_CERR); /* ME8-ME9  */
	ADF_CSR_WR(csr, ADF_ERRMSK5, ADF_C62X_ERRMSK5_CERR); /* SSM2-SSM4 */

	/* Reset everything except VFtoPF1_16 */
	adf_csr_fetch_and_and(csr, ADF_ERRMSK3, ADF_C62X_VF2PF1_16);
	/* Disable Secure RAM correctable error interrupt */
	adf_csr_fetch_and_or(csr, ADF_ERRMSK3, ADF_C62X_ERRMSK3_CERR);

	/* RI CPP bus interface error detection and reporting. */
	ADF_CSR_WR(csr, ADF_C62X_RICPPINTCTL, ADF_C62X_RICPP_EN);

	/* TI CPP bus interface error detection and reporting. */
	ADF_CSR_WR(csr, ADF_C62X_TICPPINTCTL, ADF_C62X_TICPP_EN);

	/* Enable CFC Error interrupts and logging */
	ADF_CSR_WR(csr, ADF_C62X_CPP_CFC_ERR_CTRL, ADF_C62X_CPP_CFC_UE);

	/* Enable SecureRAM to fix and log Correctable errors */
	ADF_CSR_WR(csr, ADF_C62X_SECRAMCERR, ADF_C62X_SECRAM_CERR);

	/* Enable SecureRAM Uncorrectable error interrupts and logging */
	ADF_CSR_WR(csr, ADF_SECRAMUERR, ADF_C62X_SECRAM_UERR);

	/* Enable Push/Pull Misc Uncorrectable error interrupts and logging */
	ADF_CSR_WR(csr, ADF_CPPMEMTGTERR, ADF_C62X_TGT_UERR);
}

static void adf_disable_error_interrupts(struct adf_accel_dev *accel_dev)
{
	struct adf_bar *misc_bar = &GET_BARS(accel_dev)[ADF_C62X_PMISC_BAR];
	void __iomem *csr = misc_bar->virt_addr;

	/* ME0-ME3 */
	ADF_CSR_WR(csr, ADF_ERRMSK0, ADF_C62X_ERRMSK0_UERR |
		   ADF_C62X_ERRMSK0_CERR);
	/* ME4-ME7 */
	ADF_CSR_WR(csr, ADF_ERRMSK1, ADF_C62X_ERRMSK1_UERR |
		   ADF_C62X_ERRMSK1_CERR);
	/* Secure RAM, CPP Push Pull, RI, TI, SSM0-SSM1, CFC */
	ADF_CSR_WR(csr, ADF_ERRMSK3, ADF_C62X_ERRMSK3_UERR |
		   ADF_C62X_ERRMSK3_CERR);
	/* ME8-ME9 */
	ADF_CSR_WR(csr, ADF_ERRMSK4, ADF_C62X_ERRMSK4_UERR |
		   ADF_C62X_ERRMSK4_CERR);
	/* SSM2-SSM4 */
	ADF_CSR_WR(csr, ADF_ERRMSK5, ADF_C62X_ERRMSK5_UERR |
		   ADF_C62X_ERRMSK5_CERR);
}

static int adf_check_uncorrectable_error(struct adf_accel_dev *accel_dev)
{
	struct adf_bar *misc_bar = &GET_BARS(accel_dev)[ADF_C62X_PMISC_BAR];
	void __iomem *csr = misc_bar->virt_addr;

	u32 errsou0 = ADF_CSR_RD(csr, ADF_ERRSOU0) & ADF_C62X_ERRMSK0_UERR;
	u32 errsou1 = ADF_CSR_RD(csr, ADF_ERRSOU1) & ADF_C62X_ERRMSK1_UERR;
	u32 errsou3 = ADF_CSR_RD(csr, ADF_ERRSOU3) & ADF_C62X_ERRMSK3_UERR;
	u32 errsou4 = ADF_CSR_RD(csr, ADF_ERRSOU4) & ADF_C62X_ERRMSK4_UERR;
	u32 errsou5 = ADF_CSR_RD(csr, ADF_ERRSOU5) & ADF_C62X_ERRMSK5_UERR;

	return (errsou0 | errsou1 | errsou3 | errsou4 | errsou5);
}

static void adf_enable_mmp_error_correction(void __iomem *csr,
					    struct adf_hw_device_data *hw_data)
{
	unsigned int dev, mmp;

	/* Enable MMP Logging */
	for_each_set_bit(dev, &hw_data->accel_mask, ADF_C62X_MAX_ACCELERATORS) {
		/* Set power-up */
		adf_csr_fetch_and_and(csr,
				      ADF_C62X_SLICEPWRDOWN(dev),
				      ~ADF_C62X_MMP_PWR_UP_MSK);

		if (hw_data->accel_capabilities_mask &
		    ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC) {
			for (mmp = 0; mmp < ADF_MAX_MMP; ++mmp) {
				/*
				 * The device supports PKE,
				 * so enable error reporting from MMP memory
				 */
				adf_csr_fetch_and_or(csr,
						     ADF_UERRSSMMMP(dev, mmp),
						     ADF_C62X_UERRSSMMMP_EN);
				/*
				 * The device supports PKE,
				 * so enable error correction from MMP memory
				 */
				adf_csr_fetch_and_or(csr,
						     ADF_CERRSSMMMP(dev, mmp),
						     ADF_C62X_CERRSSMMMP_EN);
			}
		} else {
			for (mmp = 0; mmp < ADF_MAX_MMP; ++mmp) {
				/*
				 * The device doesn't support PKE,
				 * so disable error reporting from MMP memory
				 */
				adf_csr_fetch_and_and(csr,
						      ADF_UERRSSMMMP(dev, mmp),
						      ~ADF_C62X_UERRSSMMMP_EN);
				/*
				 * The device doesn't support PKE,
				 * so disable error correction from MMP memory
				 */
				adf_csr_fetch_and_and(csr,
						      ADF_CERRSSMMMP(dev, mmp),
						      ~ADF_C62X_CERRSSMMMP_EN);
			}
		}

		/* Restore power-down value */
		adf_csr_fetch_and_or(csr,
				     ADF_C62X_SLICEPWRDOWN(dev),
				     ADF_C62X_MMP_PWR_UP_MSK);

		/* Disabling correctable error interrupts. */
		ADF_CSR_WR(csr,
			   ADF_C62X_INTMASKSSM(dev),
			   ADF_C62X_INTMASKSSM_UERR);
	}
}

static void adf_enable_error_correction(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	struct adf_bar *misc_bar = &GET_BARS(accel_dev)[ADF_C62X_PMISC_BAR];
	void __iomem *csr = misc_bar->virt_addr;
	unsigned int i;

	/* Enable Accel Engine error detection & correction */
	for_each_set_bit(i, &hw_device->ae_mask, ADF_C62X_MAX_ACCELENGINES) {
		adf_csr_fetch_and_or(csr, ADF_C62X_AE_CTX_ENABLES(i),
				     ADF_C62X_ENABLE_AE_ECC_ERR);
		adf_csr_fetch_and_or(csr, ADF_C62X_AE_MISC_CONTROL(i),
				     ADF_C62X_ENABLE_AE_ECC_PARITY_CORR);
	}

	/* Enable shared memory error detection & correction */
	for_each_set_bit(i, &hw_device->accel_mask, ADF_C62X_MAX_ACCELERATORS) {
		adf_csr_fetch_and_or(csr, ADF_UERRSSMSH(i),
				     ADF_C62X_ERRSSMSH_EN);
		adf_csr_fetch_and_or(csr, ADF_CERRSSMSH(i),
				     ADF_C62X_ERRSSMSH_EN);
		adf_csr_fetch_and_or(csr, ADF_PPERR(i),
				     ADF_C62X_PPERR_EN);
	}

	adf_enable_error_interrupts(csr);
	adf_enable_mmp_error_correction(csr, hw_device);
}

static void adf_enable_ints(struct adf_accel_dev *accel_dev)
{
	void __iomem *addr;
#ifdef ALLOW_SLICE_HANG_INTERRUPT
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	u32 i;
#endif

	addr = (&GET_BARS(accel_dev)[ADF_C62X_PMISC_BAR])->virt_addr;

	/* Enable bundle and misc interrupts */
	ADF_CSR_WR(addr, ADF_C62X_SMIAPF0_MASK_OFFSET,
		   ADF_C62X_SMIA0_MASK);
	ADF_CSR_WR(addr, ADF_C62X_SMIAPF1_MASK_OFFSET,
		   ADF_C62X_SMIA1_MASK);
#ifdef ALLOW_SLICE_HANG_INTERRUPT
	/* Enable slice hang interrupt */
	for_each_set_bit(i, &hw_device->accel_mask, ADF_C62X_MAX_ACCELERATORS) {
		ADF_CSR_WR(addr, ADF_SHINTMASKSSM(i),
			   ADF_ENABLE_SLICE_HANG);
	}
#endif
}

static u32 get_ae_clock(struct adf_hw_device_data *self)
{
	/*
	 * Clock update interval is <16> ticks for c62x.
	 */
	return self->clock_frequency / 16;
}

static int measure_clock(struct adf_accel_dev *accel_dev)
{
	u32 frequency;
	int ret = 0;

	ret = adf_dev_measure_clock(accel_dev, &frequency,
				    ADF_C62X_MIN_AE_FREQ,
				    ADF_C62X_MAX_AE_FREQ);
	if (ret)
		return ret;

	accel_dev->hw_device->clock_frequency = frequency;
	return 0;
}

static u32 c62x_get_hw_cap(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;
	u32 legfuses;
	u32 capabilities;
	u32 straps;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 fuses = hw_data->fuses;

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
		ICP_ACCEL_CAPABILITIES_ZUC +
		ICP_ACCEL_CAPABILITIES_SHA3 +
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
	if (legfuses & ICP_ACCEL_MASK_EIA3_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_ZUC;
	if (legfuses & ICP_ACCEL_MASK_SHA3_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_SHA3;

	pci_read_config_dword(pdev, ADF_C62X_SOFTSTRAP_CSR_OFFSET,
			      &straps);
	if ((straps | fuses) & ADF_C62X_POWERGATE_PKE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC;
	if ((straps | fuses) & ADF_C62X_POWERGATE_DC)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_COMPRESSION;

	return capabilities;
}

/**
 * get_pci_link_width() - Gets the PCI link width of given pci_dev structure
 * @pdev:	Pointer to PCI device
 *
 * Function gets the PCI link width by reading the PCI capability register
 */
static u16 get_pci_link_width(struct pci_dev *pdev)
{
	u16 lnkcap;

	pci_read_config_word(pdev, pdev->pcie_cap + PCI_EXP_LNKCAP, &lnkcap);
	return (lnkcap & PCI_EXP_LNKCAP_MLW) >> ADF_PCIE_LNKCAP_MLW_SHIFT;
}

/**
 * get_physical_slot() - Gets the physical slot where the PCI device resides
 * @pdev:	Pointer to PCI device
 *
 * Function gets the physical slot where the PCI device is residing by
 * reading the slot capability register. Bits 31:19 in the register indicates
 * the physical slot where the device is attached.
 */
static int get_physical_slot(struct pci_dev *pdev)
{
	u32 lnkcap;

	if (!pdev)
		return -ENODEV;

	pci_read_config_dword(pdev, pdev->pcie_cap + PCI_EXP_SLTCAP, &lnkcap);
	return (lnkcap & PCI_EXP_SLTCAP_PSN) >> ADF_PCIE_SLOT_OFFSET;
}

static struct pci_dev *get_root_port_dev(struct pci_bus *bus)
{
	struct pci_bus *bus_t = bus;
	struct pci_dev *pdev = NULL;
	u16 dev_id = 0;

	while (bus_t) {
		/**
		 * Null check is required as the PCI bus structures do not get
		 * populated in a pass through virtualized environment and
		 * pci_read_config_word do not check for null internally.
		 */
		if (!bus_t->self)
			break;
		pci_read_config_word(bus_t->self, PCI_DEVICE_ID, &dev_id);
		bus_t = bus->parent;
		if (dev_id == ADF_C62X_ROOT_DEV0 ||
		    dev_id == ADF_C62X_ROOT_DEV1) {
			pdev = bus_t->self;
			break;
		}
	}
	return pdev;
}

/**
 * get_sku_variant() - Gets the SKU variant for the given PCI device
 * @pdev:		Pointer to PCI device
 *
 * List of PCI devices is traversed and matched with the
 * physical slot number of the given PCI device to identify the SKU variant.
 */
static u16 get_sku_variant(struct pci_dev *pdev)
{
	struct pci_dev *dev1 = NULL, *dev2 = NULL, *temp = NULL;
	u16 no_x16 = 0, no_x8 = 0, no_x4 = 0, sku_variant = 0, width = 0;
	int src_phy_slot = 0, dst_phy_slot = 0;

	temp = get_root_port_dev(pdev->bus);
	src_phy_slot = get_physical_slot(temp);
	while ((dev1 = pci_get_device(PCI_VENDOR_ID_INTEL,
				      ADF_C62X_PCI_DEVICE_ID, dev1))) {
		dev2 = get_root_port_dev(dev1->bus);
		dst_phy_slot = get_physical_slot(dev2);
		/**
		 * Iterates through the pci device list and finds the pci device
		 * having the same physical slot number. Identify and increment
		 * the number of devices only if the slot numbers match.
		 * This is to properly find the SKU variant when multiple
		 * different c62x cards are placed in the system.
		 */
		if (src_phy_slot == dst_phy_slot) {
			if (src_phy_slot == -ENODEV)
				break;
			width = get_pci_link_width(dev2);
			switch (width) {
			case ADF_PCIE_LNK_X8:
				no_x8++;
				break;
			case ADF_PCIE_LNK_X16:
				no_x16++;
				break;
			case ADF_PCIE_LNK_X4:
				no_x4++;
				break;
			default:
				break;
			}
		}
	}

	if (no_x16 == 0 && no_x8 == 3) {
		sku_variant = ADF_C62X_SKU_3X8;
	} else if (no_x16 == 3 && no_x8 == 0) {
		sku_variant = ADF_C62X_SKU_3X16;
	} else if (no_x16 == 2 && no_x8 == 1) {
		sku_variant = ADF_C62X_SKU_3X24;
	} else {
		dev_warn(&pdev->dev,
			 "Unknown SKU detected. RL configuration set as (2x16 + 1x8) SKU\n");
		sku_variant = ADF_C62X_SKU_3X24;
	}

	return sku_variant;
}

static int get_sla_units(struct adf_accel_dev *accel_dev, u32 **sla_au)
{
	u8 i = 0;
	enum adf_cfg_fw_image_type fw_image_type = ADF_FW_IMAGE_DEFAULT;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 clock_frequency = GET_HW_DATA(accel_dev)->clock_frequency;
	u32 max_tolerance = ADF_APPLY_PERCENTAGE(ADF_C62X_AE_FREQ,
						 ADF_AE_FREQ_TOLERANCE);
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);
	u16 sku_variant = 0, freq_variant = ADF_C62X_DEFAULT;

	sku_variant = get_sku_variant(pdev);

	if (clock_frequency > ADF_C62X_AE_FREQ + max_tolerance)
		freq_variant = ADF_C62X_800MHZ;

	if (hw_data->get_fw_image_type(accel_dev, &fw_image_type))
		return -EFAULT;

	for (i = 0; i < ARRAY_SIZE(slau_cfg); i++) {
		if (fw_image_type == slau_cfg[i].fw_image_type)
			break;
	}

	if (i < ARRAY_SIZE(slau_cfg))
		*sla_au = slau_cfg[i].slau_supported[sku_variant][freq_variant];

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
		strlcpy(uof_name, ADF_CXXX_AE_FW_NAME,
			ADF_CFG_MAX_VAL_LEN_IN_BYTES);
		break;
	case ADF_FW_IMAGE_CRYPTO:
		strlcpy(uof_name, ADF_CXXX_AE_FW_NAME_CRYPTO,
			ADF_CFG_MAX_VAL_LEN_IN_BYTES);
		break;
	case ADF_FW_IMAGE_COMPRESSION:
		strlcpy(uof_name, ADF_CXXX_AE_FW_NAME_COMPRESSION,
			ADF_CFG_MAX_VAL_LEN_IN_BYTES);
		break;
	case ADF_FW_IMAGE_CUSTOM1:
		strlcpy(uof_name, ADF_CXXX_AE_FW_NAME_CUSTOM1,
			ADF_CFG_MAX_VAL_LEN_IN_BYTES);
		break;
	default:
		dev_err(&GET_DEV(accel_dev),
			"Unsupported ServicesProfile.\n");
		return -EFAULT;
	}

	return 0;
}


static void adf_print_dev_err_registers(struct adf_accel_dev *accel_dev)
{
	adf_print_gen2_err_registers(accel_dev);
	adf_print_err_registers(accel_dev);
}

void adf_init_hw_data_c62x(struct adf_hw_device_data *hw_data)
{
	hw_data->dev_class = &c62x_class;
	hw_data->instance_id = c62x_class.instances++;
	hw_data->num_banks = ADF_C62X_ETR_MAX_BANKS;
	hw_data->num_rings_per_bank = ADF_ETR_MAX_RINGS_PER_BANK;
	hw_data->num_accel = ADF_C62X_MAX_ACCELERATORS;
	hw_data->num_logical_accel = 1;
	hw_data->num_engines = ADF_C62X_MAX_ACCELENGINES;
	hw_data->tx_rx_gap = ADF_C62X_RX_RINGS_OFFSET;
	hw_data->tx_rings_mask = ADF_C62X_TX_RINGS_MASK;
	hw_data->alloc_irq = adf_isr_resource_alloc;
	hw_data->free_irq = adf_isr_resource_free;
	hw_data->enable_error_correction = adf_enable_error_correction;
	hw_data->check_uncorrectable_error = adf_check_uncorrectable_error;
	hw_data->print_err_registers = adf_print_dev_err_registers;
	hw_data->disable_error_interrupts = adf_disable_error_interrupts;
	hw_data->get_accel_mask = get_accel_mask;
	hw_data->get_ae_mask = get_ae_mask;
	hw_data->get_num_accels = get_num_accels;
	hw_data->get_num_aes = get_num_aes;
	hw_data->get_sram_bar_id = get_sram_bar_id;
	hw_data->get_etr_bar_id = get_etr_bar_id;
	hw_data->get_misc_bar_id = get_misc_bar_id;
	hw_data->get_pf2vf_offset = get_pf2vf_offset;
	hw_data->get_vintmsk_offset = get_vintmsk_offset;
	hw_data->get_arb_info = get_gen2_arb_info;
	hw_data->get_admin_info = get_gen2_admin_info;
	hw_data->get_clock_speed = get_clock_speed;
	hw_data->get_sku = get_sku;
#if defined(CONFIG_PCI_IOV)
	hw_data->process_and_get_vf2pf_int = process_and_get_vf2pf_int;
	hw_data->enable_vf2pf_interrupts = enable_vf2pf_interrupts;
	hw_data->disable_vf2pf_interrupts = disable_vf2pf_interrupts;
#endif
	hw_data->fw_name = ADF_C62X_FW;
	hw_data->fw_mmp_name = ADF_C62X_MMP;
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
	hw_data->set_ssm_wdtimer = adf_set_ssm_wdtimer;
	hw_data->check_slice_hang = adf_check_slice_hang;
	hw_data->enable_vf2pf_comms = adf_pf_enable_vf2pf_comms;
	hw_data->disable_vf2pf_comms = adf_pf_disable_vf2pf_comms;
	hw_data->min_iov_compat_ver = ADF_PFVF_COMPATIBILITY_VERSION;
	hw_data->get_heartbeat_status = adf_get_heartbeat_status;
	hw_data->get_ae_clock = get_ae_clock;
	hw_data->reset_device = adf_reset_flr;
	hw_data->clock_frequency = ADF_C62X_AE_FREQ;
	hw_data->measure_clock = measure_clock;
	hw_data->get_accel_cap = c62x_get_hw_cap;
	hw_data->ring_to_svc_map = ADF_DEFAULT_RING_TO_SRV_MAP;
	hw_data->pre_reset = adf_dev_pre_reset;
	hw_data->post_reset = adf_dev_post_reset;
	hw_data->fw_load = adf_gen2_ae_fw_load;
	hw_data->get_ring_to_svc_map = adf_get_services_enabled;
	hw_data->extended_dc_capabilities = 0;
	hw_data->config_device = adf_config_device;
	hw_data->set_asym_rings_mask = adf_cfg_set_asym_rings_mask;
	hw_data->get_sla_units = get_sla_units;
	hw_data->get_slices_for_svc = adf_gen2_get_slices_for_svc;
	hw_data->calc_sla_units = adf_gen2_calc_sla_units;
	hw_data->get_fw_image_type = adf_cfg_get_fw_image_type;
	hw_data->get_fw_name = get_fw_name;
	hw_data->get_dc_ae_mask = adf_gen2_get_dc_ae_mask;
}

void adf_clean_hw_data_c62x(struct adf_hw_device_data *hw_data)
{
	hw_data->dev_class->instances--;
}
