// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2016 - 2021 Intel Corporation */

#include <linux/atomic.h>
#include <adf_accel_devices.h>
#include <adf_common_drv.h>
#include <adf_pf2vf_msg.h>
#include <adf_cfg.h>
#include <adf_gen3_hw_data.h>
#include "adf_c4xxx_hw_data.h"
#include "adf_c4xxx_ras.h"
#include "adf_c4xxx_reset.h"
#include "adf_heartbeat.h"
#include "icp_qat_hw.h"
#include "adf_c4xxx_accel_units.h"
#include "adf_c4xxx_aram.h"
#include "adf_c4xxx_misc_error_stats.h"
#include "adf_c4xxx_pke_replay_stats.h"

static struct adf_slau_cfg slau_cfg[] = {
	{ADF_FW_IMAGE_DEFAULT_C4XXX,
		{
			/* HIGH_SKU */
			{86000, 72000, 100000},
			/* MID_SKU */
			{43000, 24000, 50000},
			/* LOW_SKU */
			{0, 0, 0},
			{0, 0, 0},
			{0, 0, 0},

			{0, 72000, 0},
			{0, 24000, 0},
			{0, 0, 0}
		}
	}
};

static u32 slau_val[ADF_MAX_SERVICES];

static struct adf_hw_device_class c4xxx_class = {
	.name = ADF_C4XXX_DEVICE_NAME,
	.type = DEV_C4XXX,
	.instances = 0
};

static u32 get_accel_mask(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;
	u32 fusectl0;
	u32 softstrappull0;

	pci_read_config_dword(pdev, ADF_C4XXX_FUSECTL0_OFFSET,
			      &fusectl0);
	pci_read_config_dword(pdev, ADF_C4XXX_SOFTSTRAPPULL0_OFFSET,
			      &softstrappull0);

	return (~(fusectl0 | softstrappull0)) & ADF_C4XXX_ACCELERATORS_MASK;
}

static u32 get_ae_mask(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;
	u32 fusectl1;
	u32 softstrappull1;

	pci_read_config_dword(pdev, ADF_C4XXX_FUSECTL1_OFFSET,
			      &fusectl1);
	pci_read_config_dword(pdev, ADF_C4XXX_SOFTSTRAPPULL1_OFFSET,
			      &softstrappull1);

	/* Assume that AE and AU disable masks are consistent, so no
	 * checks against the AU mask are performed
	 */
	return (~(fusectl1 | softstrappull1)) & ADF_C4XXX_ACCELENGINES_MASK;
}

static u32 get_num_accels(struct adf_hw_device_data *self)
{
	u32 i, ctr = 0;

	if (!self || !self->accel_mask)
		return 0;

	for_each_set_bit(i, &self->accel_mask, ADF_C4XXX_MAX_ACCELERATORS)
		ctr++;
	return ctr;
}

static u32 get_num_aes(struct adf_hw_device_data *self)
{
	u32 i, ctr = 0;

	if (!self || !self->ae_mask)
		return 0;

	for_each_set_bit(i, &self->ae_mask, ADF_C4XXX_MAX_ACCELENGINES)
		ctr++;
	return ctr;
}

static u32 get_misc_bar_id(struct adf_hw_device_data *self)
{
	return ADF_C4XXX_PMISC_BAR;
}

static u32 get_etr_bar_id(struct adf_hw_device_data *self)
{
	return ADF_C4XXX_ETR_BAR;
}

static u32 get_sram_bar_id(struct adf_hw_device_data *self)
{
	return ADF_C4XXX_SRAM_BAR;
}

static enum dev_sku_info get_sku(struct adf_hw_device_data *self)
{
	u32 aes = get_num_aes(self);
	u32 capabilities = self->accel_capabilities_mask;
	bool sym_only_sku = false;

	dev_dbg(NULL, "AEs = %d\n", aes);

	/* Check if SKU is capable only of symmetric cryptography
	 * via device capabilities.
	 */
	if ((capabilities & ADF_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC) &&
	    !(capabilities & ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC) &&
	    !(capabilities & ADF_ACCEL_CAPABILITIES_COMPRESSION))
		sym_only_sku = true;

	switch (aes) {
	case ADF_C4XXX_HIGH_SKU_AES:
		if (sym_only_sku)
			return DEV_SKU_1_SYM;
		return DEV_SKU_1;
	case ADF_C4XXX_MED_SKU_AES:
		if (sym_only_sku)
			return DEV_SKU_2_SYM;
		return DEV_SKU_2;
	case ADF_C4XXX_LOW_SKU_AES:
		if (sym_only_sku)
			return DEV_SKU_3_SYM;
		return DEV_SKU_3;
	default:
		return DEV_SKU_UNKNOWN;
	};

	return DEV_SKU_UNKNOWN;
}

static u32 get_clock_speed(struct adf_hw_device_data *self)
{
	/* C4XXX CPP clock is equal to high-speed clock */
	return self->clock_frequency;
}

static void adf_enable_mmp_error_correction(void __iomem *csr,
					    struct adf_hw_device_data *hw_data)
{
	unsigned int accel, mmp;
	unsigned long uerrssmmmp_mask, cerrssmmmp_mask;
	enum operation op;
	unsigned long accel_mask;

	/* Prepare values and operation that will be performed on
	 * UERRSSMMMP and CERRSSMMMP registers on each MMP
	 */
	if (hw_data->accel_capabilities_mask &
		ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC) {
		uerrssmmmp_mask = ADF_C4XXX_UERRSSMMMP_EN;
		cerrssmmmp_mask = ADF_C4XXX_CERRSSMMMP_EN;
		op = OR;
	} else {
		uerrssmmmp_mask = ~ADF_C4XXX_UERRSSMMMP_EN;
		cerrssmmmp_mask = ~ADF_C4XXX_CERRSSMMMP_EN;
		op = AND;
	}

	accel_mask = hw_data->accel_mask;

	/* Enable MMP Logging */
	for_each_set_bit(accel, &accel_mask, ADF_C4XXX_MAX_ACCELERATORS) {
		/* Set power-up */
		adf_csr_fetch_and_and(csr, ADF_C4XXX_SLICEPWRDOWN(accel),
				      ~ADF_C4XXX_MMP_PWR_UP_MSK);

		for (mmp = 0; mmp < ADF_C4XXX_MAX_MMP; ++mmp) {
			adf_csr_fetch_and_update(op,
						 csr,
						 ADF_C4XXX_UERRSSMMMP(accel,
								      mmp),
						 uerrssmmmp_mask);
			adf_csr_fetch_and_update(op,
						 csr,
						 ADF_C4XXX_CERRSSMMMP(accel,
								      mmp),
						 cerrssmmmp_mask);
		}

		/* Restore power-down value */
		adf_csr_fetch_and_or(csr, ADF_C4XXX_SLICEPWRDOWN(accel),
				     ADF_C4XXX_MMP_PWR_UP_MSK);
	}
}

#if defined(CONFIG_PCI_IOV)
static void process_and_get_vf2pf_int(void __iomem *pmisc_addr,
				      u32 vf_int_mask_sets[ADF_MAX_VF2PF_SET])
{
	u32 sources[ADF_MAX_VF2PF_SET], disabled[ADF_MAX_VF2PF_SET];
	u8 i;

	for (i = 0; i < ADF_MAX_VF2PF_SET; i++) {
		/* Get the interrupt sources triggered by VFs */
		sources[i] = ADF_CSR_RD(pmisc_addr,
					ADF_C4XXX_ERRSOU_VF2PF_OFFSET(i));

		/* Get the already disabled interrupts */
		disabled[i] = ADF_CSR_RD(pmisc_addr,
					 ADF_C4XXX_ERRMSK_VF2PF_OFFSET(i));
		/*
		 * To avoid adding duplicate entries to work queue, clear
		 * source interrupt bits that are already masked in
		 * ERRMSK register.
		 */
		vf_int_mask_sets[i] = sources[i] & ~disabled[i];
	}

	/*
	 * Due to HW limitations, when disabling the interrupts,
	 * we can't just disable the requested sources, as this would
	 * lead to missed interrupts if sources change just before
	 * writing to ERRMSK. To resolve this, disable all interrupts and
	 * re-enable only the sources that are not currently being serviced
	 * and the sources that were not already disabled.
	 * Re-enabling will trigger a new interrupt for the
	 * sources that have changed in the meantime, if any.
	 */
	for (i = 0; i < ADF_MAX_VF2PF_SET; i++)
		ADF_CSR_WR(pmisc_addr,
			   ADF_C4XXX_ERRMSK_VF2PF_OFFSET(i),
			   ADF_VF2PF_REG_MASK);

	for (i = 0; i < ADF_MAX_VF2PF_SET; i++)
		ADF_CSR_WR(pmisc_addr,
			   ADF_C4XXX_ERRMSK_VF2PF_OFFSET(i),
			   sources[i] | disabled[i]);
}

static void enable_vf2pf_interrupts(void __iomem *pmisc_addr,
				    u32 vf_mask, u8 i)
{
	adf_csr_fetch_and_and(pmisc_addr,
			      ADF_C4XXX_ERRMSK_VF2PF_OFFSET(i),
			      ~vf_mask);
}

static void disable_vf2pf_interrupts(void __iomem *pmisc_addr,
				     u32 vf_mask, u8 i)
{
	adf_csr_fetch_and_or(pmisc_addr,
			     ADF_C4XXX_ERRMSK_VF2PF_OFFSET(i),
			     vf_mask);
}
#endif

static u32 get_pf2vf_offset(u32 i)
{
	return ADF_C4XXX_PF2VF_OFFSET(i);
}

static u32 get_vintmsk_offset(u32 i)
{
	return ADF_C4XXX_VINTMSK_OFFSET(i);
}

static void get_arb_info(struct adf_arb_info *arb_csrs_info)
{
	arb_csrs_info->arbiter_offset = ADF_C4XXX_ARB_OFFSET;
	arb_csrs_info->wrk_cfg_offset = ADF_C4XXX_ARB_WQCFG_OFFSET;
	arb_csrs_info->dbg_rst_arb_offset = ADF_C4XXX_ARB_DBG_RST_ARB_OFFSET;
}

static void get_admin_info(struct adf_admin_info *admin_csrs_info)
{
	admin_csrs_info->mailbox_offset = ADF_C4XXX_MAILBOX_BASE_OFFSET;
	admin_csrs_info->admin_msg_ur = ADF_C4XXX_ADMINMSGUR_OFFSET;
	admin_csrs_info->admin_msg_lr = ADF_C4XXX_ADMINMSGLR_OFFSET;
}

static void adf_enable_error_interrupts(struct adf_accel_dev *accel_dev)
{
	void __iomem *csr, *aram_csr;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	u32 accel;
	unsigned long accel_mask;

	csr = (&GET_BARS(accel_dev)[ADF_C4XXX_PMISC_BAR])->virt_addr;
	aram_csr = (&GET_BARS(accel_dev)[ADF_C4XXX_SRAM_BAR])->virt_addr;
	accel_mask = hw_device->accel_mask;

	for_each_set_bit(accel, &accel_mask, ADF_C4XXX_MAX_ACCELERATORS) {
		/* Enable shared memory, MMP, CPP, PPERR interrupts
		 * for a given accel
		 */
		ADF_CSR_WR(csr,
			   ADF_C4XXX_GET_INTMASKSSM_OFFSET(accel),
			   0);

		/* Enable SPP parity error interrupts for a given accel */
		ADF_CSR_WR(csr,
			   ADF_C4XXX_GET_SPPPARERRMSK_OFFSET(accel),
			   0);

		/* Enable ssm soft parity errors on given accel */
		ADF_CSR_WR(csr,
			   ADF_C4XXX_GET_SSMSOFTERRORPARITY_MASK_OFFSET(accel),
			   ADF_C4XXX_SSMSOFTERRORPARITY_MASK_VAL);
	}

	/* Enable interrupts for VFtoPF0_127. */
	ADF_CSR_WR(csr, ADF_C4XXX_ERRMSK4, ADF_C4XXX_VF2PF0_31);
	ADF_CSR_WR(csr, ADF_C4XXX_ERRMSK5, ADF_C4XXX_VF2PF32_63);
	ADF_CSR_WR(csr, ADF_C4XXX_ERRMSK6, ADF_C4XXX_VF2PF64_95);
	ADF_CSR_WR(csr, ADF_C4XXX_ERRMSK7, ADF_C4XXX_VF2PF96_127);

	/* Enable interrupts signaling ECC correctable errors for all AEs */
	ADF_CSR_WR(csr, ADF_C4XXX_ERRMSK8, ADF_C4XXX_ERRMSK8_COERR);
	ADF_CSR_WR(csr, ADF_C4XXX_HI_ME_COR_ERRLOG_ENABLE,
		   ADF_C4XXX_HI_ME_COR_ERRLOG_ENABLE_MASK);

	/* Enable error interrupts reported by ERRSOU9 */
	ADF_CSR_WR(csr, ADF_C4XXX_ERRMSK9, ADF_C4XXX_ERRMSK9_IRQ_MASK);

	/* Enable uncorrectable errors on all the AE */
	ADF_CSR_WR(csr, ADF_C4XXX_HI_ME_UNCERR_LOG_ENABLE,
		   ADF_C4XXX_HI_ME_UNCERR_LOG_ENABLE_MASK);

	/* Enable CPP Agent to report command parity errors */
	ADF_CSR_WR(csr, ADF_C4XXX_HI_CPP_AGENT_CMD_PAR_ERR_LOG_ENABLE,
		   ADF_C4XXX_HI_CPP_AGENT_CMD_PAR_ERR_LOG_ENABLE_MASK);

	/* Enable reporting of RI memory parity errors */
	ADF_CSR_WR(csr, ADF_C4XXX_RI_MEM_PAR_ERR_EN0,
		   ADF_C4XXX_RI_MEM_PAR_ERR_EN0_MASK);

	/* Enable reporting of TI memory parity errors */
	ADF_CSR_WR(csr, ADF_C4XXX_TI_MEM_PAR_ERR_EN0,
		   ADF_C4XXX_TI_MEM_PAR_ERR_EN0_MASK);
	ADF_CSR_WR(csr, ADF_C4XXX_TI_MEM_PAR_ERR_EN1,
		   ADF_C4XXX_TI_MEM_PAR_ERR_EN1_MASK);

	/* Enable SSM errors */
	ADF_CSR_WR(csr, ADF_C4XXX_ERRMSK10, ADF_C4XXX_ERRMSK10_SSM_ERR);

	/* Enable miscellaneous errors (ethernet doorbell aram, ici, ice) */
	ADF_CSR_WR(csr, ADF_C4XXX_ERRMSK11, ADF_C4XXX_ERRMSK11_ERR);

	/* RI CPP bus interface error detection and reporting. */
	ADF_CSR_WR(csr, ADF_C4XXX_RICPPINTCTL, ADF_C4XXX_RICPP_EN);

	/* TI CPP bus interface error detection and reporting. */
	ADF_CSR_WR(csr, ADF_C4XXX_TICPPINTCTL, ADF_C4XXX_TICPP_EN);

	/* Enable CFC Error interrupts and logging. */
	ADF_CSR_WR(csr, ADF_C4XXX_CPP_CFC_ERR_CTRL, ADF_C4XXX_CPP_CFC_UE);

	/* Enable ARAM correctable error detection. */
	ADF_CSR_WR(aram_csr, ADF_C4XXX_ARAMCERR, ADF_C4XXX_ARAM_CERR);

	/* Enable ARAM uncorrectable error detection. */
	ADF_CSR_WR(aram_csr, ADF_C4XXX_ARAMUERR, ADF_C4XXX_ARAM_UERR);

	/* Enable Push/Pull Misc Uncorrectable error interrupts and logging */
	ADF_CSR_WR(aram_csr, ADF_C4XXX_CPPMEMTGTERR, ADF_C4XXX_TGT_UERR);
}

static void adf_enable_error_correction(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	struct adf_accel_unit_info *au_info = accel_dev->au_info;
	struct adf_bar *misc_bar =
		&GET_BARS(accel_dev)[ADF_C4XXX_PMISC_BAR];
	void __iomem *csr = misc_bar->virt_addr;
	unsigned int val, i;
	unsigned long ae_mask;
	unsigned long accel_mask;

	ae_mask = hw_device->ae_mask;

	/* Enable Accel Engine error detection & correction */
	for_each_set_bit(i, &ae_mask, ADF_C4XXX_MAX_ACCELENGINES) {
		val = ADF_CSR_RD(csr, ADF_C4XXX_AE_CTX_ENABLES(i));
		val |= ADF_C4XXX_ENABLE_AE_ECC_ERR;
		ADF_CSR_WR(csr, ADF_C4XXX_AE_CTX_ENABLES(i), val);
		val = ADF_CSR_RD(csr, ADF_C4XXX_AE_MISC_CONTROL(i));
		val |= ADF_C4XXX_ENABLE_AE_ECC_PARITY_CORR;
		ADF_CSR_WR(csr, ADF_C4XXX_AE_MISC_CONTROL(i), val);
	}

	accel_mask = hw_device->accel_mask;

	/* Enable shared memory error detection & correction */
	for_each_set_bit(i, &accel_mask, ADF_C4XXX_MAX_ACCELERATORS) {
		val = ADF_CSR_RD(csr, ADF_C4XXX_UERRSSMSH(i));
		val |= ADF_C4XXX_ERRSSMSH_EN;
		ADF_CSR_WR(csr, ADF_C4XXX_UERRSSMSH(i), val);
		val = ADF_CSR_RD(csr, ADF_C4XXX_CERRSSMSH(i));
		val |= ADF_C4XXX_ERRSSMSH_EN;
		ADF_CSR_WR(csr, ADF_C4XXX_CERRSSMSH(i), val);
	}

	adf_enable_ras_c4xxx(accel_dev);
	adf_enable_mmp_error_correction(csr, hw_device);
#ifdef ALLOW_SLICE_HANG_INTERRUPT
	adf_enable_slice_hang_detection_c4xxx(accel_dev);
#endif
	adf_enable_error_interrupts(accel_dev);

	if (adf_misc_error_add_c4xxx(accel_dev))
		dev_dbg(&GET_DEV(accel_dev), "Failed to add misc error counter\n");

	if (au_info->asym_ae_msk)
		if (adf_pke_replay_counters_add_c4xxx(accel_dev))
			dev_dbg(&GET_DEV(accel_dev),
				"Failed to add pke replay statistics counter\n");
}

static void adf_disable_error_correction(struct adf_accel_dev *accel_dev)
{
	adf_misc_error_remove_c4xxx(accel_dev);
	adf_pke_replay_counters_remove_c4xxx(accel_dev);
}

static void adf_enable_ints(struct adf_accel_dev *accel_dev)
{
	void __iomem *addr;

	addr = (&GET_BARS(accel_dev)[ADF_C4XXX_PMISC_BAR])->virt_addr;

	/* Enable bundle interrupts */
	ADF_CSR_WR(addr, ADF_C4XXX_SMIAPF0_MASK_OFFSET,
		   ADF_C4XXX_SMIA0_MASK);
	ADF_CSR_WR(addr, ADF_C4XXX_SMIAPF1_MASK_OFFSET,
		   ADF_C4XXX_SMIA1_MASK);
	ADF_CSR_WR(addr, ADF_C4XXX_SMIAPF2_MASK_OFFSET,
		   ADF_C4XXX_SMIA2_MASK);
	ADF_CSR_WR(addr, ADF_C4XXX_SMIAPF3_MASK_OFFSET,
		   ADF_C4XXX_SMIA3_MASK);
	/*Enable misc interrupts*/
	ADF_CSR_WR(addr, ADF_C4XXX_SMIAPF4_MASK_OFFSET,
		   ADF_C4XXX_SMIA4_MASK);
}

static u32 get_ae_clock(struct adf_hw_device_data *self)
{
	/* Clock update interval is <16> ticks for c4xxx. */
	return self->clock_frequency / 16;
}

static u32 adf_set_default_sku_freq_c4xxx(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 sku;

	if (!hw_data->get_sku) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to set default frequency - get_sku not set\n");
		return -EFAULT;
	}

	sku = hw_data->get_sku(hw_data);

	switch (sku) {
	case DEV_SKU_1:
	case DEV_SKU_1_SYM:
		hw_data->clock_frequency = ADF_C4XXX_MAX_AE_FREQ;
		break;
	case DEV_SKU_2:
	case DEV_SKU_2_SYM:
	case DEV_SKU_3:
	case DEV_SKU_3_SYM:
		hw_data->clock_frequency = ADF_C4XXX_MIN_AE_FREQ;
		break;
	default:
		dev_err(&GET_DEV(accel_dev),
			"Failed to set default frequency - unknown SKU\n");
		return -EFAULT;
	}

	return 0;
}

static int measure_clock(struct adf_accel_dev *accel_dev)
{
	u32 frequency;
	int ret = 0;

	ret = adf_dev_measure_clock(accel_dev, &frequency,
				    ADF_C4XXX_MIN_AE_FREQ,
				    ADF_C4XXX_MAX_AE_FREQ);
	if (ret)
		return ret;

	accel_dev->hw_device->clock_frequency = frequency;
	return 0;
}

static u32 get_hw_cap(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;
	u32 legfuses;
	u32 softstrappull2;
	u32 fusectl2;
	u32 capabilities;

	/* Read accelerator capabilities mask */
	pci_read_config_dword(pdev, ADF_DEVICE_LEGFUSE_OFFSET,
			      &legfuses);
	capabilities =
		ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC |
		ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC |
		ICP_ACCEL_CAPABILITIES_CIPHER |
		ICP_ACCEL_CAPABILITIES_AUTHENTICATION |
		ICP_ACCEL_CAPABILITIES_COMPRESSION |
		ICP_ACCEL_CAPABILITIES_ZUC |
		ICP_ACCEL_CAPABILITIES_SM3 |
		ICP_ACCEL_CAPABILITIES_SM4 |
		ICP_ACCEL_CAPABILITIES_EXT_ALGCHAIN |
		ICP_ACCEL_CAPABILITIES_INLINE |
		ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY |
		ICP_ACCEL_CAPABILITIES_SHA3_EXT |
		ICP_ACCEL_CAPABILITIES_SM2 |
		ICP_ACCEL_CAPABILITIES_CHACHA_POLY |
		ICP_ACCEL_CAPABILITIES_AESGCM_SPC |
		ICP_ACCEL_CAPABILITIES_ECEDMONT;
	if (legfuses & ICP_ACCEL_MASK_CIPHER_SLICE) {
		capabilities &= ~ICP_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC;
		capabilities &= ~ICP_ACCEL_CAPABILITIES_CIPHER;
		capabilities &= ~ICP_ACCEL_CAPABILITIES_EXT_ALGCHAIN;
	}
	if (legfuses & ICP_ACCEL_MASK_AUTH_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_AUTHENTICATION;
	if (legfuses & ICP_ACCEL_MASK_PKE_SLICE)
		capabilities &= ~(ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC |
				  ICP_ACCEL_CAPABILITIES_ECEDMONT);
	if (legfuses & ICP_ACCEL_MASK_PKE_SLICE) {
		capabilities &= ~ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC;
		capabilities &= ~ICP_ACCEL_CAPABILITIES_SM2;
	}
	if (legfuses & ICP_ACCEL_MASK_COMPRESS_SLICE) {
		capabilities &= ~ICP_ACCEL_CAPABILITIES_COMPRESSION;
		capabilities &= ~ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY;
	}
	if (legfuses & ICP_ACCEL_MASK_EIA3_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_ZUC;
	if (legfuses & ICP_ACCEL_MASK_SM3_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_SM3;
	if (legfuses & ICP_ACCEL_MASK_SM4_SLICE)
		capabilities &= ~ICP_ACCEL_CAPABILITIES_SM4;

	capabilities &= ~ICP_ACCEL_CAPABILITIES_INLINE;

	/* Read fusectl2 & softstrappull2 registers to check out if
	 * PKE/DC are enabled/disabled
	 */
	pci_read_config_dword(pdev, ADF_C4XXX_FUSECTL2_OFFSET,
			      &fusectl2);
	pci_read_config_dword(pdev, ADF_C4XXX_SOFTSTRAPPULL2_OFFSET,
			      &softstrappull2);
	/* Disable PKE/DC cap if there are no PKE/DC-enabled AUs. */
	if (!(~fusectl2 & ~softstrappull2 & ADF_C4XXX_FUSE_PKE_MASK))
		capabilities &= ~ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC;
	if (!(~fusectl2 & ~softstrappull2 & ADF_C4XXX_FUSE_COMP_MASK))
		capabilities &= ~(ICP_ACCEL_CAPABILITIES_COMPRESSION |
				  ICP_ACCEL_CAPABILITIES_CNV_INTEGRITY);

	return capabilities;
}

static void get_max_num_slices(enum dev_sku_info sku,
			       u32 *max_pke_slices,
			       u32 *max_cipher_slices,
			       u32 *max_dc_slices)
{
	if (!max_pke_slices || !max_cipher_slices || !max_dc_slices)
		return;

	*max_pke_slices = 0;
	*max_cipher_slices = 0;
	*max_dc_slices = 0;

	switch (sku) {
	case DEV_SKU_1:
		*max_pke_slices = ADF_C4XXX_SKU1_MAX_PKE_SLICES_FOR_RL;
		*max_dc_slices = ADF_C4XXX_SKU1_MAX_DC_SLICES_FOR_RL;
		*max_cipher_slices = ADF_C4XXX_SKU1_MAX_CIPHER_SLICES_FOR_RL;
		break;
	case DEV_SKU_2:
		*max_pke_slices = ADF_C4XXX_SKU2_MAX_PKE_SLICES_FOR_RL;
		*max_dc_slices = ADF_C4XXX_SKU2_MAX_DC_SLICES_FOR_RL;
		*max_cipher_slices = ADF_C4XXX_SKU2_MAX_CIPHER_SLICES_FOR_RL;
		break;
	case DEV_SKU_3:
		*max_pke_slices = ADF_C4XXX_SKU3_MAX_PKE_SLICES_FOR_RL;
		*max_dc_slices = ADF_C4XXX_SKU3_MAX_DC_SLICES_FOR_RL;
		*max_cipher_slices = ADF_C4XXX_SKU3_MAX_CIPHER_SLICES_FOR_RL;
		break;
	case DEV_SKU_1_SYM:
		*max_cipher_slices = ADF_C4XXX_SKU1_MAX_CIPHER_SLICES_FOR_RL;
		break;
	case DEV_SKU_2_SYM:
		*max_cipher_slices = ADF_C4XXX_SKU2_MAX_CIPHER_SLICES_FOR_RL;
		break;
	case DEV_SKU_3_SYM:
		*max_cipher_slices = ADF_C4XXX_SKU3_MAX_CIPHER_SLICES_FOR_RL;
		break;
	default:
		*max_pke_slices = 0;
		*max_cipher_slices = 0;
		*max_dc_slices = 0;
	}
}

static int get_sla_units(struct adf_accel_dev *accel_dev, u32 **sla_au)
{
	u8 i = 0;
	enum adf_cfg_fw_image_type fw_image_type = ADF_FW_IMAGE_DEFAULT;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 clock_frequency = GET_HW_DATA(accel_dev)->clock_frequency;
	u32 max_pke_slices = 0, max_cipher_slices = 0, max_dc_slices = 0;
	u32 slices = 0;
	enum dev_sku_info sku;

	sku = hw_data->get_sku(hw_data);

	if (hw_data->get_fw_image_type(accel_dev, &fw_image_type))
		return -EFAULT;

	for (i = 0; i < ARRAY_SIZE(slau_cfg); i++) {
		if (fw_image_type == slau_cfg[i].fw_image_type)
			break;
	}

	if (i < ARRAY_SIZE(slau_cfg)) {
		if (clock_frequency <= ADF_C4XXX_MIN_AE_FREQ)
			*sla_au = slau_cfg[i].slau_supported[sku];
		else if (clock_frequency > ADF_C4XXX_MIN_AE_FREQ &&
			 clock_frequency < ADF_C4XXX_MAX_AE_FREQ)
			*sla_au = slau_cfg[i].slau_supported[sku];
		else
			*sla_au = slau_cfg[i].slau_supported[sku];
	}

	get_max_num_slices(sku, &max_pke_slices, &max_cipher_slices,
			   &max_dc_slices);

	for (i = 0; i < ADF_MAX_SERVICES; i++)
		slau_val[i] = *(*sla_au + i);

	/* Scale down the max SLA units based on number of slices can be used
	 * to service the request when rate limiting is enabled.
	 */
	if (max_pke_slices) {
		slices = hw_data->get_slices_for_svc(accel_dev, ADF_SVC_ASYM);
		slau_val[ADF_SVC_ASYM] =  (slau_val[ADF_SVC_ASYM] * slices)
					/ max_pke_slices;
	}
	if (max_cipher_slices) {
		slices = hw_data->get_slices_for_svc(accel_dev, ADF_SVC_SYM);
		slau_val[ADF_SVC_SYM] =  (slau_val[ADF_SVC_SYM] * slices)
					/ max_cipher_slices;
	}
	if (max_dc_slices) {
		slices = hw_data->get_slices_for_svc(accel_dev, ADF_SVC_DC);
		slau_val[ADF_SVC_DC] =  (slau_val[ADF_SVC_DC] * slices)
					/ max_dc_slices;
	}

	for (i = 0; i < ADF_MAX_SERVICES; i++) {
		/* Round SLA to nearest K */
		slau_val[i] =
		roundup(slau_val[i], AU_ROUNDOFF);
	}

	*sla_au = slau_val;

	return 0;
}

static void adf_set_asym_rings_mask(struct adf_accel_dev *accel_dev)
{
	int service;
	u16 ena_srv_mask;
	u16 service_type;
	u16 asym_mask = 0;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;

	ena_srv_mask = hw_data->ring_to_svc_map;

	/* parse each service */
	for (service = 0;
	     service < ADF_CFG_MAX_SERVICES;
	     service++) {
		service_type =
			GET_SRV_TYPE(ena_srv_mask, service);
		switch (service_type) {
		case CRYPTO:
		case ASYM:
			SET_ASYM_MASK_C4XXX(asym_mask, service);
			if (service_type == CRYPTO)
				service++;
			break;
		}
	}

	hw_data->asym_rings_mask = asym_mask;
}

static void adf_configure_iov_threads_c4xxx(struct adf_accel_dev *accel_dev,
					    bool enable)
{
	void __iomem *csr_base;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 num_aes = hw_data->get_num_aes(hw_data);
	u32 reg = 0x0;
	u32 i;

	csr_base = (&GET_BARS(accel_dev)[ADF_C4XXX_PMISC_BAR])->virt_addr;

	/* Set/Unset Valid bits in AE Thread to PCIe Function Mapping */
	for (i = 0; i < ADF_C4XXX_AE2FUNC_REG_PER_AE * num_aes; i++) {
		reg = ADF_CSR_RD((u8 *)csr_base + ADF_C4XXX_AE2FUNC_MAP_OFFSET,
				 i * ADF_C4XXX_AE2FUNC_MAP_REG_SIZE);
		if (enable)
			reg |= ADF_C4XXX_AE2FUNC_MAP_VALID;
		else
			reg &= ~ADF_C4XXX_AE2FUNC_MAP_VALID;
		ADF_CSR_WR((u8 *)csr_base + ADF_C4XXX_AE2FUNC_MAP_OFFSET,
			   i * ADF_C4XXX_AE2FUNC_MAP_REG_SIZE,
			   reg);
	}
}

static u32 adf_get_dc_ae_mask_c4xxx(struct adf_accel_dev *accel_dev)
{
	return accel_dev->au_info->dc_ae_msk;
}

void adf_init_hw_data_c4xxx(struct adf_hw_device_data *hw_data)
{
	hw_data->dev_class = &c4xxx_class;
	hw_data->instance_id = c4xxx_class.instances++;
	hw_data->num_banks = ADF_GEN3_ETR_MAX_BANKS;
	hw_data->num_rings_per_bank = ADF_C4XXX_NUM_RINGS_PER_BANK;
	hw_data->num_accel = ADF_C4XXX_MAX_ACCELERATORS;
	hw_data->num_engines = ADF_C4XXX_MAX_ACCELENGINES;
	hw_data->num_logical_accel = 1;
	hw_data->tx_rx_gap = ADF_C4XXX_RX_RINGS_OFFSET;
	hw_data->tx_rings_mask = ADF_C4XXX_TX_RINGS_MASK;
	hw_data->alloc_irq = adf_isr_resource_alloc;
	hw_data->free_irq = adf_isr_resource_free;
	hw_data->enable_error_correction = adf_enable_error_correction;
	hw_data->init_ras = adf_init_ras_c4xxx;
	hw_data->exit_ras = adf_exit_ras_c4xxx;
	hw_data->disable_error_correction = adf_disable_error_correction;
	hw_data->ras_interrupts = adf_ras_interrupts_c4xxx;
	hw_data->get_accel_mask = get_accel_mask;
	hw_data->get_ae_mask = get_ae_mask;
	hw_data->get_num_accels = get_num_accels;
	hw_data->get_num_aes = get_num_aes;
	hw_data->get_sram_bar_id = get_sram_bar_id;
	hw_data->get_etr_bar_id = get_etr_bar_id;
	hw_data->get_misc_bar_id = get_misc_bar_id;
	hw_data->get_arb_info = get_arb_info;
	hw_data->get_admin_info = get_admin_info;
	hw_data->get_clock_speed = get_clock_speed;
	hw_data->get_sku = get_sku;
	hw_data->fw_name = ADF_C4XXX_FW;
	hw_data->fw_mmp_name = ADF_C4XXX_MMP;
	hw_data->init_admin_comms = adf_init_admin_comms;
	hw_data->exit_admin_comms = adf_exit_admin_comms;
	hw_data->configure_iov_threads = adf_configure_iov_threads_c4xxx;
	hw_data->disable_iov = adf_disable_sriov;
	hw_data->send_admin_init = adf_send_admin_init;
	hw_data->init_arb = adf_init_arb_c4xxx;
	hw_data->exit_arb = adf_exit_arb_c4xxx;
	hw_data->disable_arb = adf_disable_arb;
	hw_data->enable_ints = adf_enable_ints;
	hw_data->set_ssm_wdtimer = adf_set_ssm_wdtimer_c4xxx;
	hw_data->reset_device = adf_reset_flr;
	hw_data->init_accel_units = adf_init_accel_units_c4xxx;
	hw_data->exit_accel_units = adf_exit_accel_units_c4xxx;
	hw_data->ring_to_svc_map = ADF_DEFAULT_RING_TO_SRV_MAP;
	hw_data->enable_vf2pf_comms = adf_pf_enable_vf2pf_comms;
	hw_data->disable_vf2pf_comms = adf_pf_disable_vf2pf_comms;
	hw_data->min_iov_compat_ver = ADF_PFVF_COMPATIBILITY_VERSION;
	hw_data->get_heartbeat_status = get_heartbeat_status_c4xxx;
	hw_data->get_ae_clock = get_ae_clock;
	hw_data->set_default_frequency = adf_set_default_sku_freq_c4xxx;
	hw_data->clock_frequency = ADF_C4XXX_AE_FREQ;
	hw_data->measure_clock = measure_clock;
	hw_data->get_pf2vf_offset = get_pf2vf_offset;
	hw_data->get_vintmsk_offset = get_vintmsk_offset;
#if defined(CONFIG_PCI_IOV)
	hw_data->process_and_get_vf2pf_int = process_and_get_vf2pf_int;
	hw_data->enable_vf2pf_interrupts = enable_vf2pf_interrupts;
	hw_data->disable_vf2pf_interrupts = disable_vf2pf_interrupts;
	hw_data->get_arbitrary_numvfs = get_arbitrary_numvfs;
#endif
	hw_data->extended_dc_capabilities = 0;
	hw_data->get_accel_cap = get_hw_cap;
	hw_data->configure_accel_units = adf_configure_accel_units_c4xxx;
	hw_data->pre_reset = adf_dev_pre_reset_c4xxx;
	hw_data->post_reset = adf_dev_post_reset_c4xxx;
	hw_data->reset_hw_units = adf_reset_hw_units_c4xxx;
	hw_data->notify_and_wait_ethernet = adf_notify_and_wait_ethernet;
	hw_data->get_eth_doorbell_msg = get_eth_doorbell_msg_c4xxx;
	hw_data->fw_load = adf_ae_fw_load_c4xxx;
	hw_data->get_ring_to_svc_map = adf_get_services_enabled;
	hw_data->config_device = adf_config_device_gen3;
	hw_data->set_asym_rings_mask = adf_set_asym_rings_mask;
	hw_data->get_fw_image_type = get_fw_image_type_c4xxx;
	hw_data->get_sla_units = get_sla_units;
	hw_data->get_slices_for_svc = adf_get_slices_for_svc_c4xxx;
	hw_data->get_fw_image_type = get_fw_image_type_c4xxx;
	hw_data->get_dc_ae_mask = adf_get_dc_ae_mask_c4xxx;
	hw_data->get_num_vfs = get_max_numvfs;
}

void adf_clean_hw_data_c4xxx(struct adf_hw_device_data *hw_data)
{
	hw_data->dev_class->instances--;
}
