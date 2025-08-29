/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2016 - 2021 Intel Corporation */

#ifndef ADF_C4XXX_HW_DATA_H_
#define ADF_C4XXX_HW_DATA_H_

#include <adf_accel_devices.h>

/* PCIe configuration space */
#define ADF_C4XXX_SRAM_BAR 0
#define ADF_C4XXX_PMISC_BAR 1
#define ADF_C4XXX_ETR_BAR 2
#define ADF_C4XXX_RX_RINGS_OFFSET 4
#define ADF_C4XXX_TX_RINGS_MASK 0xF

#define ADF_C4XXX_MAX_ACCELERATORS 12
#define ADF_C4XXX_MAX_ACCELUNITS 6
#define ADF_C4XXX_MAX_ACCELENGINES 32

/* Soft straps offsets */
#define ADF_C4XXX_SOFTSTRAPPULL0_OFFSET (0x344)
#define ADF_C4XXX_SOFTSTRAPPULL1_OFFSET (0x348)
#define ADF_C4XXX_SOFTSTRAPPULL2_OFFSET (0x34C)

/* Physical function fuses offsets */
#define ADF_C4XXX_FUSECTL0_OFFSET       (0x350)
#define ADF_C4XXX_FUSECTL1_OFFSET       (0x354)
#define ADF_C4XXX_FUSECTL2_OFFSET       (0x358)

#define ADF_C4XXX_FUSE_PKE_MASK  (0xFFF000)
#define ADF_C4XXX_FUSE_COMP_MASK (0x000FFF)

#define ADF_C4XXX_ACCELERATORS_MASK (0xFFF)
#define ADF_C4XXX_ACCELENGINES_MASK (0xFFFFFFFF)
#define ADF_C4XXX_CIPHER_CRC_ACCELENGINES_MASK (0xF6DBF6DB)

#define ADF_C4XXX_SMIAPF0_MASK_OFFSET (0x60000 + 0x20)
#define ADF_C4XXX_SMIAPF1_MASK_OFFSET (0x60000 + 0x24)
#define ADF_C4XXX_SMIAPF2_MASK_OFFSET (0x60000 + 0x28)
#define ADF_C4XXX_SMIAPF3_MASK_OFFSET (0x60000 + 0x2C)
#define ADF_C4XXX_SMIAPF4_MASK_OFFSET (0x60000 + 0x30)
#define ADF_C4XXX_SMIA0_MASK 0xFFFFFFFF
#define ADF_C4XXX_SMIA1_MASK 0xFFFFFFFF
#define ADF_C4XXX_SMIA2_MASK 0xFFFFFFFF
#define ADF_C4XXX_SMIA3_MASK 0xFFFFFFFF
#define ADF_C4XXX_SMIA4_MASK 0x1

/* Bank and ring configuration */
#define ADF_C4XXX_NUM_RINGS_PER_BANK 8

/* Error detection and correction */
#define ADF_C4XXX_AE_CTX_ENABLES(i) (0x40818 + ((i) * 0x1000))
#define ADF_C4XXX_AE_MISC_CONTROL(i) (0x40960 + ((i) * 0x1000))
#define ADF_C4XXX_ENABLE_AE_ECC_ERR BIT(28)
#define ADF_C4XXX_ENABLE_AE_ECC_PARITY_CORR (BIT(24) | BIT(12))
#define ADF_C4XXX_UERRSSMSH(i) (0x18 + ((i) * 0x4000))
#define ADF_C4XXX_CERRSSMSH(i) (0x10 + ((i) * 0x4000))
#define ADF_C4XXX_CERRSSMSH_INTS_CLEAR_MASK (~BIT(0))
#define ADF_C4XXX_ERRSSMSH_EN BIT(3)
#define ADF_C4XXX_PF2VF_OFFSET(i)	(0x62400 + ((i) * 0x04))
#define ADF_C4XXX_VINTMSK_OFFSET(i)	(0x62200 + ((i) * 0x04))

/* Error source registers */
#define ADF_C4XXX_ERRSOU4 (0x60000 + 0x50)
#define ADF_C4XXX_ERRSOU5 (0x60000 + 0x54)
#define ADF_C4XXX_ERRSOU6 (0x60000 + 0x58)
#define ADF_C4XXX_ERRSOU7 (0x60000 + 0x5C)
#define ADF_C4XXX_ERRSOU8 (0x60000 + 0x60)
#define ADF_C4XXX_ERRSOU9 (0x60000 + 0x64)
#define ADF_C4XXX_ERRSOU10 (0x60000 + 0x68)
#define ADF_C4XXX_ERRSOU11 (0x60000 + 0x6C)

/* Error source mask registers */
#define ADF_C4XXX_ERRMSK4 (0x60000 + 0xD0)
/* Slice power down register */
#define ADF_C4XXX_SLICEPWRDOWN(i)   (((i) * 0x4000) + 0x2C)

/* Enabling PKE0 to PKE4. */
#define ADF_C4XXX_MMP_PWR_UP_MSK \
	(BIT(20) | BIT(19) | BIT(18) | BIT(17) | BIT(16))

/* Error registers for MMP0-MMP4. */
#define ADF_C4XXX_MAX_MMP (5)

#define ADF_C4XXX_MMP_BASE(i)       ((i) * 0x1000 % 0x3800)
#define ADF_C4XXX_CERRSSMMMP(i, n)  ((i) * 0x4000 + \
		     ADF_C4XXX_MMP_BASE(n) + 0x380)
#define ADF_C4XXX_UERRSSMMMP(i, n)  ((i) * 0x4000 + \
		     ADF_C4XXX_MMP_BASE(n) + 0x388)
/* Bit<3> enables logging of MMP uncorrectable errors */
#define ADF_C4XXX_UERRSSMMMP_EN BIT(3)

/* Bit<3> enables logging of MMP correctable errors */
#define ADF_C4XXX_CERRSSMMMP_EN BIT(3)

#define ADF_C4XXX_ERRSOU_VF2PF_OFFSET(i) (ADF_C4XXX_ERRSOU4 + ((i) * 0x04))
#define ADF_C4XXX_ERRMSK_VF2PF_OFFSET(i) (ADF_C4XXX_ERRMSK4 + ((i) * 0x04))

/* Error source mask registers */
#define ADF_C4XXX_ERRMSK4 (0x60000 + 0xD0)
#define ADF_C4XXX_ERRMSK5 (0x60000 + 0xD4)
#define ADF_C4XXX_ERRMSK6 (0x60000 + 0xD8)
#define ADF_C4XXX_ERRMSK7 (0x60000 + 0xDC)
#define ADF_C4XXX_ERRMSK8 (0x60000 + 0xE0)
#define ADF_C4XXX_ERRMSK9 (0x60000 + 0xE4)
#define ADF_C4XXX_ERRMSK10 (0x60000 + 0xE8)
#define ADF_C4XXX_ERRMSK11 (0x60000 + 0xEC)

/* Enable VF2PF interrupt in ERRMSK4 to ERRMSK7 */
#define ADF_C4XXX_VF2PF0_31 0x0
#define ADF_C4XXX_VF2PF32_63 0x0
#define ADF_C4XXX_VF2PF64_95 0x0
#define ADF_C4XXX_VF2PF96_127 0x0

/* AEx Correctable Error Mask in ERRMSK8 */
#define ADF_C4XXX_ERRMSK8_COERR 0x0
#define ADF_C4XXX_ERRSOU8_MECORR_MASK           BIT(0)
#define ADF_C4XXX_HI_ME_COR_ERRLOG_ENABLE       (0x61600)
#define ADF_C4XXX_HI_ME_COR_ERRLOG_ENABLE_MASK  (0xFFFFFFFF)

/* Group of registers related to ERRSOU9 handling
 *
 * AEx Uncorrectable Error Mask in ERRMSK9
 * CPP Command Parity Errors Mask in ERRMSK9
 * RI Memory Parity Errors Mask in ERRMSK9
 * TI Memory Parity Errors Mask in ERRMSK9
 */
#define ADF_C4XXX_ERRMSK9_IRQ_MASK              0x0
#define ADF_C4XXX_HI_ME_UNCERR_LOG_ENABLE       (0x61608)
#define ADF_C4XXX_HI_ME_UNCERR_LOG_ENABLE_MASK  (0xFFFFFFFF)

/* HI CPP Agents Command parity Error Log
 * CSR name: hicppagentcmdparerrlog
 */
#define ADF_C4XXX_HI_CPP_AGENT_CMD_PAR_ERR_LOG_ENABLE        (0x61604)
#define ADF_C4XXX_HI_CPP_AGENT_CMD_PAR_ERR_LOG_ENABLE_MASK   (0xFFFFFFFF)

/* RI Memory Parity Error Status Register
 * CSR name: rimem_parerr_sts
 */
#define ADF_C4XXX_RI_MEM_PAR_ERR_EN0            (0x61614)
#define ADF_C4XXX_RI_MEM_PAR_ERR_EN0_MASK       (0x7FFFFF)

/* TI Memory Parity Error Status Register
 * CSR name: ti_mem_par_err_sts0, ti_mem_par_err_sts1
 */
#define ADF_C4XXX_TI_MEM_PAR_ERR_EN0            (0x68608)
#define ADF_C4XXX_TI_MEM_PAR_ERR_EN0_MASK       (0xFFFFFFFF)
#define ADF_C4XXX_TI_MEM_PAR_ERR_EN1            (0x68614)
#define ADF_C4XXX_TI_MEM_PAR_ERR_EN1_MASK       (0x7FFFF)

/* Enable SSM<11:0> in ERRMSK10 */
#define ADF_C4XXX_ERRMSK10_SSM_ERR 0x0

/* Return address of SSMSOFTERRORPARITY_MASK register for given accel */
#define ADF_C4XXX_SSMSOFTERRORPARITY_MASK_VAL (0x00)
#define ADF_C4XXX_SSMSOFTERRORPARITY_MASK (0x1008)
#define ADF_C4XXX_GET_SSMSOFTERRORPARITY_MASK_OFFSET(accel) \
	(ADF_C4XXX_SSMSOFTERRORPARITY_MASK + ((accel) * 0x4000))

/* Accelerator Interrupt Mask (SSM)
 * CSR name: intmaskssm[0..11]
 * Returns address of INTMASKSSM register for a given accel.
 * This register is used to unmask SSM interrupts to host
 * reported by ERRSOU10.
 */
#define ADF_C4XXX_GET_INTMASKSSM_OFFSET(accel) ((accel) * 0x4000)

/* Base address of SPP parity error mask register
 * CSR name: sppparerrmsk[0..11]
 */
#define ADF_C4XXX_SPPPARERRMSK_OFFSET (0x2028)

/* Returns address of SPPPARERRMSK register for a given accel.
 * This register is used to unmask SPP parity errors interrupts to host
 * reported by ERRSOU10.
 */
#define ADF_C4XXX_GET_SPPPARERRMSK_OFFSET(accel)			       \
	(ADF_C4XXX_SPPPARERRMSK_OFFSET + ((accel) * 0x4000))

/* ethernet doorbell in ERRMSK11
 * timisc in ERRMSK11
 * rimisc in ERRMSK11
 * ppmiscerr in ERRMSK11
 * cerr in ERRMSK11
 * uerr in ERRMSK11
 * ici in ERRMSK11
 * ice in ERRMSK11
 */
#define ADF_C4XXX_ERRMSK11_ERR 0x0
/*
 * BIT(7) disables ICI interrupt
 * BIT(8) disables ICE interrupt
 */
#define ADF_C4XXX_ERRMSK11_ERR_DISABLE_ICI_ICE_INTR (BIT(7) | BIT(8))

/* RI CPP interface control register. */
#define ADF_C4XXX_RICPPINTCTL (0x61000 + 0x004)
/*
 * BIT(3) enables error parity checking on CPP.
 * BIT(2) enables error detection and reporting on the RI Parity Error.
 * BIT(1) enables error detection and reporting on the RI CPP Pull interface.
 * BIT(0) enables error detection and reporting on the RI CPP Push interface.
 */
#define ADF_C4XXX_RICPP_EN (BIT(3) | BIT(2) | BIT(1) | BIT(0))

/* TI CPP interface control register. */
#define ADF_C4XXX_TICPPINTCTL (0x68000 + 0x538)
/*
 * BIT(4) enables 'stop and scream' feature for TI RF.
 * BIT(3) enables CPP command and pull data parity checking.
 * BIT(2) enables data parity error detection and reporting on the TI CPP
 *        Pull interface.
 * BIT(1) enables error detection and reporting on the TI CPP Pull interface.
 * BIT(0) enables error detection and reporting on the TI CPP Push interface.
 */
#define ADF_C4XXX_TICPP_EN (BIT(4) | BIT(3) | BIT(2) | BIT(1) | BIT(0))

/* CPP error control and logging register */
#define ADF_C4XXX_CPP_CFC_ERR_CTRL (0x70000 + 0xC00)

/*
 * BIT(1) enables generation of irqs to the PCIe endpoint
 *        for the errors specified in CPP_CFC_ERR_STATUS
 * BIT(0) enables detecting and logging of push/pull data errors.
 */
#define ADF_C4XXX_CPP_CFC_UE (BIT(1) | BIT(0))

#define ADF_C4XXX_DEF_ASYM_MASK 0x1

/* Arbiter configuration */
#define ADF_C4XXX_ARB_OFFSET			0x80000
#define ADF_C4XXX_ARB_WQCFG_OFFSET		0x200
#define ADF_C4XXX_ARB_DBG_RST_ARB_OFFSET	0x718

/* Admin Interface Reg Offset */
#define ADF_C4XXX_ADMINMSGUR_OFFSET (0x60000 + 0x8000 + 0x400 + 0x174)
#define ADF_C4XXX_ADMINMSGLR_OFFSET (0x60000 + 0x8000 + 0x400 + 0x178)
#define ADF_C4XXX_MAILBOX_BASE_OFFSET		0x40970

/* AE to function mapping */
#define ADF_C4XXX_AE2FUNC_REG_PER_AE        8
#define ADF_C4XXX_AE2FUNC_MAP_OFFSET        0x68800
#define ADF_C4XXX_AE2FUNC_MAP_REG_SIZE      4
#define ADF_C4XXX_AE2FUNC_MAP_VALID         BIT(8)

/* Default accel unit configuration */
#define ADF_C4XXX_NUM_CY_AU {[DEV_SKU_1] = 4,\
			     [DEV_SKU_1_SYM] = 6,\
			     [DEV_SKU_2] = 3,\
			     [DEV_SKU_2_SYM] = 4,\
			     [DEV_SKU_3] = 1,\
			     [DEV_SKU_3_SYM] = 2,\
			     [DEV_SKU_UNKNOWN] = 0}
#define ADF_C4XXX_NUM_DC_AU {[DEV_SKU_1] = 2,\
			     [DEV_SKU_1_SYM] = 0,\
			     [DEV_SKU_2] = 1,\
			     [DEV_SKU_2_SYM] = 0,\
			     [DEV_SKU_3] = 1,\
			     [DEV_SKU_3_SYM] = 0,\
			     [DEV_SKU_UNKNOWN] = 0}

/* SKU configurations */
#define ADF_C4XXX_HIGH_SKU_AES	32
#define ADF_C4XXX_MED_SKU_AES	24
#define ADF_C4XXX_LOW_SKU_AES	12

/* Firmware Binary */
#define ADF_C4XXX_FW "qat_c4xxx.bin"
#define ADF_C4XXX_MMP "qat_c4xxx_mmp.bin"

#define ADF_C4XXX_AE_FREQ     (800 * 1000000)
#define ADF_C4XXX_MIN_AE_FREQ (571 * 1000000)
#define ADF_C4XXX_MAX_AE_FREQ (800 * 1000000)

#define SET_ASYM_MASK_C4XXX(asym_mask, srv) \
	((asym_mask) |= 1 << (srv))

void adf_init_hw_data_c4xxx(struct adf_hw_device_data *hw_data);
void adf_clean_hw_data_c4xxx(struct adf_hw_device_data *hw_data);
int adf_init_arb_c4xxx(struct adf_accel_dev *accel_dev);
void adf_exit_arb_c4xxx(struct adf_accel_dev *accel_dev);
int adf_ae_fw_load_c4xxx(struct adf_accel_dev *accel_dev);
int get_heartbeat_status_c4xxx(struct adf_accel_dev *accel_dev);
#endif
