/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2017 - 2018, 2020 - 2021 Intel Corporation */

#ifndef ADF_RAS_H_
#define ADF_RAS_H_

#include <linux/types.h>

#define ADF_RAS_CORR            0
#define ADF_RAS_UNCORR_NONFATAL 1
#define ADF_RAS_UNCORR_FATAL    2

#define ADF_RAS_ERRORS	3

#define ADF_C4XXX_UERRSSMSH(i) (0x18 + ((i) * 0x4000))
#define ADF_C4XXX_UERRSSMSH_INTS_CLEAR_MASK (~BIT(0) ^ BIT(16))
#define ADF_C4XXX_CERRSSMSH(i) (0x10 + ((i) * 0x4000))
#define ADF_C4XXX_CERRSSMSH_INTS_CLEAR_MASK (~BIT(0))

/* AEx Correctable Error Mask in ERRMSK8 */
#define ADF_C4XXX_ERRMSK8_COERR 0x0
#define ADF_C4XXX_ERRSOU8_MECORR_MASK           BIT(0)
#define ADF_C4XXX_HI_ME_COR_ERRLOG              (0x60104)
#define ADF_C4XXX_HI_ME_COR_ERRLOG_ENABLE       (0x61600)
#define ADF_C4XXX_HI_ME_COR_ERRLOG_ENABLE_MASK  (0xFFFFFFFF)
#define ADF_C4XXX_HI_ME_COR_ERRLOG_SIZE_IN_BITS (32)

/* Group of registers related to ERRSOU9 handling
 *
 * AEx Uncorrectable Error Mask in ERRMSK9
 * CPP Command Parity Errors Mask in ERRMSK9
 * RI Memory Parity Errors Mask in ERRMSK9
 * TI Memory Parity Errors Mask in ERRMSK9
 */
#define ADF_C4XXX_ERRMSK9_IRQ_MASK              0x0
#define ADF_C4XXX_ME_UNCORR_ERROR               BIT(0)
#define ADF_C4XXX_CPP_CMD_PAR_ERR               BIT(1)
#define ADF_C4XXX_RI_MEM_PAR_ERR                BIT(2)
#define ADF_C4XXX_TI_MEM_PAR_ERR                BIT(3)

#define ADF_C4XXX_ERRSOU9_ERROR_MASK	(ADF_C4XXX_ME_UNCORR_ERROR |	       \
					 ADF_C4XXX_CPP_CMD_PAR_ERR |	       \
					 ADF_C4XXX_RI_MEM_PAR_ERR |	       \
					 ADF_C4XXX_TI_MEM_PAR_ERR)

#define ADF_C4XXX_HI_ME_UNCERR_LOG              (0x60100)
#define ADF_C4XXX_HI_ME_UNCERR_LOG_ENABLE       (0x61608)
#define ADF_C4XXX_HI_ME_UNCERR_LOG_ENABLE_MASK  (0xFFFFFFFF)
#define ADF_C4XXX_HI_ME_UNCOR_ERRLOG_BITS       (32)

/* HI CPP Agents Command parity Error Log
 * CSR name: hicppagentcmdparerrlog
 */
#define ADF_C4XXX_HI_CPP_AGENT_CMD_PAR_ERR_LOG  (0x6010C)
#define ADF_C4XXX_HI_CPP_AGENT_CMD_PAR_ERR_LOG_ENABLE        (0x61604)
#define ADF_C4XXX_HI_CPP_AGENT_CMD_PAR_ERR_LOG_ENABLE_MASK   (0xFFFFFFFF)
#define ADF_C4XXX_TI_CMD_PAR_ERR                BIT(0)
#define ADF_C4XXX_RI_CMD_PAR_ERR                BIT(1)
#define ADF_C4XXX_ICI_CMD_PAR_ERR               BIT(2)
#define ADF_C4XXX_ICE_CMD_PAR_ERR               BIT(3)
#define ADF_C4XXX_ARAM_CMD_PAR_ERR              BIT(4)
#define ADF_C4XXX_CFC_CMD_PAR_ERR               BIT(5)
#define ADF_C4XXX_SSM_CMD_PAR_ERR(value)        (((u32)(value) >> 6) & 0xFFF)

/* RI Memory Parity Error Status Register
 * CSR name: rimem_parerr_sts
 */
#define ADF_C4XXX_RI_MEM_PAR_ERR_STS            (0x61610)
#define ADF_C4XXX_RI_MEM_PAR_ERR_EN0            (0x61614)
#define ADF_C4XXX_RI_MEM_PAR_ERR_FERR           (0x61618)
#define ADF_C4XXX_RI_MEM_PAR_ERR_EN0_MASK       (0x7FFFFF)
#define ADF_C4XXX_RI_MEM_MSIX_TBL_INT_MASK	(BIT(22))
#define ADF_C4XXX_RI_MEM_PAR_ERR_STS_MASK       \
	(ADF_C4XXX_RI_MEM_PAR_ERR_EN0_MASK ^ ADF_C4XXX_RI_MEM_MSIX_TBL_INT_MASK)

/* TI Memory Parity Error Status Register
 * CSR name: ti_mem_par_err_sts0, ti_mem_par_err_sts1
 */
#define ADF_C4XXX_TI_MEM_PAR_ERR_STS0           (0x68604)
#define ADF_C4XXX_TI_MEM_PAR_ERR_EN0            (0x68608)
#define ADF_C4XXX_TI_MEM_PAR_ERR_EN0_MASK       (0xFFFFFFFF)
#define ADF_C4XXX_TI_MEM_PAR_ERR_STS1           (0x68610)
#define ADF_C4XXX_TI_MEM_PAR_ERR_EN1            (0x68614)
#define ADF_C4XXX_TI_MEM_PAR_ERR_EN1_MASK       (0x7FFFF)
#define ADF_C4XXX_TI_MEM_PAR_ERR_STS1_MASK      \
	(ADF_C4XXX_TI_MEM_PAR_ERR_EN1_MASK)
#define ADF_C4XXX_TI_MEM_PAR_ERR_FIRST_ERROR    (0x68618)

/* RAS error mask for SSM<11:0> error sources */
#define ADF_C4XXX_ERRSOU10_RAS_MASK 0x1FFF

/* Return address of SSMSOFTERRORPARITY_MASK register for given accel */
#define ADF_C4XXX_SSMSOFTERRORPARITY_MASK_VAL (0x00)
#define ADF_C4XXX_SSMSOFTERRORPARITY_MASK (0x1008)
#define ADF_C4XXX_GET_SSMSOFTERRORPARITY_MASK_OFFSET(accel) \
	(ADF_C4XXX_SSMSOFTERRORPARITY_MASK + ((accel) * 0x4000))
#define ADF_C4XXX_IASTATSSM_UERRSSMSH_MASK	BIT(0)
#define ADF_C4XXX_IASTATSSM_CERRSSMSH_MASK	BIT(1)
#define ADF_C4XXX_IASTATSSM_UERRSSMMMP0_MASK	BIT(2)
#define ADF_C4XXX_IASTATSSM_CERRSSMMMP0_MASK	BIT(3)
#define ADF_C4XXX_IASTATSSM_UERRSSMMMP1_MASK	BIT(4)
#define ADF_C4XXX_IASTATSSM_CERRSSMMMP1_MASK	BIT(5)
#define ADF_C4XXX_IASTATSSM_UERRSSMMMP2_MASK	BIT(6)
#define ADF_C4XXX_IASTATSSM_CERRSSMMMP2_MASK	BIT(7)
#define ADF_C4XXX_IASTATSSM_UERRSSMMMP3_MASK	BIT(8)
#define ADF_C4XXX_IASTATSSM_CERRSSMMMP3_MASK	BIT(9)
#define ADF_C4XXX_IASTATSSM_UERRSSMMMP4_MASK	BIT(10)
#define ADF_C4XXX_IASTATSSM_CERRSSMMMP4_MASK	BIT(11)
#define ADF_C4XXX_IASTATSSM_PPERR_MASK		BIT(12)
#define ADF_C4XXX_IASTATSSM_SPPPAR_ERR_MASK	BIT(14)
#define ADF_C4XXX_IASTATSSM_CPPPAR_ERR_MASK	BIT(15)
#define ADF_C4XXX_IASTATSSM_RFPAR_ERR_MASK	BIT(16)

#define ADF_C4XXX_IAINTSTATSSM(i)	((i) * 0x4000 + 0x206C)
#define ADF_C4XXX_IASTATSSM_MASK	0x1DFFF
#define ADF_C4XXX_IASTATSSM_CLR_MASK	0xFFFE2000
#define ADF_C4XXX_IASTATSSM_BITS	17
#define ADF_C4XXX_IASTATSSM_SLICE_HANG_ERR_BIT	13
#define ADF_C4XXX_IASTATSSM_SPP_PAR_ERR_BIT	14
#define ADF_C4XXX_IASTATSSM_CPP_PAR_ERR_BIT	15

/* Base addresses of SliceHang status registers */
#define ADF_C4XXX_SLICEHANGSTATUS (0x4C)
#define ADF_C4XXX_IASLICEHANGSTATUS (0x50)

/* Return address of IASLICEHANGSTATUS register for a given accelerator */
#define ADF_C4XXX_IASLICEHANGSTATUS_OFFSET(accel) \
		(ADF_C4XXX_IASLICEHANGSTATUS + ((accel) * 0x4000))

/* SliceHang clear mask for SLICEHANGSTATUS register */
#define ADF_C4XXX_CLEAR_FW_SLICE_HANG 0x1F3377

/* Return address of SLICEHANGSTATUS register for a given accelerator */
#define ADF_C4XXX_SLICEHANGSTATUS_OFFSET(accel) \
		(ADF_C4XXX_SLICEHANGSTATUS + ((accel) * 0x4000))

/* Return interrupt accelerator source mask */
#define ADF_C4XXX_IRQ_SRC_MASK(accel) (1U << (accel))

/* RAS enabling related registers */
#define ADF_C4XXX_SSMFEATREN (0x2010)
#define ADF_C4XXX_SSMSOFTERRORPARITY_MASK (0x1008)
#define ADF_C4XXX_SSMSOFTERRORPARITY(i) ((i) * 0x4000 + 0x1000)
#define ADF_C4XXX_SSMCPPERR(i) ((i) * 0x4000 + 0x2030)

/* RAS mask for errors reported by ERRSOU11 */
#define ADF_C4XXX_ERRSOU11_ERROR_MASK (0x1FF)
#define ADF_C4XXX_TI_MISC BIT(0)
#define ADF_C4XXX_RI_PUSH_PULL_PAR_ERR BIT(1)
#define ADF_C4XXX_TI_PUSH_PULL_PAR_ERR BIT(2)
#define ADF_C4XXX_ARAM_CORR_ERR BIT(3)
#define ADF_C4XXX_ARAM_UNCORR_ERR BIT(4)
#define ADF_C4XXX_TI_PULL_PAR_ERR BIT(5)
#define ADF_C4XXX_RI_PUSH_PAR_ERR BIT(6)

/* TI Misc error status */
#define ADF_C4XXX_TI_MISC_STS (0x6854C)
#define ADF_C4XXX_TI_MISC_ERR_MASK (BIT(0))
#define ADF_C4XXX_GET_TI_MISC_ERR_TYPE(status) ((status) >> 1 & 0x3)
#define ADF_C4XXX_TI_BME_RESP_ORDER_ERR (0x1)
#define ADF_C4XXX_TI_RESP_ORDER_ERR (0x2)

/* RI CPP interface status register */
#define ADF_C4XXX_RI_CPP_INT_STS (0x61118)
#define ADF_C4XXX_RI_CPP_INT_STS_PUSH_ERR BIT(0)
#define ADF_C4XXX_RI_CPP_INT_STS_PULL_ERR BIT(1)
#define ADF_C4XXX_RI_CPP_INT_STS_PUSH_DATA_PAR_ERR BIT(2)
#define ADF_C4XXX_GET_CPP_BUS_FROM_STS(status) ((status) >> 31 & 0x1)

/* RI CPP interface control register. */
#define ADF_C4XXX_RICPPINTCTL (0x61000 + 0x004)
/*
 * BIT(3) enables error parity checking on CPP.
 * BIT(2) enables error detection and reporting on the RI Parity Error.
 * BIT(1) enables error detection and reporting on the RI CPP Pull interface.
 * BIT(0) enables error detection and reporting on the RI CPP Push interface.
 */
#define ADF_C4XXX_RICPP_EN (BIT(3) | BIT(2) | BIT(1) | BIT(0))

/* TI CPP interface status register */
#define ADF_C4XXX_TI_CPP_INT_STS (0x6853C)
#define ADF_C4XXX_TI_CPP_INT_STS_PUSH_ERR BIT(0)
#define ADF_C4XXX_TI_CPP_INT_STS_PULL_ERR BIT(1)
#define ADF_C4XXX_TI_CPP_INT_STS_PUSH_DATA_PAR_ERR BIT(2)

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

/* ARAM error interrupt enable registers */
#define ADF_C4XXX_ARAMCERR (0x101700)
#define ADF_C4XXX_ARAMUERR (0x101704)
#define ADF_C4XXX_CPPMEMTGTERR (0x101710)
#define ADF_C4XXX_ARAM_CORR_ERR_MASK (BIT(0))
#define ADF_C4XXX_ARAM_UNCORR_ERR_MASK (BIT(0))
#define ADF_C4XXX_CLEAR_CSR_BIT(csr, bit_num) ((csr) &= ~(BIT(bit_num)))

/* ARAM correctable errors defined in ARAMCERR
 * Bit<3> Enable fixing and logging correctable errors by hardware.
 * Bit<26> Enable interrupt to host for ARAM correctable errors.
 */
#define ADF_C4XXX_ARAM_CERR (BIT(3) | BIT(26))

/* ARAM correctable errors defined in ARAMUERR
 * Bit<3> Enable detection and logging of ARAM uncorrectable errors.
 * Bit<19> Enable interrupt to host for ARAM uncorrectable errors.
 */
#define ADF_C4XXX_ARAM_UERR (BIT(3) | BIT(19))

/* Misc memory target error registers in CPPMEMTGTERR
 * Bit<2> CPP memory push/pull error enable bit
 * Bit<7> RI push/pull error enable bit
 * Bit<8> ARAM pull data parity check bit
 * Bit<9> RAS push error enable bit
 */
#define ADF_C4XXX_TGT_UERR (BIT(9) | BIT(8) | BIT(7) | BIT(2))

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
#define ADF_C4XXX_UERRSSMMMPAD(i, n)    ((i) * 0x4000 + \
		     ADF_C4XXX_MMP_BASE(n) + 0x38C)
#define ADF_C4XXX_INTMASKSSM(i)     ((i) * 0x4000 + 0x0)

#define ADF_C4XXX_UERRSSMMMP_INTS_CLEAR_MASK ((BIT(16) | BIT(0)))
#define ADF_C4XXX_CERRSSMMMP_INTS_CLEAR_MASK BIT(0)
#define ADF_C4XXX_PPERR_INTS_CLEAR_MASK BIT(0)

/* parser ram ecc uerr */
#define ADF_C4XXX_PARSER_UERR_INTR BIT(0)
/* multiple err */
#define ADF_C4XXX_PARSER_MUL_UERR_INTR BIT(18)
#define ADF_C4XXX_PARSER_DESC_UERR_INTR_ENA BIT(20)

#define ADF_C4XXX_MAC_IP 0x8

#define ADF_C4XXX_MAC_ERROR_TX_UNDERRUN BIT(6)
#define ADF_C4XXX_MAC_ERROR_TX_FCS BIT(7)
#define ADF_C4XXX_MAC_ERROR_TX_DATA_CORRUPT BIT(8)
#define ADF_C4XXX_MAC_ERROR_RX_OVERRUN BIT(9)
#define ADF_C4XXX_MAC_ERROR_RX_OVERRUN BIT(9)
#define ADF_C4XXX_MAC_ERROR_RX_RUNT BIT(10)
#define ADF_C4XXX_MAC_ERROR_RX_UNDERSIZE BIT(11)
#define ADF_C4XXX_MAC_ERROR_RX_JABBER BIT(12)
#define ADF_C4XXX_MAC_ERROR_RX_OVERSIZE BIT(13)
#define ADF_C4XXX_MAC_ERROR_RX_FCS BIT(14)
#define ADF_C4XXX_MAC_ERROR_RX_FRAME BIT(15)
#define ADF_C4XXX_MAC_ERROR_RX_CODE BIT(16)
#define ADF_C4XXX_MAC_ERROR_RX_PREAMBLE BIT(17)
#define ADF_C4XXX_MAC_RX_LINK_UP BIT(21)
#define ADF_C4XXX_MAC_INVALID_SPEED BIT(31)
#define ADF_C4XXX_MAC_PIA_RX_FIFO_OVERRUN BIT(32)
#define ADF_C4XXX_MAC_PIA_TX_FIFO_OVERRUN BIT(33)
#define ADF_C4XXX_MAC_PIA_TX_FIFO_UNDERRUN BIT(34)

#define ADF_C4XXX_RF_PAR_ERR_BITS 32
#define ADF_C4XXX_MAX_STR_LEN 64
#define RF_PAR_MUL_MAP(bit_num) (((bit_num) - 2) / 4)
#define RF_PAR_MAP(bit_num) (((bit_num) - 3) / 4)

/* cd rf parity error
 * BIT(2) rf parity mul 0
 * BIT(3) rf parity 0
 * BIT(10) rf parity mul 2
 * BIT(11) rf parity 2
 */
#define ADF_C4XXX_CD_RF_PAR_ERR_1_INTR  (BIT(2) | BIT(3)	\
					 | BIT(10) | BIT(11))


/* Congestion mgmt events */
#define ADF_C4XXX_CONGESTION_MGMT_CTPB_GLOBAL_CROSSED BIT(1)
#define ADF_C4XXX_CONGESTION_MGMT_XOFF_CIRQ_OUT BIT(2)
#define ADF_C4XXX_CONGESTION_MGMT_XOFF_CIRQ_IN BIT(3)

/* RAS enabling related registers values to be written */
#define ADF_C4XXX_SSMFEATREN_VAL (0xFD)

/* RAS enabling related registers */
#define ADF_C4XXX_SSMFEATREN (0x2010)

/* Return address of SSMFEATREN register for given accel */
#define ADF_C4XXX_GET_SSMFEATREN_OFFSET(accel) \
	(ADF_C4XXX_SSMFEATREN + ((accel) * 0x4000))

struct adf_accel_dev;

int adf_init_ras_c4xxx(struct adf_accel_dev *accel_dev);
void adf_exit_ras_c4xxx(struct adf_accel_dev *accel_dev);

bool adf_ras_interrupts_c4xxx(struct adf_accel_dev *accel_dev,
			      bool *reset_required);
void adf_enable_ras_c4xxx(struct adf_accel_dev *accel_dev);

#endif /* ADF_RAS_H */
