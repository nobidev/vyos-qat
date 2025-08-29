/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2021 Intel Corporation */

#ifndef ADF_C4XXX_ARAM_H_
#define ADF_C4XXX_ARAM_H_

/* ARAM CSR register addresses in SRAM BAR */
#define ARAM_CSR_BAR_OFFSET		   0x100000
#define ADF_C4XXX_REG_SA_CTRL_LOCK	   (ARAM_CSR_BAR_OFFSET + 0x00)
#define ADF_C4XXX_REG_SA_DB_CTRL	   (ARAM_CSR_BAR_OFFSET + 0x1C)

#define ADF_C4XXX_SADB_SIZE_BIT BIT(24)

/* REG_SA_CTRL_LOCK default value */
#define ADF_C4XXX_DEFAULT_SA_CTRL_LOCKOUT	BIT(0)

#define ADF_C4XXX_NUM_ARAM_ENTRIES	8

/* ARAM region sizes in bytes */
#define ADF_C4XXX_1MB_SIZE		(1024 * 1024)
#define ADF_C4XXX_2MB_ARAM_SIZE		(2 * ADF_C4XXX_1MB_SIZE)
#define ADF_C4XXX_4MB_ARAM_SIZE		(4 * ADF_C4XXX_1MB_SIZE)
#define ADF_C4XXX_DEFAULT_MMP_REGION_SIZE    (1024 * 256)
#define ADF_C4XXX_DEFAULT_SKM_REGION_SIZE    (1024 * 256)
#define ADF_C4XXX_AU_COMPR_INTERM_SIZE	(1024 * 128 * 2 * 2)

/* ARAM error interrupt enable registers */
#define ADF_C4XXX_ARAMCERR (0x101700)
#define ADF_C4XXX_ARAMUERR (0x101704)
#define ADF_C4XXX_CPPMEMTGTERR (0x101710)

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

int adf_init_aram_config_c4xxx(struct adf_accel_dev *accel_dev);
void adf_exit_aram_config_c4xxx(struct adf_accel_dev *accel_dev);
#endif /* ADF_C4XXX_ARAM_H_ */

