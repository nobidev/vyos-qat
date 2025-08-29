/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2020 - 2021 Intel Corporation */

#ifndef ADF_GEN2_HW_DATA_H_
#define ADF_GEN2_HW_DATA_H_

#include "adf_accel_devices.h"
#include "adf_transport_internal.h"

#define ADF_ETR_MAX_RINGS_PER_BANK	16

/* Arbiter configuration */
#define ADF_ARB_OFFSET			0x30000
#define ADF_ARB_WRK_2_SER_MAP_OFFSET	0x180
#define ADF_ARB_REG_SIZE		0x4
#define ADF_ARB_REG_SLOT		0x1000
#define ADF_ARB_RINGSRVARBEN_OFFSET	0x19C
#define ADF_ARB_DBG_RST_ARB_OFFSET	0x418

#define ADF_AE_PAIR 2
#define ADF_ASYM_SLICES_PER_AE_PAIR 5

#define ADF_IOV_VINTSOU_OFFSET		0x204

#define WRITE_CSR_ARB_RINGSRVARBEN(csr_addr, index, value) \
	ADF_CSR_WR(csr_addr, ADF_ARB_RINGSRVARBEN_OFFSET + \
	(ADF_ARB_REG_SLOT * (index)), value)

#define WRITE_CSR_ARB_WRK_2_SER_MAP(csr_addr, csr_offset, \
	wrk_to_ser_map_offset, index, value) \
	ADF_CSR_WR(csr_addr, ((csr_offset) + (wrk_to_ser_map_offset)) + \
	(ADF_ARB_REG_SIZE * (index)), value)

void get_gen2_arb_info(struct adf_arb_info *arb_csrs_info);
void get_gen2_admin_info(struct adf_admin_info *admin_csrs_info);
int adf_gen2_init_arb(struct adf_accel_dev *accel_dev);
void adf_gen2_exit_arb(struct adf_accel_dev *accel_dev);
int adf_gen2_ae_fw_load(struct adf_accel_dev *accel_dev);
u32 get_gen2_vintsou_offset(void);
u32 adf_gen2_get_dc_ae_mask(struct adf_accel_dev *accel_dev);
u32 adf_gen2_get_slices_for_svc(struct adf_accel_dev *accel_dev,
				enum adf_svc_type svc);
int adf_gen2_calc_sla_units(struct adf_accel_dev *accel_dev,
			    struct sla_sku_dev *sla_sku);

#endif
