// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2020 - 2021 Intel Corporation */

#include <adf_accel_devices.h>
#include <adf_common_drv.h>
#include <adf_cfg.h>
#include "adf_c4xxx_aram.h"
#include "adf_c4xxx_hw_data.h"
#include "adf_c4xxx_accel_units.h"

int adf_init_aram_config_c4xxx(struct adf_accel_dev *accel_dev)
{
	u32 aram_size = ADF_C4XXX_2MB_ARAM_SIZE;
	u32 ibuff_mem_needed = 0;
	u32 usable_aram_size = 0;
	struct adf_hw_aram_info *aram_info;
	u32 sa_db_ctl_value = 0;
	void __iomem *aram_csr_base;
	u32 i;
	/* Allocate memory for adf_hw_aram_info */
	accel_dev->aram_info = kzalloc(sizeof(*accel_dev->aram_info), GFP_DMA);
	if (!accel_dev->aram_info)
		return -ENOMEM;
	aram_info = accel_dev->aram_info;


	/* Initialise DC ME mask, "1" = ME is used for DC operations */
	aram_info->dc_ae_mask = accel_dev->au_info->dc_ae_msk;

	/* Initialise CY ME mask, "1" = ME is used for CY operations */
	aram_info->cy_ae_mask = accel_dev->au_info->sym_ae_msk;
	aram_info->cy_ae_mask |= accel_dev->au_info->asym_ae_msk;

	/* Configure number of long words in the ARAM */
	aram_info->num_aram_lw_entries = ADF_C4XXX_NUM_ARAM_ENTRIES;

	/* Reset region offset values to 0xffffffff */
	aram_info->mmp_region_offset = ~aram_info->mmp_region_offset;
	aram_info->skm_region_offset = ~aram_info->skm_region_offset;
	aram_info->inter_buff_aram_region_offset =
		 ~aram_info->inter_buff_aram_region_offset;

	/* Determine ARAM size */
	aram_csr_base = (&GET_BARS(accel_dev)[ADF_C4XXX_SRAM_BAR])->virt_addr;
	sa_db_ctl_value = ADF_CSR_RD(aram_csr_base, ADF_C4XXX_REG_SA_DB_CTRL);

	aram_size = (sa_db_ctl_value & ADF_C4XXX_SADB_SIZE_BIT)
		? ADF_C4XXX_2MB_ARAM_SIZE : ADF_C4XXX_4MB_ARAM_SIZE;
	dev_info(&GET_DEV(accel_dev),
		 "Total available accelerator memory: %uMB\n",
		 aram_size / ADF_C4XXX_1MB_SIZE);
	sa_db_ctl_value &= ADF_C4XXX_SADB_SIZE_BIT;

	/* Compute MMP region offset */
	aram_info->mmp_region_size = ADF_C4XXX_DEFAULT_MMP_REGION_SIZE;
	aram_info->mmp_region_offset = aram_size - aram_info->mmp_region_size;

	if (accel_dev->au_info->num_cy_au) {
		/* Crypto is available therefore we must
		 * include space in the ARAM for SKM.
		 */
		aram_info->skm_region_size = ADF_C4XXX_DEFAULT_SKM_REGION_SIZE;
		/* Compute SKM region offset */
		aram_info->skm_region_offset = aram_size -
			(aram_info->mmp_region_size +
					aram_info->skm_region_size);
	}


	/* REG_SA_DB_CTRL register initialisation */
	ADF_CSR_WR(aram_csr_base, ADF_C4XXX_REG_SA_DB_CTRL, sa_db_ctl_value);

	/*
	 * REG_SA_CTRL_LOCK register initialisation. We set the lock
	 * bit in order to prevent the REG_SA_DB_CTRL to be
	 * overwritten
	 */
	ADF_CSR_WR(aram_csr_base, ADF_C4XXX_REG_SA_CTRL_LOCK,
		   ADF_C4XXX_DEFAULT_SA_CTRL_LOCKOUT);

	if (accel_dev->au_info->num_dc_au) {
		/* Compression is available therefore we must see if there is
		 * space in the ARAM for intermediate buffers.
		 */
		aram_info->inter_buff_aram_region_size = 0;
		usable_aram_size = aram_size -
				(aram_info->mmp_region_size
						+ aram_info->skm_region_size);

		for (i = 1; i <= accel_dev->au_info->num_dc_au; i++) {
			if ((i * ADF_C4XXX_AU_COMPR_INTERM_SIZE) >
				usable_aram_size)
				break;

			ibuff_mem_needed = i * ADF_C4XXX_AU_COMPR_INTERM_SIZE;
		}

		/* Set remaining ARAM to intermediate buffers. Firmware handles
		 * fallback to DRAM for cases were number of AU assigned
		 * to compression exceeds available ARAM memory.
		 */
		aram_info->inter_buff_aram_region_size = ibuff_mem_needed;

		/* If ARAM is used for compression set its initial offset. */
		if (aram_info->inter_buff_aram_region_size)
			aram_info->inter_buff_aram_region_offset = 0;
	}

	return 0;
}

void adf_exit_aram_config_c4xxx(struct adf_accel_dev *accel_dev)
{
	kfree(accel_dev->aram_info);
	accel_dev->aram_info = NULL;
}
