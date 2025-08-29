// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2020 - 2021 Intel Corporation */

#include "adf_accel_devices.h"
#include "adf_common_drv.h"
#include "adf_cfg_common.h"
#include "icp_qat_fw_init_admin.h"
#include "adf_transport_internal.h"
#include "icp_qat_hw.h"
#include "adf_c4xxx_hw_data.h"
#include "adf_c4xxx_accel_units.h"

/* Default 4 partitions for services */
#define ADF_C4XXX_PART_ASYM                   0
#define ADF_C4XXX_PART_SYM                    1
#define ADF_C4XXX_PART_UNUSED                 2
#define ADF_C4XXX_PART_DC                     3
#define ADF_C4XXX_PARTS_PER_GRP               16

#define ADF_C4XXX_PARTITION_LUT_OFFSET        0x81000

#define ADF_C4XXX_DEFAULT_PARTITIONS   (ADF_C4XXX_PART_ASYM     |      \
					ADF_C4XXX_PART_SYM << 8 |      \
					ADF_C4XXX_PART_UNUSED << 16  | \
					ADF_C4XXX_PART_DC << 24)

#define READ_CSR_WQM(csr_addr, csr_offset, index)                        \
		     ADF_CSR_RD(csr_addr,                                \
				(csr_offset) + ((index) * ADF_C4XXX_WQM_SIZE))

#define ADF_C4XXX_PARTTITION_SHIFT 8
#define ADF_C4XXX_PARTITION(svc, ring) \
	((svc) << ((ring) * ADF_C4XXX_PARTTITION_SHIFT))

static void adf_get_partitions_mask(struct adf_accel_dev *accel_dev,
				    u32 *partitions_mask)
{
	u32 enabled_partitions_msk = 0;
	u8 ring_pair = 0;
	enum adf_cfg_service_type serv_type = 0;
	u16 ring_to_svc_map = accel_dev->hw_device->ring_to_svc_map;

	for (ring_pair = 0; ring_pair < ADF_CFG_NUM_SERVICES; ring_pair++) {
		serv_type =
			GET_SRV_TYPE(ring_to_svc_map, ring_pair);
		switch (serv_type) {
		case CRYPTO:
			enabled_partitions_msk |=
				ADF_C4XXX_PARTITION(ADF_C4XXX_PART_ASYM,
						    ring_pair++);
			enabled_partitions_msk |=
				ADF_C4XXX_PARTITION(ADF_C4XXX_PART_SYM,
						    ring_pair);
			break;
		case COMP:
			enabled_partitions_msk |=
				ADF_C4XXX_PARTITION(ADF_C4XXX_PART_DC,
						    ring_pair);
			break;
		case SYM:
			enabled_partitions_msk |=
				ADF_C4XXX_PARTITION(ADF_C4XXX_PART_SYM,
						    ring_pair);
			break;
		case ASYM:
			enabled_partitions_msk |=
				ADF_C4XXX_PARTITION(ADF_C4XXX_PART_ASYM,
						    ring_pair);
			break;
		default:
			enabled_partitions_msk |=
				ADF_C4XXX_PARTITION(ADF_C4XXX_PART_UNUSED,
						    ring_pair);
			break;
		}
	}
	*partitions_mask = enabled_partitions_msk;
}

static void adf_enable_sym_threads(struct adf_accel_dev *accel_dev, u32 ae,
				   u32 partition)
{
	void __iomem *csr = accel_dev->transport->banks[0].csr_addr;
	const struct adf_ae_info *ae_info = accel_dev->au_info->ae_info;
	u32 num_sym_thds = ae_info[ae].num_sym_thd;
	u32 i;
	u32 part_group = partition / ADF_C4XXX_PARTS_PER_GRP;
	u32 wkrthd2_partmap = part_group << ADF_C4XXX_PARTS_PER_GRP |
		(BIT(partition % ADF_C4XXX_PARTS_PER_GRP));

	for (i = 0; i < num_sym_thds; i++)
		ADF_WRITE_CSR_WQM(csr, ADF_GEN3_WRKTHD2PARTMAP,
				  (ae * ADF_NUM_THREADS_PER_AE + i),
				  wkrthd2_partmap);
}

static void adf_enable_asym_threads(struct adf_accel_dev *accel_dev, u32 ae,
				    u32 partition)
{
	void __iomem *csr = accel_dev->transport->banks[0].csr_addr;
	const struct adf_ae_info *ae_info = accel_dev->au_info->ae_info;
	u32 num_asym_thds = ae_info[ae].num_asym_thd;
	u32 i;
	u32 part_group = partition / ADF_C4XXX_PARTS_PER_GRP;
	u32 wkrthd2_partmap = part_group << ADF_C4XXX_PARTS_PER_GRP |
		(BIT(partition % ADF_C4XXX_PARTS_PER_GRP));
	/* For asymmetric cryptography SKU we have one thread less */
	u32 num_all_thds = ADF_NUM_THREADS_PER_AE - 2;

	for (i = num_all_thds; i > (num_all_thds - num_asym_thds); i--)
		ADF_WRITE_CSR_WQM(csr, ADF_GEN3_WRKTHD2PARTMAP,
				  (ae * ADF_NUM_THREADS_PER_AE + i),
				  wkrthd2_partmap);
}

static void adf_enable_dc_threads(struct adf_accel_dev *accel_dev, u32 ae,
				  u32 partition)
{
	void __iomem *csr = accel_dev->transport->banks[0].csr_addr;
	const struct adf_ae_info *ae_info = accel_dev->au_info->ae_info;
	u32 num_dc_thds = ae_info[ae].num_dc_thd;
	u32 i;
	u32 part_group = partition / ADF_C4XXX_PARTS_PER_GRP;
	u32 wkrthd2_partmap = part_group << ADF_C4XXX_PARTS_PER_GRP |
		(BIT(partition % ADF_C4XXX_PARTS_PER_GRP));

	for (i = 0; i < num_dc_thds; i++)
		ADF_WRITE_CSR_WQM(csr, ADF_GEN3_WRKTHD2PARTMAP,
				  (ae * ADF_NUM_THREADS_PER_AE + i),
				  wkrthd2_partmap);
}

/* Initialise Resource partitioning.
 * Initialise a default set of 4 partitions to arbitrate
 * request rings per bundle.
 */
int adf_init_arb_c4xxx(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	void __iomem *csr = accel_dev->transport->banks[0].csr_addr;
	struct adf_accel_unit_info *au_info = accel_dev->au_info;
	u32 i;
	unsigned long ae_mask;
	u32 partitions_mask = 0;

	/* invoke common adf_init_arb */
	adf_init_arb(accel_dev);

	adf_get_partitions_mask(accel_dev, &partitions_mask);
	for (i = 0; i < hw_data->num_banks; i++)
		ADF_WRITE_CSR_WQM(csr, ADF_C4XXX_PARTITION_LUT_OFFSET, i,
				  partitions_mask);

	ae_mask = hw_data->ae_mask;

	if (hw_data->accel_capabilities_mask &
		ICP_ACCEL_CAPABILITIES_CIPHER_CRC){
		ae_mask &= ADF_C4XXX_CIPHER_CRC_ACCELENGINES_MASK;
	}

	/* Assigning default partitions to accel engine
	 * worker threads
	 */
	for_each_set_bit(i, &ae_mask, ADF_C4XXX_MAX_ACCELENGINES) {
		if (BIT(i) & au_info->sym_ae_msk)
			adf_enable_sym_threads(accel_dev, i,
					       ADF_C4XXX_PART_SYM);
		if (BIT(i) & au_info->asym_ae_msk)
			adf_enable_asym_threads(accel_dev, i,
						ADF_C4XXX_PART_ASYM);
		if (BIT(i) & au_info->dc_ae_msk)
			adf_enable_dc_threads(accel_dev, i,
					      ADF_C4XXX_PART_DC);
	}

	return 0;
}

/* Disable the resource partitioning feature
 * and restore the default partitioning scheme
 */
void adf_exit_arb_c4xxx(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	void __iomem *csr;
	u32 i;
	unsigned long ae_mask;

	if (!accel_dev->transport)
		return;
	csr = accel_dev->transport->banks[0].csr_addr;

	/* Restore the default partitionLUT registers */
	for (i = 0; i < hw_data->num_banks; i++)
		ADF_WRITE_CSR_WQM(csr, ADF_C4XXX_PARTITION_LUT_OFFSET, i,
				  ADF_C4XXX_DEFAULT_PARTITIONS);

	ae_mask = hw_data->ae_mask;

	/* Reset worker thread to partition mapping */
	for (i = 0; i < hw_data->num_engines * ADF_NUM_THREADS_PER_AE; i++) {
		if (!test_bit((u32)(i / ADF_NUM_THREADS_PER_AE), &ae_mask))
			continue;

		ADF_WRITE_CSR_WQM(csr, ADF_GEN3_WRKTHD2PARTMAP,
				  i, 0);
	}
}

struct adf_hb_count {
	u16	ae_thread[ADF_NUM_THREADS_PER_AE];
};

int get_heartbeat_status_c4xxx(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	struct icp_qat_fw_init_admin_hb_stats_gen3 *live_s =
			(struct icp_qat_fw_init_admin_hb_stats_gen3 *)
					accel_dev->admin->virt_hb_addr;
	const size_t max_aes = hw_device->num_engines;
	const size_t stats_size = max_aes *
			sizeof(struct icp_qat_fw_init_admin_hb_stats_gen3);
	int ret = 0;
	size_t ae, thr;

	/*
	 * Memory layout of Heartbeat
	 *
	 * +----------------+----------------+---------+
	 * |   Live value   |   Last value   |  Count  |
	 * +----------------+----------------+---------+
	 * \_______________/\_______________/\________/
	 *         ^                ^            ^
	 *         |                |            |
	 *         |                |            max_aes * sizeof(adf_hb_count)
	 *         |      max_aes * sizeof(icp_qat_fw_init_admin_hb_stats_gen3)
	 *         max_aes * sizeof(icp_qat_fw_init_admin_hb_stats_gen3)
	 */
	struct icp_qat_fw_init_admin_hb_stats_gen3 *curr_s;
	struct icp_qat_fw_init_admin_hb_stats_gen3 *last_s = live_s + max_aes;
	struct adf_hb_count *count = (struct adf_hb_count *)(last_s + max_aes);

	curr_s = kmalloc(stats_size, GFP_KERNEL);
	if (!curr_s)
		return -ENOMEM;

	memcpy(curr_s, live_s, stats_size);

	for_each_set_bit(ae, &hw_device->ae_mask, max_aes) {
		for (thr = 0; thr < ADF_NUM_THREADS_PER_AE; ++thr) {
			struct icp_qat_fw_init_admin_hb_cnt *curr =
					&curr_s[ae].stats[thr];
			struct icp_qat_fw_init_admin_hb_cnt *prev =
					&last_s[ae].stats[thr];
			u16 req = curr->req_heartbeat_cnt;
			u16 resp = curr->resp_heartbeat_cnt;
			u16 last = prev->resp_heartbeat_cnt;

			if ((thr == ADF_AE_ADMIN_THREAD || req != resp) &&
			    resp == last) {
				u16 retry = ++count[ae].ae_thread[thr];

				if (retry >= ADF_CFG_HB_COUNT_THRESHOLD)
					ret = -EIO;
			} else {
				count[ae].ae_thread[thr] = 0;
			}
		}
	}

	/* Copy current stats for the next iteration */
	memcpy(last_s, curr_s, stats_size);
	kfree(curr_s);

	return ret;
}
