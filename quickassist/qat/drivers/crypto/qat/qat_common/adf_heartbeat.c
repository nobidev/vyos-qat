// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2017 - 2021 Intel Corporation */
#include <linux/random.h>
#include <linux/module.h>
#include "adf_heartbeat.h"
#include "adf_common_drv.h"
#include "adf_cfg.h"
#include "adf_cfg_strings.h"
#include "icp_qat_fw_init_admin.h"
#include "adf_transport_internal.h"
#include "adf_accel_devices.h"

#define MAX_HB_TICKS 0xFFFFFFFF

static int adf_check_hb_poll_freq(struct adf_accel_dev *accel_dev)
{
	u64 curr_hb_check_time = 0;

	curr_hb_check_time = adf_clock_get_current_time();

	if ((curr_hb_check_time - accel_dev->heartbeat->last_hb_check_time)
	    < accel_dev->heartbeat->hb_timer) {
		dev_warn(&GET_DEV(accel_dev),
			 "HB poll frequency is higher than configured HB timer\n");
		return -EINVAL;
	}
	accel_dev->heartbeat->last_hb_check_time = curr_hb_check_time;

	return 0;
}

int adf_heartbeat_init(struct adf_accel_dev *accel_dev)
{
	if (accel_dev->heartbeat)
		adf_heartbeat_clean(accel_dev);

	accel_dev->heartbeat = kzalloc(sizeof(*accel_dev->heartbeat),
					 GFP_KERNEL);
	if (!accel_dev->heartbeat)
		return -ENOMEM;

	return 0;
}

void adf_heartbeat_clean(struct adf_accel_dev *accel_dev)
{
	kfree(accel_dev->heartbeat);
	accel_dev->heartbeat = NULL;
}

int adf_get_hb_timer(struct adf_accel_dev *accel_dev, unsigned int *value)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	char timer_str[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
	unsigned int timer_val = ADF_CFG_HB_DEFAULT_VALUE;
	u32 clk_per_sec = 0;

	if (!hw_data->get_ae_clock)
		return -EINVAL;

	clk_per_sec = (u32)hw_data->get_ae_clock(hw_data);

	/* Get Heartbeat Timer value from the configuration */
	if (!adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC,
				     ADF_HEARTBEAT_TIMER, (char *)timer_str)) {
		if (kstrtouint((char *)timer_str, ADF_CFG_BASE_DEC,
			       &timer_val))
			timer_val = ADF_CFG_HB_DEFAULT_VALUE;
	}

	if (timer_val < ADF_MIN_HB_TIMER_MS) {
		dev_err(&GET_DEV(accel_dev),
			"%s value cannot be lesser than %u\n",
			ADF_HEARTBEAT_TIMER, ADF_MIN_HB_TIMER_MS);
		return -EINVAL;
	}

	/* Convert msec to clocks */
	clk_per_sec = clk_per_sec / 1000;
	*value = timer_val * clk_per_sec;

	accel_dev->heartbeat->hb_timer = timer_val;

	return 0;
}

struct adf_hb_count {
	u16	ae_thread[ADF_NUM_HB_CNT_PER_AE];
};

int adf_get_heartbeat_status(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	struct icp_qat_fw_init_admin_hb_stats *live_s =
			(struct icp_qat_fw_init_admin_hb_stats *)
					accel_dev->admin->virt_hb_addr;
	const size_t max_aes = hw_device->get_num_aes(hw_device);
	const size_t stats_size = max_aes *
			sizeof(struct icp_qat_fw_init_admin_hb_stats);
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
	 *         |            max_aes * sizeof(icp_qat_fw_init_admin_hb_stats)
	 *         max_aes * sizeof(icp_qat_fw_init_admin_hb_stats)
	 */
	struct icp_qat_fw_init_admin_hb_stats *curr_s;
	struct icp_qat_fw_init_admin_hb_stats *last_s = live_s + max_aes;
	struct adf_hb_count *count = (struct adf_hb_count *)(last_s + max_aes);

	curr_s = kmalloc(stats_size, GFP_KERNEL);
	if (!curr_s)
		return -ENOMEM;

	memcpy(curr_s, live_s, stats_size);

	for_each_set_bit(ae, &hw_device->ae_mask, max_aes) {
		for (thr = 0; thr < ADF_NUM_HB_CNT_PER_AE; ++thr) {
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
EXPORT_SYMBOL_GPL(adf_get_heartbeat_status);

int adf_heartbeat_status(struct adf_accel_dev *accel_dev,
			 enum adf_device_heartbeat_status *hb_status)
{
	/* Heartbeat is not implemented in VFs at the moment so they do not
	 * set get_heartbeat_status. Also, in case the device is not up,
	 * unsupported should be returned */
	if (!accel_dev || !accel_dev->hw_device ||
	    !accel_dev->hw_device->get_heartbeat_status) {
		*hb_status = DEV_HB_UNSUPPORTED;
		return 0;
	}

	if (!adf_dev_started(accel_dev) ||
	    test_bit(ADF_STATUS_RESTARTING, &accel_dev->status)) {
		*hb_status = DEV_HB_UNRESPONSIVE;
		return 0;
	}
	if (adf_check_hb_poll_freq(accel_dev) == -EINVAL) {
		*hb_status = DEV_HB_UNSUPPORTED;
		return 0;
	}
	accel_dev->heartbeat->hb_sent_counter++;
	if (unlikely(accel_dev->hw_device->get_heartbeat_status(accel_dev))) {
		dev_err(&GET_DEV(accel_dev),
			"ERROR: QAT is not responding.\n");
		*hb_status = DEV_HB_UNRESPONSIVE;
		accel_dev->heartbeat->hb_failed_counter++;
		return adf_notify_fatal_error(accel_dev);
	}

	*hb_status = DEV_HB_ALIVE;

	return 0;
}

#ifdef QAT_HB_FAIL_SIM
static int adf_set_max_hb_timer(struct adf_accel_dev *accel_dev)
{
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp resp;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 ae_mask = hw_data->ae_mask;

	memset(&req, 0, sizeof(req));
	req.cmd_id = ICP_QAT_FW_HEARTBEAT_TIMER_SET;

	if (!accel_dev->admin) {
		dev_err(&GET_DEV(accel_dev), "adf_admin not available\n");
		return -EFAULT;
	}

	req.hb_cfg_ptr = accel_dev->admin->phy_hb_addr;
	req.heartbeat_ticks = MAX_HB_TICKS;

	if (adf_send_admin(accel_dev, &req, &resp, ae_mask)) {
		dev_err(&GET_DEV(accel_dev),
			"Error changing Heartbeat timer\n");
		return -EFAULT;
	}

	return 0;
}

static int adf_disable_arbiter(struct adf_accel_dev *accel_dev,
			       u32 ae,
			       u32 thr)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_accel_pci *accel_pci_dev = &accel_dev->accel_pci_dev;
	void __iomem *csr = accel_dev->transport->banks[0].csr_addr;
	const u32 *thd_2_arb_cfg = NULL;
	u32 ae_thr_map;
	struct adf_arb_info info;

	if (ADF_AE_STRAND0_THREAD == thr || ADF_AE_STRAND1_THREAD == thr)
		thr = ADF_AE_ADMIN_THREAD;

	/* Disable the worker thread to partition map
	 * for selected accelerator engine and thread.
	 */
	if (IS_QAT_GEN3(accel_pci_dev->pci_dev->device)) {
		ADF_WRITE_CSR_WQM(csr, ADF_GEN3_WRKTHD2PARTMAP,
				  ae * ADF_NUM_THREADS_PER_AE + thr, 0);
		return 0;
	}

	hw_data->get_arb_info(&info);
	hw_data->get_arb_mapping(accel_dev, &thd_2_arb_cfg);
	if (!thd_2_arb_cfg)
		return -EFAULT;

	/* Disable scheduling for this particular AE and thread */
	ae_thr_map = *(thd_2_arb_cfg + ae);
	ae_thr_map &= ~(0x0F << (thr * 4));

	adf_write_csr_arb_wrk_2_ser_map(csr, info.arbiter_offset,
					info.wrk_thd_2_srv_arb_offset, ae,
					ae_thr_map);
	return 0;
}

static int adf_set_hb_counters_fail(struct adf_accel_dev *accel_dev,
				    u32 ae,
				    u32 thr)
{
	struct icp_qat_fw_init_admin_hb_stats *stats =
			(struct icp_qat_fw_init_admin_hb_stats *)
					accel_dev->admin->virt_hb_addr;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	const size_t max_aes = hw_device->get_num_aes(hw_device);
	u16 num_rsp = stats[ae].stats[thr].resp_heartbeat_cnt;

	/* Inject live.req != live.rsp and live.rsp == last.rsp
	 * to trigger the heartbeat error detection
	 */
	stats[ae].stats[thr].req_heartbeat_cnt++;
	stats += max_aes;
	stats[ae].stats[thr].resp_heartbeat_cnt = num_rsp;

	return 0;
}

int adf_heartbeat_simulate_failure(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	struct adf_accel_pci *accel_pci_dev = &accel_dev->accel_pci_dev;
	const size_t max_aes = hw_device->get_num_aes(hw_device);
	u32 rand, rand_ae, rand_thr, max_thr;
	unsigned long ae_mask = hw_device->ae_mask;

	if (IS_QAT_GEN3(accel_pci_dev->pci_dev->device))
		max_thr = ADF_NUM_THREADS_PER_AE;
	else
		max_thr = ADF_NUM_HB_CNT_PER_AE;

	do {
		get_random_bytes(&rand, sizeof(rand));
		rand_ae = rand % max_aes;
	} while (!test_bit(rand_ae, &ae_mask));

	get_random_bytes(&rand, sizeof(rand));
	rand_thr = rand % max_thr;

	dev_info(&GET_DEV(accel_dev),
		 "adf_heartbeat_simulate_failure for random AE %u, thr %u\n",
		 rand_ae, rand_thr);

	/* Increase the heartbeat timer to prevent FW updating HB counters */
	if (adf_set_max_hb_timer(accel_dev))
		return -EFAULT;

	/* Change arbiter to stop processing any packet */
	if (adf_disable_arbiter(accel_dev, rand_ae, rand_thr))
		return -EFAULT;

	/* Change HB counters memory to simulate a hang */
	if (adf_set_hb_counters_fail(accel_dev, rand_ae, rand_thr))
		return -EFAULT;

	return 0;
}

#endif
