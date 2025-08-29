// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2019, 2021 Intel Corporation */

#include "adf_c4xxx_pke_replay_stats.h"
#include "adf_c4xxx_accel_units.h"
#include "adf_common_drv.h"
#include "icp_qat_fw_init_admin.h"

#include <linux/seq_file.h>
#include <linux/debugfs.h>

#ifdef CONFIG_DEBUG_FS
#define PKE_REPLAY_DBG_FILE "pke_replay_stats"
#define LINE	\
	"+-----------------------------------------------------------------+\n"
#define BANNER	\
	"|             PKE Replay Statistics for Qat Device                |\n"

static int adf_get_fw_pke_stats(struct adf_accel_dev *accel_dev,
				u32 *pass_count,
				u32 *fail_count)
{
	struct icp_qat_fw_init_admin_req req = {0};
	struct icp_qat_fw_init_admin_resp resp = {0};
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	unsigned long sym_ae_msk = 0;
	u8 sym_ae_msk_size = 0;
	u8 i = 0;

	if (!pass_count || !fail_count)
		return -EFAULT;

	if (!hw_device) {
		dev_dbg(&GET_DEV(accel_dev), "Failed to get hw_device\n");
		return -EFAULT;
	}

	sym_ae_msk = accel_dev->au_info->sym_ae_msk;
	sym_ae_msk_size = sizeof(accel_dev->au_info->sym_ae_msk) *
		BITS_PER_BYTE;

	req.cmd_id = ICP_QAT_FW_PKE_REPLAY_STATS_GET;
	for_each_set_bit(i, &sym_ae_msk, sym_ae_msk_size) {
		memset(&resp,
		       0,
		       sizeof(struct icp_qat_fw_init_admin_resp));
		if (adf_put_admin_msg_sync(accel_dev, i, &req, &resp) ||
		    resp.status) {
			return -EFAULT;
		}
		*pass_count += resp.pass_count;
		*fail_count += resp.fail_count;
	}
	return 0;
}

static int adf_pke_replay_counters_show(struct seq_file *sfile, void *v)
{
	struct adf_accel_dev *accel_dev;
	int ret = 0;
	u32 pass_counter = 0;
	u32 fail_counter = 0;

	accel_dev = sfile->private;

	seq_printf(sfile, LINE);
	seq_printf(sfile, BANNER);
	seq_printf(sfile, LINE);

	ret =  adf_get_fw_pke_stats(accel_dev, &pass_counter, &fail_counter);
	if (ret)
		return ret;

	seq_printf(sfile,
		   "| Successful Asymmetric Replays:   %30u |\n"
		   "| Unsuccessful Asymmetric Replays: %30u |\n",
		   pass_counter, fail_counter);
	seq_printf(sfile, LINE);

	return 0;
}

static int adf_pke_replay_counters_open(struct inode *inode, struct file *file)
{
	struct adf_accel_dev *accel_dev;

	accel_dev = inode->i_private;
	if (!accel_dev)
		return -EFAULT;

	if (!adf_dev_started(accel_dev)) {
		dev_err(&GET_DEV(accel_dev),
			"Qat Device not started\n");
		return -EFAULT;
	}
	return single_open(file, adf_pke_replay_counters_show, accel_dev);
}

static const struct file_operations qat_pke_replay_ctr_fops = {
	.owner = THIS_MODULE,
	.open = adf_pke_replay_counters_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/**
 * adf_pke_replay_counters_add_c4xxx() - Create debugfs entry for
 * acceleration pke replay statistics counters.
 * @accel_dev:  Pointer to acceleration device.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_pke_replay_counters_add_c4xxx(struct adf_accel_dev *accel_dev)
{
	/* accel_dev->debugfs_dir should always be non-NULL here */
	accel_dev->pke_replay_dbgfile =
		debugfs_create_file(PKE_REPLAY_DBG_FILE,
				    0400,
				    accel_dev->debugfs_dir,
				    accel_dev,
				    &qat_pke_replay_ctr_fops);
	if (!accel_dev->pke_replay_dbgfile) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to create qat pke replay debugfs entry.\n");
		return -EFAULT;
	}
	return 0;
}

/**
 * adf_pke_replay_counters_remove_c4xxx() - Remove debugfs entry for
 * acceleration pke replay statistics counters.
 * @accel_dev:  Pointer to acceleration device.
 *
 * Return: void
 */
void adf_pke_replay_counters_remove_c4xxx(struct adf_accel_dev *accel_dev)
{
	debugfs_remove(accel_dev->pke_replay_dbgfile);
	accel_dev->pke_replay_dbgfile = NULL;
}
#else
int adf_pke_replay_counters_add_c4xxx(struct adf_accel_dev *accel_dev)
{
	return 0;
}

void adf_pke_replay_counters_remove_c4xxx(struct adf_accel_dev *accel_dev)
{
}
#endif
