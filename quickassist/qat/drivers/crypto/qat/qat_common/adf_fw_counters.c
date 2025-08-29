// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2018 - 2019, 2021 Intel Corporation */

#include "adf_fw_counters.h"
#include "adf_common_drv.h"
#include "icp_qat_fw_init_admin.h"
#include <linux/seq_file.h>

static int qat_fw_counters_show(struct seq_file *sfile, void *v)
{
	struct adf_accel_dev *accel_dev;
	struct adf_hw_device_data *hw_device;
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp resp;
	u8 i = 0;
	char line[] = "+------------------------------------------------+\n";
	char banner[] = "| FW Statistics for Qat Device                   |\n";

	accel_dev = sfile->private;
	hw_device = accel_dev->hw_device;
	if (!hw_device) {
		dev_dbg(&GET_DEV(accel_dev),
			"Failed to get hw_device.\n");
		return -EFAULT;
	}

	seq_printf(sfile, line);
	seq_printf(sfile, banner);
	seq_printf(sfile, line);
	memset(&req, 0, sizeof(struct icp_qat_fw_init_admin_req));
	req.cmd_id = ICP_QAT_FW_COUNTERS_GET;

	for_each_set_bit(i, &hw_device->ae_mask,
			 GET_MAX_ACCELENGINES(accel_dev)) {
		memset(&resp, 0, sizeof(struct icp_qat_fw_init_admin_resp));
		if (adf_put_admin_msg_sync(accel_dev, i, &req, &resp) ||
		    resp.status) {
			return -EFAULT;
		}
		seq_printf(sfile,
			   "| %s[AE %2d]:%20llu |\n",
			   "Firmware Requests ", i,
			   resp.req_rec_count);
		seq_printf(sfile,
			   "| %s[AE %2d]:%20llu |\n",
			   "Firmware Responses", i,
			   resp.resp_sent_count);
		seq_printf(sfile,
			   "| %s[AE %2d]:%20u |\n",
			   "RAS Events        ", i,
			   resp.ras_event_count);
		seq_printf(sfile, line);
	}
	return 0;
}

static int qat_fw_counters_open(struct inode *inode, struct file *file)
{
	struct adf_accel_dev *accel_dev;

	accel_dev = inode->i_private;
	if (!accel_dev)
		return -EFAULT;

	if (!adf_dev_started(accel_dev))
		return -EFAULT;

	return single_open(file, qat_fw_counters_show, accel_dev);
}

static const struct file_operations qat_fw_counters_fops = {
	.owner = THIS_MODULE,
	.open = qat_fw_counters_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/**
 * adf_fw_counters_add() - Create debugfs entry for
 * acceleration device FW counters.
 * @accel_dev:  Pointer to acceleration device.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_fw_counters_add(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device;

	if (!accel_dev)
		return -EFAULT;

	hw_device = accel_dev->hw_device;
	if (!hw_device) {
		dev_dbg(&GET_DEV(accel_dev),
			"Failed to get hw_device.\n");
		return -EFAULT;
	}

	/* accel_dev->debugfs_dir should always be non-NULL here */
	accel_dev->fw_cntr_dbgfile = debugfs_create_file("fw_counters", 0400,
							 accel_dev->debugfs_dir,
							 accel_dev,
							 &qat_fw_counters_fops);
	if (!accel_dev->fw_cntr_dbgfile) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to create qat fw counters debugfs entry.\n");
		return -EFAULT;
	}
	return 0;
}

/**
 * adf_fw_counters_remove() - Remove debugfs entry for
 * acceleration device FW counters.
 * @accel_dev:  Pointer to acceleration device.
 *
 * Return: void
 */
void adf_fw_counters_remove(struct adf_accel_dev *accel_dev)
{
	debugfs_remove(accel_dev->fw_cntr_dbgfile);
}
