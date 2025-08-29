// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2019 - 2021 Intel Corporation */

#include "adf_c4xxx_misc_error_stats.h"
#include "adf_common_drv.h"
#include "adf_cfg_common.h"

#include <linux/seq_file.h>
#include <linux/debugfs.h>

#define MISC_ERROR_DBG_FILE "misc_error_stats"
#ifdef CONFIG_DEBUG_FS
#define LINE	\
	"+-----------------------------------------------------------------+\n"
#define BANNER	\
	"|          Miscellaneous Error Statistics for Qat Device          |\n"

static int qat_misc_error_show(struct seq_file *sfile, void *v)
{
	seq_printf(sfile, LINE);
	seq_printf(sfile, BANNER);
	seq_printf(sfile, LINE);

	seq_printf(sfile,
		   "| Miscellaneous Error:   %40llu |\n",
		   ((struct adf_dev_miscellaneous_stats *)
		   misc_counter)->misc_counter);
	seq_printf(sfile, LINE);

	return 0;
}

static int qat_misc_error_open(struct inode *inode, struct file *file)
{
	struct adf_accel_dev *accel_dev;

	accel_dev = inode->i_private;
	if (!accel_dev)
		return -ENODEV;

	if (!adf_dev_started(accel_dev)) {
		dev_err(&GET_DEV(accel_dev),
			"Qat Device not started\n");
		return -ENODEV;
	}
	return single_open(file, qat_misc_error_show, accel_dev);
}

static const struct file_operations qat_misc_error_fops = {
	.owner = THIS_MODULE,
	.open = qat_misc_error_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/**
 * adf_misc_error_add_c4xxx() - Create debugfs entry for
 * acceleration device Freq counters.
 * @accel_dev:  Pointer to acceleration device.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_misc_error_add_c4xxx(struct adf_accel_dev *accel_dev)
{
	/* accel_dev->debugfs_dir should always be non-NULL here */
	accel_dev->misc_error_dbgfile =
		debugfs_create_file(MISC_ERROR_DBG_FILE,
				    0400,
				    accel_dev->debugfs_dir,
				    accel_dev,
				    &qat_misc_error_fops);
	if (!accel_dev->misc_error_dbgfile) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to create qat miscellaneous error debugfs entry.\n");
		return -ENOENT;
	}

	misc_counter = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!misc_counter) {
		debugfs_remove(accel_dev->misc_error_dbgfile);
		return -ENOMEM;
	}

	memset(misc_counter, 0, PAGE_SIZE);

	return 0;
}

/**
 * adf_misc_error_remove_c4xxx() - Remove debugfs entry for
 * acceleration device misc error counter.
 * @accel_dev:  Pointer to acceleration device.
 *
 * Return: void
 */
void adf_misc_error_remove_c4xxx(struct adf_accel_dev *accel_dev)
{
	debugfs_remove(accel_dev->misc_error_dbgfile);
	accel_dev->misc_error_dbgfile = NULL;

	kfree(misc_counter);
	misc_counter = NULL;
}
#else
int adf_misc_error_add_c4xxx(struct adf_accel_dev *accel_dev)
{
	return 0;
}

void adf_misc_error_remove_c4xxx(struct adf_accel_dev *accel_dev)
{
}
#endif
