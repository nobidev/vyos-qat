// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2017 - 2018, 2020 - 2021 Intel Corporation */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/seq_file.h>
#include <adf_accel_devices.h>
#include <adf_common_drv.h>
#include <adf_cfg.h>
#include "adf_c4xxx_hw_data.h"
#include "adf_c4xxx_accel_units.h"

#ifdef CONFIG_DEBUG_FS
/* String buffer size */
#define AE_INFO_BUFFER_SIZE 50

static DEFINE_MUTEX(ae_config_read_lock);

static u8 find_first_me_index(const unsigned long au_mask)
{
	u8 i;

	/* Retrieve the index of the first ME of an accel unit */
	for_each_set_bit(i, &au_mask, ADF_C4XXX_MAX_ACCELENGINES)
		return i;

	return 0;
}


static u8 get_au_index(u8 au_mask)
{
	u8 au_index = 0;

	while (au_mask) {
		if (au_mask == BIT(0))
			return au_index;
		au_index++;
		au_mask = au_mask >> 1;
	}

	return 0;
}

static void adf_print_ae_config_data(struct seq_file *sfile)
{
	struct adf_accel_dev *accel_dev = sfile->private;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_accel_unit *accel_unit = accel_dev->au_info->au;
	u8 i, j;
	u8 au_index;
	u8 ae_index;
	u8 num_aes;
	u32 num_au = get_num_accel_units_c4xxx(hw_data);
	char ae_info_buff[AE_INFO_BUFFER_SIZE];

	for (i = 0; i < num_au; i++) {
		/* Retrieve accel unit index */
		au_index = get_au_index(accel_unit[i].au_mask);

		/* Retrieve index of fist ME in current accel unit */
		ae_index = find_first_me_index(accel_unit[i].ae_mask);
		num_aes = accel_unit[i].num_ae;

		memset(ae_info_buff, '\0', AE_INFO_BUFFER_SIZE);
		/* Retrieve accel unit type */
		switch (accel_unit[i].services) {
		case ADF_ACCEL_CRYPTO:
			snprintf(ae_info_buff, sizeof(ae_info_buff),
				 "\tAccel unit %d - CRYPTO", au_index);
			seq_printf(sfile, "%s\n", ae_info_buff);
			/* Display ME assignment for a particular accel unit */
			for (j = ae_index; j < (num_aes + ae_index); j++)
				seq_printf(sfile, "\t\tAE[%d]: crypto\n", j);
			break;
		case ADF_ACCEL_COMPRESSION:
			snprintf(ae_info_buff, sizeof(ae_info_buff),
				 "\tAccel unit %d - COMPRESSION", au_index);
			seq_printf(sfile, "%s\n", ae_info_buff);
			/* Display ME assignment for a particular accel unit */
			for (j = ae_index; j < (num_aes + ae_index); j++) {
				if (BIT(j) & accel_unit[i].comp_ae_mask)
					seq_printf(sfile,
						   "\t\tAE[%d]: compression\n",
						   j);
				else
					seq_printf(sfile,
						   "\t\tAE[%d]: null\n", j);
			}
			break;
		case ADF_ACCEL_SERVICE_NULL:
		default:
			break;
		}
	}
}

static void *adf_ae_config_start(struct seq_file *sfile, loff_t *pos)
{
	mutex_lock(&ae_config_read_lock);

	if (*pos == 0)
		return SEQ_START_TOKEN;
	else
		return NULL;
}

static int adf_ae_config_show(struct seq_file *sfile, void *v)
{
	if (v == SEQ_START_TOKEN) {
		/* Display AE assignment */
		adf_print_ae_config_data(sfile);
	}

	return 0;
}

static void *adf_ae_config_next(struct seq_file *sfile, void *v, loff_t *pos)
{
	return NULL;
}

static void adf_ae_config_stop(struct seq_file *sfile, void *v)
{
	mutex_unlock(&ae_config_read_lock);
}

static const struct seq_operations adf_ae_config_sops = {
	.start = adf_ae_config_start,
	.next = adf_ae_config_next,
	.stop = adf_ae_config_stop,
	.show = adf_ae_config_show
};

static int adf_ae_config_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &adf_ae_config_sops);

	if (!ret) {
		struct seq_file *seq_f = file->private_data;

		seq_f->private = inode->i_private;
	}
	return ret;
}

static const struct file_operations adf_ae_config_debug_fops = {
	.owner = THIS_MODULE,
	.open = adf_ae_config_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

static int adf_add_debugfs_ae_config(struct adf_accel_dev *accel_dev)
{
	struct dentry *debugfs_ae_config = NULL;

	/* Create ae_config debug file */
	debugfs_ae_config =
		debugfs_create_file("ae_config",
				    0400,
				    accel_dev->debugfs_dir,
				    accel_dev,
				    &adf_ae_config_debug_fops);
	if (!debugfs_ae_config) {
		dev_err(&GET_DEV(accel_dev),
			"Could not create debug ae config entry\n");
		return -EFAULT;
	}
	accel_dev->debugfs_ae_config = debugfs_ae_config;

	return 0;
}

int adf_init_ae_config_c4xxx(struct adf_accel_dev *accel_dev)
{
	int ret = 0;
	struct adf_accel_pci *accel_pci_dev = &accel_dev->accel_pci_dev;
	struct pci_dev *pdev = accel_pci_dev->pci_dev;

	/* Add a new file in debug file system with h/w version. */
	ret = adf_add_debugfs_ae_config(accel_dev);
	if (ret) {
		adf_exit_ae_config_c4xxx(accel_dev);
		dev_err(&pdev->dev,
			"Could not create debugfs ae config file\n");
		return -EFAULT;
	}

	return 0;
}

void adf_exit_ae_config_c4xxx(struct adf_accel_dev *accel_dev)
{
	if (!accel_dev->debugfs_ae_config)
		return;

	/* Delete ae configuration file */
	debugfs_remove(accel_dev->debugfs_ae_config);
	accel_dev->debugfs_ae_config = NULL;
}
#else
int adf_init_ae_config_c4xxx(struct adf_accel_dev *accel_dev)
{
	return 0;
}

void adf_exit_ae_config_c4xxx(struct adf_accel_dev *accel_dev)
{
}
#endif
