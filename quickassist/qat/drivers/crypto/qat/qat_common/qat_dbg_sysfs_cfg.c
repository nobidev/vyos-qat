// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2021-2022 Intel Corporation */

#include <linux/debugfs.h>

#include "qat_dbg.h"
#include "qat_dbg_sysfs_cfg.h"
#include "adf_accel_devices.h"
#include "adf_cfg_common.h"
#include "qat_dbg_cfg.h"

#define QATD_SYS_BUFFER_SIZE 256
#define QATD_PARAM_MAX_SZ 128
#define QATD_PARAM_BASE_DEC 10
#define QATD_SYS_FS_PERM 0400
#define QATD_SYS_FS_SUBDIR_DEPTH 2

static int qat_dbg_cfg_open(struct inode *inode, struct file *file);
static ssize_t qat_dbg_param_write(struct file *file,
				   const char __user *user_buffer, size_t count,
				   loff_t *position);
static ssize_t qat_dbg_param_read(struct file *file, char __user *user_buf,
				  size_t count, loff_t *ppos);

static const struct file_operations qat_dbg_p_fops = {
	.open = qat_dbg_cfg_open,
	.write = qat_dbg_param_write,
	.read = qat_dbg_param_read
};

static struct qatd_instance_config config_tbl[ADF_MAX_DEVICES];
static unsigned int config_tbl_tail = ADF_MAX_DEVICES;

static int qat_dbg_cfg_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;

	return 0;
}

/**
 * qat_dbg_sysfs_cfg_init() - Create debuggability sysfs configuration files
 * @parent_dir:   Pointer to sysfs directory structure which will contain
 *                created sysfs.
 * @qatd_config:  Pointer to debuggability sysfs entries structure pointer.
 * @data:         Pointer to data which will be used on sysfs file R/W
 *                operations.
 *
 * Function creates debuggability files to expose debuggability parameters in
 * debugfs filesystem under specified directory.
 *
 * Return: 0 on success, error code otherwise.
 */
static int qat_dbg_sysfs_cfg_init(struct dentry *parent_dir,
				  struct qatd_dentry_config **qatd_config,
				  void *data)
{
	struct qatd_dentry_config *dentry_config;

	if (!qatd_config)
		return -EINVAL;

	dentry_config =
		kzalloc(sizeof(struct qatd_dentry_config), GFP_KERNEL);

	if (!dentry_config)
		return -EFAULT;

	*qatd_config = dentry_config;

	/* Create directory for qat dbg */
	dentry_config->qat_dbg_dir =
		debugfs_create_dir(QATD_PARAM_SYSFS_DIR,
				   parent_dir);
	if (!dentry_config->qat_dbg_dir)
		return -EFAULT;

	/* Create files to expose QAT debug params */
	dentry_config->debug_enabled =
		debugfs_create_file(QATD_PARAM_ENABLED, QATD_SYS_FS_PERM,
				    dentry_config->qat_dbg_dir,
				    data,
				    &qat_dbg_p_fops);
	if (!dentry_config->debug_enabled)
		return -EFAULT;

	dentry_config->debug_level =
		debugfs_create_file(QATD_PARAM_LEVEL, QATD_SYS_FS_PERM,
				    dentry_config->qat_dbg_dir,
				    data,
				    &qat_dbg_p_fops);
	if (!dentry_config->debug_level)
		return -EFAULT;

	dentry_config->buffer_pool_size =
		debugfs_create_file(QATD_PARAM_BUFFER_POOL_SZ, QATD_SYS_FS_PERM,
				    dentry_config->qat_dbg_dir,
				    data,
				    &qat_dbg_p_fops);
	if (!dentry_config->buffer_pool_size)
		return -EFAULT;

	dentry_config->buffer_size_mb =
		debugfs_create_file(QATD_PARAM_BUFFER_SZ, QATD_SYS_FS_PERM,
				    dentry_config->qat_dbg_dir,
				    data,
				    &qat_dbg_p_fops);
	if (!dentry_config->buffer_size_mb)
		return -EFAULT;

	dentry_config->dump_dir =
		debugfs_create_file(QATD_PARAM_DUMP_DIR, QATD_SYS_FS_PERM,
				    dentry_config->qat_dbg_dir,
				    data,
				    &qat_dbg_p_fops);
	if (!dentry_config->dump_dir)
		return -EFAULT;

	dentry_config->dump_dir_size_mb =
		debugfs_create_file(QATD_PARAM_DUMP_DIR_SZ, QATD_SYS_FS_PERM,
				    dentry_config->qat_dbg_dir,
				    data,
				    &qat_dbg_p_fops);
	if (!dentry_config->dump_dir_size_mb)
		return -EFAULT;

	dentry_config->cont_sync_enabled =
		debugfs_create_file(QATD_PARAM_CS_ENABLED, QATD_SYS_FS_PERM,
				    dentry_config->qat_dbg_dir,
				    data,
				    &qat_dbg_p_fops);
	if (!dentry_config->cont_sync_enabled)
		return -EFAULT;

	dentry_config->cont_sync_log_dir =
		debugfs_create_file(QATD_PARAM_CS_DIR, QATD_SYS_FS_PERM,
				    dentry_config->qat_dbg_dir,
				    data,
				    &qat_dbg_p_fops);
	if (!dentry_config->cont_sync_log_dir)
		return -EFAULT;

	dentry_config->cont_sync_max_log_files =
		debugfs_create_file(QATD_PARAM_CS_MAX_FILES_NO,
				    QATD_SYS_FS_PERM,
				    dentry_config->qat_dbg_dir,
				    data,
				    &qat_dbg_p_fops);
	if (!dentry_config->cont_sync_max_log_files)
		return -EFAULT;

	dentry_config->cont_sync_max_log_size_mb =
		debugfs_create_file(QATD_PARAM_CS_MAX_FILE_SZ,
				    QATD_SYS_FS_PERM,
				    dentry_config->qat_dbg_dir,
				    data,
				    &qat_dbg_p_fops);
	if (!dentry_config->cont_sync_max_log_size_mb)
		return -EFAULT;

	dentry_config->dump_on_crash =
		debugfs_create_file(QATD_PARAM_DUMP_ON_P_CRASH,
				    QATD_SYS_FS_PERM,
				    dentry_config->qat_dbg_dir,
				    data,
				    &qat_dbg_p_fops);
	if (!dentry_config->dump_on_crash)
		return -EFAULT;

	return 0;
}

/**
 * qat_dbg_sysfs_cfg_deinit() - Destroy debuggability sysfs configuration files
 * @qatd_config: Pointer to debuggability sysfs entries structure pointer.
 *
 * Function removes debuggability sysfs files from debugfs filesystem.
 *
 * Return: none.
 */
static void qat_dbg_sysfs_cfg_deinit(struct qatd_dentry_config **qatd_config)
{
	struct qatd_dentry_config *dentry_config;

	if (!qatd_config)
		return;

	dentry_config = *qatd_config;
	if (!dentry_config)
		return;

	debugfs_remove(dentry_config->debug_enabled);
	dentry_config->debug_enabled = NULL;

	debugfs_remove(dentry_config->debug_level);
	dentry_config->debug_level = NULL;

	debugfs_remove(dentry_config->buffer_pool_size);
	dentry_config->buffer_pool_size = NULL;

	debugfs_remove(dentry_config->buffer_size_mb);
	dentry_config->buffer_size_mb = NULL;

	debugfs_remove(dentry_config->dump_dir);
	dentry_config->dump_dir = NULL;

	debugfs_remove(dentry_config->dump_dir_size_mb);
	dentry_config->dump_dir_size_mb = NULL;

	debugfs_remove(dentry_config->cont_sync_enabled);
	dentry_config->cont_sync_enabled = NULL;

	debugfs_remove(dentry_config->cont_sync_log_dir);
	dentry_config->cont_sync_log_dir = NULL;

	debugfs_remove(dentry_config->cont_sync_max_log_files);
	dentry_config->cont_sync_max_log_files = NULL;

	debugfs_remove(dentry_config->cont_sync_max_log_size_mb);
	dentry_config->cont_sync_max_log_size_mb = NULL;

	debugfs_remove(dentry_config->dump_on_crash);
	dentry_config->dump_on_crash = NULL;

	debugfs_remove(dentry_config->qat_dbg_dir);
	dentry_config->qat_dbg_dir = NULL;

	kfree(dentry_config);
	*qatd_config = NULL;
}

/**
 * qat_dbg_create_dettached_vf_sysfs() - Create debuggability sysfs
 * configuration files and their parent directory for detached VF
 * @vf_info: Pointer to acceleration device VF structure.
 *
 * Function creates debuggability sysfs files in debugfs filesystem for
 * detached VF.
 *
 * Return: 0 on success, error code otherwise.
 */
static int qat_dbg_create_dettached_vf_sysfs(struct adf_accel_vf_info *vf_info)
{
	char name[ADF_DEVICE_NAME_LENGTH];
	struct adf_pci_address pci_addr;
	struct adf_accel_dev *accel_dev = vf_info->accel_dev;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);

	if (adf_get_vf_pci_addr(accel_dev, vf_info->vf_nr, &pci_addr)) {
		dev_err(&pdev->dev, "Could not obtain VF%u PCI address\n",
			vf_info->vf_nr);
		return -EFAULT;
	}

	snprintf(name, sizeof(name), "%s%s%s_%04x:%02x:%02x.%x",
		 ADF_DEVICE_NAME_PREFIX, hw_data->dev_class->name,
		 QATD_DETACHED_VF_NAME_SUFFIX,
		 pci_domain_nr(accel_to_pci_dev(accel_dev)->bus),
		 pci_addr.bus,
		 pci_addr.dev,
		 pci_addr.func);

	vf_info->debugfs_dir = debugfs_create_dir(name, NULL);
	if (!vf_info->debugfs_dir) {
		dev_err(&pdev->dev, "Could not create debugfs dir %s\n", name);
		return -EFAULT;
	}
	if (config_tbl_tail == 0) {
		dev_err(&pdev->dev,
			"Could not create debugfs for %s. Too many VFs\n",
			name);
		return -EFAULT;
	}

	vf_info->qatd_instance_id = --config_tbl_tail;

	return 0;
}

/**
 * qat_dbg_check_config() - Check debuggability sysfs configuration
 * @d_config: Pointer to debuggability configuration instance.
 * @accel_dev: Pointer to acceleration device.
 *
 * Function checks correctness of debugability parameters provided via sysfs.
 *
 * Return: 0 on success, error code otherwise
 */
static int qat_dbg_check_config(struct qatd_instance_config *d_config,
				struct adf_accel_dev *accel_dev)
{
	if (d_config->buffer_pool_size < QATD_BUF_POOL_MIN ||
	    d_config->buffer_pool_size > QATD_BUF_POOL_MAX) {
		dev_err(&GET_DEV(accel_dev),
			"Buffer pool should be in range %d..%d\n",
			QATD_BUF_POOL_MIN, QATD_BUF_POOL_MAX);
		return -EFAULT;
	}

	if (d_config->buffer_size < (QATD_BUF_SIZE_MIN << QATD_1MB_SHIFT) ||
	    d_config->buffer_size > (QATD_BUF_SIZE_MAX << QATD_1MB_SHIFT)) {
		dev_err(&GET_DEV(accel_dev),
			"Buffer size should be in range %d..%d\n",
			QATD_BUF_SIZE_MIN, QATD_BUF_SIZE_MAX);
		return -EFAULT;
	}

	if (strnlen(d_config->dump_dir, sizeof(d_config->dump_dir)) == 0) {
		dev_err(&GET_DEV(accel_dev),
			"Dump directory should be configured\n");
		return -EFAULT;
	}

	if (d_config->debug_level > 3) {
		dev_err(&GET_DEV(accel_dev),
			"Debug level should be in range 0..3\n");
		return -EFAULT;
	}

	if (d_config->dump_on_proc_crash > 1) {
		dev_err(&GET_DEV(accel_dev),
			"Dump on process crash should be in range 0..1\n");
		return -EFAULT;
	}

	if (d_config->sync_mode == QATD_SYNC_ON_CRASH)
		goto success;

	if (strnlen(d_config->cont_sync_dir,
		    sizeof(d_config->cont_sync_dir)) == 0) {
		dev_err(&GET_DEV(accel_dev),
			"Cont sync directory should be configured\n");
		return -EFAULT;
	}

	if (d_config->cont_sync_max_files_no < QATD_SYNC_FILES_MIN ||
	    d_config->cont_sync_max_files_no > QATD_SYNC_FILES_MAX) {
		dev_err(&GET_DEV(accel_dev),
			"Cont sync max files should be in range %d..%d\n",
			QATD_SYNC_FILES_MIN, QATD_SYNC_FILES_MAX);
		return -EFAULT;
	}

	if ((d_config->cont_sync_max_file_size <
	    (QATD_SYNC_FILE_SZ_MIN << QATD_1MB_SHIFT)) ||
	    (d_config->cont_sync_max_file_size >
	    (QATD_SYNC_FILE_SZ_MAX << QATD_1MB_SHIFT))) {
		dev_err(&GET_DEV(accel_dev),
			"Cont sync max files size should be in range %d..%d\n",
			QATD_SYNC_FILE_SZ_MIN, QATD_SYNC_FILE_SZ_MAX);
		return -EFAULT;
	}
success:

	return 0;
}

/**
 * qat_dbg_sysfs_get_first_subdir() - Get debugfs first level subdir-name of
 * a file
 * @file: Pointer to a configuration file.
 * @filename: Pointer to pointer which will store obtained filename.
 *
 * Function returns name of first level subdir inside debugfs where the given
 * file is contained. The function also extracts the file filename.
 *
 * Return: Pointer to c-string containing folder name
 */
static char *qat_dbg_sysfs_get_first_subdir(struct file *file, char **filename)
{
	struct dentry *d_entry;
	char *iname = NULL;
	int level = 0;

	d_entry = file->f_path.dentry;
	if (d_entry)
		iname = d_entry->d_iname;
	if (!iname)
		return NULL;
	/* Go predefined number of levels up in dir tree */
	for (level = 0; level < QATD_SYS_FS_SUBDIR_DEPTH && d_entry; level++)
		d_entry = d_entry->d_parent;
	if (!d_entry)
		return NULL;

	*filename = iname;
	return d_entry->d_iname;
}

/**
 * qat_dbg_param_write() - Write debuggability parameters
 * @file: Pointer to a configuration file.
 * @user_buffer: Pointer to user buffer.
 * @count: Maximum number of bytes to write.
 * @position: Current position in the buffer.
 * Function provides mechanism to write debuggability parameters via sysfs.
 *
 * Return: Number of bytes wrote on success, error code otherwise
 */
static ssize_t qat_dbg_param_write(struct file *file,
				   const char __user *user_buffer,
				   size_t count, loff_t *position)
{
	char *first_subdir, *f_name;
	struct qatd_instance_config *d_config;
	struct adf_accel_dev *accel_dev = NULL;
	struct adf_accel_vf_info *vf_info = NULL;
	char str[QATD_SYS_BUFFER_SIZE] = {0};
	int ret = 0, dbg_enabled = 0, cs_enabled = 0, reload_config = 0;

	/* Basic defensive checks */
	if (!file || !file->private_data)
		return -EFAULT;

	if (count == 0 || count > QATD_SYS_BUFFER_SIZE)
		return -EFAULT;

	ret = simple_write_to_buffer(str, QATD_SYS_BUFFER_SIZE,
				     position, user_buffer, count);
	if (ret != count)
		return -EFAULT;

	first_subdir = qat_dbg_sysfs_get_first_subdir(file, &f_name);
	if (!first_subdir)
		return -EFAULT;

	if (strstr(first_subdir, QATD_DETACHED_VF_NAME_SUFFIX)) {
		/* Detached VF */
		vf_info = file->private_data;
		if (vf_info->qatd_instance_id >= ADF_MAX_DEVICES)
			return -EFAULT;
		d_config = &config_tbl[vf_info->qatd_instance_id];
	} else {
		/* Managed accelerator */
		accel_dev = file->private_data;
		if (accel_dev->accel_id > config_tbl_tail) {
			dev_err(&GET_DEV(accel_dev),
				"Cannot configure Debuggability for PF - too many VFs\n");
			return -EFAULT;
		}
		d_config = &config_tbl[accel_dev->accel_id];
	}

	if (!strncmp(f_name, QATD_PARAM_ENABLED, QATD_PARAM_MAX_SZ)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC, &dbg_enabled))
			return -EFAULT;
		reload_config = 1;
	}
	if (!strncmp(f_name, QATD_PARAM_DUMP_DIR, QATD_PARAM_MAX_SZ)) {
		memset(d_config->dump_dir, 0, sizeof(d_config->dump_dir));
		memcpy(d_config->dump_dir, str, count - 1);
	}
	if (!strncmp(f_name, QATD_PARAM_DUMP_DIR_SZ, QATD_PARAM_MAX_SZ)) {
		if (kstrtoul(str, ADF_CFG_BASE_DEC,
			     &d_config->dump_dir_max_size))
			return -EFAULT;
		d_config->dump_dir_max_size <<= QATD_1MB_SHIFT;
	}
	if (!strncmp(f_name, QATD_PARAM_BUFFER_POOL_SZ, QATD_PARAM_MAX_SZ)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC,
			       &d_config->buffer_pool_size))
			return -EFAULT;
	}
	if (!strncmp(f_name, QATD_PARAM_BUFFER_SZ, QATD_PARAM_MAX_SZ)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC,
			       &d_config->buffer_size))
			return -EFAULT;
		d_config->buffer_size <<= QATD_1MB_SHIFT;
	}
	if (!strncmp(f_name, QATD_PARAM_LEVEL, QATD_PARAM_MAX_SZ)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC,
			       &d_config->debug_level))
			return -EFAULT;
	}
	if (!strncmp(f_name, QATD_PARAM_CS_ENABLED, QATD_PARAM_MAX_SZ)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC, &cs_enabled))
			return -EFAULT;
		if (cs_enabled)
			d_config->sync_mode = QATD_SYNC_CONT;
		else
			d_config->sync_mode = QATD_SYNC_ON_CRASH;
	}
	if (!strncmp(f_name, QATD_PARAM_CS_DIR, QATD_PARAM_MAX_SZ)) {
		memset(d_config->cont_sync_dir, 0,
		       sizeof(d_config->cont_sync_dir));
		memcpy(d_config->cont_sync_dir, str, count - 1);
	}
	if (!strncmp(f_name, QATD_PARAM_CS_MAX_FILE_SZ, QATD_PARAM_MAX_SZ)) {
		if (kstrtoul(str, ADF_CFG_BASE_DEC,
			     &d_config->cont_sync_max_file_size))
			return -EFAULT;
		d_config->cont_sync_max_file_size <<= QATD_1MB_SHIFT;
	}
	if (!strncmp(f_name, QATD_PARAM_CS_MAX_FILES_NO, QATD_PARAM_MAX_SZ)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC,
			       &d_config->cont_sync_max_files_no))
			return -EFAULT;
	}
	if (!strncmp(f_name, QATD_PARAM_DUMP_ON_P_CRASH, QATD_PARAM_MAX_SZ)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC,
			       &d_config->dump_on_proc_crash))
			return -EFAULT;
	}

	if (!reload_config)
		return count;
	if (!dbg_enabled) {
		/* Disabling feature */
		if (vf_info)
			qat_dbg_shutdown_instance_vf(vf_info, false);
		else
			qat_dbg_shutdown_instance(accel_dev);

		return count;
	}
	/* Check current config */
	ret = qat_dbg_check_config(d_config, accel_dev);
	if (ret)
		return -EFAULT;

	/* Attempt to turn on or reconfigure feature */
	if (vf_info) {
		/* Detached VF */
		struct adf_pci_address pci_addr;
		struct adf_accel_pci pci_info = {0};

		/* Instance may exists - attempt to reconfigure */
		qat_dbg_shutdown_instance_vf(vf_info, false);
		accel_dev = adf_devmgr_add_fake_dev();
		if (!accel_dev)
			return -EFAULT;

		vf_info->qatd_fake_dev = accel_dev;
		if (adf_get_vf_pci_addr(vf_info->accel_dev, vf_info->vf_nr,
					&pci_addr)) {
			dev_err(&GET_DEV(vf_info->accel_dev),
				"Could not obtain VF%u PCI address\n",
				vf_info->vf_nr);
			return -EFAULT;
		}

		pci_info.pci_dev = adf_get_pci_dev_by_bdf(&pci_addr);
		if (!pci_info.pci_dev)
			return -EFAULT;

		memcpy(&accel_dev->accel_pci_dev, &pci_info,
		       sizeof(struct adf_accel_pci));
		accel_dev->hw_device = vf_info->accel_dev->hw_device;
		/* Do not set accel_dev->is_vf since it is checked in
		 * adf_error_notifier() */
	} else /* Managed accelerator - Instance may exist
		* - attempt to reconfigure */
		qat_dbg_shutdown_instance(accel_dev);

	ret = qat_dbg_init_instance_sysfs(accel_dev, d_config);
	if (ret)
		return -EFAULT;

	return count;
}

/**
 * qat_dbg_param_read() - Read debuggability parameters via sysfs
 * @file: Pointer to a configuration file.
 * @user_buf: Pointer to user buffer.
 * @count: Maximum number of bytes to read.
 * @ppos: Current position in the buffer.
 *
 * Function provides access to read debuggability parameters via sysfs.
 *
 * Return: Number of bytes read on success, error code or negative value
 * otherwise
 */
static ssize_t qat_dbg_param_read(struct file *file,
				  char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	char *first_subdir, *f_name;
	struct adf_accel_dev *accel_dev;
	struct adf_accel_vf_info *vf_info;
	struct qatd_instance *dbg_inst;
	char buf[QATD_SYS_BUFFER_SIZE];
	int len = 0;
	int enabled = 0;

	if (!file || !file->private_data)
		return -EFAULT;

	first_subdir = qat_dbg_sysfs_get_first_subdir(file, &f_name);
	if (!first_subdir)
		return -EFAULT;

	if (strstr(first_subdir, QATD_DETACHED_VF_NAME_SUFFIX)) {
		/* Detached VF */
		vf_info = file->private_data;
		accel_dev = vf_info->qatd_fake_dev;
	} else /* Managed accelerator */
		accel_dev = file->private_data;

	if (!accel_dev)
		return -EFAULT;

	dbg_inst = accel_dev->qatd_instance;
	if (!strncmp(f_name, QATD_PARAM_ENABLED, QATD_PARAM_MAX_SZ))
	{
		if (dbg_inst)
		{
			enabled = 1;
		} else
		{
			/* This case is hit while configuration is checked by
			 * the Debuggability Daemon. On particular device
			 * disabled, the Daemon needs to read whether
			 * Debuggability is enabled.
			 */
			enabled = qat_dbg_is_enabled(accel_dev);
			if (-ENODEV == enabled)
				return -EFAULT;
			enabled = !enabled;
		}

		len = scnprintf(buf, sizeof(buf), "%u\n", enabled);
		goto return_response;
	}

	if (!dbg_inst)
		return -EFAULT;

	if (!strncmp(f_name, QATD_PARAM_DUMP_DIR, QATD_PARAM_MAX_SZ)) {
		len = scnprintf(buf, sizeof(buf), "%s\n",
				dbg_inst->config.dump_dir);
	}
	if (!strncmp(f_name, QATD_PARAM_DUMP_DIR_SZ, QATD_PARAM_MAX_SZ)) {
		len = scnprintf(buf, sizeof(buf), "%lu\n",
				dbg_inst->config.dump_dir_max_size
				>> QATD_1MB_SHIFT);
	}
	if (!strncmp(f_name, QATD_PARAM_BUFFER_POOL_SZ, QATD_PARAM_MAX_SZ)) {
		len = scnprintf(buf, sizeof(buf), "%u\n",
				dbg_inst->config.buffer_pool_size);
	}
	if (!strncmp(f_name, QATD_PARAM_BUFFER_SZ, QATD_PARAM_MAX_SZ)) {
		len = scnprintf(buf, sizeof(buf), "%u\n",
				dbg_inst->config.buffer_size >> QATD_1MB_SHIFT);
	}
	if (!strncmp(f_name, QATD_PARAM_LEVEL, QATD_PARAM_MAX_SZ)) {
		len = scnprintf(buf, sizeof(buf), "%u\n",
				dbg_inst->config.debug_level);
	}
	if (!strncmp(f_name, QATD_PARAM_CS_ENABLED, QATD_PARAM_MAX_SZ)) {
		if (dbg_inst->config.sync_mode == QATD_SYNC_CONT)
			len = scnprintf(buf, sizeof(buf), "%u\n", 1);
		else
			len = scnprintf(buf, sizeof(buf), "%u\n", 0);
	}
	if (!strncmp(f_name, QATD_PARAM_CS_DIR, QATD_PARAM_MAX_SZ)) {
		len = scnprintf(buf, sizeof(buf), "%s\n",
				dbg_inst->config.cont_sync_dir);
	}
	if (!strncmp(f_name, QATD_PARAM_CS_MAX_FILE_SZ, QATD_PARAM_MAX_SZ)) {
		len = scnprintf(buf, sizeof(buf), "%lu\n",
				dbg_inst->config.cont_sync_max_file_size >>
				QATD_1MB_SHIFT);
	}
	if (!strncmp(f_name, QATD_PARAM_CS_MAX_FILES_NO, QATD_PARAM_MAX_SZ)) {
		len = scnprintf(buf, sizeof(buf), "%u\n",
				dbg_inst->config.cont_sync_max_files_no);
	}
	if (!strncmp(f_name, QATD_PARAM_DUMP_ON_P_CRASH, QATD_PARAM_MAX_SZ)) {
		len = scnprintf(buf, sizeof(buf), "%u\n",
				dbg_inst->config.dump_on_proc_crash);
	}

return_response:
	if (len <= 0)
		return -EFAULT;

	return simple_read_from_buffer(user_buf, count, ppos, buf, len + 1);
}

/**
 * qat_dbg_sysfs_cfg_add() - Add debuggability sysfs configuration files
 * @accel_dev: Pointer to acceleration device.
 *
 * Function creates debuggability files to expose debuggability parameters in
 * debugfs filesystem, in appropriate directory.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_sysfs_cfg_add(struct adf_accel_dev *accel_dev)
{
	if (!accel_dev)
		return -EINVAL;

	if (qat_dbg_sysfs_cfg_init(accel_dev->debugfs_dir,
				   &accel_dev->qatd_config,
				   accel_dev)) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to create QAT dbg debugfs entry.\n");
		qat_dbg_sysfs_cfg_del(accel_dev);

		return -EFAULT;
	}

	return 0;
}

/**
 * qat_dbg_sysfs_cfg_add_vf() - Add debuggability sysfs configuration files
 * for detached VF
 * @vf_info: Pointer to acceleration device VF structure.
 *
 * Function creates debuggability files to expose debuggability parameters in
 * debugfs filesystem, in appropriate directory, which is also created.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_sysfs_cfg_add_vf(struct adf_accel_vf_info *vf_info)
{
	struct adf_accel_dev *accel_dev;

	if (!vf_info)
		return -EINVAL;
	if (qat_dbg_create_dettached_vf_sysfs(vf_info))
		goto on_fail;
	/* Do not create by default fake accelerators for all VFs */
	if (qat_dbg_sysfs_cfg_init(vf_info->debugfs_dir,
				   &vf_info->qatd_config,
				   vf_info)) {
		accel_dev = vf_info->accel_dev;
		dev_err(&GET_DEV(accel_dev),
			"Failed to create sysfs entires for qat_dev%u VF %u\n",
			accel_dev->accel_id, vf_info->vf_nr);
		goto on_fail;
	}

	return 0;

on_fail:
	qat_dbg_sysfs_cfg_del_vf(vf_info);
	return -EFAULT;
}

/**
 * qat_dbg_sysfs_cfg_del() - Delete debuggability sysfs configuration files
 * @accel_dev: Pointer to acceleration device.
 *
 * Function deletes debuggability sysfs files with exposed parameters from
 * debugfs filesystem.
 *
 * Return: none.
 */
void qat_dbg_sysfs_cfg_del(struct adf_accel_dev *accel_dev)
{
	if (!accel_dev)
		return;

	qat_dbg_sysfs_cfg_deinit(&accel_dev->qatd_config);
}


/**
 * qat_dbg_sysfs_cfg_del_vf() - Delete detached VF debuggability sysfs
 * configuration files and their directory
 * @vf_info: Pointer to acceleration device VF structure.
 *
 * Function deletes debuggability sysfs files with exposed parameters from
 * debugfs filesystem.
 *
 * Return: none.
 */
void qat_dbg_sysfs_cfg_del_vf(struct adf_accel_vf_info *vf_info)
{
	if (!vf_info)
		return;

	qat_dbg_sysfs_cfg_deinit(&vf_info->qatd_config);
	debugfs_remove(vf_info->debugfs_dir);
	vf_info->debugfs_dir = NULL;
	if (config_tbl_tail < ADF_MAX_DEVICES)
		config_tbl_tail++;
}
