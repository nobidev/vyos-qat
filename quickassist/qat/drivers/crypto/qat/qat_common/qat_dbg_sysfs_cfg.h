/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2021 - 2022 Intel Corporation */

/***************************************************************************
 * @file qat_dbg_config.h
 *
 * This file provides Linux kernel QAT sysfs based configuration definitions.
 *
 ***************************************************************************/

#ifndef QAT_DBG_SYSFS_CFG_H_
#define QAT_DBG_SYSFS_CFG_H_

struct adf_accel_dev;

struct qatd_dentry_config {
	struct dentry *qat_dbg_dir;
	struct dentry *debug_enabled;
	struct dentry *debug_level;
	struct dentry *buffer_pool_size;
	struct dentry *buffer_size_mb;
	struct dentry *dump_dir;
	struct dentry *dump_dir_size_mb;
	struct dentry *dump_on_crash;
	struct dentry *cont_sync_enabled;
	struct dentry *cont_sync_log_dir;
	struct dentry *cont_sync_max_log_files;
	struct dentry *cont_sync_max_log_size_mb;
} __packed __aligned(64);

int qat_dbg_sysfs_cfg_add(struct adf_accel_dev *accel_dev);
int qat_dbg_sysfs_cfg_add_vf(struct adf_accel_vf_info *vf_info);
void qat_dbg_sysfs_cfg_del(struct adf_accel_dev *qatd_dev);
void qat_dbg_sysfs_cfg_del_vf(struct adf_accel_vf_info *vf_info);
#endif /* QAT_DBG_CONFIG_H_ */
