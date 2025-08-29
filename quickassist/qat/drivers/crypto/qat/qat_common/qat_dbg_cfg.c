// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2021 Intel Corporation */

/***************************************************************************
 * @file qat_dbg_cfg.c
 *
 * This file provides Linux kernel QAT debug configuration utils.
 *
 ***************************************************************************/

/* Project headers */
#include "adf_cfg.h"
#include "adf_cfg_common.h"
#include "qat_dbg_cfg.h"

#define QATD_SHIFT_MUL_BY_1M 20

/**
 * qat_dbg_is_enabled() - Is debuggability enabled
 * @accel_dev: Pointer to acceleration device.
 *
 * Function checks whether debuggability is enabled.
 *
 * Return: 0 if enabled, error code otherwise.
 */
int qat_dbg_is_enabled(struct adf_accel_dev *accel_dev)
{
	char str[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
	int dbg_enabled;

	if (!adf_cfg_get_param_value(accel_dev, ADF_DEBUG_SEC,
				     ADF_DEBUG_ENABLED, str)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC,
			       &dbg_enabled)) {
			return -EFAULT;
		}

		if (dbg_enabled)
		{
			return 0;
		}

		return -EEXIST;
	}

	return -ENODEV;
}

/**
 * qat_dbg_configure_instance() - Configure debuggability instance
 * @inst: Pointer to debuggability instance.
 * @accel_dev: Pointer to acceleration device.
 *
 * Function configures debuggability instance basing on debuggability section
 * in configuration file.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_configure_instance(struct qatd_instance *inst,
			       struct adf_accel_dev *accel_dev)
{
	char str[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
	int cont_sync_enabled = 0;

	if (!adf_cfg_get_param_value(accel_dev, ADF_DEBUG_SEC,
				     ADF_DEBUG_NUM_BUFFERS, str)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC,
			       &inst->config.buffer_pool_size)) {
			return -EFAULT;
		}
	}

	if (!adf_cfg_get_param_value(accel_dev, ADF_DEBUG_SEC,
				     ADF_DEBUG_BUFFER_SZ, str)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC,
			       &inst->config.buffer_size)) {
			return -EFAULT;
		}
		/* Multiply by 1M */
		inst->config.buffer_size <<= QATD_SHIFT_MUL_BY_1M;
	}

	if (!adf_cfg_get_param_value(accel_dev, ADF_DEBUG_SEC,
				     ADF_DEBUG_MAX_LOGDIR_SZ, str)) {
		if (kstrtoul(str, ADF_CFG_BASE_DEC,
			     &inst->config.dump_dir_max_size)) {
			return -EFAULT;
		}
		/* Multiply by 1M */
		inst->config.dump_dir_max_size <<= QATD_SHIFT_MUL_BY_1M;
	}

	if (adf_cfg_get_param_value(accel_dev, ADF_DEBUG_SEC, ADF_DEBUG_LOG_DIR,
				    inst->config.dump_dir)) {
		return -EFAULT;
	}

	if (!adf_cfg_get_param_value(accel_dev, ADF_DEBUG_SEC,
				     ADF_DEBUG_LEVEL, str)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC,
			       &inst->config.debug_level)) {
			return -EFAULT;
		}
	}

	if (!adf_cfg_get_param_value(accel_dev, ADF_DEBUG_SEC,
				     ADF_DEBUG_DUMP_ON_PCRASH, str)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC,
			       &inst->config.dump_on_proc_crash)) {
			inst->config.dump_on_proc_crash = 0;
		}
	}

	if (!adf_cfg_get_param_value(accel_dev, ADF_DEBUG_SEC,
				     ADF_DEBUG_CONT_SYNC_ENABLED, str)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC, &cont_sync_enabled))
			return -EFAULT;
	}

	if (cont_sync_enabled) {
		inst->config.sync_mode = QATD_SYNC_CONT;
	} else {
		inst->config.sync_mode = QATD_SYNC_ON_CRASH;
		goto success;
	}

	if (adf_cfg_get_param_value(accel_dev, ADF_DEBUG_SEC,
				    ADF_DEBUG_CONT_SYNC_DIR,
				    inst->config.cont_sync_dir)) {
		return -EFAULT;
	}

	if (!adf_cfg_get_param_value(accel_dev, ADF_DEBUG_SEC,
				     ADF_DEBUG_CONT_SYNC_MAX_LOG_SIZE, str)) {
		if (kstrtoul(str, ADF_CFG_BASE_DEC,
			     &inst->config.cont_sync_max_file_size)) {
			return -EFAULT;
		}
		/* Multiply by 1M */
		inst->config.cont_sync_max_file_size <<= QATD_SHIFT_MUL_BY_1M;
	}

	if (!adf_cfg_get_param_value(accel_dev, ADF_DEBUG_SEC,
				     ADF_DEBUG_CONT_SYNC_MAX_LOG_FILES, str)) {
		if (kstrtouint(str, ADF_CFG_BASE_DEC,
			       &inst->config.cont_sync_max_files_no)) {
			return -EFAULT;
		}
	}

success:
	return 0;
}

