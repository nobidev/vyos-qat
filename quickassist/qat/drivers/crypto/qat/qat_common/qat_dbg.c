// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2021 - 2022 Intel Corporation */

/***************************************************************************
 * @file qat_dbg.c
 *
 * This file provides Linux kernel QAT debug implementation.
 *
 ***************************************************************************/

/* System headers */
#include <linux/sched.h>

/* Project headers */
#include "adf_cfg.h"
#include "adf_cfg_common.h"
#include "adf_common_drv.h"
#include "qat_dbg.h"
#include "qat_dbg_cfg.h"
#include "qat_dbg_mem_pool.h"
#include "qat_dbg_phy_map.h"
#include "qat_dbg_sysfs_cfg.h"

static DEFINE_MUTEX(qat_dbg_mutex);

/**
 * qat_dbg_check_debounce() - ensure no debounce effect
 * @inst: QAT Debuggability instance.
 *
 * Function ensures that no debounce effect happens. The effect takes place when
 * one error arrives twice to debuggability as there are multiple sources of
 * errors: AER and ISR.
 *
 * @return 0 if there is no debounce, error code otherwise.
 */
static int qat_dbg_check_debounce(struct qatd_instance *inst)
{
	struct timespec64 time;
	unsigned long current_ts;

	/* Extract current time */
	ktime_get_real_ts64(&time);
	current_ts = (u32)(time.tv_sec);

	/* Check if last crash took place within debounce time out */
	mutex_lock(&inst->mutex);
	if (current_ts - inst->last_crash_ts < QATD_CRASH_DEBOUNCE_TIME) {
		mutex_unlock(&inst->mutex);
		return -EFAULT;
	}
	inst->last_crash_ts = current_ts;
	mutex_unlock(&inst->mutex);

	return 0;
}

/**
 * qat_dbg_init_instance_internal() - Common routine to initialize
 * debuggability instance
 * @accel_dev: Pointer to acceleration device.
 * @config: Pointer to debuggability configuration instance.
 *
 * Function initializes debuggability instance using given configuration if
 * it is not equal to NULL, or configuration from QAT device configuration file
 * otherwise.
 *
 * Return: 0 on success, error code otherwise.
 */
static int qat_dbg_init_instance_internal(struct adf_accel_dev *accel_dev,
					  struct qatd_instance_config *config)
{
	struct qatd_instance *dbg_inst;
	int ret;

	mutex_lock(&qat_dbg_mutex);

	if (accel_dev->qatd_instance) {
		dev_info(&GET_DEV(accel_dev),
			 "Debug instance already configured.\n");
		mutex_unlock(&qat_dbg_mutex);
		return 0;
	}

	dbg_inst = kzalloc(sizeof(*dbg_inst), GFP_KERNEL);
	if (!dbg_inst) {
		mutex_unlock(&qat_dbg_mutex);
		return -ENOMEM;
	}

	dbg_inst->last_crash_ts = 0;

	if (config) {
		dbg_inst->config = *config;
	} else {
		ret = qat_dbg_configure_instance(dbg_inst, accel_dev);
		if (ret != 0)
			goto on_error;
	}

	ret = qat_dbg_buffer_init_all(dbg_inst);
	if (ret != 0)
		goto on_error;

	dev_info(&GET_DEV(accel_dev),
		 "Debug memory pool initialized (%d buffers)\n",
		 dbg_inst->config.buffer_pool_size);

	mutex_init(&dbg_inst->mutex);

	accel_dev->qatd_instance = dbg_inst;

	mutex_unlock(&qat_dbg_mutex);

	return 0;

on_error:
	kfree(dbg_inst);
	mutex_unlock(&qat_dbg_mutex);

	return ret;
}

/**
 * qat_dbg_fatal_error_handler() - Debuggability handle fatal error
 * @accel_dev: Pointer to acceleration device.
 *
 * Function handles fatal error by storing physical memory map if the debounce
 * effect didn't take place.
 */
void qat_dbg_fatal_error_handler(struct adf_accel_dev *accel_dev)
{
	if (!accel_dev || !accel_dev->qatd_instance)
		return;

	if (qat_dbg_check_debounce(accel_dev->qatd_instance))
		return;

	/* Storing physical memory map in memory */
	qat_dbg_phy_map_store(accel_dev);
}

/**
 * qat_dbg_proc_crash_handler() - Debuggability handle process crash
 * @accel_dev: Pointer to acceleration device.
 *
 * Function handles process crash by storing physical memory map if the debounce
 * effect didn't take place. It also notifies subservices about process crash.
 */
void qat_dbg_proc_crash_handler(struct adf_accel_dev *accel_dev)
{
	if (!accel_dev || !accel_dev->qatd_instance)
		return;

	if (qat_dbg_check_debounce(accel_dev->qatd_instance))
		return;

	/* Storing physical memory map in memory */
	qat_dbg_phy_map_store(accel_dev);

	/* Sending K2U notification */
	adf_dev_proc_crash_notify(accel_dev);
}

/**
 * qat_dbg_err_resp_handler() - Debuggability error response handler
 * @accel_dev: Pointer to acceleration device.
 *
 * Function stores physical process memory map and send notification about
 * error response.
 */
void qat_dbg_err_resp_handler(struct adf_accel_dev *accel_dev)
{
	if (!accel_dev || !accel_dev->qatd_instance)
		return;

	if (qat_dbg_check_debounce(accel_dev->qatd_instance))
		return;

	/* Storing physical memory map in memory */
	qat_dbg_phy_map_store(accel_dev);

	/* Sending K2U notification */
	adf_dev_err_resp_notify(accel_dev);
}

int qat_dbg_open_handler(void)
{
	return 0;
}

/**
 * qat_dbg_release_handler() - Debuggability release handler
 * @pid: Process identifier.
 *
 * Function releases all buffers associated with provided process identifier
 * and calls process crash handler in case of abnormal application exit.
 */
int qat_dbg_release_handler(int pid)
{
	u32 id;
	struct adf_accel_dev *accel_dev;
	struct qatd_instance *dbg_inst;
	int released = 0;

	for (id = 0; id < ADF_MAX_DEVICES; id++) {
		accel_dev = qatd_get_dev_by_id(id);
		if (!accel_dev || !accel_dev->qatd_instance)
			continue;

		dbg_inst = accel_dev->qatd_instance;

		mutex_lock(&dbg_inst->mutex);
		released = qat_dbg_buffer_release_all(dbg_inst, pid);
		mutex_unlock(&dbg_inst->mutex);
		if (released)
			qat_dbg_proc_crash_handler(accel_dev);
	}

	return 0;
}

/**
 * qat_dbg_mmap_handler() - Debuggability mmap handler
 * @buffer_idx: Debug buffer identifier.
 * @dbg_inst_idx: Debuggability instance identifier.
 * @size: Requested region.
 * @ring: Pointer to debug ring buffer.
 *
 * Function sets pointer to requested ring buffer if provided parameters
 * related to that buffer are appropriate.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_mmap_handler(int buffer_idx, int dbg_inst_idx, int size,
			 struct qatd_ring_desc **ring)
{
	struct qatd_buffer_desc *buffer;
	struct adf_accel_dev *accel_dev;
	struct qatd_instance *dbg_inst;

	accel_dev = qatd_get_dev_by_id(dbg_inst_idx);
	if (!accel_dev)
		return -EFAULT;

	dbg_inst = accel_dev->qatd_instance;
	if (!dbg_inst) {
		dev_err(&GET_DEV(accel_dev),
			"QAT: Requested dbg instance is NULL\n");
		return -EINVAL;
	}

	if (size > dbg_inst->config.buffer_size) {
		dev_err(&GET_DEV(accel_dev),
		       "QAT: Requested region exceeds max value: %u\n",
		       dbg_inst->config.buffer_size);
		return -EINVAL;
	}

	buffer = qat_dbg_buffer_get(dbg_inst, buffer_idx);
	if (!buffer) {
		dev_err(&GET_DEV(accel_dev),
		       "QAT: Unable to find dbg buffer: %u\n",
		       buffer_idx);
		return -EINVAL;
	}
	if (!buffer->ring) {
		dev_err(&GET_DEV(accel_dev),
		       "QAT: NULL debug buffer\n");
		return -EINVAL;
	}

	*ring = buffer->ring;

	return 0;
}

/**
 * qat_dbg_handle_buffer_request() - Handle debug buffer request
 * @req: Request from userspace.
 *
 * Function handles debuggability buffer request from userspace.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_handle_buffer_request(struct qatd_ioctl_req *req)
{
	int ret = 0;
	int free_buffer_id = -1;
	struct qatd_buffer_desc *new_buffer = NULL;
	struct adf_accel_dev *accel_dev;
	struct qatd_instance *dbg_inst;
	pid_t pid;

	accel_dev = qatd_get_dev_by_id(req->instance_id);
	if (!accel_dev)
		return -EFAULT;

	dbg_inst = accel_dev->qatd_instance;
	if (!dbg_inst) {
		dev_err(&GET_DEV(accel_dev),
		       "QAT: FATAL - requested instance is NULL\n");
		return -EFAULT;
	}
	pid = task_tgid_vnr(current);

	mutex_lock(&dbg_inst->mutex);
	ret = qat_dbg_buffer_alloc(dbg_inst, (int)pid, &free_buffer_id);
	mutex_unlock(&dbg_inst->mutex);
	if (ret)
		return ret;
	if (free_buffer_id < 0)
		return -EAGAIN;

	new_buffer = qat_dbg_buffer_get(dbg_inst, free_buffer_id);
	if (!new_buffer || !new_buffer->ring)
		return -EFAULT;

	if (dbg_inst->config.sync_mode == QATD_SYNC_ON_CRASH)
		/* Move tail to head, to prepare buffer to collect data */
		qat_dbg_buffer_clean(dbg_inst, free_buffer_id);

	/* Filling the request with the expected buffer to be mmaped in US */
	req->buffer_sz = dbg_inst->config.buffer_size;
	req->buffer_addr = ((req->instance_id << QATD_POOL_SIZE_SHIFT) +
			    free_buffer_id) << PAGE_SHIFT;
	req->buffer_id = free_buffer_id;

	return 0;
}

/**
 * qat_dbg_handle_status_request() - Handle debug status request
 * @req: Request from userspace.
 *
 * Function handles debuggability status request from userspace.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_handle_status_request(struct qatd_ioctl_req *req)
{
	int ret = 0;
	struct adf_accel_dev *accel_dev;
	struct qatd_instance *dbg_inst;

	accel_dev = qatd_get_dev_by_id(req->instance_id);
	if (!accel_dev)
		return -EFAULT;

	if (!accel_dev->qatd_instance) {
		req->debug_level = 0;
		req->sync_mode = 0;
		req->status = 0;
		return 0;
	}

	dbg_inst = accel_dev->qatd_instance;
	req->debug_level = dbg_inst->config.debug_level;
	req->sync_mode = dbg_inst->config.sync_mode;
	req->status = 1;

	return ret;
}

/**
 * qat_dbg_handle_release_request() - Handle debug release request
 * @req: Request from userspace.
 *
 * Function handles debuggability release request from userspace.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_handle_release_request(struct qatd_ioctl_req *req)
{
	struct adf_accel_dev *accel_dev;
	struct qatd_instance *dbg_inst;
	struct qatd_buffer_desc *buffer;

	accel_dev = qatd_get_dev_by_id(req->instance_id);
	if (!accel_dev)
		return -EFAULT;

	dbg_inst = accel_dev->qatd_instance;
	if (!dbg_inst) {
		dev_err(&GET_DEV(accel_dev),
		       "QAT: FATAL - requested instance is NULL\n");
		return -EFAULT;
	}

	/* Release/send buffer to sync */
	buffer = qat_dbg_buffer_get(dbg_inst, req->buffer_id);
	if (!buffer) {
		dev_err(&GET_DEV(accel_dev),
		       "QAT: Error: Unable to find buffer: %d\n",
		       req->buffer_id);
		return -EFAULT;
	}

	mutex_lock(&dbg_inst->mutex);
	qat_dbg_buffer_release(dbg_inst, req->buffer_id);
	mutex_unlock(&dbg_inst->mutex);

	return 0;
}

/**
 * qat_dbg_handle_sync_request() - Handle debug synchronization request
 * @req: Request from userspace.
 *
 * Function handles debuggability synchronization request from userspace.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_handle_sync_request(struct qatd_ioctl_req *req)
{
	int ret = 0;
	int free_buffer_id = -1;
	struct adf_accel_dev *accel_dev;
	struct qatd_instance *dbg_inst;
	struct qatd_buffer_desc *buffer;
	struct qatd_buffer_desc *new_buffer;
	pid_t pid;

	accel_dev = qatd_get_dev_by_id(req->instance_id);
	if (!accel_dev)
		return -EFAULT;

	dbg_inst = accel_dev->qatd_instance;
	if (!dbg_inst) {
		dev_err(&GET_DEV(accel_dev),
		       "QAT: No dbg instance available for device: %d\n",
		       req->instance_id);
		return -EFAULT;
	}

	/* Release/send buffer to sync */
	buffer = qat_dbg_buffer_get(dbg_inst, req->buffer_id);
	if (!buffer) {
		dev_err(&GET_DEV(accel_dev),
		       "QAT: Unable to find buffer: %d\n",
		       req->buffer_id);
		return -EFAULT;
	}
	pid = task_tgid_vnr(current);

	mutex_lock(&dbg_inst->mutex);
	qat_dbg_buffer_release(dbg_inst, req->buffer_id);
	ret = qat_dbg_buffer_alloc(dbg_inst, (int)pid, &free_buffer_id);
	mutex_unlock(&dbg_inst->mutex);
	if (ret)
		return ret;
	if (free_buffer_id < 0)
		return -EAGAIN;

	new_buffer = qat_dbg_buffer_get(dbg_inst, free_buffer_id);
	if (!new_buffer || !new_buffer->ring)
		return -EFAULT;

	if (dbg_inst->config.sync_mode == QATD_SYNC_ON_CRASH)
		/* Move tail to head, to prepare buffer to collect data */
		qat_dbg_buffer_clean(dbg_inst, free_buffer_id);

	/* Filling the request with the expected buffer to be mmaped in US */
	req->buffer_sz = dbg_inst->config.buffer_size;
	req->buffer_addr = ((req->instance_id << QATD_POOL_SIZE_SHIFT) +
			    free_buffer_id) << PAGE_SHIFT;
	req->buffer_id = free_buffer_id;

	return 0;
}

/**
 * qat_dbg_handle_err_resp_request() - Debuggability handle error response
 * @req: Userspace request.
 *
 * Function handles error response request.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_handle_err_resp_request(struct qatd_ioctl_req *req)
{
	struct adf_accel_dev *accel_dev;

	accel_dev = qatd_get_dev_by_id(req->instance_id);
	if (!accel_dev || !accel_dev->qatd_instance)
		return -EFAULT;

	qat_dbg_err_resp_handler(accel_dev);

	return 0;
}

/**
 * qat_dbg_handle_manual_dump_request() - Debuggability handle manual dump
 * @req: Userspace request.
 *
 * Function handles manual dump request by storing physical memory map and
 * notifying subservices about manual dump.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_handle_manual_dump_request(struct qatd_ioctl_req *req)
{
	struct adf_accel_dev *accel_dev;

	accel_dev = qatd_get_dev_by_id(req->instance_id);
	if (!accel_dev || !accel_dev->qatd_instance)
		return -EFAULT;

	/* Storing physical memory map in memory */
	qat_dbg_phy_map_store(accel_dev);

	/* Sending K2U notification */
	adf_dev_manual_dump_notify(accel_dev);

	return 0;
}

/**
 * qat_dbg_init_instance_sysfs() - Initialize debuggability instance via sysfs
 * @accel_dev: Pointer to acceleration device.
 * @config: Pointer to debuggability configuration instance.
 *
 * Function initializes debuggability instance using parameters provided via sysfs.
 *
 * Return: 0 on success, error code otherwise.
 */
int qat_dbg_init_instance_sysfs(struct adf_accel_dev *accel_dev,
				struct qatd_instance_config *config)
{
	if (!accel_dev)
		return -EFAULT;

	if (adf_dev_started(accel_dev)) {
		if (adf_devmgr_in_reset(accel_dev) ||
		    adf_dev_in_use(accel_dev)) {
			dev_err(&GET_DEV(accel_dev), "Device busy\n");
			return -EBUSY;
		}
	}

	return qat_dbg_init_instance_internal(accel_dev, config);
}

/**
 * qat_dbg_init_instance() - Initialize debuggability instance
 * @accel_dev: Pointer to acceleration device.
 *
 * Function initializes debuggability instance.
 *
 * Return: 0 on success, error code otherwise.
 */
int qat_dbg_init_instance(struct adf_accel_dev *accel_dev)
{
	if (!accel_dev)
		return -EFAULT;

	if (qat_dbg_is_enabled(accel_dev))
		return 0;

	if (adf_dev_started(accel_dev)) {
		if (adf_devmgr_in_reset(accel_dev) ||
		    adf_dev_in_use(accel_dev)) {
			dev_err(&GET_DEV(accel_dev), "Device busy\n");
			return -EBUSY;
		}
	} else {
		dev_err(&GET_DEV(accel_dev), "Device not started\n");
		return -EFAULT;
	}

	return qat_dbg_init_instance_internal(accel_dev, NULL);
}

/**
 * qat_dbg_shutdown_instance() - Shutdown debuggability instance
 * @accel_dev: Pointer to acceleration device.
 *
 * Function shuts down debuggability instance.
 */
void qat_dbg_shutdown_instance(struct adf_accel_dev *accel_dev)
{
	struct qatd_instance *dbg_inst;

	if (!accel_dev)
		return;

	if (adf_dev_started(accel_dev)) {
		if (adf_devmgr_in_reset(accel_dev) ||
		    adf_dev_in_use(accel_dev)) {
			dev_err(&GET_DEV(accel_dev), "Device busy\n");
			return;
		}
	}

	mutex_lock(&qat_dbg_mutex);

	dbg_inst = accel_dev->qatd_instance;
	if (!dbg_inst)
		goto out;

	/* Sending K2U shutdown notification */
	adf_dev_dbg_shutdown_notify(accel_dev);

	mutex_destroy(&dbg_inst->mutex);

	qat_dbg_buffer_shutdown_all(dbg_inst);

	kfree(dbg_inst);

	accel_dev->qatd_instance = NULL;

	dev_info(&GET_DEV(accel_dev),
		 "Successfully released dbg buffer mem pool\n");
out:
	mutex_unlock(&qat_dbg_mutex);
}

/**
 * qat_dbg_restart_instance() - Restart debuggability instance
 * @accel_dev: Pointer to acceleration device.
 *
 * Function restarts debuggability instance.
 */
int qat_dbg_restart_instance(struct adf_accel_dev* accel_dev)
{
	struct qatd_instance *dbg_inst;

	if (!accel_dev)
		return -EFAULT;

	if (qat_dbg_is_enabled(accel_dev))
		return 0;

	if (adf_dev_started(accel_dev)) {
		if (adf_dev_in_use(accel_dev)) {
			dev_err(&GET_DEV(accel_dev), "Device busy\n");
			return -EBUSY;
		}
	} else {
		dev_err(&GET_DEV(accel_dev), "Device not started\n");
		return -EFAULT;
	}

	dbg_inst = accel_dev->qatd_instance;
	if (!dbg_inst)
	{
		dev_err(&GET_DEV(accel_dev),
			"QAT: Requested dbg instance is NULL\n");
		return -EINVAL;
	}

	mutex_lock(&dbg_inst->mutex);
	dbg_inst->last_crash_ts = 0;
	mutex_unlock(&dbg_inst->mutex);

	return 0;
}

/**
 * qat_dbg_unregister_handler() - Unregister debuggability handler
 *
 * Function unregister debuggability handler.
 */
void qat_dbg_unregister_handler(void)
{
	struct adf_accel_dev *accel_dev;
	u32 id;

	for (id = 0; id < ADF_MAX_DEVICES; id++) {
		accel_dev = qatd_get_dev_by_id(id);
		if (!accel_dev || !accel_dev->qatd_instance)
			continue;

		qat_dbg_shutdown_instance(accel_dev);
	}

	qat_dbg_phy_map_free();
}

/**
 * qat_dbg_init_instance_vf() - Initialize debuggability instance for VF
 * @vf_info: Pointer to acceleration device Virtual Function structure.
 *
 * Function initializes debuggability instance for detached VF.
 *
 * Return: 0 on success, error code otherwise.
 */
int qat_dbg_init_instance_vf(struct adf_accel_vf_info *vf_info)
{
	/* Add only debuggability sysfs for detached VF */
	return qat_dbg_sysfs_cfg_add_vf(vf_info);
}

/**
 * qat_dbg_shutdown_instance_vf() - Shutdown debuggability VF instance
 * @vf_info:       Pointer to acceleration device Virtual Function structure.
 * @remove_sysfs:  If true the instance will not be able to reconfigure.
 *
 * Function shuts down debuggability detached VF instance.
 */
void qat_dbg_shutdown_instance_vf(struct adf_accel_vf_info *vf_info,
				  bool remove_sysfs)
{
	struct adf_accel_dev *accel_dev;
	struct adf_pci_address pci_addr;

	if (!vf_info)
		return;

	accel_dev = vf_info->qatd_fake_dev;
	if (accel_dev) {
		adf_devmgr_get_dev_pci_addr(accel_dev, &pci_addr);
		dev_info(&GET_DEV(accel_dev),
			 "Removing Debuggability configuration for device "
			 "%04x:%02x:%02x.%x\n",
			 pci_domain_nr(accel_to_pci_dev(accel_dev)->bus),
			 pci_addr.bus,
			 pci_addr.dev,
			 pci_addr.func);

		qat_dbg_shutdown_instance(accel_dev);
		adf_devmgr_rm_fake_dev(accel_dev);
		vf_info->qatd_fake_dev = NULL;
	}
	if (remove_sysfs)
		qat_dbg_sysfs_cfg_del_vf(vf_info);
}
