/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2021 - 2022 Intel Corporation */
#ifndef QAT_DBG_H_
#define QAT_DBG_H_

#include "qat_dbg_user.h"
#include "adf_accel_devices.h"
#include "adf_common_drv.h"

#define QATD_DETACHED_VF_NAME_SUFFIX "_vf"

struct qatd_instance {
	/* Configuration */
	struct qatd_instance_config config;
	/* Used to calculate debounce time */
	unsigned long last_crash_ts;
	/* Mutex instance */
	struct mutex mutex;
	/* Buffers for each device */
	struct qatd_buffer_desc *dma_buffers_mng;
} __packed __aligned(64);

int qat_dbg_init_instance(struct adf_accel_dev *accel_dev);
void qat_dbg_shutdown_instance(struct adf_accel_dev *accel_dev);
int qat_dbg_init_instance_vf(struct adf_accel_vf_info *vf_info);
void qat_dbg_shutdown_instance_vf(struct adf_accel_vf_info *vf_info,
				  bool remove_sysfs);
int qat_dbg_init_instance_sysfs(struct adf_accel_dev *accel_dev,
				struct qatd_instance_config *config);
int qat_dbg_restart_instance(struct adf_accel_dev *accel_dev);

int qat_dbg_handle_status_request(struct qatd_ioctl_req *req);
int qat_dbg_handle_buffer_request(struct qatd_ioctl_req *req);
int qat_dbg_handle_release_request(struct qatd_ioctl_req *req);
int qat_dbg_handle_sync_request(struct qatd_ioctl_req *req);
int qat_dbg_handle_manual_dump_request(struct qatd_ioctl_req *req);
int qat_dbg_handle_err_resp_request(struct qatd_ioctl_req *req);

void qat_dbg_unregister_handler(void);
int qat_dbg_mmap_handler(int buffer_idx, int dbg_inst_idx,
			 int size, struct qatd_ring_desc **ring);
int qat_dbg_open_handler(void);
int qat_dbg_release_handler(int pid);

void qat_dbg_fatal_error_handler(struct adf_accel_dev *accel_dev);
void qat_dbg_proc_crash_handler(struct adf_accel_dev *accel_dev);
void qat_dbg_err_resp_handler(struct adf_accel_dev *accel_dev);

#endif /* QAT_DBG_H_ */
