/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2021 - 2022 Intel Corporation */
#ifndef QAT_DBG_CFG_H_
#define QAT_DBG_CFG_H_

#include "qat_dbg.h"

#define QATD_BUF_POOL_MIN 50
#define QATD_BUF_POOL_MIN_VF 2
#define QATD_BUF_POOL_MAX 2000
#define QATD_BUF_SIZE_MIN 2
#define QATD_BUF_SIZE_MAX 4
#define QATD_SYNC_FILES_MIN 10
#define QATD_SYNC_FILES_MAX 100
#define QATD_SYNC_FILE_SZ_MIN 100
#define QATD_SYNC_FILE_SZ_MAX 1000
#define QATD_DUMP_DIR_SZ_MIN 1024

int qat_dbg_is_enabled(struct adf_accel_dev *accel_dev);

int qat_dbg_configure_instance(struct qatd_instance *inst,
			       struct adf_accel_dev *accel_dev);

#endif /* QAT_DBG_CFG_H_ */
