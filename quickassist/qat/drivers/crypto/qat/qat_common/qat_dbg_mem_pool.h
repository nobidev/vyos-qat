/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2021 Intel Corporation */

/***************************************************************************
 * @file qat_dbg_mem_pool.h
 *
 * This file provides Linux kernel QAT debug memory pool utilities.
 *
 ***************************************************************************/

#ifndef QAT_DBG_MEM_POOL_H_
#define QAT_DBG_MEM_POOL_H_

#include "qat_dbg.h"

struct qatd_buffer_desc *qat_dbg_buffer_get(struct qatd_instance *dbg_inst,
					      unsigned int buffer_id);

int qat_dbg_buffer_init_all(struct qatd_instance *dbg_inst);
int qat_dbg_buffer_shutdown_all(struct qatd_instance *dbg_inst);
int qat_dbg_buffer_alloc(struct qatd_instance *dbg_inst, int pid,
			  int *buffer_id);
void qat_dbg_buffer_release(struct qatd_instance *dbg_inst,
			     unsigned int buffer_id);
int qat_dbg_buffer_release_all(struct qatd_instance *dbg_inst, int pid);
void qat_dbg_buffer_clean(struct qatd_instance *dbg_inst,
			   unsigned int buffer_id);

#endif /* QAT_DBG_MEM_POOL_H_ */
