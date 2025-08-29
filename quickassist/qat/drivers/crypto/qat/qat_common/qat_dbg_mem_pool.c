// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2021 - 2022 Intel Corporation */

/***************************************************************************
 * @file qat_dbg_mem_pool.c
 *
 * This file provides Linux kernel QAT debug memory pool utilities.
 *
 ***************************************************************************/
#include "qat_dbg_mem_pool.h"
#include "adf_cfg_common.h"
#include "adf_accel_devices.h"

/**
 * qat_dbg_buffer_get() - Get debuggability buffer
 * @dbg_inst: Pointer to debuggability instance.
 * @buffer_id: debug buffer identifier.
 *
 * Function returns file buffer stored in debuggability instance.
 *
 * Return: pointer to qatd_buffer_desc on success, NULL otherwise
 */
struct qatd_buffer_desc *qat_dbg_buffer_get(struct qatd_instance *dbg_inst,
					      unsigned int buffer_id)
{
	if (!dbg_inst) {
		pr_err("QAT: NULL instance - buffer get failed\n");
		return NULL;
	}

	if (buffer_id >= dbg_inst->config.buffer_pool_size) {
		pr_err("QAT: Out of scope dbg buffer req: %d\n", buffer_id);
		return NULL;
	}

	return &dbg_inst->dma_buffers_mng[buffer_id];
}

/**
 * qat_dbg_buffer_init_all() - Initialize all debuggability buffers
 * @dbg_inst: Pointer to debuggability instance.
 *
 * Function initializes all debuggability buffers associated with provided
 * debuggability instance.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_buffer_init_all(struct qatd_instance *dbg_inst)
{
	unsigned int i;
	int success;
	struct qatd_buffer_desc *buffer;

	if (!dbg_inst) {
		pr_err("QAT: NULL instance - mem pool init failed\n");
		return -EFAULT;
	}

	dbg_inst->dma_buffers_mng =
		kcalloc(dbg_inst->config.buffer_pool_size,
			sizeof(*dbg_inst->dma_buffers_mng),
			GFP_KERNEL);

	if (!dbg_inst->dma_buffers_mng) {
		pr_err("QAT: Buffer descriptors memory allocation failed\n");
		return -ENOMEM;
	}

	for (i = 0, success = 0; i < dbg_inst->config.buffer_pool_size; i++) {
		struct qatd_ring_desc ring_desc = {
				.buffer_id = i,
				.log_level = 1,
				.log_entries = 0,
				.log_entries_all = 0,
				.ring_size = dbg_inst->config.buffer_size,
				.last_ts = 0,
				.overlaps = 0,
				.head = 0,
				.tail = 0,
				.end = 0
		};

		buffer = dbg_inst->dma_buffers_mng + i;
		buffer->state = QATD_BUFFER_FREE;
		buffer->owner_pid = 0;
		buffer->id = i;

		/* init this mmap area */
		buffer->ring =
			kzalloc(dbg_inst->config.buffer_size, GFP_KERNEL);
		if (!buffer->ring)
			goto fail;

		success++;
		memcpy(buffer->ring, &ring_desc, sizeof(struct qatd_ring_desc));
	}

	return 0;
fail:

	for (i = 0; i < success; i++) {
		buffer = dbg_inst->dma_buffers_mng + i;
		kfree(buffer->ring);
		buffer->ring = NULL;
	}

	kfree(dbg_inst->dma_buffers_mng);
	dbg_inst->dma_buffers_mng = NULL;

	return -ENOMEM;
}

/**
 * qat_dbg_buffer_shutdown_all() - Shut down all debuggability buffers
 * @dbg_inst: Pointer to debuggability instance.
 *
 * Function initializes all debuggability buffers associated with provided
 * debuggability instance.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_buffer_shutdown_all(struct qatd_instance *dbg_inst)
{
	int i;

	if (!dbg_inst) {
		pr_err("QAT: NULL instance - mem pool de-init failed\n");
		return -EFAULT;
	}

	for (i = 0; i < dbg_inst->config.buffer_pool_size; i++) {
		if (!dbg_inst->dma_buffers_mng[i].ring)
			continue;
		memset(dbg_inst->dma_buffers_mng[i].ring, 0,
		       dbg_inst->config.buffer_size);
		kfree(dbg_inst->dma_buffers_mng[i].ring);
		dbg_inst->dma_buffers_mng[i].ring = NULL;
	}

	kfree(dbg_inst->dma_buffers_mng);
	dbg_inst->dma_buffers_mng = NULL;

	return 0;
}

/**
 * qat_dbg_buffer_alloc() - Allocate debuggability buffers
 * @dbg_inst: Pointer to debuggability instance.
 * @pid: Process identifier.
 * @buffer_id: Buffer identifier.
 * Function sets up initial configuration of a first free buffer found in
 * debuggability instance, sets its state to busy and provides access to it via
 * buffer_id pointer.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_buffer_alloc(struct qatd_instance *dbg_inst, int pid,
			  int *buffer_id)
{
	unsigned int i;
	unsigned long long oldest_ts = 0;
	int buffer_candidate = -1;
	unsigned int buffers_in_sync = 0;

	if (!dbg_inst) {
		pr_err("QAT: NULL instance - buffer alloc failed\n");
		return -EINVAL;
	}

	for (i = 0; i < dbg_inst->config.buffer_pool_size; i++) {
		struct qatd_buffer_desc *buffer =
			dbg_inst->dma_buffers_mng + i;

		if (buffer->state == QATD_BUFFER_FREE)	{
			/* Get ring descriptor to check whether it might be
			 * written, based on timestamp of last detected error */
			struct qatd_ring_desc *ring_desc = buffer->ring;

			if (dbg_inst->config.sync_mode == QATD_SYNC_CONT) {
				if (ring_desc->head != ring_desc->tail) {
					buffers_in_sync++;
					continue;
				}
				ring_desc->head = 0;
				ring_desc->tail = 0;
				ring_desc->end = 0;
			}

			if (ring_desc->last_ts == 0) {
				buffer_candidate = i;
				break;
			}
			if (oldest_ts == 0 ||
			    oldest_ts > ring_desc->last_ts) {
				buffer_candidate = i;
				oldest_ts = ring_desc->last_ts;
			}
		}
	}

	if (buffer_candidate >= 0) {
		dbg_inst->dma_buffers_mng[buffer_candidate].owner_pid = pid;
		dbg_inst->dma_buffers_mng[buffer_candidate].state =
			QATD_BUFFER_BUSY;
		*buffer_id = buffer_candidate;
		return 0;
	}
	if (buffers_in_sync) {
		/* Segments not available due to sync in progress */
		return -EAGAIN;
	}

	/* No buffers available */
	return -ENOMEM;
}

/**
 * qat_dbg_buffer_clean() - Clean debuggability buffer
 * @dbg_inst: Pointer to debuggability instance.
 * @buffer_id: Pointer to debuggability buffer identifier.
 *
 * Function 'cleans' the buffer by setting ring buffer tail equal head and
 * setting end to zero.
 */
void qat_dbg_buffer_clean(struct qatd_instance *dbg_inst,
			   unsigned int buffer_id)
{
	struct qatd_buffer_desc *buffer = NULL;

	buffer = qat_dbg_buffer_get(dbg_inst, buffer_id);

	if (!buffer)
		return;

	buffer->ring->tail = buffer->ring->head;
	buffer->ring->end = 0;
}

/**
 * qat_dbg_buffer_release() - Release debuggability buffer
 * @dbg_inst: Pointer to debuggability instance.
 * @buffer_id: Pointer to debuggability buffer identifier.
 *
 * Function releases the provided debuggability buffer by setting it as free
 * and removing association with any process or thread identifier.
 */
void qat_dbg_buffer_release(struct qatd_instance *dbg_inst,
			     unsigned int buffer_id)
{
	struct qatd_buffer_desc *buffer = NULL;

	buffer = qat_dbg_buffer_get(dbg_inst, buffer_id);

	if (!buffer)
		return;

	buffer->state = QATD_BUFFER_FREE;
	buffer->owner_pid = 0;
}

/**
 * qat_dbg_buffer_release_all() - Release all debuggability buffers
 * @dbg_inst: Pointer to debuggability instance.
 * @pid: Process identifier.
 *
 * Function releases all debuggability buffers associated to provided process
 * identifier.
 *
 * Return: number of released debuggability buffers
 */
int qat_dbg_buffer_release_all(struct qatd_instance *dbg_inst, int pid)
{
	int i;
	int released_ctr = 0;

	for (i = 0; i < dbg_inst->config.buffer_pool_size; i++) {
		if (dbg_inst->dma_buffers_mng[i].owner_pid != pid)
			continue;

		if (dbg_inst->dma_buffers_mng[i].state != QATD_BUFFER_BUSY)
			continue;

		released_ctr++;
		qat_dbg_buffer_release(dbg_inst, i);
	}

	return released_ctr;
}
