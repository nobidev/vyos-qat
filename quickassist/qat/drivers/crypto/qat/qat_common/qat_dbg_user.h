/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2021 - 2022 Intel Corporation */
#ifndef QAT_DBG_USER_H_
#define QAT_DBG_USER_H_

#include "qat_dbg_common.h"

#define QATD_POOL_SIZE_SHIFT 10
#define QATD_MAX_POOL_SIZE BIT(QATD_POOL_SIZE_SHIFT)
#define QATD_BUFFER_ID_MASK (QATD_MAX_POOL_SIZE - 1)

struct qatd_ring_desc {
	/* Segment identifier */
	unsigned int buffer_id;
	/* Debug level */
	unsigned int log_level;
	/* Entries to log counter */
	unsigned int log_entries;
	/* Entries to log counter */
	unsigned int log_entries_all;
	/* Ring buffer size */
	unsigned int ring_size;
	/* Last error timestamp */
	unsigned long long last_ts;
	/* Counter of buffer overlaps */
	unsigned int overlaps;
	/* Message head */
	unsigned int head;
	/* Message tail */
	unsigned int tail;
	/* Message end */
	unsigned int end;
} __packed __aligned(64);

struct qatd_ioctl_req {
	/* Segment identifier */
	unsigned int buffer_id;
	/* Instance identifier */
	unsigned int instance_id;
	/* Request result; 0 on success */
	int request_result;
	/* Debuggability status; on vs off */
	int status;
	/* Debug level */
	unsigned int debug_level;
	/* Sync mode - continuous vs dump on crash */
	unsigned int sync_mode;
	/* Segment address */
	unsigned int buffer_addr;
	/* Buffer size */
	unsigned int buffer_sz;
	/* Virtual request source address */
	void *src_virt;
	/* Virtual request destination address */
	void *dst_virt;
	/* Physical request source address */
	unsigned long src_phys;
	/* Physical request destination address */
	unsigned long dst_phys;
} __packed __aligned(64);

struct qatd_ioctl_bsf2id_req {
	/* PCI domain */
	int domain;
	/* PCI bus */
	u8 bus;
	/* PCI device (slot) */
	u8 dev;
	/* PCI function */
	u8 func;
	/* Request result; 0 on success */
	int request_result;
	/* Request response: accelerator id */
	u32 device_id;
};

#endif
