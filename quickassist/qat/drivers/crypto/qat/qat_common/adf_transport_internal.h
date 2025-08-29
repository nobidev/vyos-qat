/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2014 - 2018, 2020 - 2021 Intel Corporation */
#ifndef ADF_TRANSPORT_INTRN_H
#define ADF_TRANSPORT_INTRN_H

#include <linux/interrupt.h>
#include <linux/spinlock_types.h>
#include "adf_transport.h"

struct adf_etr_ring_debug_entry {
	char ring_name[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
	struct dentry *debug;
};

struct adf_etr_ring_data {
	void *base_addr;
	atomic_t *inflights;
	adf_callback_fn callback;
	struct adf_etr_bank_data *bank;
	dma_addr_t dma_addr;
	struct adf_etr_ring_debug_entry *ring_debug;
	u32 head;
	u32 tail;
	u32 csr_tail_offset;
	u32 max_inflights;
	u32 threshold;
	spinlock_t lock;	/* protects ring data struct */
	uint8_t ring_number;
	uint8_t ring_size;
	uint8_t msg_size;
	uint8_t reserved;
};

struct adf_etr_bank_data {
	struct adf_etr_ring_data *rings;
	struct work_struct resp_handler_wq;
	void __iomem *csr_addr;
	struct adf_accel_dev *accel_dev;
	uint32_t irq_coalesc_timer;
	uint16_t ring_mask;
	uint16_t irq_mask;
	struct dentry *bank_debug_dir;
	struct dentry *bank_debug_cfg;
	spinlock_t lock;	/* protects bank data struct */
	uint32_t bank_number;
};

struct adf_etr_data {
	struct adf_etr_bank_data *banks;
	struct dentry *debug;
};

void adf_response_handler_wq(struct work_struct *data);
int adf_handle_response(struct adf_etr_ring_data *ring, u32 quota);
bool adf_check_resp_ring(struct adf_etr_ring_data *ring);

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
int adf_bank_debugfs_add(struct adf_etr_bank_data *bank);
void adf_bank_debugfs_rm(struct adf_etr_bank_data *bank);
int adf_ring_debugfs_add(struct adf_etr_ring_data *ring, const char *name);
void adf_ring_debugfs_rm(struct adf_etr_ring_data *ring);
#else
static inline int adf_bank_debugfs_add(struct adf_etr_bank_data *bank)
{
	return 0;
}

static inline void adf_bank_debugfs_rm(struct adf_etr_bank_data *bank)
{
}

static inline int adf_ring_debugfs_add(struct adf_etr_ring_data *ring,
				       const char *name)
{
	return 0;
}

static inline void adf_ring_debugfs_rm(struct adf_etr_ring_data *ring)
{
}
#endif
#endif
