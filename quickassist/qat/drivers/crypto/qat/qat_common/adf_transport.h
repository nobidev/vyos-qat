/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2014, 2018, 2021 Intel Corporation */
#ifndef ADF_TRANSPORT_H
#define ADF_TRANSPORT_H

#include "adf_accel_devices.h"

struct adf_etr_ring_data;

typedef void (*adf_callback_fn)(void *resp_msg);

int adf_create_ring(struct adf_accel_dev *accel_dev, const char *section,
		    uint32_t bank_num, uint32_t num_mgs, uint32_t msg_size,
		    const char *ring_name, adf_callback_fn callback,
		    int poll_mode, struct adf_etr_ring_data **ring_ptr);

int adf_recreate_ring(struct adf_accel_dev *accel_dev, const char *section,
		      uint32_t bank_num, uint32_t num_mgs, uint32_t msg_size,
		      const char *ring_name, adf_callback_fn callback,
		      int poll_mode, struct adf_etr_ring_data **ring_ptr);

bool adf_ring_nearly_full(struct adf_etr_ring_data *ring);
int adf_send_message(struct adf_etr_ring_data *ring, uint32_t *msg);
void adf_remove_ring(struct adf_etr_ring_data *ring);
void adf_reset_ring(struct adf_etr_ring_data *ring);
int adf_poll_bank(u32 accel_id, u32 bank_num, u32 quota);
int adf_poll_all_banks(u32 accel_id, u32 quota);
#endif
