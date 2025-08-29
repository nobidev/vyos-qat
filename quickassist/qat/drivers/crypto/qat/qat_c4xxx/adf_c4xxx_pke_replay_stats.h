/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2019, 2021 Intel Corporation */

#ifndef ADF_C4XXX_PKE_REPLAY_STATS_H_
#define ADF_C4XXX_PKE_REPLAY_STATS_H_

#include "adf_accel_devices.h"

int adf_pke_replay_counters_add_c4xxx(struct adf_accel_dev *accel_dev);
void adf_pke_replay_counters_remove_c4xxx(struct adf_accel_dev *accel_dev);

#endif

