/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2019, 2021 Intel Corporation */

#ifndef ADF_CTL_RL_H_
#define ADF_CTL_RL_H_

int adf_ctl_ioctl_sla_create(unsigned long arg);
int adf_ctl_ioctl_sla_update(unsigned long arg);
int adf_ctl_ioctl_sla_delete(unsigned long arg);
int adf_ctl_ioctl_sla_get_caps(unsigned long arg);
int adf_ctl_ioctl_sla_get_list(unsigned long arg);
int adf_ctl_ioctl_du_start(unsigned long arg);
int adf_ctl_ioctl_du_stop(unsigned long arg);
int adf_ctl_ioctl_du_query(unsigned long arg);
int adf_ctl_ioctl_du_query_vf(unsigned long arg);

#endif
