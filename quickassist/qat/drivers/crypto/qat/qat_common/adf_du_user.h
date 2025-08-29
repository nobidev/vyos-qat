/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2019, 2021 Intel Corporation */
#ifndef ADF_DU_USER_H_
#define ADF_DU_USER_H_

#include "adf_cfg_common.h"

#define ALL_VF_DU UINT_MAX
/*
 * struct adf_user_du - to be used with:
 * IOCTL_DU_QUERY to get utilization for device.
 *
 * @pf_addr:		Bus Device Function of the PF
 * @vf_addr:		Bus Device Function of the VF
 * @svc_type:		service type to measure device utilization
 * @slau_supported:	for PF, it is total device capacity
 *			for VF, it is user configured SLA
 * @slau_utilized:	returned value of utilization of given service
 * @slau_util_percent:  slau percentage computed against device capacity
 */
struct adf_user_du {
	struct adf_pci_address pf_addr;
	struct adf_pci_address vf_addr;
	enum adf_svc_type svc_type;
	u32 slau_supported;
	u32 slau_utilized;
	u16 slau_util_percent;
};

#endif
