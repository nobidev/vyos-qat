/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2019, 2021 Intel Corporation */

#ifndef ADF_DU_H_
#define ADF_DU_H_

#include "adf_du_user.h"

int adf_du_start(struct adf_pci_address *pci_addr);
int adf_du_stop(struct adf_pci_address *pci_addr);
int adf_du_query(struct adf_user_du *du);
int adf_du_query_vf(struct adf_user_du *du);
#endif
