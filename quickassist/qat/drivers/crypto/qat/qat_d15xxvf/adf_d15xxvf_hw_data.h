/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2016 - 2019, 2021 Intel Corporation */
#ifndef ADF_D15XXVF_HW_DATA_H_
#define ADF_D15XXVF_HW_DATA_H_

#define ADF_D15XXIOV_PMISC_BAR 1
#define ADF_D15XXIOV_ACCELERATORS_MASK 0x1
#define ADF_D15XXIOV_ACCELENGINES_MASK 0x1
#define ADF_D15XXIOV_MAX_ACCELERATORS 1
#define ADF_D15XXIOV_MAX_ACCELENGINES 1
#define ADF_D15XXIOV_RX_RINGS_OFFSET 8
#define ADF_D15XXIOV_TX_RINGS_MASK 0xFF
#define ADF_D15XXIOV_ETR_BAR 0
#define ADF_D15XXIOV_ETR_MAX_BANKS 1
#define ADF_D15XXIOV_PF2VF_OFFSET	0x200
#define ADF_D15XXIOV_VINTMSK_OFFSET	0x208
#define ADF_D15XX_VFFUSECTL_OFFSET 0x40
#define ADF_D15XX_VFLEGFUSE_OFFSET 0x4C

#define ADF_D15XX_AE_FREQ (685 * 1000000)

void adf_init_hw_data_d15xxiov(struct adf_hw_device_data *hw_data);
void adf_clean_hw_data_d15xxiov(struct adf_hw_device_data *hw_data);
#endif
