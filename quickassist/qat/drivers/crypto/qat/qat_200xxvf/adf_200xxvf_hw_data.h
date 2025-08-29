/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2020 - 2021 Intel Corporation */
#ifndef ADF_200XXVF_HW_DATA_H_
#define ADF_200XXVF_HW_DATA_H_

#define ADF_200XXIOV_PMISC_BAR 1
#define ADF_200XXIOV_ACCELERATORS_MASK 0x1
#define ADF_200XXIOV_ACCELENGINES_MASK 0x1
#define ADF_200XXIOV_MAX_ACCELERATORS 1
#define ADF_200XXIOV_MAX_ACCELENGINES 1
#define ADF_200XXIOV_RX_RINGS_OFFSET 8
#define ADF_200XXIOV_TX_RINGS_MASK 0xFF
#define ADF_200XXIOV_ETR_BAR 0
#define ADF_200XXIOV_ETR_MAX_BANKS 1
#define ADF_200XXIOV_PF2VF_OFFSET	0x200
#define ADF_200XXIOV_VINTMSK_OFFSET	0x208
#define ADF_200XX_VFFUSECTL_OFFSET 0x40
#define ADF_200XX_VFLEGFUSE_OFFSET 0x4C

#define ADF_200XX_AE_FREQ (685 * 1000000)
void adf_init_hw_data_200xxiov(struct adf_hw_device_data *hw_data);
void adf_clean_hw_data_200xxiov(struct adf_hw_device_data *hw_data);
#endif
