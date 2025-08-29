/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2021 - 2022 Intel Corporation */
#ifndef QAT_DBG_PHY_MAP_H_
#define QAT_DBG_PHY_MAP_H_

ssize_t qat_dbg_phy_map_read(char *buff, size_t len, loff_t *off);
void qat_dbg_phy_map_store(struct adf_accel_dev *accel_dev);
void qat_dbg_phy_map_copy(struct adf_accel_dev *accel_dev_dst,
			  struct adf_accel_dev *accel_dev_src);
void qat_dbg_phy_map_free(void);

#endif /* QAT_DBG_PHY_MAP_H_ */
