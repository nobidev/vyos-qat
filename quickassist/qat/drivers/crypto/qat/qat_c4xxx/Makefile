########################################################################
# SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
# Copyright(c) 2016 - 2017, 2019 - 2021 Intel Corporation
########################################################################

ccflags-y := -I$(src)/../qat_common
obj-$(CONFIG_CRYPTO_DEV_QAT_C4XXX) += qat_c4xxx.o
qat_c4xxx-objs := adf_drv.o adf_c4xxx_hw_data.o adf_c4xxx_accel_units.o \
		  adf_c4xxx_aram.o adf_c4xxx_arbiter.o \
		  adf_c4xxx_fw_load.o \
		  adf_c4xxx_reset.o adf_c4xxx_misc_error_stats.o \
		  adf_c4xxx_ras.o adf_c4xxx_pke_replay_stats.o \
		  adf_c4xxx_ae_config.o
