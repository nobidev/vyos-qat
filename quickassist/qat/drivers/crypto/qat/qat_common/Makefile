########################################################################
#  SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
#  Copyright(c) 2014 - 2021 Intel Corporation
########################################################################

obj-$(CONFIG_CRYPTO_DEV_QAT) += intel_qat.o
intel_qat-objs := adf_cfg.o \
	adf_isr.o \
	adf_ctl_drv.o \
	adf_common_drv.o \
	adf_dev_mgr.o \
	adf_dev_err.o \
	adf_init.o \
	adf_accel_engine.o \
	adf_aer.o \
	adf_transport.o \
	adf_admin.o \
	adf_hw_arbiter.o \
	adf_gen2_hw_data.o \
	adf_gen3_hw_data.o \
	adf_gen4_hw_data.o \
	qat_algs_send.o \
	qat_uclo.o \
	qat_hal.o \
	adf_cfg_dev_dbg.o \
	adf_heartbeat.o \
	adf_heartbeat_dbg.o \
	adf_ver_dbg.o \
	adf_clock.o \
	adf_pf2vf_dbg.o \
	adf_fw_counters.o \
	adf_cnvnr_freq_counters.o

ifeq ($(QAT_UIO), y)
ifeq ($(ICP_QAT_DBG), y)
intel_qat-objs += qat_dbg_drv.o \
	qat_dbg.o \
	qat_dbg_cfg.o \
	qat_dbg_mem_pool.o \
	qat_dbg_sysfs_cfg.o \
	qat_dbg_phy_map.o
endif
endif

ifeq ($(QAT_NO_LKCF), y)
intel_qat-objs += qat_crypto_stubs.o
else
intel_qat-objs += qat_crypto.o \
	qat_algs.o \
	qat_asym_algs.o
endif

intel_qat-$(CONFIG_DEBUG_FS) += adf_transport_debug.o
intel_qat-$(CONFIG_PCI_IOV) += adf_sriov.o adf_pf2vf_msg.o \
			       adf_vf2pf_msg.o adf_vf_isr.o \
			       adf_pf2vf_capabilities.o \
			       adf_pf2vf_ring_to_svc_map.o
