########################################################################
#  SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
#  Copyright(c) 2014 - 2017, 2020 - 2021, 2023 Intel Corporation
########################################################################
obj-$(CONFIG_CRYPTO_DEV_QAT) += qat_common/
obj-$(CONFIG_CRYPTO_DEV_QAT_DH895xCC) += qat_dh895xcc/
obj-$(CONFIG_CRYPTO_DEV_QAT_C62X) += qat_c62x/

ifndef QAT_XEN_PLATFORM
obj-$(CONFIG_CRYPTO_DEV_QAT_C3XXX) += qat_c3xxx/
obj-$(CONFIG_CRYPTO_DEV_QAT_200XX) += qat_200xx/
obj-$(CONFIG_CRYPTO_DEV_QAT_C4XXX) += qat_c4xxx/
obj-$(CONFIG_CRYPTO_DEV_QAT_DH895xCCVF) += qat_dh895xccvf/
obj-$(CONFIG_CRYPTO_DEV_QAT_C3XXXVF) += qat_c3xxxvf/
obj-$(CONFIG_CRYPTO_DEV_QAT_C62XVF) += qat_c62xvf/
obj-$(CONFIG_CRYPTO_DEV_QAT_D15XX) += qat_d15xx/
obj-$(CONFIG_CRYPTO_DEV_QAT_D15XXVF) += qat_d15xxvf/
obj-$(CONFIG_CRYPTO_DEV_QAT_200XXVF) += qat_200xxvf/
obj-$(CONFIG_CRYPTO_DEV_QAT_C4XXXVF) += qat_c4xxxvf/
endif

subdir-ccflags-$(QAT_UIO) += -DQAT_UIO=y
subdir-ccflags-$(QAT_LEGACY_ALGORITHMS) += -DQAT_LEGACY_ALGORITHMS=n
subdir-ccflags-$(ALLOW_SLICE_HANG_INTERRUPT) += -DALLOW_SLICE_HANG_INTERRUPT=n





