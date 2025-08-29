########################################################################
#  SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
#  Copyright(c) 2015 - 2017, 2020 - 2021 Intel Corporation
########################################################################
export CONFIG_CRYPTO_DEV_QAT=m
export CONFIG_CRYPTO_DEV_QAT_DH895xCC=m
export CONFIG_CRYPTO_DEV_QAT_DH895xCCVF=m
export CONFIG_CRYPTO_DEV_QAT_C3XXX=m
export CONFIG_CRYPTO_DEV_QAT_C62X=m
export CONFIG_CRYPTO_DEV_QAT_C3XXXVF=m
export CONFIG_CRYPTO_DEV_QAT_C62XVF=m
export CONFIG_CRYPTO_DEV_QAT_C4XXX=m
export CONFIG_CRYPTO_DEV_QAT_C4XXXVF=m
export CONFIG_CRYPTO_DEV_QAT_D15XX=m
export CONFIG_CRYPTO_DEV_QAT_D15XXVF=m
export CONFIG_CRYPTO_DEV_QAT_200XX=m
export CONFIG_CRYPTO_DEV_QAT_200XXVF=m
export QAT_UIO?=y
export ICP_HB_FAIL_SIM?=n
export QAT_LEGACY_ALGORITHMS?=n

ifeq ($(ICP_HB_FAIL_SIM),y)
$(info Compiling with Heartbeat Failure Simulation feature)
endif

ifdef CONFIG_SUSE_KERNEL
subdir-ccflags-y += -DSUSE_MAJOR_VERSION=${QAT_SUSE_MAJOR_VERSION}
subdir-ccflags-y += -DSUSE_MINOR_VERSION=${QAT_SUSE_MINOR_VERSION}
endif

ifdef QAT_XEN_PLATFORM
subdir-ccflags-y += -DQAT_XEN_PLATFORM
endif

ifeq ($(KERNELRELEASE),)
KDIR ?= $(INSTALL_MOD_PATH)/lib/modules/$(shell uname -r)/build
ifneq ($(shell if [ -e $(KDIR)/include/config/auto.conf ]; then echo 1; fi),1)
  $(error ERROR: Kernel header files not found.  Install the appropriate \
    kernel development package necessary for building external kernel modules \
    or run 'make oldconfig && make modules_prepare' on kernel src to fix it)
endif
include $(KDIR)/include/config/auto.conf
INSTALL_FW_PATH ?= $(INSTALL_MOD_PATH)/lib/firmware

default: modules

# Error out on missing kernel config dependencies
CONFIG_%:
	$(if $($@), , $(error $@ not enabled in kernel configuration))

KCONFIG_DEP := CONFIG_X86 CONFIG_PCI CONFIG_CRYPTO CONFIG_CRYPTO_HW
KCONFIG_DEP += CONFIG_FW_LOADER
KCONFIG_DEP += CONFIG_CRYPTO_AEAD CONFIG_CRYPTO_AUTHENC CONFIG_CRYPTO_ALGAPI
KCONFIG_DEP += CONFIG_CRYPTO_AES CONFIG_CRYPTO_CBC
KCONFIG_DEP += CONFIG_CRYPTO_SHA1 CONFIG_CRYPTO_SHA256 CONFIG_CRYPTO_SHA512
ifeq ($(QAT_UIO),y)
KCONFIG_DEP += CONFIG_UIO
endif

modules: $(KCONFIG_DEP)
	$(MAKE) -C $(KDIR) M=$(CURDIR) $@

modules_install: modules
	@# Install the external/out-of-tree modules under the
	@# $(INSTALL_MOD_PATH)/lib/modules/$(KERNELRELEASE)/updates/
	@# directory in order to supersede any in-kernel modules with the
	@# same name.  Do not remove the latter modules as that could corrupt
	@# the package manager (e.g. rpm) database.
	$(MAKE) -C $(KDIR) M=$(CURDIR) INSTALL_MOD_DIR=updates $@

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) $@

help:
	@echo ''
	@echo '  Building external/out-of-tree Intel(R) QuickAssist Technology modules.'
	@echo ''
	@echo '  Syntax: make [install-location-options] [target]'
	@echo ''
	@echo '  install-location-options'
	@echo '    [KDIR=<path>]             - path to kernel source (default: running kernel)'
	@echo '    [INSTALL_MOD_PATH=<path>] - optional prefix to the default /lib/modules/...'
	@echo '    [INSTALL_FW_PATH=<path>]  - default: $$(INSTALL_MOD_PATH)/lib/firmware/'
	@echo ''
	@echo '  target'
	@echo '    [modules]                 - default target, build the module(s)'
	@echo '    {modules_install}         - install the module(s) and firmware'
	@echo '    {clean}                   - remove generated files'
	@echo ''

.PHONY: default modules modules_install clean help
else
subdir-ccflags-y += -include $(src)/compat/qat_compat.h
obj-m := drivers/crypto/qat/
endif
