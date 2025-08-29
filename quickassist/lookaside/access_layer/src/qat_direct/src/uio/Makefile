################################################################
#   BSD LICENSE
# 
#   Copyright(c) 2007-2023 Intel Corporation. All rights reserved.
#   All rights reserved.
# 
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
# 
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
# 
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
#  version: QAT.L.4.24.0-00005
################################################################
# Ensure The ICP_ENV_DIR environmental var is defined.
ifndef ICP_ENV_DIR
$(error ICP_ENV_DIR is undefined. Please set the path to your environment makefile \
        "-> setenv ICP_ENV_DIR <path>")
endif

ICP_OS_LEVEL=user_space

#Add your project environment Makefile
include $(ICP_ENV_DIR)/environment.mk
include $(ICP_ENV_DIR)/$(ICP_OS)_$(ICP_OS_LEVEL).mk

#include the makefile with all the default and common Make variable definitions
include $(ICP_BUILDSYSTEM_PATH)/build_files/common.mk

OUTPUT_NAME=libadf_uio

SOURCES=$(wildcard *.c)

USE_LEGACY_TRANSPORTCTL=y
EXTRA_CFLAGS += -fno-strict-aliasing
EXTRA_CFLAGS += -DQAT_UIO
EXTRA_CFLAGS += -DUSER_SPACE
EXTRA_CFLAGS += -DUSE_ADF_DRV_HEADERS
EXTRA_CFLAGS += -DQAT_WITH_LIBUDEV


#common includes between all supported OSes
INT_INCLUDES=$(addprefix -I, $(shell ls -d $(QAT_DIRECT_ROOT)/src/common/include $(QAT_DIRECT_ROOT)/src/include))
EXT_INCLUDES=$(addprefix -I, $(QAT_DIRECT_ROOT)/src/include)
REF_INCLUDES=$(addprefix -I, $(ICP_ROOT)/quickassist/utilities/libusdm_drv \
                $(OSAL_DIR)/include \
                $(OSAL_DIR)/src/linux/user_space/include \
                $(API_DIR)/ \
                $(API_DIR)/lac \
                $(API_DIR)/dc \
                $(ICP_ROOT)/quickassist/lookaside/firmware/include \
                $(ICP_ROOT)/quickassist/qat/drivers/crypto/qat/qat_common \
                $(LAC_DIR)/src/common/include \
                $(LAC_DIR)/src/common/crypto/sym/include \
                $(LAC_DIR)/src/common/compression/include \
                $(LAC_DIR)/include)

CFLAGS+=$(REF_INCLUDES) $(INT_INCLUDES) $(EXT_INCLUDES)

# On the line directly below list the outputs you wish to build for,
# e.g "lib_static lib_shared exe module" as show below
install: lib_static

###################Include rules makefiles########################
include $(ICP_BUILDSYSTEM_PATH)/build_files/rules.mk
###################End of Rules inclusion#########################
