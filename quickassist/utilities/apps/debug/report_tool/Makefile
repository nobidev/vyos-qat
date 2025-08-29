################################################################
# This file is provided under a dual BSD/GPLv2 license.  When using or
#   redistributing this file, you may do so under either license.
# 
#   GPL LICENSE SUMMARY
# 
#   Copyright(c) 2007-2023 Intel Corporation. All rights reserved.
# 
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of version 2 of the GNU General Public License as
#   published by the Free Software Foundation.
# 
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   General Public License for more details.
# 
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
#   The full GNU General Public License is included in this distribution
#   in the file called LICENSE.GPL.
# 
#   Contact Information:
#   Intel Corporation
# 
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
# 
#  version: QAT.L.4.24.0-00005
################################################################
# Ensure The ICP_ENV_DIR environmental var is defined.
ifndef ICP_ENV_DIR
$(error ICP_ENV_DIR is undefined. Please set the path to your environment makefile \
        "-> setenv ICP_ENV_DIR <path>")
endif
ICP_OS_LEVEL=user_space

# Include the makefile with all the default and common Make variable definitions
include $(ICP_BUILDSYSTEM_PATH)/build_files/common.mk
EXE_FLAGS+=$(ICP_BUILD_OUTPUT)/libosal.a

ifeq ($(ICP_ARCH_USER), i386)
EXTRA_CFLAGS += -m32
EXE_FLAGS += -m32
endif

ifeq ($(ICP_ARCH_USER), i686)
EXTRA_CFLAGS += -m32
EXE_FLAGS += -m32
EXTRA_CFLAGS += -march=i686
endif
EXTRA_CFLAGS += -DUSER_SPACE
INT_INCLUDES=$(addprefix -I, $(shell ls -d $(QAT_DIRECT_ROOT)/src/include/*/ $(QAT_DIRECT_ROOT)/src/uio)
EXT_INCLUDES=$(addprefix -I, $(QAT_DIRECT_ROOT)/src/include $(SAL_DIR)/linux/include)

REF_INCLUDES=$(addprefix -I, $(ICP_ROOT)/quickassist/utilities/libusdm_drv \
                $(OSAL_DIR)/include \
                $(OSAL_DIR)/src/linux/user_space/include \
                $(API_DIR)/ \
                $(API_DIR)/lac \
                $(API_DIR)/dc \
                $(ICP_ROOT)/quickassist/lookaside/firmware/include \
                $(ICP_ROOT)/quickassist/lookaside/access_layer/include \
                $(ICP_ROOT)/quickassist/lookaside/access_layer/src/common/crypto/sym/include \
                $(ICP_ROOT)/quickassist/lookaside/access_layer/src/common/compression/include \
                $(ICP_ROOT)/quickassist/qat/drivers/crypto/qat/qat_common \
                $(ICP_ROOT)/quickassist/lookaside/access_layer/src/qat_direct/src/include \
                $(ICP_ROOT)/quickassist/lookaside/access_layer/src/qat_direct/src/common/include \
                $(LAC_DIR)/src/common/include)

ifeq ($(CXX), icpc)
CXXFLAGS += -Wwrite-strings -std=c++0x
else
CXXFLAGS += -Wwrite-strings -std=c++0x -Wno-stringop-truncation
endif
BUILD    := ./build
OBJ_DIR  := $(BUILD)/
APP_DIR  := $(BUILD)/
TARGET   := qat_dbg_report
INCLUDE  :=
SRC      := $(wildcard *.cpp)

OBJECTS  := $(SRC:%.cpp=$(OBJ_DIR)/%.o)
INCLUDE += $(REF_INCLUDES)

all: build $(APP_DIR)/$(TARGET)

$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(EXTRA_CFLAGS) $(INCLUDE) -c $< -o $@ $(LDFLAGS)

$(APP_DIR)/$(TARGET): $(OBJECTS)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -o $(APP_DIR)/$(TARGET) $^ $(LDFLAGS) $(EXE_FLAGS)

.PHONY: all build clean debug release

build:
	@mkdir -p $(APP_DIR)
	@mkdir -p $(OBJ_DIR)

debug: CXXFLAGS += -DDEBUG -g
debug: all

release: CXXFLAGS += -O2
release: all

clean:
	-@rm -rvf $(OBJ_DIR)/*
	-@rm -rvf $(APP_DIR)/*
