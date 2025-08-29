#########################################################################
#
# @par
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
############################################################################

####################Common variables and definitions########################
# Ensure The ICP_ENV_DIR environmental var is defined.
ifndef ICP_ENV_DIR
$(error ICP_ENV_DIR is undefined. Please set the path to your environment makefile \
        "-> setenv ICP_ENV_DIR <path>")
endif

#Add your project environment Makefile
include $(ICP_ENV_DIR)/environment.mk
#Lac include paths
include $(LAC_DIR)/common.mk
#include the makefile with all the default and common Make variable definitions
include $(ICP_BUILDSYSTEM_PATH)/build_files/common.mk

#Add the name for the executable, Library or Module output definitions
OUTPUT_NAME=compression

# List of Source Files to be compiled (to be in a single line or on different lines separated by a "\" and tab.
SOURCES=dc_datapath.c \
	dc_header_footer.c \
	dc_ns_datapath.c \
	dc_ns_header_footer.c \
	dc_session.c \
	dc_dp.c \
	dc_stats.c \
	icp_sal_dc_err_sim.c \
	dc_buffers.c

ifeq ($(ICP_OS_LEVEL), user_space)
SOURCES+=dc_chain.c
endif

ifeq ($(ICP_OS_LEVEL), user_space)
SOURCES+=dc_crc32.c
endif

ifeq ($(ICP_DC_ERROR_SIMULATION),1)
SOURCES+=dc_err_sim.c
endif

#common includes between all supported OSes
INCLUDES+=-I$(LAC_DIR)/src/common/compression/include \
	      -I$(API_DIR)/dc

#include your $(ICP_OS)_$(ICP_OS_LEVEL).mk file
include $(ICP_ENV_DIR)/$(ICP_OS)_$(ICP_OS_LEVEL).mk

ifeq ($(ICP_OS_LEVEL),user_space)
EXTRA_CFLAGS += -DUSER_SPACE
# QAT Debuggability
ifeq ($(ICP_QAT_DBG),y)
EXTRA_CFLAGS+=-DICP_QAT_DBG
endif
else
EXTRA_CFLAGS += -DKERNEL_SPACE

# Check for defense with stack protection in kernel
ifeq ($(KERNEL_DEFENSES_STACK_PROTECTION), n)
STACK_PROTECTION=-fstack-protector -fstack-protector-strong
EXTRA_CFLAGS := $(filter-out $(STACK_PROTECTION), $(EXTRA_CFLAGS))
endif
endif

ifeq ($(ICP_DC_RETURN_COUNTERS_ON_ERROR),1)
EXTRA_CFLAGS += -DICP_DC_RETURN_COUNTERS_ON_ERROR
endif



ifeq ($(ICP_DC_ERROR_SIMULATION),1)
EXTRA_CFLAGS += -DICP_DC_ERROR_SIMULATION
endif

ifdef ICP_DC_ONLY
EXTRA_CFLAGS += -DICP_DC_ONLY
endif

ifeq ($(ICP_ARCH_USER),i386)
NASM_CFLAGS = -f elf32
else ifeq ($(ICP_ARCH_USER),i686)
NASM_CFLAGS = -f elf32
else
NASM_CFLAGS = -f elf64
endif

ifdef ICP_TRACE
EXTRA_CFLAGS += -DICP_TRACE
endif

ifdef ICP_DC_DYN_NOT_SUPPORTED
EXTRA_CFLAGS += -DICP_DC_DYN_NOT_SUPPORTED
endif

ifeq ($(CNV_STRICT_MODE),1)
EXTRA_CFLAGS += -DCNV_STRICT_MODE
endif

# On the line directly below list the outputs you wish to build for
install: lib_static
ifeq ($(ICP_OS_LEVEL), user_space)
ADDITIONAL_OBJECTS+=$(LAC_DIR)/src/common/compression/build/linux_2.6/user_space/crc32_gzip_refl_by8.o
lib_static: crc32_gzip_refl_by8.o
install: lib_static

crc32_gzip_refl_by8.o: crc32_gzip_refl_by8.S
	mkdir -p build/linux_2.6/user_space
	nasm $(NASM_CFLAGS) -D LINUX -X gnu crc32_gzip_refl_by8.S \
	  -o build/linux_2.6/user_space/crc32_gzip_refl_by8.o\
	                   || echo "ASM compilation failed, check nasm availability";
endif
###################Include rules makefiles########################
include $(ICP_BUILDSYSTEM_PATH)/build_files/rules.mk
###################End of Rules inclusion#########################

