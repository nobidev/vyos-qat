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
include $(ICP_ENV_DIR)/environment.mk

IO?=uio
SUBDIRS=common $(IO)
BUILD_OUTPUT_DIR=build
LIB_STATIC=libadf_user.a

default: all

dirs:
	test -d $(BUILD_OUTPUT_DIR) || mkdir -p $(BUILD_OUTPUT_DIR);

libadf_$(IO).a:
	@$(MAKE) -C ./$(IO)

libadf_common.a:
	@$(MAKE) -C ./common

all: dirs libadf_$(IO).a libadf_common.a
	@for dir in $(SUBDIRS); do                                          \
	(cp $$dir/build/$(ICP_OS)/$(ICP_OS_LEVEL)/*.o $(BUILD_OUTPUT_DIR)   \
	    2>/dev/null;)                                                   \
	done;                                                               \
	echo "Creating static library $(LIB_STATIC)" ;                      \
	cmd="$(AR) rcs $(LIB_STATIC) $(BUILD_OUTPUT_DIR)/*.o";              \
	echo "$$cmd";                                                       \
	$$cmd

clean:
	$(MAKE) -C ./$(IO) clean
	$(MAKE) -C ./common clean
	@-rm -rf $(BUILD_OUTPUT_DIR)
	@-rm -f libadf_[a-z]*.a
