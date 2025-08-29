/*****************************************************************************
 *
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2023 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 *  version: QAT.L.4.24.0-00005
 *
 *****************************************************************************/
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "adf_kernel_types.h"
#include "adf_cfg_common.h"
#include "cpa.h"
#include "icp_platform.h"

#define ADF_CTL_DEVICE_NAME "/dev/qat_adf_ctl"

extern int adf_io_accel_dev_exist(int dev_id);

CpaStatus adf_io_getNumDevices(unsigned int *num_devices)
{
    int fd = -1;
    int res = 0;
    Cpa32U num_dev = 0;
    CpaStatus status = CPA_STATUS_FAIL;

    ICP_CHECK_FOR_NULL_PARAM(num_devices);
    *num_devices = 0;

    fd = open(ADF_CTL_DEVICE_NAME, O_RDONLY);
    if (fd < 0)
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    /* send the request down to get the device
     * information from kernel space. */
    res = ioctl(fd, IOCTL_GET_NUM_DEVICES, &num_dev);
    if (!res)
    {
        *num_devices = num_dev;
        status = CPA_STATUS_SUCCESS;
    }
    close(fd);

    return status;
}

CpaBoolean adf_io_isDeviceAvailable(void)
{
    Cpa32U num_devices = 0, dev_id = 0;

    if (adf_io_getNumDevices(&num_devices) == CPA_STATUS_SUCCESS)
        if (num_devices <= ADF_MAX_DEVICES)
            for (dev_id = 0; dev_id < num_devices; dev_id++)
                if (adf_io_accel_dev_exist(dev_id))
                    return CPA_TRUE;

    return CPA_FALSE;
}
