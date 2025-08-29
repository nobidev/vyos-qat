/***************************************************************************
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
 ***************************************************************************/
#include <fcntl.h>
#include <sys/ioctl.h>

#include "cpa.h"
#include "adf_kernel_types.h"
#include "adf_cfg_user.h"
#include "icp_platform.h"
#include "icp_accel_devices.h"
#include "adf_user_cfg.h"

#include "adf_dev_ring_ctl.h"


static int open_dev()
{
    int file_desc = -1;

    file_desc = open(ADF_CTL_DEVICE_NAME, O_RDWR);
    if (file_desc < 0)
    {
        ADF_ERROR("Error: Failed to open device %s\n", ADF_CTL_DEVICE_NAME);
    }
    return file_desc;
}

static void close_dev(int fd)
{
    close(fd);
}

enum ring_ioctl_ops
{
    RING_OP_RESERVE,
    RING_OP_RELEASE,
    RING_OP_ENABLE,
    RING_OP_DISABLE
};

STATIC CpaStatus ring_ioctl(Cpa16U accel_id,
                            Cpa16U bank_nr,
                            Cpa16U ring_nr,
                            enum ring_ioctl_ops op)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    struct adf_user_reserve_ring reserve;
    int fd = open_dev();

    if (fd < 0)
        return CPA_STATUS_FAIL;

    reserve.accel_id = accel_id;
    reserve.bank_nr = bank_nr;
    reserve.ring_mask = 1 << ring_nr;

    switch (op)
    {
        case RING_OP_RESERVE:
            if (ioctl(fd, IOCTL_RESERVE_RING, &reserve) < 0)
                status = CPA_STATUS_FAIL;
            break;
        case RING_OP_RELEASE:
            if (ioctl(fd, IOCTL_RELEASE_RING, &reserve) < 0)
                status = CPA_STATUS_FAIL;
            break;
        case RING_OP_ENABLE:
            if (ioctl(fd, IOCTL_ENABLE_RING, &reserve) < 0)
                status = CPA_STATUS_FAIL;
            break;
        case RING_OP_DISABLE:
            if (ioctl(fd, IOCTL_DISABLE_RING, &reserve) < 0)
                status = CPA_STATUS_FAIL;
            break;
        default:
            ADF_ERROR("Error: invalid ring operation %d\n", op);
            status = CPA_STATUS_FAIL;
    }

    close_dev(fd);
    return status;
}

CpaStatus adf_io_reserve_ring(Cpa16U accel_id, Cpa16U bank_nr, Cpa16U ring_nr)

{
    return ring_ioctl(accel_id, bank_nr, ring_nr, RING_OP_RESERVE);
}

CpaStatus adf_io_release_ring(Cpa16U accel_id, Cpa16U bank_nr, Cpa16U ring_nr)
{
    return ring_ioctl(accel_id, bank_nr, ring_nr, RING_OP_RELEASE);
}

CpaStatus adf_io_enable_ring(adf_dev_ring_handle_t *ring)
{
    ICP_CHECK_FOR_NULL_PARAM(ring);
    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(ring->accel_dev, CPA_STATUS_FAIL);

    return ring_ioctl(ring->accel_dev->accelId,
                      ring->bank_num,
                      ring->ring_num,
                      RING_OP_ENABLE);
}

CpaStatus adf_io_disable_ring(adf_dev_ring_handle_t *ring)
{
    ICP_CHECK_FOR_NULL_PARAM(ring);
    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(ring->accel_dev, CPA_STATUS_FAIL);

    return ring_ioctl(ring->accel_dev->accelId,
                      ring->bank_num,
                      ring->ring_num,
                      RING_OP_DISABLE);
}
