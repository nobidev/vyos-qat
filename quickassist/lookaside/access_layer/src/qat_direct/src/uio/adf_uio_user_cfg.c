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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include "cpa.h"
#include "adf_kernel_types.h"
#include "adf_cfg_user.h"
#include "icp_platform.h"
#include "icp_accel_devices.h"
#include "adf_user_cfg.h"
#include "adf_io_cfg.h"

/*
 * User process section name used by application
 */
static char proxy_process_name[ADF_CFG_MAX_PROCESS_LEN] = { 0 };

/*
 * Open kernel driver interface
 */
static int open_dev()
{
    int file_desc = -1;

    file_desc = open(ADF_CTL_DEVICE_NAME, O_RDONLY);
    if (file_desc < 0)
    {
        ADF_ERROR("Error: Failed to open device %s\n", ADF_CTL_DEVICE_NAME);
    }
    return file_desc;
}

/*
 * Close kernel driver interface
 */
static void close_dev(int fd)
{
    close(fd);
}

/*
 * icp_adf_cfgGetParamValue
 * This function is used to determine the value configured for the
 * given parameter name.
 */
CpaStatus adf_io_cfgGetParamValue(icp_accel_dev_t *accel_dev,
                                  const char *pSection,
                                  const char *pParamName,
                                  char *pParamValue)
{
    CpaStatus status = CPA_STATUS_FAIL;
    struct adf_user_cfg_ctl_data config = { { 0 } };
    struct adf_user_cfg_key_val kval = { { 0 } };
    struct adf_user_cfg_section section = { { 0 } };

    int fd = -1;
    int res = 0;

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);
    ICP_CHECK_FOR_NULL_PARAM(pSection);
    ICP_CHECK_FOR_NULL_PARAM(pParamName);
    ICP_CHECK_FOR_NULL_PARAM(pParamValue);

    /* do ioctl to get the data */
    fd = open_dev();
    if (fd < 0)
    {
        return CPA_STATUS_FAIL;
    }

    config.device_id = accel_dev->accelId;
    config.config_section = &section;
    snprintf(section.name, ADF_CFG_MAX_SECTION_LEN_IN_BYTES, "%s", pSection);
    section.params = &kval;
    snprintf(kval.key, ADF_CFG_MAX_KEY_LEN_IN_BYTES, "%s", pParamName);

    /* send the request down to get the configuration
     * information from kernel space. */
    res = ioctl(fd, IOCTL_GET_CFG_VAL, &config);
    if (!res)
    {
        snprintf(pParamValue, ADF_CFG_MAX_VAL_LEN_IN_BYTES, "%s", kval.val);
        status = CPA_STATUS_SUCCESS;
    }
    close_dev(fd);

    return status;
}

Cpa32S adf_io_cfgGetDomainAddress(Cpa16U packageId)
{
    struct adf_dev_status_info dev_info = { 0 };
    int fd = open_dev();
    int domain = ADF_IO_OPERATION_FAIL_CPA32S;

    if (fd < 0)
        return domain;

    dev_info.accel_id = packageId;
    if (!ioctl(fd, IOCTL_STATUS_ACCEL_DEV, &dev_info))
    {
        domain = dev_info.domain;
    }

    close_dev(fd);

    return domain;
}

Cpa16U adf_io_cfgGetBusAddress(Cpa16U packageId)
{
    struct adf_dev_status_info dev_info = { 0 };
    Cpa16U bdf = ADF_IO_OPERATION_FAIL_CPA16U;
    int fd = open_dev();

    if (fd < 0)
        return bdf;

    dev_info.accel_id = packageId;
    if (!ioctl(fd, IOCTL_STATUS_ACCEL_DEV, &dev_info))
    {
        /* Device bus address (B.D.F)
         * Bit 15 14 13 12 11 10 09 08 07 06 05 04 03 02 01 00
         *    |-BUS-------------------|-DEVICE-------|-FUNCT--|
         */
        bdf = dev_info.fun & 0x07;
        bdf |= (dev_info.dev & 0x1F) << 3;
        bdf |= (dev_info.bus & 0xFF) << 8;
    }

    close_dev(fd);

    return bdf;
}

/*
 * adf_io_cfgCheckUserSection
 * check if user process section exists in device cfg
 */
int adf_io_cfgCheckUserSection(int dev_id, uint8_t *pSectionPresent)
{
    struct adf_user_section_data sec_data = { { 0 } };
    int ret = 0, fd = open_dev();

    if (fd < 0)
        return -EFAULT;

    /* set to false by default */
    *pSectionPresent = false;

    sec_data.device_id = dev_id;
    snprintf(sec_data.name, ADF_CFG_MAX_PROCESS_LEN, "%s", proxy_process_name);

    /* Send the request down to check the config in kernel space. */
    if (!ioctl(fd, IOCTL_CHECK_CFG_SECTION, &sec_data))
        *pSectionPresent = sec_data.is_section_present;
    else
        ret = errno;

    close_dev(fd);

    return ret;
}

/*
 * adf_io_reset_device
 *
 * reset device - calls the IOCTL in
 * the driver which resets the device based on accelId
 */
CpaStatus adf_io_reset_device(Cpa32U accelId)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    struct adf_user_cfg_ctl_data ctl_data = { { 0 } };
    int fd;

    fd = open_dev();
    if (fd < 0)
    {
        return CPA_STATUS_FAIL;
    }

    ctl_data.device_id = accelId;
    if (ioctl(fd, IOCTL_RESET_ACCEL_DEV, &ctl_data))
    {
        if (EBUSY == errno)
        {
            ADF_ERROR("Device busy \n");
            status = CPA_STATUS_RETRY;
        }
        else
        {
            ADF_ERROR("Failed to reset device \n");
            status = CPA_STATUS_FAIL;
        }
    }

    close_dev(fd);

    return status;
}

/*
 * adf_set_proxy_process_name
 * Sets the proxy_process_name to user section name used by application
 */
CpaStatus adf_set_proxy_process_name(char *name)
{
    if (strnlen(name, ADF_CFG_MAX_PROCESS_LEN) == ADF_CFG_MAX_PROCESS_LEN)
    {
        ADF_ERROR("Error: Process name too long, maximum process name is %d\n",
                  ADF_CFG_MAX_PROCESS_LEN - 1);
        return CPA_STATUS_FAIL;
    }
    snprintf(proxy_process_name, ADF_CFG_MAX_PROCESS_LEN, "%s", name);

    return CPA_STATUS_SUCCESS;
}
