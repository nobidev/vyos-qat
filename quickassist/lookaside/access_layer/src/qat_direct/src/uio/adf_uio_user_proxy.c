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
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <libudev.h>
#include <poll.h>
#include "Osal.h"
#include "OsalOsTypes.h"
#include "OsalTypes.h"
#include "cpa.h"
#include "icp_platform.h"
#include "icp_platform_user.h"
#include "adf_io_user_proxy.h"
#include "cpa.h"
#include "adf_user_cfg.h"
#include "adf_common_drv.h"

#define ADF_DEV_PROCESSES_PATH "/dev/qat_dev_processes"

/*
 * Mutex guarding serialized access to icp_dev_processes
 */
STATIC OsalMutex processes_lock;
STATIC int process_info_file = -1;

extern struct udev *udev;
extern struct udev_monitor *mon;

CpaStatus adf_set_proxy_process_name(char *name);

CpaStatus adf_io_userProcessToStart(char const *const name_tml,
                                    size_t name_tml_len,
                                    char *name,
                                    size_t name_len)
{
    ssize_t ret;

    ICP_CHECK_FOR_NULL_PARAM(name_tml);
    ICP_CHECK_FOR_NULL_PARAM(name);

    if (osalMutexLock(&processes_lock, OSAL_WAIT_FOREVER))
    {
        ADF_ERROR("Mutex lock error %d\n", errno);
        return CPA_STATUS_FAIL;
    }
    if (process_info_file != -1)
    {
        ADF_ERROR("File " ADF_DEV_PROCESSES_PATH " already opened\n");
        osalMutexUnlock(&processes_lock);
        return CPA_STATUS_FAIL;
    }
    process_info_file = open(ADF_DEV_PROCESSES_PATH, O_RDWR);
    if (process_info_file < 0)
    {
        ADF_ERROR("Cannot open " ADF_DEV_PROCESSES_PATH " file\n");
        process_info_file = -1;
        /* Error when opening process file - release mutex
         * and exit with error */
        osalMutexUnlock(&processes_lock);
        return CPA_STATUS_FAIL;
    }
    ret = write(process_info_file, name_tml, name_tml_len);
    if (ret < 0)
    {
        close(process_info_file);
        process_info_file = -1;
        ADF_ERROR("Error reading " ADF_DEV_PROCESSES_PATH " file\n");
        osalMutexUnlock(&processes_lock);
        return CPA_STATUS_FAIL;
    }
    if (ret == 0)
    {
        ret = read(process_info_file, name, name_len);
        if (ret == 0 && !adf_set_proxy_process_name(name))
        {
            if (osalMutexUnlock(&processes_lock))
            {
                close(process_info_file);
                process_info_file = -1;
                ADF_ERROR("Mutex unlock error %d\n", errno);
                return CPA_STATUS_FAIL;
            }
            return CPA_STATUS_SUCCESS;
        }
    }

    close(process_info_file);
    process_info_file = -1;
    osalMutexUnlock(&processes_lock);
    return CPA_STATUS_FAIL;
}

CpaStatus adf_io_userProxyInit(char const *const name)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(name, CPA_STATUS_INVALID_PARAM);

    if (!processes_lock)
    {
        if (OSAL_SUCCESS != ICP_MUTEX_INIT(&processes_lock))
        {
            ADF_ERROR("Mutex init failed for processes_lock\n");
            status = CPA_STATUS_RESOURCE;
        }
    }

    return status;
}

void adf_io_userProcessStop(void)
{
    if (process_info_file > 0)
        close(process_info_file);
    process_info_file = -1;
}

void adf_io_userProxyShutdown(void)
{
    osalMutexDestroy(&processes_lock);
}

CpaStatus adf_io_resetUserProxy(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    if (process_info_file > 0)
        close(process_info_file);
    process_info_file = -1;
    /* there is no option to reset the mutex, hence destroying
     * it and re-initializing. */
    if (processes_lock)
        osalMutexDestroy(&processes_lock);
    if (OSAL_SUCCESS != ICP_MUTEX_INIT(&processes_lock))
    {
        ADF_ERROR("Mutex init failed for processes_lock\n");
        status = CPA_STATUS_RESOURCE;
    }
    return status;
}

CpaBoolean adf_io_pollProxyEvent(Cpa32U *dev_id, enum adf_event *event)
{
    struct udev_device *dev;
    const char *eventStr = NULL;
    const char *accelIdStr = NULL;
    char eventString[EVENT_MAX_LEN];
    char accelIdString[ACCELID_MAX_LEN];
    struct pollfd udevPollFd = { 0, POLLIN, 0 };

    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(dev_id, CPA_FALSE);
    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(event, CPA_FALSE);

    udevPollFd.fd = udev_monitor_get_fd(mon);

    if (udevPollFd.fd > 0)
    {
        /* Poll for events on single fd(i.e., udev monitor) with 0 time out.
         * Value > 0 indicates new events on fd.
         */
        if (poll(&udevPollFd, 1, 0) > 0)
        {
            dev = udev_monitor_receive_device(mon);
            if (dev)
            {
                eventStr = udev_device_get_property_value(dev, "qat_event");
                accelIdStr = udev_device_get_property_value(dev, "accelid");
                if (eventStr && accelIdStr)
                {
                    ICP_STRLCPY(eventString, eventStr, sizeof(eventString));
                    ICP_STRLCPY(
                        accelIdString, accelIdStr, sizeof(accelIdString));
                }
                udev_device_unref(dev);
            }
        }
        if (!eventStr || !accelIdStr)
            return CPA_FALSE;

        if (!strncmp(eventString, "init", sizeof(eventString)))
            *event = ADF_EVENT_INIT;
        else if (!strncmp(eventString, "shutdown", sizeof(eventString)))
            *event = ADF_EVENT_SHUTDOWN;
        else if (!strncmp(eventString, "restarting", sizeof(eventString)))
            *event = ADF_EVENT_RESTARTING;
        else if (!strncmp(eventString, "restarted", sizeof(eventString)))
            *event = ADF_EVENT_RESTARTED;
        else if (!strncmp(eventString, "start", sizeof(eventString)))
            *event = ADF_EVENT_START;
        else if (!strncmp(eventString, "stop", sizeof(eventString)))
            *event = ADF_EVENT_STOP;
        else if (!strncmp(eventString, "error", sizeof(eventString)))
            *event = ADF_EVENT_ERROR;
        else
        {
            ADF_ERROR("Unknown event \"%s\" received\n", eventString);
            return CPA_FALSE;
        }

        *dev_id = strtoul(accelIdString, NULL, 0);

        return CPA_TRUE;
    }
    return CPA_FALSE;
}
