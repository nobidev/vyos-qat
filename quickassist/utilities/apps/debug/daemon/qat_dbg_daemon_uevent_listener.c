/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2023 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
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
 * 
 *  version: QAT.L.4.24.0-00005
 *
 ****************************************************************************/
/****************************************************************************
 * @file qat_dbg_daemon_uevent_listener.h
 *
 * @description
 *        This file provides implementation of kernel space to user space
 *        QAT messages listener utilities.
 *
 ****************************************************************************/

/* System headers */
#include <libudev.h>
#include <poll.h>
#include <stdio.h>
#include <errno.h>

/* Project headers */
#include "qat_dbg_daemon_uevent_listener.h"
#include "qat_dbg_daemon.h"
#include "icp_platform.h"

/*
*******************************************************************************
* Private definitions
*******************************************************************************
*/
#define QAT_DBG_EVENT_ERROR "error"
#define QAT_DBG_EVENT_PROC_CRASH "proc_crash"
#define QAT_DBG_EVENT_MANUAL_DUMP "manual_dump"
#define QAT_DBG_EVENT_ERR_RESP "err_resp"
#define QAT_DBG_EVENT_DBG_SHUTDOWN "dbg_shutdown"
#define QAT_DBG_EVENT_MAX_LEN 20
#define QAT_DBG_ACCELID_MAX_LEN 5

/*
*******************************************************************************
* Private global variables
*******************************************************************************
*/
STATIC struct udev *usdev = NULL;
STATIC struct udev_monitor *udevMonitor = NULL;

/*
*******************************************************************************
* Public functions
*******************************************************************************
*/
CpaStatus qatDbgUeventMonitorCreate(void)
{
    CpaStatus status = CPA_STATUS_FAIL;

    usdev = udev_new();
    if (!usdev)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "Can't create udev");
        goto on_exit;
    }

    udevMonitor = udev_monitor_new_from_netlink(usdev, "udev");
    if (!udevMonitor)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "Can't create udev monitor");
        goto on_exit;
    }
    if (udev_monitor_filter_add_match_subsystem_devtype(
            udevMonitor, "pci", NULL))
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "Can't add udev match filter");
        goto on_exit;
    }
    if (udev_monitor_enable_receiving(udevMonitor))
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Can't bind monitor to event source");
        goto on_exit;
    }

    status = CPA_STATUS_SUCCESS;
on_exit:
    if (CPA_STATUS_SUCCESS != status)
    {
        qatDbgUeventMonitorDelete();
    }

    return status;
}

void qatDbgUeventMonitorDelete(void)
{
    if (udevMonitor)
    {
        udev_monitor_unref(udevMonitor);
        udevMonitor = NULL;
    }
    if (usdev)
    {
        udev_unref(usdev);
        usdev = NULL;
    }
}

CpaStatus qatDbgUeventProxyPoll(struct qat_dbg_uevent *event)
{
    struct pollfd udevPollFd = {0};
    struct udev_device *dev;
    const char *eventStr = NULL;
    const char *accelIdStr = NULL;
    char eventString[QAT_DBG_EVENT_MAX_LEN];
    char accelIdString[QAT_DBG_ACCELID_MAX_LEN];
    long int sAccelId = 0;

    ICP_CHECK_FOR_NULL_PARAM(event);

    udevPollFd.fd = udev_monitor_get_fd(udevMonitor);
    if (!QAT_DBG_IS_FD_VALID(udevPollFd.fd))
    {
        return CPA_STATUS_FAIL;
    }

    udevPollFd.events = POLLIN;
    /* Infinite for pool */
    if (poll(&udevPollFd, 1, -1) > 0)
    {
        dev = udev_monitor_receive_device(udevMonitor);
        if (dev)
        {
            eventStr = udev_device_get_property_value(dev, "qat_event");
            if (eventStr)
            {
                snprintf(eventString, sizeof(eventString), "%s", eventStr);
            }
            accelIdStr = udev_device_get_property_value(dev, "accelid");
            if (accelIdStr)
            {
                snprintf(
                    accelIdString, sizeof(accelIdString), "%s", accelIdStr);
            }
            udev_device_unref(dev);
        }
    }
    if (!eventStr || !accelIdStr)
    {
        return CPA_STATUS_FAIL;
    }

    /* Obtain accelerator id */
    errno = 0;
    sAccelId = strtol(accelIdString, NULL, 10);
    if (sAccelId < 0)
    {
        return CPA_STATUS_FAIL;
    }
    event->accelId = sAccelId;
    QAT_DBG_LOG_MSG(
        QAT_DBG_LOG_LVL_INFO, "Received QAT event: %s from device: %ld", eventString, sAccelId);

    /* Recognize event */
    if (!strncmp(eventString, QAT_DBG_EVENT_ERROR, sizeof(eventString)))
    {
        event->event = ADF_EVENT_ERROR;
    }
    else if (!strncmp(
                 eventString, QAT_DBG_EVENT_PROC_CRASH, sizeof(eventString)))
    {
        event->event = ADF_EVENT_PROC_CRASH;
    }
    else if (!strncmp(
                 eventString, QAT_DBG_EVENT_MANUAL_DUMP, sizeof(eventString)))
    {
        event->event = ADF_EVENT_MANUAL_DUMP;
    }
    else if (!strncmp(eventString, QAT_DBG_EVENT_ERR_RESP, sizeof(eventString)))
    {
        event->event = ADF_EVENT_ERR_RESP;
    }
    else if (!strncmp(
                 eventString, QAT_DBG_EVENT_DBG_SHUTDOWN, sizeof(eventString)))
    {
        event->event = ADF_EVENT_DBG_SHUTDOWN;
    }
    else
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    return CPA_STATUS_SUCCESS;
}