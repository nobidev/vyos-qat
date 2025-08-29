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
 * @file qat_dbg_daemon.c
 *
 * @description
 *        This file is QAT debug synchronization daemon main file.
 *
 ****************************************************************************/

/* System headers */
#define _GNU_SOURCE
#include <stdlib.h>
#include <signal.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <unistd.h>
#include <poll.h>
#include <grp.h>
#include <pthread.h>

/* Project headers */
#include "qat_dbg_daemon.h"
#include "qat_dbg_daemon_uevent_listener.h"
#include "qat_dbg_daemon_crash_dump.h"
#include "qat_dbg_daemon_cont_sync.h"
#include "qat_dbg_daemon_phys_map.h"
#include "icp_platform.h"
#include "icp_adf_dbg_log.h"
#include "adf_cfg_common.h"
#include "qat_dbg_daemon_config.h"

/*
*******************************************************************************
* Private definitions
*******************************************************************************
*/
#define QAT_DBG_DEAMON_MSG_PREFIX "qat_dbg_sync_daemon"
#define QAT_DBG_DAEMON_GROUP "qat"

#define QAT_DBG_TERMINATE(status)                                              \
    exit((CPA_STATUS_SUCCESS == (status)) ? EXIT_SUCCESS : EXIT_FAILURE)
#define LOOP_FOREVER while (1)

/*
*******************************************************************************
* Private declarations of thread routines
*******************************************************************************
*/
STATIC void qatDbgUeventMonitorWorker(void *args);
STATIC void qatDbgContSyncWorker(void *args);
/*
*******************************************************************************
* Private declarations of threads management routines
*******************************************************************************
*/
STATIC CpaStatus qatDbgUeventMonitorStart(void);
STATIC void qatDbgUeventMonitorStop(void);
STATIC ssize_t qatDbgContSyncStart(void);
STATIC void qatDbgContSyncStopDev(size_t devId);
STATIC void qatDbgContSyncStop(void);

/*
*******************************************************************************
* Private declarations of daemon management routines
*******************************************************************************
*/
STATIC ssize_t qatDbgDaemonInit(void);
STATIC void qatDbgDaemonDeinitDev(size_t devId);
STATIC void qatDbgDaemonDeinit(void);
STATIC CpaStatus qatDbgDaemonizeProcess(void);

/*
*******************************************************************************
* Private variables
*******************************************************************************
*/
STATIC qat_dbg_dev_instance_t qatDbgDevices[ADF_MAX_DEVICES];
STATIC OsalThread qatDbgUeventMonitorThread;

/*
*******************************************************************************
* Private functions
*******************************************************************************
*/
/*
*******************************************************************************
* Daemon initialization functions
*******************************************************************************
*/
STATIC CpaStatus qatDbgGetDevConfig(size_t devId)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    ICP_CHECK_PARAM_LT_MAX(devId, ADF_MAX_DEVICES);

    qatDbgDevices[devId].accelId = devId;
    status = qatDbgGetDevDebugConfig(&qatDbgDevices[devId]);
    if (CPA_STATUS_SUCCESS != status)
    {
        qatDbgDevices[devId].enabled = 0;
        return status;
    }

    qatDbgDevices[devId].enabled = 1;

    return CPA_STATUS_SUCCESS;
}

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Init QAT debug daemon
 *
 * @description
 *        This function perform initialization of QAT Debuggability
 *        daemon for all devices configured with this feature
 *        enabled.
 *
 * @retval Number of QAT devices with Debuggability feature
 *         enabled. Negative value on any device initialization
 *         failure.
 *
 ******************************************************************
 */
STATIC ssize_t qatDbgDaemonInit(void)
{
    int fd = QAT_DBG_INVALID_FD;
    size_t devId = 0;
    ssize_t debugDevsNum = 0;
    size_t bufferId = 0;
    size_t mmapOffset = 0;
    void *ptr = NULL;
    long pageSize = 0;

    pageSize = sysconf(_SC_PAGE_SIZE);
    if (pageSize <= 0)
    {
        return pageSize;
    }

    fd = QAT_DBG_OPEN(QATD_DEVICE_FILENAME, O_RDWR | O_NDELAY);
    if (!QAT_DBG_IS_FD_VALID(fd))
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "Unable to open QAT debug device");

        return -1;
    }

    osalMemSet(qatDbgDevices, 0, sizeof(qatDbgDevices));
    for (devId = 0; devId < ADF_MAX_DEVICES; devId++)
    {
        /* Obtain configuration for each device */
        if (CPA_STATUS_SUCCESS != qatDbgGetDevConfig(devId))
            continue;
        if (!qatDbgDevices[devId].enabled)
            continue;

        debugDevsNum++;
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                        "Device %u configuration:\n",
                        (unsigned int)devId);
        qatDbgLogDevDebugConfig(&qatDbgDevices[devId].config);
        /* Allocate memory based on configurable by user parameter */
        qatDbgDevices[devId].bufferPool =
            (qat_dbg_buffer_desc_t **)ICP_ZALLOC_GEN(
                qatDbgDevices[devId].config.buffer_pool_size *
                sizeof(qat_dbg_buffer_desc_t *));
        if (!qatDbgDevices[devId].bufferPool)
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "Memory allocation failed");
            break;
        }

        for (bufferId = 0;
             bufferId < qatDbgDevices[devId].config.buffer_pool_size;
             bufferId++)
        {
            mmapOffset =
                ((devId << QATD_POOL_SIZE_SHIFT) + bufferId) * (size_t)pageSize;
            ptr = ICP_MMAP(0,
                           qatDbgDevices[devId].config.buffer_size,
                           PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_LOCKED,
                           fd,
                           mmapOffset);
            if (MAP_FAILED == ptr)
            {
                QAT_DBG_LOG_MSG(
                    QAT_DBG_LOG_LVL_ERR,
                    "Memory mapping buffer to U/S failed for dev: %u",
                    (unsigned int)devId);
                goto on_exit;
            }

            qatDbgDevices[devId].bufferPool[bufferId] =
                (qat_dbg_buffer_desc_t *)ptr;
        }
    }

on_exit:
    close(fd);
    if (devId == ADF_MAX_DEVICES)
    {
        return debugDevsNum;
    }
    /* Cleanup on failure */
    qatDbgDaemonDeinit();

    return -1;
}

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Deinit QAT debug daemon for specific device
 *
 * @description
 *        This function performs deinitialization of QAT Debuggability
 *        daemon for given device for which the daemon has been
 *        initialized.
 *
 * @param[in]  devId  device identifier
 *
 * @retval None
 *
 ******************************************************************
 */
STATIC void qatDbgDaemonDeinitDev(size_t devId)
{
    size_t bufferId;
    void *ptr;

    if (devId >= ADF_MAX_DEVICES)
        return;
    if (!qatDbgDevices[devId].enabled)
        return;

    qatDbgDevices[devId].enabled = 0;
    if (!qatDbgDevices[devId].bufferPool)
        return;
    /* Un-mapping mapped regions */
    for (bufferId = 0; bufferId < qatDbgDevices[devId].config.buffer_pool_size;
         bufferId++)
    {
        ptr = qatDbgDevices[devId].bufferPool[bufferId];
        if (ptr)
        {
            if (ICP_MUNMAP(ptr, qatDbgDevices[devId].config.buffer_size))
            {
                QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                                "Munmap failed for dev: %u buffer: %u",
                                (unsigned int)devId,
                                (unsigned int)bufferId);
            }
        }
    }
    /* Free allocated memory */
    ICP_FREE(qatDbgDevices[devId].bufferPool);
    qatDbgDevices[devId].bufferPool = NULL;
}

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Deinit QAT debug daemon
 *
 * @description
 *        This function performs deinitialization of QAT Debuggability
 *        daemon for all devices for which the daemon has been
 *        initialized.
 *
 * @retval None
 *
 ******************************************************************
 */
STATIC void qatDbgDaemonDeinit(void)
{
    size_t devId;

    for (devId = 0; devId < ADF_MAX_DEVICES; devId++)
    {
        qatDbgDaemonDeinitDev(devId);
    }
}
/*
*******************************************************************************
* Private utilities functions
*******************************************************************************
*/
/*
 ******************************************************************
 * @ingroup qatDbg
 *        Debounce debug dump requests
 *
 * @description
 *        This function uses current and previous function call
 *        timestamp to reduce number of successful responses which
 *        causes dumping of debug data to the persistent storage.
 *
 * @param[in]   devInstance  pointer to device configuration
 *                           structure
 *
 * @retval CPA_TRUE              Debug buffers dump may be
 *                               performed
 * @retval CPA_FALSE             Debug dump should be skipped since
 *                               the previous one was done no more
 *                               than `QATD_CRASH_DEBOUNCE_TIME`
 *                               seconds ago
 *
 ******************************************************************
 */
STATIC CpaBoolean qatDbgDebounceDump(qat_dbg_dev_instance_t *devInstance)
{
    Cpa64U currentTs;

    if (!devInstance)
    {
        return CPA_FALSE;
    }

    currentTs = time(NULL);
    if ((currentTs - devInstance->lastCrashTs) < QATD_CRASH_DEBOUNCE_TIME)
    {
        return CPA_FALSE;
    }

    devInstance->lastCrashTs = currentTs;

    return CPA_TRUE;
}
/*
*******************************************************************************
* Events handlers
*******************************************************************************
*/
STATIC void qatDbgCrashHandler(Cpa32U devId, CpaBoolean isProcessCrash)
{
    qat_dbg_dev_instance_t *devInstance = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (devId >= ADF_MAX_DEVICES)
    {
        return;
    }

    devInstance = &qatDbgDevices[devId];
    if (!devInstance->enabled)
    {
        return;
    }
    if (QATD_SYNC_CONT == devInstance->config.sync_mode)
    {
        size_t i;

        for (i = 0; i < devInstance->config.buffer_pool_size; i++)
        {
            status = qatDbgSyncBuffer(devInstance, i);
            if (CPA_STATUS_SUCCESS != status)
            {
                QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                                "Failed to sync buffer %u",
                                (unsigned int)i);
            }
        }
    }
    if (isProcessCrash && !devInstance->config.dump_on_proc_crash)
    {
        return;
    }
    if (!qatDbgDebounceDump(devInstance))
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "QAT: Skipped dump due to debounce time\n");
        return;
    }
    if (QATD_SYNC_CONT == devInstance->config.sync_mode)
    {
        ssize_t procsMmapSize;

        procsMmapSize = qatDbgStoreProcsMmaps(
            devInstance, devInstance->config.cont_sync_dir);
        if (procsMmapSize <= 0)
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Failed to save process memory regions");
        }
    }
    else
    {
        status = qatDbgCrashDump(devInstance);
        if (CPA_STATUS_SUCCESS != status)
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "Crash dump failed");
        }
    }
}

STATIC void qatDbgProcessCrashEventHandler(Cpa32U devId)
{
    qatDbgCrashHandler(devId, CPA_TRUE);
}

STATIC void qatDbgCrashEventHandler(Cpa32U devId)
{
    qatDbgCrashHandler(devId, CPA_FALSE);
}

STATIC void qatDbgManualDumpEventHandler(Cpa32U devId)
{
    qatDbgCrashEventHandler(devId);
}

STATIC void qatDbgErrRespEventHandler(Cpa32U devId)
{
    qatDbgCrashEventHandler(devId);
}

STATIC void qatDbgShutdownEventHandler(Cpa32U devId)
{
    if (devId < ADF_MAX_DEVICES)
    {
        size_t debugDevsNum = 0;

        qatDbgContSyncStopDev(devId);
        qatDbgDaemonDeinitDev(devId);
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                        "Deinitialized daemon for device dev %u",
                        devId);
        for (devId = 0; devId < ADF_MAX_DEVICES; devId++)
        {
            if (qatDbgDevices[devId].enabled)
            {
                debugDevsNum++;
            }
        }
        if (debugDevsNum)
            return;
    }
    else
    {
        qatDbgContSyncStop();
        qatDbgUeventMonitorStop();
        /* Skip qatDbgDaemonDeinit(), allow OS to cleanup */
    }

    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO, "Graceful shutdown done");
    QAT_DBG_TERMINATE(CPA_STATUS_SUCCESS);
}

/*
*******************************************************************************
* Signals handlers
*******************************************************************************
*/
STATIC void qatDbgTerminateSignalHandler(int signal)
{
    (void)signal;
    qatDbgShutdownEventHandler(ADF_MAX_DEVICES);
}
/*
*******************************************************************************
* QAT kernel events listener related routines
*******************************************************************************
*/
STATIC CpaStatus qatDbgUeventMonitorStart(void)
{
    OSAL_STATUS status;

    status = osalThreadCreate(
        &qatDbgUeventMonitorThread, NULL, qatDbgUeventMonitorWorker, NULL);
    if (OSAL_STATUS_SUCCESS != status)
    {
        QAT_DBG_LOG_MSG(
            QAT_DBG_LOG_LVL_ERR,
            "Failed to create QAT events monitor thread: running fallback");
        if (pthread_create(&qatDbgUeventMonitorThread,
                           NULL,
                           (void *(*)(void *))qatDbgUeventMonitorWorker,
                           NULL))
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Events monitor thread creation failed");
            return CPA_STATUS_FAIL;
        }
        (void)pthread_detach(qatDbgUeventMonitorThread);
    }

    status = osalThreadStart(&qatDbgUeventMonitorThread);
    if (OSAL_STATUS_SUCCESS != status)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Failed to start QAT events monitor thread");

        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

STATIC void qatDbgUeventMonitorStop(void)
{
    OSAL_STATUS status;

    status = osalThreadKill(&qatDbgUeventMonitorThread);
    if (OSAL_STATUS_SUCCESS != status)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Stopping QAT events listener thread failed");
        return;
    }

    qatDbgUeventMonitorDelete();
    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO, "QAT events listener worker stopped");
}

STATIC void qatDbgUeventMonitorWorker(void *args)
{
    struct qat_dbg_uevent event = {0};

    (void)args;

    if (CPA_STATUS_SUCCESS != qatDbgUeventMonitorCreate())
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Failed to create QAT events monitor");
        QAT_DBG_TERMINATE(CPA_STATUS_FAIL);
    }

    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO, "QAT events listener worker started");
    LOOP_FOREVER
    {
        if (CPA_STATUS_SUCCESS != qatDbgUeventProxyPoll(&event))
            continue;

        switch (event.event)
        {
            case ADF_EVENT_ERROR:
                qatDbgCrashEventHandler(event.accelId);
                break;
            case ADF_EVENT_PROC_CRASH:
                qatDbgProcessCrashEventHandler(event.accelId);
                break;
            case ADF_EVENT_MANUAL_DUMP:
                qatDbgManualDumpEventHandler(event.accelId);
                break;
            case ADF_EVENT_ERR_RESP:
                qatDbgErrRespEventHandler(event.accelId);
                break;
            case ADF_EVENT_DBG_SHUTDOWN:
                qatDbgShutdownEventHandler(event.accelId);
                break;
            default:
                break;
        }
    }
}

/*
*******************************************************************************
* Continuous sync related routines
*******************************************************************************
*/
STATIC ssize_t qatDbgContSyncStart(void)
{
    long cpuCount = 0;
    long targetCpu = 0;
    size_t devId = 0;
    struct qat_dbg_cont_sync_data *cSync = NULL;
    OSAL_STATUS status = OSAL_STATUS_SUCCESS;
    ssize_t threadsNum = 0;

    cpuCount = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpuCount <= 0)
    {
        QAT_DBG_LOG_MSG(
            QAT_DBG_LOG_LVL_ERR,
            "Failed to obtain number of processors for thread binding");
    }

    for (devId = 0; devId < ADF_MAX_DEVICES; devId++)
    {
        if (!qatDbgDevices[devId].enabled)
            continue;
        if (QATD_SYNC_CONT != qatDbgDevices[devId].config.sync_mode)
            continue;

        cSync = &qatDbgDevices[devId].contSync;
        cSync->logFile.fd = QAT_DBG_INVALID_FD;
        /* Open most recent file or create the new one */
        if (CPA_STATUS_SUCCESS != qatDbgSyncOpenPrevFile(&qatDbgDevices[devId]))
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Failed to create debug log file");
            break;
        }
        /* Initialize cont-sync mutex */
        if (OSAL_STATUS_SUCCESS != osalMutexInit(&cSync->mutex))
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "Failed to init Osal mutex");
            break;
        }
        /* Create sync thread */
        status = osalThreadCreate(&cSync->thread,
                                  NULL,
                                  qatDbgContSyncWorker,
                                  &qatDbgDevices[devId].accelId);
        if (OSAL_STATUS_SUCCESS != status)
        {
            QAT_DBG_LOG_MSG(
                QAT_DBG_LOG_LVL_ERR,
                "Failed to create cont-sync thread: running fallback");
            if (pthread_create(&cSync->thread,
                               NULL,
                               (void *(*)(void *))qatDbgContSyncWorker,
                               (void *)&qatDbgDevices[devId].accelId))
            {
                QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                                "Cont-sync thread creation failed");
                break;
            }
            (void)pthread_detach(cSync->thread);
        }
        /* Start sync thread */
        status = osalThreadStart(&cSync->thread);
        if (OSAL_STATUS_SUCCESS != status)
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Failed to start cont-sync thread");
            break;
        }

        threadsNum++;
        if (cpuCount > 0)
        {
            targetCpu = labs((cpuCount - threadsNum)) % cpuCount;
            osalThreadBind(&cSync->thread, targetCpu);
        }
    }

    if (devId == ADF_MAX_DEVICES)
    {
        return threadsNum;
    }
    /* Cleanup on failure */
    qatDbgContSyncStop();

    return -1;
}

STATIC void qatDbgContSyncStopDev(size_t devId)
{
    struct qat_dbg_cont_sync_data *cSync;
    struct qat_dbg_cont_sync_log *logFile;
    OSAL_STATUS status;

    if (devId >= ADF_MAX_DEVICES)
        return;
    if (!qatDbgDevices[devId].enabled)
        return;
    if (QATD_SYNC_CONT != qatDbgDevices[devId].config.sync_mode)
        return;

    cSync = &qatDbgDevices[devId].contSync;
    logFile = &cSync->logFile;
    if (!QAT_DBG_IS_FD_VALID(logFile->fd))
        return;

    close(logFile->fd);
    logFile->fd = QAT_DBG_INVALID_FD;
    status = osalThreadKill(&cSync->thread);
    if (OSAL_STATUS_SUCCESS != status)
    {
        QAT_DBG_LOG_MSG(
            QAT_DBG_LOG_LVL_ERR, "Killing cont-sync worker %zu failed", devId);
    }

    status = osalMutexDestroy(&cSync->mutex);
    if (OSAL_STATUS_SUCCESS != status)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Destroying sync worker %zu mutex failed",
                        devId);
    }
}

STATIC void qatDbgContSyncStop(void)
{
    size_t devId;

    for (devId = 0; devId < ADF_MAX_DEVICES; devId++)
    {
        qatDbgContSyncStopDev(devId);
    }

    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO, "Cont-sync workers de-init done");
}

STATIC void qatDbgContSyncWorker(void *args)
{
    Cpa32U devId = 0;
    qat_dbg_dev_instance_t *devInstance = NULL;
    size_t i = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    int msgId = 0;
    icp_adf_dbg_sync_msg_t message = {0};
    ssize_t msgLen = 0;

    devId = *((Cpa32U *)args);
    if (devId >= ADF_MAX_DEVICES)
    {
        return;
    }

    devInstance = &qatDbgDevices[devId];
    /* Sync remaining data at startup */
    for (i = 0; i < devInstance->config.buffer_pool_size; i++)
    {
        status = qatDbgSyncBuffer(devInstance, i);
        if (CPA_STATUS_SUCCESS != status)
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Failed to sync buffer %u",
                            (unsigned int)i);
        }
    }
    /* Obtain System V message queue identifier */
    msgId = msgget(QATD_DAEMON_KEY + devId, QATD_IPC_PERM | IPC_CREAT);
    if (-1 == msgId)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                        "Failed to setup cont-sync worker for device %u",
                        (unsigned int)devId);
        return;
    }

    LOOP_FOREVER
    {
        /* Argument msgsz should include size of field mtype in struct msgbuf
         */
        msgLen = msgrcv(msgId, &message, sizeof(message), QATD_IPC_MSGTYPE, 0);
        if (msgLen > 0)
        {
            (void)qatDbgSyncBuffer(devInstance, message.buffer_id);
        }
    }
}

/*
*******************************************************************************
* Daemon routine
*******************************************************************************
*/
STATIC CpaStatus qatDbgDaemonizeProcess(void)
{
    int pipeFds[2];
    long i;
    pid_t pid;
    struct group *grInfo;

    /* Close all open file descriptors except stdin, stdout, stderr */
    for (i = sysconf(_SC_OPEN_MAX); i >= 3; i--)
    {
        close(i);
    }
    /* Create communication channel between parent and child */
    if (pipe(pipeFds))
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Daemon communication channel creation failed");
        QAT_DBG_TERMINATE(CPA_STATUS_FAIL);
    }
    /* Fork off the parent process */
    pid = fork();
    /* Check for error */
    if (pid < 0)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "Child process create failed");
        QAT_DBG_TERMINATE(CPA_STATUS_FAIL);
    }
    /* Check for child process */
    if (!pid)
    {
        /* On success: The child process becomes session leader */
        if (setsid() < 0)
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Failed to become group leader");
            QAT_DBG_TERMINATE(CPA_STATUS_FAIL);
        }
        /* Fork off for the second time to ensure that the daemon won't acquire
         * a TTY again. This can be done only by session leader. */
        pid = fork();
        /* Check for error */
        if (pid < 0)
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Second child process create failed");
            QAT_DBG_TERMINATE(CPA_STATUS_FAIL);
        }
        /* Success: Let the first child terminate - session leader */
        if (pid > 0)
        {
            QAT_DBG_TERMINATE(CPA_STATUS_SUCCESS);
        }
        /* Second child is daemon: try to redirect standard descriptors to
         * /dev/null */
        if (!freopen("/dev/null", "r", stdin))
        {
            fclose(stdin);
        }
        if (!freopen("/dev/null", "w", stdout))
        {
            fclose(stdout);
        }
        if (!freopen("/dev/null", "w", stderr))
        {
            fclose(stderr);
        }

        /* Set new files permissions */
        grInfo = getgrnam(QAT_DBG_DAEMON_GROUP);
        if (NULL == grInfo)
        {
            QAT_DBG_LOG_MSG(
                QAT_DBG_LOG_LVL_ERR,
                "Failed to obtain gid for group " QAT_DBG_DAEMON_GROUP);
        }
        else
        {
            if (setgid(grInfo->gr_gid))
            {
                QAT_DBG_LOG_MSG(
                    QAT_DBG_LOG_LVL_ERR,
                    "Failed to set gid for group " QAT_DBG_DAEMON_GROUP);
            }
        }
        /* Others will not have access to all created by daemon files */
        umask(S_IRWXO);
        /* Change the working directory to the root directory */
        /* or other appropriate directory */
        if (chdir("/"))
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Changing current directory to '/' failed");
            QAT_DBG_TERMINATE(CPA_STATUS_FAIL);
        }

        /* Inform original process about initialization finish */
        if (write(pipeFds[1], &pid, sizeof(pid)) != sizeof(pid))
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Daemon status communication error");
        }
    }
    else
    {
        /* Parent: wait for daemon initialization finish */
        struct pollfd pollFd = {0};

        pollFd.fd = pipeFds[0];
        pollFd.events = POLLIN;
        (void)poll(&pollFd, 1, 3000);
        QAT_DBG_TERMINATE(CPA_STATUS_SUCCESS);
    }

    close(pipeFds[0]);
    close(pipeFds[1]);

    return CPA_STATUS_SUCCESS;
}

int main(int argc, char **argv)
{
    ssize_t devCtr;
    sigset_t sigMask;

    QAT_DBG_LOG_INIT(QAT_DBG_DEAMON_MSG_PREFIX);
    /* Start daemon */
    if (CPA_STATUS_SUCCESS != qatDbgDaemonizeProcess())
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDERR,
                "Unable to daemonize QAT debug sync daemon\n");
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Unable to daemonize QAT debug sync daemon");
        goto on_fail;
    }

    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO, "Starting daemon...");
    devCtr = qatDbgDaemonInit();
    if (devCtr < 0)
    {
        /* Proper message already printed out by above init function */
        goto on_fail;
    }
    if (!devCtr)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                        "Daemon exited due to no debug instances running");

        return 0;
    }
    /* Start continuous sync threads */
    devCtr = qatDbgContSyncStart();
    if (devCtr < 0)
    {
        /* Proper message already printed out by above function */
        goto on_fail2;
    }

    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                    "Initialized cont-sync mode for %d devices",
                    (int)devCtr);
    /* Start event monitor */
    if (CPA_STATUS_SUCCESS != qatDbgUeventMonitorStart())
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Failed to start QAT events listener");
        goto on_fail3;
    }

    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO, "Daemon started");
    /* Configure termination signal handlers */
    if (SIG_ERR == signal(SIGINT, qatDbgTerminateSignalHandler))
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Unable to configure signal handler");
        /* Don't stop daemon on this error */
    }
    if (SIG_ERR == signal(SIGTERM, qatDbgTerminateSignalHandler))
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Unable to configure signal handler");
        /* Don't stop daemon on this error */
    }
    /* Block main thread */
    if (sigemptyset(&sigMask))
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "Signal waiting procedure failed");
        goto on_fail3;
    }

    LOOP_FOREVER
    {
        int inSignal = 0;

        (void)sigwait(&sigMask, &inSignal);
        /* Just in case */
        osalSleep(3);
    }

on_fail3:
    qatDbgContSyncStop();
on_fail2:
    qatDbgDaemonDeinit();
on_fail:
    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "Stopping daemon...");

    return -1;
}