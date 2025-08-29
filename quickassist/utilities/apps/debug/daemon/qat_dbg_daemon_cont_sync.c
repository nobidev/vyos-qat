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
 ***************************************************************************/
/****************************************************************************
 * @file qat_dbg_daemon_cont_sync.c
 *
 * @description
 *        This file provides implementation of functions related to the
 *        daemon continuous sync mode of Debuggability.
 *
 ****************************************************************************/

/* System headers */
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>

/* Project headers */
#include "qat_dbg_daemon_cont_sync.h"
#include "icp_platform.h"

/*
*******************************************************************************
* Private definitions
*******************************************************************************
*/
#define QAT_DBG_SYNC_FILE_PREFIX "data_inst_"

/*
*******************************************************************************
* Private functions
*******************************************************************************
*/
/*
 ******************************************************************
 * @ingroup qatDbg
 *        Obtain debug log file path
 *
 * @description
 *        Obtain debug log file path which is generated on given
 *        log number and QAT device Debuggability configuration.
 *
 * @param[out]  path         pointer to destination buffer
 * @param[in]   pathMaxLen   destination buffer length
 * @param[in]   logNumber    log number which will be part of
 *                           filename
 * @param[in]   devInstance  pointer to device configuration
 *                           structure
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments given
 * @retval CPA_STATUS_SUCCESS        Operation successful
 * @retval CPA_STATUS_FAIL           Operation failed
 *
 ******************************************************************
 */
STATIC CpaStatus qatDbgSyncGetLogFilePath(char *path,
                                          size_t pathMaxLen,
                                          size_t logNumber,
                                          qat_dbg_dev_instance_t *devInstance)
{
    int len = 0;

    ICP_CHECK_FOR_NULL_PARAM(path);
    ICP_CHECK_FOR_NULL_PARAM(devInstance);

    len = snprintf(path,
                   pathMaxLen,
                   "%s/" QAT_DBG_SYNC_FILE_PREFIX
                   "%02u_" QAT_DBG_PCI_ADDR_FORMAT ".log.%04u",
                   devInstance->config.cont_sync_dir,
                   devInstance->accelId,
                   devInstance->pci_addr.domain,
                   devInstance->pci_addr.bus,
                   devInstance->pci_addr.dev,
                   devInstance->pci_addr.func,
                   (unsigned int)logNumber);
    if (len <= 0)
    {
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Open file for debug logs storage
 *
 * @description
 *        Open debug log file and setup continuous sync mode
 *        log file related operational structure.
 *
 * @param[in]   devInstance  pointer to device configuration
 *                           structure
 * @param[in]   overwrite    if equal to CPA_TRUE then file will be
 *                           overwritten if it exits, if set to
 *                           CPA_FALSE then the log file will be
 *                           opened in append mode.
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments given
 * @retval CPA_STATUS_SUCCESS        Operation successful
 * @retval CPA_STATUS_FAIL           Operation failed
 *
 ******************************************************************
 */
STATIC CpaStatus qatDbgSyncOpenLogFile(qat_dbg_dev_instance_t *devInstance,
                                       CpaBoolean overwrite)
{
    struct qat_dbg_cont_sync_data *cSync = NULL;
    struct qat_dbg_cont_sync_log *logFile = NULL;
    char filePath[QAT_DBG_FILE_PATH_MAX_LEN] = {0};
    int fd = QAT_DBG_INVALID_FD;
    int status = 0;
    struct stat fileStat = {0};
    int openFlags = 0;

    ICP_CHECK_FOR_NULL_PARAM(devInstance);

    cSync = &devInstance->contSync;
    logFile = &cSync->logFile;
    if (CPA_STATUS_SUCCESS !=
        qatDbgSyncGetLogFilePath(
            filePath, sizeof(filePath), logFile->fileNum, devInstance))
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "Creating log file name failed!");

        return CPA_STATUS_FAIL;
    }

    openFlags = O_CREAT | O_WRONLY;
    if (!overwrite)
    {
        openFlags |= O_APPEND;
    }

    fd = QAT_DBG_OPEN(filePath, openFlags, QAT_DBG_LOG_FILE_PREM);
    if (!QAT_DBG_IS_FD_VALID(fd))
    {
        QAT_DBG_LOG_MSG(
            QAT_DBG_LOG_LVL_ERR, "Opening file: %s failed", filePath);

        return CPA_STATUS_FAIL;
    }

    /* Copy file path to device instance structure */
    status =
        snprintf(logFile->filePath, QAT_DBG_FILE_PATH_MAX_LEN, "%s", filePath);
    if (status <= 0)
    {
        QAT_DBG_LOG_MSG(
            QAT_DBG_LOG_LVL_ERR,
            "Copying file name into device instance structure failed!");
        close(fd);

        return CPA_STATUS_FAIL;
    }
    if (!overwrite)
    {
        /* Getting stats only in case of openning old file */
        status = stat((const char *)logFile->filePath, &fileStat);
        if (0 != status || 0 > fileStat.st_size)
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Failed to open debug log file!");
            close(fd);

            return CPA_STATUS_FAIL;
        }

        logFile->fileSize = fileStat.st_size;
    }
    else
    {
        logFile->fileSize = 0;
    }

    logFile->fd = fd;
    logFile->fileNum =
        (logFile->fileNum + 1) % devInstance->config.cont_sync_max_files_no;

    return CPA_STATUS_SUCCESS;
}

/*
*******************************************************************************
* Public functions
*******************************************************************************
*/
CpaStatus qatDbgSyncOpenPrevFile(qat_dbg_dev_instance_t *devInstance)
{
    struct qat_dbg_cont_sync_data *cSync = NULL;
    struct qat_dbg_cont_sync_log *logFile = NULL;
    char filePath[QAT_DBG_FILE_PATH_MAX_LEN] = {0};
    int status = 0;
    struct stat fileStat = {0};
    size_t i = 0;
    unsigned long recentLogMtime = 0;
    size_t recentLogSize = 0;
    size_t recentLogNumber = 0;
    CpaBoolean overwrite = CPA_FALSE;

    ICP_CHECK_FOR_NULL_PARAM(devInstance);

    cSync = &devInstance->contSync;
    logFile = &cSync->logFile;
    /* Create cont_sync directory if does not exists */
    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                    "Creating cont-sync directory: %s",
                    devInstance->config.cont_sync_dir);
    errno = 0;
    status = mkdir(devInstance->config.cont_sync_dir, QAT_DBG_LOG_DIR_PERM);
    if (status != 0 && errno != EEXIST)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Creating dir: %s failed - cont-sync setup failed",
                        devInstance->config.cont_sync_dir);

        return CPA_STATUS_FAIL;
    }

    for (i = 0; i < devInstance->config.cont_sync_max_files_no; i++)
    {
        if (CPA_STATUS_SUCCESS !=
            qatDbgSyncGetLogFilePath(
                filePath, sizeof(filePath), i, devInstance))
        {
            continue;
        }

        status = stat((const char *)filePath, &fileStat);
        if (0 != status || 0 > fileStat.st_size)
        {
            continue;
        }
        if (fileStat.st_mtime >= recentLogMtime)
        {
            recentLogMtime = fileStat.st_mtime;
            recentLogSize = fileStat.st_size;
            recentLogNumber = i;
        }
    }

    /* Open the latest file or first one as default */
    logFile->fileNum = recentLogNumber;
    /* If the log file does not contain space for new data then use the next
     * file number */
    if (recentLogSize >= devInstance->config.cont_sync_max_file_size)
    {
        logFile->fileNum =
            (logFile->fileNum + 1) % devInstance->config.cont_sync_max_files_no;

        overwrite = CPA_TRUE;
    }

    return qatDbgSyncOpenLogFile(devInstance, overwrite);
}

CpaStatus qatDbgSyncBuffer(qat_dbg_dev_instance_t *devInstance, size_t bufferId)
{
    struct qat_dbg_cont_sync_data *cSync = NULL;
    struct qat_dbg_cont_sync_log *logFile = NULL;
    qat_dbg_buffer_desc_t *ringDesc = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *startPtr = NULL;
    Cpa8U *startDataPtr = NULL;
    Cpa8U *headPtr = NULL;
    Cpa8U *tailPtr = NULL;
    Cpa8U *endPtr = NULL;
    size_t writeLen = 0;
    size_t bytesWritten = 0;

    ICP_CHECK_FOR_NULL_PARAM(devInstance);
    ICP_CHECK_PARAM_LT_MAX(bufferId, devInstance->config.buffer_pool_size);

    ringDesc = devInstance->bufferPool[bufferId];
    if (!ringDesc)
    {
        return CPA_STATUS_FAIL;
    }
    if (ringDesc->head == ringDesc->tail)
    {
        /* Nothing to sync */
        return CPA_STATUS_SUCCESS;
    }
    if (ringDesc->head > ringDesc->ring_size ||
        ringDesc->tail > ringDesc->ring_size)
    {
        QAT_DBG_LOG_MSG(
            QAT_DBG_LOG_LVL_ERR,
            "Debug ring buffer %u is invalid: head: %u, tail: %u, size: %u",
            (unsigned int)bufferId,
            ringDesc->head,
            ringDesc->tail,
            ringDesc->ring_size);

        return CPA_STATUS_FAIL;
    }

    cSync = &devInstance->contSync;
    if (OSAL_STATUS_SUCCESS != osalMutexLock(&cSync->mutex, OSAL_WAIT_FOREVER))
    {
        return CPA_STATUS_FAIL;
    }
    logFile = &cSync->logFile;
    if (!QAT_DBG_IS_FD_VALID(logFile->fd))
    {
        status = qatDbgSyncOpenLogFile(devInstance, CPA_FALSE);
        if (CPA_STATUS_SUCCESS != status)
            goto on_exit;
    }

    startPtr = (Cpa8U *)ringDesc;
    startDataPtr = startPtr + sizeof(qat_dbg_buffer_desc_t);
    headPtr = startDataPtr + ringDesc->head;
    tailPtr = startDataPtr + ringDesc->tail;
    if (ringDesc->end > ringDesc->head)
    {
        endPtr = startDataPtr + ringDesc->end;
    }
    else
    {
        endPtr = startPtr + ringDesc->ring_size;
    }
    /* Calculate amount of data to write */
    if (headPtr > tailPtr)
    {
        writeLen = (size_t)(headPtr - tailPtr);
    }
    else
    {
        writeLen = (size_t)(endPtr - tailPtr);
        writeLen += (size_t)(headPtr - startDataPtr);
    }
    if (writeLen > ringDesc->ring_size)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Debug ring buffer %u descriptor is invalid",
                        (unsigned int)bufferId);
        status = CPA_STATUS_FAIL;
        goto on_exit;
    }
    if ((logFile->fileSize + writeLen) >
        devInstance->config.cont_sync_max_file_size)
    {
        close(logFile->fd);
        logFile->fd = QAT_DBG_INVALID_FD;
        status = qatDbgSyncOpenLogFile(devInstance, CPA_TRUE);
        if (CPA_STATUS_SUCCESS != status)
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Creating new cont-sync file failed");
            goto on_exit;
        }
    }

    do
    {
        if (headPtr > tailPtr)
        {
            ssize_t wResult = write(logFile->fd, tailPtr, writeLen);

            if (wResult < 0)
                break;

            bytesWritten += (size_t)wResult;
            ringDesc->tail = ringDesc->head;
        }
        else
        {
            ssize_t wResult;

            /* We have to sync two separated segments */
            /* 1. from tail to end */
            wResult = write(logFile->fd, tailPtr, endPtr - tailPtr);
            if (wResult < 0)
                break;

            bytesWritten += (size_t)wResult;
            ringDesc->tail = 0;
            /* 2. from start to head */
            wResult = write(logFile->fd, startDataPtr, headPtr - startDataPtr);
            if (wResult < 0)
                break;

            bytesWritten += (size_t)wResult;
            ringDesc->tail = ringDesc->head;
        }
    } while (0);

    logFile->fileSize += bytesWritten;
    if (writeLen != bytesWritten)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Sync failed - remaining data to sync: %u",
                        (unsigned int)(writeLen - bytesWritten));
        status = CPA_STATUS_RETRY;
    }
    else
    {
        status = CPA_STATUS_SUCCESS;
    }

on_exit:
    osalMutexUnlock(&cSync->mutex);

    return status;
}