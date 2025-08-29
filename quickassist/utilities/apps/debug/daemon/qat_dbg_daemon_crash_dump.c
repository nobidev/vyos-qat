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
 * @file qat_dbg_daemon_crash_dump.c
 *
 * @description
 *        This file provides implementation of functions related to the
 *        daemon crash dump mode of Debuggability.
 *
 ****************************************************************************/
#define _GNU_SOURCE

/* System headers */
#include <time.h>
#include <ftw.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>

/* Project headers */
#include "qat_dbg_daemon_crash_dump.h"
#include "qat_dbg_daemon_phys_map.h"
#include "icp_platform.h"

/*
*******************************************************************************
* Private definitions
*******************************************************************************
*/
#define QAT_DBG_CRASH_DUMP_DIR_PREFIX "qat_crash_dev_"
#define QAT_DBG_CRASH_DUMP_FILE_PREFIX "dbg_ring_"
#define QAT_DBG_CRASH_DUMP_DIR_MAX_FDS 10

/*
*******************************************************************************
* Private types definition
*******************************************************************************
*/
struct qat_dbg_dir_info
{
    char name[QATD_MAX_FILE_NAME];
    size_t size;
    time_t date;
    struct qat_dbg_dir_info *next;
};

/*
*******************************************************************************
* Private variables
*******************************************************************************
*/
STATIC struct qat_dbg_dir_info *crashDirFirstEntry = NULL;
STATIC struct qat_dbg_dir_info *crashDirCurrentEntry = NULL;
STATIC size_t crashDirSize = 0;

/*
*******************************************************************************
* Private functions
*******************************************************************************
*/
/*
*******************************************************************************
* nftw callbacks
*******************************************************************************
*/
/*
 ******************************************************************
 * @ingroup qatDbg
 *        Calculate size of directory
 *
 * @description
 *        This function is a callback for nftw function with
 *        imposed arguments. This implementation creates forward
 *        linked list of all one-level-depth subfolders inside
 *        scanned directory and calculates its size, which is
 *        stored at `crashDirSize` global variable.
 *
 * @param[in]   path        path to the scanned object
 * @param[in]   objectStat  stat information about the scanned object
 * @param[in]   objectType  scanned object type indicator
 * @param[in]   ftwInfo     pointer to FTW structure
 *
 * @retval  0                    Continue nftw scan
 * @retval -1                    Stop nftw scan
 *
 ******************************************************************
 */
STATIC int qatDbgNftwScanCallback(const char *path,
                                  const struct stat *objectStat,
                                  int objectType,
                                  struct FTW *ftwInfo)
{
    /* Look for directory inside root path which name starts with
     * `QAT_DBG_CRASH_DUMP_DIR_PREFIX` */
    if (objectType == FTW_D && ftwInfo->level == 1 &&
        !strncmp(path + ftwInfo->base,
                 QAT_DBG_CRASH_DUMP_DIR_PREFIX,
                 sizeof(QAT_DBG_CRASH_DUMP_DIR_PREFIX) - 1))
    {
        struct qat_dbg_dir_info *dirInfo = NULL;

        dirInfo = ICP_MALLOC_GEN(sizeof(struct qat_dbg_dir_info));
        if (!dirInfo)
            return -1;

        dirInfo->next = NULL;
        snprintf(dirInfo->name, QATD_MAX_FILE_NAME, "%s", path);
        dirInfo->size = 0;
        dirInfo->date = objectStat->st_ctime;

        if (!crashDirFirstEntry)
        {
            crashDirFirstEntry = dirInfo;
        }
        else
        {
            crashDirCurrentEntry->next = dirInfo;
        }
        crashDirCurrentEntry = dirInfo;
    }
    /* Look for files and dirs inside existing subfolder of root path */
    else if (ftwInfo->level >= 2 &&
             (objectType == FTW_F || objectType == FTW_D))
    {
        /* Respect only files inside crashDirCurrentEntry */
        if (crashDirCurrentEntry != NULL &&
            !strncmp(crashDirCurrentEntry->name,
                     path,
                     strlen(crashDirCurrentEntry->name)))
        {
            crashDirCurrentEntry->size += objectStat->st_size;
            crashDirSize += objectStat->st_size;
        }
    }

    return 0;
}

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Remove directory
 *
 * @description
 *        This function is a callback for nftw function with
 *        imposed arguments. This implementation removes all
 *        objects passed to it.
 *
 * @param[in]   path        path to the scanned object
 * @param[in]   objectStat  stat information about the scanned object
 * @param[in]   objectType  scanned object type indicator
 * @param[in]   ftwInfo     pointer to FTW structure
 *
 * @retval  0                    Continue deleting objects
 * @retval -1                    Stop deleting objects
 *
 ******************************************************************
 */
STATIC int qatDbgNftwRemoveCallback(const char *path,
                                    const struct stat *objectStat,
                                    int objectType,
                                    struct FTW *ftwInfo)
{
    (void)objectStat;
    (void)objectType;
    (void)ftwInfo;

    if (remove(path))
    {
        return -1;
    }

    return 0;
}

/*
*******************************************************************************
* File tree related functions
*******************************************************************************
*/
STATIC struct qat_dbg_dir_info *qatDbgFindOldestDir(void)
{
    struct qat_dbg_dir_info *dirInfo = crashDirFirstEntry;
    struct qat_dbg_dir_info *oldest = crashDirFirstEntry;

    while (dirInfo)
    {
        /* Set to actual folder if the default initialized one contains empty
         * path */
        if (!strnlen(oldest->name, sizeof(oldest->name)))
        {
            oldest = dirInfo;
        }

        if (strnlen(dirInfo->name, sizeof(dirInfo->name)) &&
            dirInfo->date <= oldest->date)
        {
            oldest = dirInfo;
        }

        dirInfo = dirInfo->next;
    }

    return oldest;
}

STATIC CpaStatus qatDbgCrashDumpRemoveOldLogs(size_t bytesToFree)
{
    struct qat_dbg_dir_info *oldest = NULL;
    size_t removedBytes = 0;

    while (removedBytes < bytesToFree)
    {
        oldest = qatDbgFindOldestDir();
        if (!oldest || !strnlen(oldest->name, sizeof(oldest->name)))
        {
            break;
        }

        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                        "Removing directory %s - freeing %u MBs",
                        oldest->name,
                        (unsigned int)(oldest->size >> QATD_1MB_SHIFT));

        if (nftw(oldest->name,
                 qatDbgNftwRemoveCallback,
                 QAT_DBG_CRASH_DUMP_DIR_MAX_FDS,
                 FTW_DEPTH | FTW_MOUNT | FTW_PHYS))
        {
            return CPA_STATUS_FAIL;
        }

        removedBytes += oldest->size;
        oldest->name[0] = 0;
    }

    if (removedBytes < bytesToFree)
    {
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Ensure that there is enough space inside dump directory
 *
 * @description
 *        This function calculates size of the given directory and
 *        creates forward linked list of all one-level-depth
 *        subfolders inside it. If calculated size plus
 *        @requiredSize is greater than maximum allowable directory
 *        size represented by @maxDirSize, then the oldest crash
 *        dumps are being removed till above condition is
 *        satisfied.
 *
 * @param[in]  dir           directory to cleanup
 * @param[in]  requiredSize  number of bytes which needs to be
 *                           stored inside given directory
 * @param[in]  maxDirSize    maximum allowable directory size in
 *                           bytes
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments given
 * @retval CPA_STATUS_SUCCESS        Operation successful
 * @retval CPA_STATUS_FAIL           Operation failed
 *
 ******************************************************************
 */
STATIC CpaStatus qatDbgCrashDumpCleanupDir(const char *dir,
                                           size_t requiredSize,
                                           size_t maxDirSize)
{
    struct qat_dbg_dir_info *tmp = NULL;
    struct qat_dbg_dir_info *dirInfo = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

    ICP_CHECK_FOR_NULL_PARAM(dir);

    /* Perform crash dump directory size calculation */
    if (nftw(dir,
             qatDbgNftwScanCallback,
             QAT_DBG_CRASH_DUMP_DIR_MAX_FDS,
             FTW_MOUNT | FTW_PHYS))
    {
        status = CPA_STATUS_FAIL;
        goto on_exit;
    }

    /* Check if in the crash dump directory is at least `requiredSize` free
     * bytes */
    if ((crashDirSize + requiredSize) > maxDirSize)
    {
        /* Remove old crash dumps logs to ensure free `requiredSize` bytes */
        if (crashDirSize < maxDirSize)
        {
            requiredSize -= (maxDirSize - crashDirSize);
        }
        status = qatDbgCrashDumpRemoveOldLogs(requiredSize);
    }

on_exit:
    /* Free memory allocated during directory size calculation */
    dirInfo = crashDirFirstEntry;
    while (dirInfo)
    {
        tmp = dirInfo;
        dirInfo = dirInfo->next;
        ICP_FREE(tmp);
    }

    crashDirFirstEntry = NULL;
    crashDirCurrentEntry = NULL;
    crashDirSize = 0;

    return status;
}

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Store debug buffer to filesystem
 *
 * @description
 *        This function writes given buffer to file inside given
 *        directory.
 *        imposed arguments. This implementation removes all
 *        objects passed to it.
 *
 * @param[in]   devInstance  pointer to device configuration
 *                           structure
 * @param[in]   bufferId     buffer identifier indexed from 0
 * @param[in]   dir          directory where buffer will be
 *                           stored
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments given
 * @retval CPA_STATUS_SUCCESS        Operation successful
 * @retval CPA_STATUS_FAIL           Operation failed
 * @retval CPA_STATUS_RETRY          Buffer has been written
 *                                   partially. Another call of
 *                                   this function is required.
 *
 ******************************************************************
 */
STATIC CpaStatus qatDbgCrashDumpBuffer(qat_dbg_dev_instance_t *devInstance,
                                       size_t bufferId,
                                       char *dir)
{
    struct qatd_ring_desc *ringDesc = NULL;
    char filePath[QAT_DBG_FILE_PATH_MAX_LEN + QAT_DBG_FILE_PATH_MAX_LEN / 4] = {
        0};
    int fd = QAT_DBG_INVALID_FD;
    ssize_t bytesWritten = 0;

    ICP_CHECK_FOR_NULL_PARAM(devInstance);
    ICP_CHECK_PARAM_LT_MAX(bufferId, devInstance->config.buffer_pool_size);
    ICP_CHECK_FOR_NULL_PARAM(dir);

    ringDesc = devInstance->bufferPool[bufferId];
    if (!ringDesc)
    {
        return CPA_STATUS_FAIL;
    }

    /* Create file name */
    snprintf(filePath,
             sizeof(filePath),
             "%s/" QAT_DBG_CRASH_DUMP_FILE_PREFIX "%04u.log",
             dir,
             (unsigned int)bufferId);
    /* Write content of ring to separated file */
    fd = QAT_DBG_OPEN(
        filePath, O_RDWR | O_CREAT | O_APPEND, QAT_DBG_LOG_FILE_PREM);
    if (!QAT_DBG_IS_FD_VALID(fd))
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "File %s open failed", filePath);

        return CPA_STATUS_FAIL;
    }

    bytesWritten = write(fd, ringDesc, ringDesc->ring_size);
    close(fd);
    if (bytesWritten != (ssize_t)ringDesc->ring_size)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Buffer dump failed %u",
                        (unsigned int)bufferId);

        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/*
*******************************************************************************
* Public functions
*******************************************************************************
*/
CpaStatus qatDbgCrashDump(qat_dbg_dev_instance_t *devInstance)
{
    time_t cTime = 0;
    struct tm timeDate = {0};
    struct tm *pTimeDate = NULL;
    int result = 0;
    size_t dumpDirSize = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    char dumpDir[QAT_DBG_FILE_PATH_MAX_LEN] = {0};
    ssize_t procsMmapSize = 0;
    size_t bufferId = 0;
    struct stat dirStat = {0};

    ICP_CHECK_FOR_NULL_PARAM(devInstance);

    cTime = time(NULL);
    pTimeDate = gmtime_r(&cTime, &timeDate);
    if (!pTimeDate)
    {
        return CPA_STATUS_FAIL;
    }

    /* Create dump directory if it doesn't exists */
    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                    "Creating crash dump directory: %s",
                    devInstance->config.dump_dir);

    errno = 0;
    result = mkdir(devInstance->config.dump_dir, QAT_DBG_LOG_DIR_PERM);
    if (result != 0 && errno != EEXIST)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Creating dir: %s failed - crash dump aborted",
                        devInstance->config.dump_dir);

        return CPA_STATUS_FAIL;
    }

    /* Calculate size of upcoming dump with procs mmaps file size approximation.
     * Approximation will be adjusted later */
    dumpDirSize = (devInstance->config.buffer_pool_size *
                   devInstance->config.buffer_size) +
                  QAT_DBG_MAX_PROCS_MMAP_SIZE;

    /* Ensure that there is enough space inside dump directory */
    status = qatDbgCrashDumpCleanupDir(devInstance->config.dump_dir,
                                       dumpDirSize,
                                       devInstance->config.dump_dir_max_size);
    if (CPA_STATUS_SUCCESS != status)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Failed to clean-up dump directory: %s",
                        devInstance->config.dump_dir);
        /* Continue dumping */
    }

    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO, "Crash dump in progress ...");

    memset(dumpDir, 0, sizeof(dumpDir));
    snprintf(dumpDir,
             sizeof(dumpDir),
             "%s/%s%02u_" QAT_DBG_PCI_ADDR_FORMAT
             "_%04d-%02d-%02d_%02d%02d%02d/",
             devInstance->config.dump_dir,
             QAT_DBG_CRASH_DUMP_DIR_PREFIX,
             devInstance->accelId,
             devInstance->pci_addr.domain,
             devInstance->pci_addr.bus,
             devInstance->pci_addr.dev,
             devInstance->pci_addr.func,
             (pTimeDate->tm_year + 1900),
             pTimeDate->tm_mon + 1,
             pTimeDate->tm_mday,
             pTimeDate->tm_hour,
             pTimeDate->tm_min,
             pTimeDate->tm_sec);

    result = mkdir(dumpDir, QAT_DBG_LOG_DIR_PERM);
    if (result)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Creating dir: %s failed - crash dump aborted",
                        dumpDir);

        return CPA_STATUS_FAIL;
    }

    procsMmapSize = qatDbgStoreProcsMmaps(devInstance, dumpDir);
    if (procsMmapSize <= 0)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Unable to dump processes memory map");

        return CPA_STATUS_FAIL;
    }

    for (bufferId = 0; bufferId < devInstance->config.buffer_pool_size;
         bufferId++)
    {
        status = qatDbgCrashDumpBuffer(devInstance, bufferId, dumpDir);
        if (CPA_STATUS_SUCCESS != status)
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Unable to dump buffer: %u",
                            (unsigned int)bufferId);

            return CPA_STATUS_FAIL;
        }
    }

    /* Adjust crash dump directory size if procs mmaps file size was under
     * approximated */
    if (procsMmapSize > QAT_DBG_MAX_PROCS_MMAP_SIZE)
    {
        status = qatDbgCrashDumpCleanupDir(
            devInstance->config.dump_dir,
            procsMmapSize - QAT_DBG_MAX_PROCS_MMAP_SIZE,
            devInstance->config.dump_dir_max_size);
        if (CPA_STATUS_SUCCESS != status)
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Failed to post clean-up dump directory: %s",
                            devInstance->config.dump_dir);
            /* Continue dumping */
        }
    }

    result = stat((const char *)dumpDir, &dirStat);
    if (result)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR, "Crash dump failed");

        return CPA_STATUS_FAIL;
    }

    QAT_DBG_LOG_MSG(
        QAT_DBG_LOG_LVL_INFO, "Crash dump done - path: %s", dumpDir);

    return CPA_STATUS_SUCCESS;
}