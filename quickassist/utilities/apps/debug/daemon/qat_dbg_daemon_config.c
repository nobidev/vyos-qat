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
 * @file qat_dbg_daemon_config.c
 *
 * @description
 *        This file provides implementation of functions related to
 *        Debuggability feature configuration.
 *
 ****************************************************************************/

/* System headers */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>

/* Project headers */
#include "qat_dbg_daemon_config.h"
#include "qat_dbg_daemon.h"
#include "adf_cfg_common.h"
#include "icp_platform.h"

/*
*******************************************************************************
* Private definitions
*******************************************************************************
*/
#define QAT_DBG_ADF_CFG_FILE "/dev/qat_adf_ctl"
#define QAT_DBG_SYSFS_PATH "/sys/kernel/debug"
#define QAT_DBG_MAX_PARAM_LEN 128

/*
*******************************************************************************
* Private functions
*******************************************************************************
*/
STATIC CpaStatus qatDbgGetDevStatus(int devId,
                                    struct adf_dev_status_info *devStatusInfo)
{
    int fd = 0;
    int status = 0;

    ICP_CHECK_PARAM_GT_MIN(devId, -1);
    ICP_CHECK_FOR_NULL_PARAM(devStatusInfo);

    fd = QAT_DBG_OPEN(QAT_DBG_ADF_CFG_FILE, O_RDWR | O_NDELAY);
    if (!QAT_DBG_IS_FD_VALID(fd))
    {
        return CPA_STATUS_FAIL;
    }

    devStatusInfo->type = DEV_UNKNOWN;
    devStatusInfo->accel_id = devId;
    status = ioctl(fd, IOCTL_DEBUG_STATUS_ACCEL_DEV, devStatusInfo);
    close(fd);
    if (status)
    {
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus qatDbgTrimStr(char *string, size_t maxLen)
{
    char *end = NULL;
    size_t len = 0;

    if (!string)
    {
        return CPA_STATUS_FAIL;
    }

    len = strnlen(string, maxLen);
    if (!len)
    {
        return CPA_STATUS_FAIL;
    }

    end = string + len;
    while (isspace(*--end))
        ;

    *(end + 1) = 0;

    return CPA_STATUS_SUCCESS;
}

/*
*******************************************************************************
* Parameters getters routines
*******************************************************************************
*/
STATIC CpaStatus qatDbgReadParamStr(char *sysfsDir,
                                    const char *paramName,
                                    char *paramValue,
                                    size_t paramMaxLen)
{
    char filePath[QAT_DBG_FILE_PATH_MAX_LEN] = {0};
    int fd = 0;
    ssize_t bytesRead = 0;

    ICP_CHECK_FOR_NULL_PARAM(sysfsDir);
    ICP_CHECK_FOR_NULL_PARAM(paramName);
    ICP_CHECK_FOR_NULL_PARAM(paramValue);
    ICP_CHECK_PARAM_GT_MIN(paramMaxLen, 0);

    snprintf(filePath, sizeof(filePath), "%s/%s", sysfsDir, paramName);
    fd = QAT_DBG_OPEN(filePath, O_RDONLY);
    if (!QAT_DBG_IS_FD_VALID(fd))
    {
        return CPA_STATUS_FAIL;
    }

    osalMemSet(paramValue, 0, paramMaxLen);
    bytesRead = read(fd, paramValue, paramMaxLen);
    close(fd);
    if (bytesRead <= 0)
    {
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus qatDbgReadParamInt(char *dir,
                                    const char *paramName,
                                    long int *paramValue)
{
    char strValue[QAT_DBG_MAX_PARAM_LEN] = {0};

    ICP_CHECK_FOR_NULL_PARAM(dir);
    ICP_CHECK_FOR_NULL_PARAM(paramName);
    ICP_CHECK_FOR_NULL_PARAM(paramValue);

    if (CPA_STATUS_SUCCESS !=
        qatDbgReadParamStr(dir, paramName, strValue, sizeof(strValue)))
    {
        return CPA_STATUS_FAIL;
    }

    errno = 0;
    *paramValue = strtol(strValue, NULL, 10);
    if ((*paramValue == LONG_MIN || *paramValue == LONG_MAX) && errno == ERANGE)
    {
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Get configuration parameter as integer via sysfs
 *
 * @description
 *        This macro obtains Debuggability configuration parameter
 *        via sysfs filesystem, converts it to integer value, and
 *        check conversion result. In case of failure the
 *        CPA_STATUS_FAIL return code is returned by the caller
 *        function.
 *
 * @context
 *        Should be called from function which returns variable of
 *        type CpaStatus
 *
 * @param[in]  sysfsDir    sysfs directory containing configuration
 *                         parameters files
 * @param[in]  paramName   configuration parameter name
 * @param[out] paramValue  pointer where requested parameter will be
 *                         stored
 *
 * @retval none
 *
 ******************************************************************
 */
#define QAT_DBG_GET_CFG_PARAM_INT(sysfsDir, paramName, paramValue)             \
    do                                                                         \
    {                                                                          \
        long int valueTemp;                                                    \
                                                                               \
        if (CPA_STATUS_SUCCESS !=                                              \
            qatDbgReadParamInt((sysfsDir), (paramName), &valueTemp))           \
        {                                                                      \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
        *(paramValue) = valueTemp;                                             \
    } while (0)

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Get configuration parameter as string via sysfs
 *
 * @description
 *        This macro obtains Debuggability configuration parameter
 *        via sysfs filesystem, removes white-space characters form
 *        the string and stores the output in \p paramValue.
 *        In case of failure the CPA_STATUS_FAIL return code is
 *        returned by the caller function.
 *
 * @context
 *        Should be called from function which returns variable of
 *        type CpaStatus
 *
 * @param[in]  sysfsDir     sysfs directory containing configuration
 *                          parameters files
 * @param[in]  paramName    configuration parameter name
 * @param[out] paramValue   pointer where requested parameter will be
 *                          stored
 * @param[in]  paramMaxLen  maximum length of buffer pointed by
 *                          paramValue
 *
 * @retval none
 *
 ******************************************************************
 */
#define QAT_DBG_GET_CFG_PARAM_STR(                                             \
    sysfsDir, paramName, paramValue, paramMaxLen)                              \
    do                                                                         \
    {                                                                          \
        if (CPA_STATUS_SUCCESS !=                                              \
            qatDbgReadParamStr(                                                \
                (sysfsDir), (paramName), (paramValue), (paramMaxLen)))         \
        {                                                                      \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
        if (CPA_STATUS_SUCCESS != qatDbgTrimStr((paramValue), (paramMaxLen)))  \
        {                                                                      \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
    } while (0)

/*
 *******************************************************************************
 * Public functions
 *******************************************************************************
 */
CpaStatus qatDbgGetDevDebugConfig(qat_dbg_dev_instance_t *devInstance)
{
    struct adf_dev_status_info devStatusInfo = {0};
    char sysfsDir[QAT_DBG_FILE_PATH_MAX_LEN] = {0};
    int enabled = 0;
    int contSyncEnabled = 0;
    qat_dbg_inst_cfg_t *instConfig = NULL;
    Cpa32U devId = 0;

    ICP_CHECK_FOR_NULL_PARAM(devInstance);
    instConfig = &(devInstance->config);
    devId = devInstance->accelId;

    if (CPA_STATUS_SUCCESS != qatDbgGetDevStatus(devId, &devStatusInfo))
    {
        return CPA_STATUS_FAIL;
    }

    snprintf(sysfsDir,
             sizeof(sysfsDir),
             "%s/qat_%s_%04x:%02x:%02x.%x/%s",
             QAT_DBG_SYSFS_PATH,
             devStatusInfo.name,
             (unsigned int)devStatusInfo.domain,
             (unsigned int)devStatusInfo.bus,
             (unsigned int)devStatusInfo.dev,
             (unsigned int)devStatusInfo.fun,
             QATD_PARAM_SYSFS_DIR);

    devInstance->pci_addr.domain = devStatusInfo.domain;
    devInstance->pci_addr.bus = devStatusInfo.bus;
    devInstance->pci_addr.dev = devStatusInfo.dev;
    devInstance->pci_addr.func = devStatusInfo.fun;

    QAT_DBG_GET_CFG_PARAM_INT(sysfsDir, QATD_PARAM_ENABLED, &enabled);
    if (!enabled)
    {
        return CPA_STATUS_FAIL;
    }
    /* Dump dir */
    QAT_DBG_GET_CFG_PARAM_STR(sysfsDir,
                              QATD_PARAM_DUMP_DIR,
                              instConfig->dump_dir,
                              sizeof(instConfig->dump_dir));

    /* Dump dir max size */
    QAT_DBG_GET_CFG_PARAM_INT(
        sysfsDir, QATD_PARAM_DUMP_DIR_SZ, &instConfig->dump_dir_max_size);
    instConfig->dump_dir_max_size <<= QATD_1MB_SHIFT;

    /* Buffer pool size */
    QAT_DBG_GET_CFG_PARAM_INT(
        sysfsDir, QATD_PARAM_BUFFER_POOL_SZ, &instConfig->buffer_pool_size);

    /* Buffer size */
    QAT_DBG_GET_CFG_PARAM_INT(
        sysfsDir, QATD_PARAM_BUFFER_SZ, &instConfig->buffer_size);
    instConfig->buffer_size <<= QATD_1MB_SHIFT;

    /* Debug level */
    QAT_DBG_GET_CFG_PARAM_INT(
        sysfsDir, QATD_PARAM_LEVEL, &instConfig->debug_level);

    /* Dump on process crash */
    QAT_DBG_GET_CFG_PARAM_INT(
        sysfsDir, QATD_PARAM_DUMP_ON_P_CRASH, &instConfig->dump_on_proc_crash);

    /* Continuous sync enable */
    QAT_DBG_GET_CFG_PARAM_INT(
        sysfsDir, QATD_PARAM_CS_ENABLED, &contSyncEnabled);
    if (!contSyncEnabled)
    {
        instConfig->sync_mode = QATD_SYNC_ON_CRASH;
        osalMemSet(
            instConfig->cont_sync_dir, 0, sizeof(instConfig->cont_sync_dir));
        instConfig->cont_sync_max_file_size = 0;
        instConfig->cont_sync_max_files_no = 0;

        return CPA_STATUS_SUCCESS;
    }

    instConfig->sync_mode = QATD_SYNC_CONT;
    /* Continuous sync dir */
    QAT_DBG_GET_CFG_PARAM_STR(sysfsDir,
                              QATD_PARAM_CS_DIR,
                              instConfig->cont_sync_dir,
                              sizeof(instConfig->cont_sync_dir));

    /* Continuous sync dir max size */
    QAT_DBG_GET_CFG_PARAM_INT(sysfsDir,
                              QATD_PARAM_CS_MAX_FILE_SZ,
                              &instConfig->cont_sync_max_file_size);
    instConfig->cont_sync_max_file_size <<= QATD_1MB_SHIFT;

    /* Continuous sync dir max file number */
    QAT_DBG_GET_CFG_PARAM_INT(sysfsDir,
                              QATD_PARAM_CS_MAX_FILES_NO,
                              &instConfig->cont_sync_max_files_no);

    /* Handle configuration errors which will cause
       program failure - should never happen */
    if (!instConfig->cont_sync_max_files_no)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Invalid configuration of device %d for param: %s:\n",
                        devId,
                        QATD_PARAM_CS_MAX_FILES_NO);

        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

void qatDbgLogDevDebugConfig(qat_dbg_inst_cfg_t *instConfig)
{
    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                    "-%s: %s",
                    QATD_PARAM_DUMP_DIR,
                    instConfig->dump_dir);
    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                    "-%s: %ld",
                    QATD_PARAM_DUMP_DIR_SZ,
                    instConfig->dump_dir_max_size >> QATD_1MB_SHIFT);

    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                    "-%s: %d",
                    QATD_PARAM_BUFFER_POOL_SZ,
                    instConfig->buffer_pool_size);
    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                    "-%s: %d",
                    QATD_PARAM_BUFFER_SZ,
                    instConfig->buffer_size >> QATD_1MB_SHIFT);

    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                    "-%s: %d",
                    QATD_PARAM_LEVEL,
                    instConfig->debug_level);

    QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                    "-%s: %d",
                    QATD_PARAM_DUMP_ON_P_CRASH,
                    instConfig->dump_on_proc_crash);

    if (instConfig->sync_mode == QATD_SYNC_CONT)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                        "-sync_mode: continuous synchronization");
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                        "-%s: %s",
                        QATD_PARAM_CS_DIR,
                        instConfig->cont_sync_dir);
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                        "-%s: %ld",
                        QATD_PARAM_CS_MAX_FILE_SZ,
                        instConfig->cont_sync_max_file_size >> QATD_1MB_SHIFT);
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                        "-%s: %d",
                        QATD_PARAM_CS_MAX_FILES_NO,
                        instConfig->cont_sync_max_files_no);
    }
    else
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                        "-sync_mode: dump crash on error");
    }
}