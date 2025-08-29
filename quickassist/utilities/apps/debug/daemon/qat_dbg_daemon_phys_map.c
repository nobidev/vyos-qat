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
 * @file qat_dbg_daemon_phys_map.c
 *
 * @description
 *        This file provides implementation of processes memory map file
 *        generation
 *
 ****************************************************************************/

/* System headers */
#include <stdio.h>

/* Project headers */
#include "qat_dbg_daemon_phys_map.h"
#include "qat_dbg_daemon_log.h"
#include "icp_adf_dbg_log.h"
#include "adf_kernel_types.h"
#include "icp_platform.h"

/*
*******************************************************************************
* Private definitions
*******************************************************************************
*/
#define QAT_DBG_MMAP_STORE_FAILED -1

/*
*******************************************************************************
* Public functions
*******************************************************************************
*/
ssize_t qatDbgStoreProcsMmaps(qat_dbg_dev_instance_t *devInstance, char *dir)
{
    FILE *file = NULL;
    char *line = NULL;
    size_t allocLen = 0;
    ssize_t readLen = 0;
    ssize_t writeLen = 0;
    ssize_t totalLen = 0;
    ssize_t result = QAT_DBG_MMAP_STORE_FAILED;
    int devId = -1;
    char outFilePath[QAT_DBG_FILE_PATH_MAX_LEN] = {0};
    FILE *outFile = NULL;

    if (!dir)
    {
        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                        "Incorrect directory for processes memory map file");

        return result;
    }

    file = fopen(QATD_DEVICE_FILENAME, "r");
    if (!file)
    {
        return result;
    }

    while (-1 != (readLen = getline(&line, &allocLen, file)))
    {
        if (!line)
            goto on_fail;

        if (sscanf(line, QATD_MMAP_DEV_HEADER " %3d", &devId) <= 0)
        {
            /* Standard region line */
            if (outFile)
            {
                writeLen = fwrite(line, sizeof(char), (size_t)readLen, outFile);
                if (writeLen != readLen)
                {
                    QAT_DBG_LOG_MSG(
                        QAT_DBG_LOG_LVL_ERR, "Saving region %s - failed", line);
                    goto on_fail;
                }
                totalLen += readLen;
            }
            continue;
        }

        /* Header found */
        if (outFile)
        {
            fclose(outFile);
            outFile = NULL;
        }
        if (devId != (int)devInstance->accelId)
            continue;

        snprintf(outFilePath,
                 sizeof(outFilePath),
                 "%s/%s%02u_" QAT_DBG_PCI_ADDR_FORMAT,
                 dir,
                 QATD_PROC_MMAP_FILE_NAME,
                 devInstance->accelId,
                 devInstance->pci_addr.domain,
                 devInstance->pci_addr.bus,
                 devInstance->pci_addr.dev,
                 devInstance->pci_addr.func);
        outFile = fopen(outFilePath, "w");
        if (!outFile)
        {
            QAT_DBG_LOG_MSG(
                QAT_DBG_LOG_LVL_ERR,
                "Unable to create processes memory map file output file %s",
                outFilePath);
            goto on_fail;
        }

        QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_INFO,
                        "Dumping physical memory regions to file: %s",
                        outFilePath);

        /* Write header */
        writeLen = fwrite(line, sizeof(char), (size_t)readLen, outFile);
        if (writeLen != readLen)
        {
            QAT_DBG_LOG_MSG(QAT_DBG_LOG_LVL_ERR,
                            "Error while writing to file: %s",
                            outFilePath);
            goto on_fail;
        }
        totalLen += readLen;
    }
    result = totalLen;

on_fail:
    if (line)
    {
        free(line);
    }
    if (outFile)
    {
        fclose(outFile);
    }
    fclose(file);

    return result;
}