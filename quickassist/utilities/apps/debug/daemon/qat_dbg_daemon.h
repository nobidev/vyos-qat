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
 * @file qat_dbg_daemon.h
 *
 * @description
 *        This file provides common utilities for QAT debug daemon and
 *        definitions of it operational structures.
 *
 ****************************************************************************/
#ifndef QAT_DBG_DAEMON_H
#define QAT_DBG_DAEMON_H

#include <sys/types.h>
#include "cpa.h"
#include "Osal.h"
#include "adf_kernel_types.h"
#include "qat_dbg_user.h"
#include "qat_dbg_daemon_log.h"
#include "qat_dbg_common.h"

/*
*******************************************************************************
* Exported definitions
*******************************************************************************
*/
#define QAT_DBG_LOG_DIR_PERM (S_IRWXU | S_IRWXG)
#define QAT_DBG_LOG_FILE_PREM (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)
#define QAT_DBG_INVALID_FD -1
#define QAT_DBG_IS_FD_VALID(fd) ((fd) >= 0)
#define QAT_DBG_FILE_PATH_MAX_LEN (QATD_MAX_FILE_NAME * 2)
#define QAT_DBG_PCI_ADDR_FORMAT "%04x_%02x_%02x_%x"

#define QAT_DBG_OPEN(...) open(__VA_ARGS__)

/*
*******************************************************************************
* Types definition
*******************************************************************************
*/
typedef struct qatd_ring_desc qat_dbg_buffer_desc_t;
typedef struct qatd_instance_config qat_dbg_inst_cfg_t;
typedef struct qatd_ioctl_bsf2id_req qat_dbg_pci_addr_t;

/*
*******************************************************************************
* Continuous sync mode log file related operational structure
*******************************************************************************
*/
struct qat_dbg_cont_sync_log
{
    /* File descriptor for open log file */
    int fd;
    /* Current size of file associated with above file descriptor */
    size_t fileSize;
    /* Number of opened log file in range <0;
     * qat_dbg_inst_cfg_t.cont_sync_max_files_no) */
    size_t fileNum;
    /* Path to the open log file */
    char filePath[QAT_DBG_FILE_PATH_MAX_LEN];
};

/*
*******************************************************************************
* Continuous sync mode operational structure
*******************************************************************************
*/
struct qat_dbg_cont_sync_data
{
    /* Log file operational data */
    struct qat_dbg_cont_sync_log logFile;
    /* IPC message queue listener thread handle */
    OsalThread thread;
    /* Synchronization mutex */
    OsalMutex mutex;
};

/*
*******************************************************************************
* Accelerator device synchronization worker structure
*******************************************************************************
*/
typedef struct qat_dbg_dev_instance_s
{
    /* QAT Device ID */
    Cpa32U accelId;
    /* Debuggability feature enable inidcator */
    Cpa32S enabled;
    /* QAT Debuggability device configuration */
    qat_dbg_inst_cfg_t config;
    /* Timestamp used to calculate time difference between crash dump requests
     */
    Cpa64U lastCrashTs;
    /* Continuous sync mode operational data */
    struct qat_dbg_cont_sync_data contSync;
    /* Pointer for debug buffers user-space memory mapping */
    qat_dbg_buffer_desc_t **bufferPool;
    /* Struct used to add Domain and BDF to logs file paths */
    qat_dbg_pci_addr_t pci_addr;
} qat_dbg_dev_instance_t;
#endif
