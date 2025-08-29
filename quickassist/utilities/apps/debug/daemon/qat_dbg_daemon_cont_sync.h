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
 * @file qat_dbg_daemon_cont_sync.h
 *
 * @description
 *        This file provides functions related to the daemon continuous sync
 *        mode of Debuggability. This mode writes data from debug buffers
 *        to the persistent storage almost in real-time.
 *
 ****************************************************************************/
#ifndef QAT_DBG_DAEMON_CONT_SYNC_H
#define QAT_DBG_DAEMON_CONT_SYNC_H

#include "qat_dbg_daemon.h"

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Open previous debug log storage file
 *
 * @description
 *        This function is looking for the last file modified by
 *        continuous sync worker. If found and the log file
 *        has capacity for a new data, this file is opened,
 *        and new data can be appended. Otherwise, a new debug log
 *        storage file is created. This function setup continuous
 *        sync mode log file related operational structure of type
 *        qat_dbg_cont_sync_log inside given devInstance structure
 *        and creates debug logs storage folder, which path
 *        is contained in that structure, if necessary.
 *
 * @param[in]   devInstance  pointer to device configuration
 *                           structure
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid devInstance parameter
 *                                   value
 * @retval CPA_STATUS_SUCCESS        Operation successful
 * @retval CPA_STATUS_FAIL           Operation failed
 *
 ******************************************************************
 */
CpaStatus qatDbgSyncOpenPrevFile(qat_dbg_dev_instance_t *devInstance);

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Save debug buffer in storage file
 *
 * @description
 *        This function writes given debug buffer to the currently
 *        opened log file. If the log file is not opened, or it
 *        does not have capacity for the buffer, the new log file
 *        is created or the oldest one overwritten according to
 *        Debuggability feature configuration of the QAT device.
 *
 * @param[in]   devInstance  pointer to device configuration
 *                           structure
 * @param[in]   bufferId     buffer identifier indexed from 0

 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments given
 * @retval CPA_STATUS_SUCCESS        Operation successful
 * @retval CPA_STATUS_FAIL           Operation failed
 * @retval CPA_STATUS_RETRY          Buffer has been written
 *                                   partially. Another call of
 *                                   this function is required
 *
 ******************************************************************
 */
CpaStatus qatDbgSyncBuffer(qat_dbg_dev_instance_t *devInstance,
                           size_t bufferId);
#endif