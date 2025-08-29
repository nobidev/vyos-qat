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
 *        This file provides kernel space to user space QAT messages
 *        listener utilities.
 *
 ****************************************************************************/
#ifndef QAT_DBG_DAEMON_UEVENT_LISTENER_H
#define QAT_DBG_DAEMON_UEVENT_LISTENER_H

#include "cpa.h"
#include "adf_common_drv.h"

/*
*******************************************************************************
* User event descriptor structure
*******************************************************************************
*/
struct qat_dbg_uevent
{
    Cpa32U accelId;
    enum adf_event event;
};

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Create event monitor
 *
 * @description
 *        This function creates event monitor for QAT kernel
 *        events.
 *
 * @retval CPA_STATUS_SUCCESS    Operation successful
 * @retval CPA_STATUS_FAIL       Operation failed
 *
 ******************************************************************
 */
CpaStatus qatDbgUeventMonitorCreate(void);

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Destroy event monitor
 *
 * @description
 *        This function destroys QAT kernel events monitor
 *        previously created by qatDbgUeventMonitorCreate() call.
 *
 * @retval None
 *
 ******************************************************************
 */
void qatDbgUeventMonitorDelete(void);

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Poll for QAT kernel event
 *
 * @description
 *        This function polls for QAT kernel event. To call this
 *        function, successful execution of
 *        qatDbgUeventMonitorCreate() must be accomplished first.
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments given
 * @retval CPA_STATUS_UNSUPPORTED    Event handling in not
 *                                   required for Debuggability
 * @retval CPA_STATUS_SUCCESS        Operation successful
 * @retval CPA_STATUS_FAIL           Operation failed
 *
 ******************************************************************
 */
CpaStatus qatDbgUeventProxyPoll(struct qat_dbg_uevent *event);
#endif