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
 * @file qat_dbg_fwaudit.h
 *
 * @description
 *        This file provides QAT firmware calls audit helpers functions.
 *
 ****************************************************************************/
#ifndef QAT_DBG_FWAUDIT_H
#define QAT_DBG_FWAUDIT_H

#include "icp_adf_dbg_log.h"

typedef struct qat_dbg_addr_range_s
{
    /* Process identification number */
    pid_t pid;
    /* Start address of a range */
    uintptr_t start;
    /* Address of the first byte above range */
    uintptr_t end;
    /* Range size in bytes */
    unsigned long long int size;
} qat_dbg_addr_range_t;

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Validate physical addresses contained in the debug
 *        message
 *
 * @description
 *        This function performs validation of all physical
 *        addresses contained in given debug message. The
 *        validation is performed by iterating over entries in
 *        proc.mmaps.dev file, contained in the path with debug logs.
 *        Each entry in the file contains information about single
 *        memory map performed by process characterized by PID.
 *        All physical addresses in debug message are checked
 *        if they are in range of at least one memory map done by
 *        the same process which generated this debug message.
 *        If an issue has been found, the debug output is printed
 *        to the stdout.
 *
 * @param[in]  msgHeader  pointer to debug entry header structure
 *
 * @retval CPA_TRUE    Invalid physical address has not been found
 * @retval CPA_FALSE   At least one physical address is outside
 *                     process memory
 *
 ******************************************************************
 */
CpaBoolean qatDbgTestPhyAddrMap(icp_adf_dbg_entry_header_t *msgHeader);

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Check if physical addresses contained in the debug
 *        message does not overlap
 *
 * @description
 *        This function performs comparison of all physical
 *        addresses ranges contained in the given debug message
 *        with each other. It is allowed for the addresses areas
 *        to be the same - one address in the same range that
 *        other one, but not one address in subrange of other.
 *
 * @param[in]  msgHeader  pointer to debug entry header structure
 *
 * @retval CPA_TRUE    Addresses overlaps have not been found
 * @retval CPA_FALSE   At least two addresses ranges overlaps
 *
 ******************************************************************
 */
CpaBoolean qatDbgTestPhyAddrOverlap(icp_adf_dbg_entry_header_t *msgHeader);

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Validate QAT response status code
 *
 * @description
 *        This function checks if the response error code is
 *        indicating an error. In that case the debug output is
 *        printed to the stdout.
 *
 * @param[in]  msgHeader  pointer to debug entry header structure
 *
 * @retval CPA_TRUE    The message status code does not indicate an error
 * @retval CPA_FALSE   The message status code indicates an error
 *
 ******************************************************************
 */
CpaBoolean qatDbgTestRespStatus(icp_adf_dbg_entry_header_t *msgHeader);

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Validate lengths fields inside QAT request contained in
 *        the debug message
 *
 * @description
 *        This function performs validation of lengths fields
 *        contained in given debug message considered as a request.
 *        The following conditions are validated:
 *          - the request is using known cipher algorithm;
 *          - the source packet size is greater than zero;
 *          - cipher offset and cipher length fits in source packet
 *            size;
 *          - the cipher length is a multiple of cipher block size
 *            in case of block ciphers.
 *        If an issue has been found, the debug output is printed
 *        to the stdout.
 *
 * @param[in]  msgHeader  pointer to debug entry header structure
 *
 * @retval CPA_TRUE    Invalid request length field has not been
 *                     found
 * @retval CPA_FALSE   At least one request length field is invalid
 *
 ******************************************************************
 */
CpaBoolean qatDbgTestReqLengths(icp_adf_dbg_entry_header_t *msgHeader);

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Validate QAT common message header
 *
 * @description
 *        This function validates the request and response service
 *        type and command identifier. For the responses the
 *        service id is also validated. Validation is performed by
 *        comparing the message values with known ones. If an issue
 *        has been found, the debug output is printed to the stdout.
 *
 * @param[in]  msgHeader  pointer to debug entry header structure
 *
 * @retval CPA_TRUE    The message common header is valid
 * @retval CPA_FALSE   The message common header is invalid
 *
 ******************************************************************
 */
CpaBoolean qatDbgTestMsgHeader(icp_adf_dbg_entry_header_t *msgHeader);

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Validate Scatter Gather Lists contained in
 *        the debug message
 *
 * @description
 *        This function checks if SGL was present in the QAT
 *        request contained in the given debug message and it was,
 *        the SGL descriptor copy inside the message is validated.
 *        The validation is performed in terms of NULL pointer to
 *        the flat buffer and zero-length of the flat buffers.
 *        If an issue has been found, the debug output is printed
 *        to the stdout.
 *
 * @param[in]  msgHeader  pointer to debug entry header structure
 *
 * @retval CPA_TRUE    Invalid SGL descriptor has not been found
 * @retval CPA_FALSE   SGL descriptor is invalid or it contains
 *                     invalid data
 *
 ******************************************************************
 */
CpaBoolean qatDbgTestReqSgl(icp_adf_dbg_entry_header_t *msgHeader);
#endif