/******************************************************************************
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
 *****************************************************************************/

/******************************************************************************
 * @file lac_logger_utils.h
 *
 * @defgroup LacLogger Look Aside Acceleration Debuggability Logger
 *
 * @ingroup LacLogger
 *
 * @description
 *      This file provides utility functions which are used to manage QAT
 *      traffic storage in debug logs for Traditional and Data Plane API.
 *      Helper functions related to Debuggability feature are also declarated
 *      in this file.
 *
 *****************************************************************************/

#ifndef LAC_LOGGER_UTILS_H_
#define LAC_LOGGER_UTILS_H_
#include "cpa.h"
#include "icp_adf_dbg_log.h"

typedef void *lac_comms_trans_handle;
/**< @ingroup LacLogger
 *      Transport (ring) handle type definiton as pointer. Defined to include
 *      only required header files.
 */
typedef void *lac_dbg_op_data_comms;
/**< @ingroup LacLogger
 *      Common opaque data type definiton used for API call logging.
 */

/*************************************************************************
 * @ingroup LacLogger
 * @description
 *      This function checks if for given \p trans_handle the
 *      requested Debuggability logging level provided in \p log_level
 *      argument is enabled.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      Yes
 * @threadSafe
 *      Yes
 *
 * @param[in] trans_handle  Transport handle
 * @param[in] log_level     Debug level
 *
 * @retval CPA_TRUE   Requested debug level is enabled for given
 *                    transport handle
 * @retval CPA_FALSE  Requested debug level is disabled for given
 *                    transport handle or invalid arguments provided
 *
 *************************************************************************/
CpaBoolean LacLogger_IsEnabled(lac_comms_trans_handle trans_handle,
                               enum icp_adf_dbg_level log_level);

/*************************************************************************
 * @ingroup LacLogger
 * @description
 *      This function extracts service data such as QAT bank and ring
 *      number from transport handle and request specific data (SGL and
 *      CY/DC algorithm) from request provided in the \p pqat_msg argument.
 *      The data is required for debug purposes and it is stored in debug
 *      content description structure pointed by \p dbg_desc argument.
 *
 * @context
 *    This function is called from the SalQatMsg_transPutMsg function.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      Yes
 * @threadSafe
 *      Yes
 *
 * @param[in]  trans_handle  Transport handle
 * @param[out] dbg_desc      Pointer to debug descriptor
 * @param[in]  pqat_msg      Pointer to QAT message
 *
 * @retval CPA_STATUS_INVALID_PARAM     Invalid arguments provided
 * @retval CPA_STATUS_FAIL              Failed to extract the debug data
 * @retval CPA_STATUS_UNSUPPORTED       Unsupported QAT request
 * @retval CPA_STATUS_SUCCESS           Data extracted successfully
 *
 *************************************************************************/
CpaStatus LacLogger_PrepFWReqTrad(lac_comms_trans_handle trans_handle,
                                  icp_adf_dbg_content_desc_t *dbg_desc,
                                  void *pqat_msg);

#ifndef ICP_DC_ONLY
/*************************************************************************
 * @ingroup LacLogger
 * @description
 *      This function is storing QAT cryptographic request prepared by
 *      Data Plane API in debug buffer. Prior to storage an extraction of
 *      service data such as QAT bank and ring number from transport
 *      handle and cryptographic algorithm from the request is performed.
 *
 * @context
 *    This function is called from Data Plane cryptographic API
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      Yes
 * @threadSafe
 *      No (Doesn't need to be thread safe for DP)
 *
 * @param[in]  trans_handle  Transport handle
 * @param[in]  pqat_msg      Pointer to QAT message
 *
 * @retval CPA_STATUS_INVALID_PARAM     Invalid arguments provided
 * @retval CPA_STATUS_FAIL              Failed to extract the debug data
 *                                      or store request in debug buffer
 * @retval CPA_STATUS_RETRY             All debug buffers are being
 *                                      synchronized with persistent
 *                                      storage and the request has not
 *                                      been stored in any of them
 * @retval CPA_STATUS_SUCCESS           Request stored successfully or
 *                                      skipped due to configuration:
 *                                      logging disabled or other log
 *                                      level than requests is configured
 *
 *************************************************************************/
CpaStatus LacLogger_LogCyDpReq(lac_comms_trans_handle trans_handle,
                               void *pqat_msg);
#endif

/*************************************************************************
 * @ingroup LacLogger
 * @description
 *      This function is storing QAT compression request prepared by
 *      Data Plane API in debug buffer. Prior to storage an extraction of
 *      service data such as QAT bank and ring number from transport
 *      handle and compression algorithm from the request is performed.
 *
 * @context
 *    This function is called from Data Plane data compression API
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      Yes
 * @threadSafe
 *      No (Doesn't need to be thread safe for DP)
 *
 * @param[in]  trans_handle  Transport handle
 * @param[in]  pqat_msg      Pointer to QAT message
 *
 * @retval CPA_STATUS_INVALID_PARAM     Invalid arguments provided
 * @retval CPA_STATUS_FAIL              Failed to extract the debug data
 *                                      or store request in debug buffer
 * @retval CPA_STATUS_RETRY             All debug buffers are being
 *                                      synchronized with persistent
 *                                      storage and the request has not
 *                                      been stored in any of them
 * @retval CPA_STATUS_SUCCESS           Request stored successfully or
 *                                      skipped due to configuration:
 *                                      logging disabled or other log
 *                                      level than requests is configured
 *
 *************************************************************************/
CpaStatus LacLogger_LogDcDpReq(lac_comms_trans_handle trans_handle,
                               void *pqat_msg);

/*************************************************************************
 * @ingroup LacLogger
 * @description
 *      This function is storing given QAT API call with its opaque data
 *      in debug buffer. NULL opaque data API calls are skipped.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      Yes
 * @threadSafe
 *      Yes (Mutex lock usage in icp_adf_log_apicall)
 *
 * @param[in]  instanceHandle  Instance handle
 * @param[in]  api_type        Type of API to log
 * @param[in]  op_data         Pointer to API opaque data
 * @param[in]  op_data_size    Size of API opaque data pointed by op_data

 * @retval CPA_STATUS_FAIL              Failed to extract transport handle
 *                                      or store API call in debug buffer
 * @retval CPA_STATUS_FATAL             Failed to lock a mutex
 * @retval CPA_STATUS_RETRY             All debug buffers are being
 *                                      synchronized with persistent
 *                                      storage and the API call has not
 *                                      been stored in any of them
 * @retval CPA_STATUS_SUCCESS           API call stored successfully or
 *                                      skipped due to configuration:
 *                                      logging disabled or other log
 *                                      level than API calls is configured
 *
 *************************************************************************/
CpaStatus LacLogger_LogApiCall(CpaInstanceHandle instanceHandle,
                               enum icp_adf_dbg_api_type api_type,
                               lac_dbg_op_data_comms op_data,
                               Cpa16U op_data_size);

/*************************************************************************
 * @ingroup LacLogger
 * @description
 *      This function is used to notify Debuggability about error response
 *      form QAT. An ioctl to Debuggability character device is performed
 *      for storing running processes memory map purpose.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      Yes
 * @threadSafe
 *      Yes
 *
 * @param[in]  trans_handle  Transport handle
 *
 * @retval CPA_STATUS_FAIL              Failed to extract transport handle
 *                                      or ioctl failed
 * @retval CPA_STATUS_INVALID_PARAM     The transport handle does not have
 *                                      Debuggability feature enabled
 * @retval CPA_STATUS_SUCCESS           Notification sent successfully
 *
 *************************************************************************/
CpaStatus LacLogger_ErrRespNotify(lac_comms_trans_handle trans_handle);

/*************************************************************************
 * @ingroup LacLogger
 * @description
 *      Default privacy cleanup callback. The function clears address of
 *      the content descriptor for symmetric cryptography requests when
 *      they use content descriptor to storage service-specific data.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      Yes
 * @threadSafe
 *      Yes
 *
 * @param[in]  pqat_msg  Pointer to QAT message
 *
 * @retval CPA_STATUS_INVALID_PARAM     NULL value of pqat_msg provided
 * @retval CPA_STATUS_SUCCESS           Private data cleared successfully
 *
 *************************************************************************/
CpaStatus LacLogger_PrivCleanupImpl(void *qat_msg);
#endif /* LAC_LOGGER_UTILS_H_ */