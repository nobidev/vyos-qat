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
 * @file lac_logger_utils.c
 *
 * @ingroup LacLogger
 *
 * Utility functions for QAT traffic debug sideband copy logging
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include "lac_logger_utils.h"
#include "lac_common.h"
#include "icp_adf_transport.h"
#include "icp_buffer_desc.h"
#include "lac_sym.h"
#include "lac_session.h"
#include "dc_session.h"
#include "dc_datapath.h"

/*
*******************************************************************************
* Include firmware headers files
*******************************************************************************
*/
#include "icp_qat_fw.h"
#include "icp_qat_fw_la.h"
#include "icp_qat_fw_comp.h"

/*
********************************************************************************
* Private definitions
********************************************************************************
*/
#define SYM_REQUEST_ALGORITHM_GET_FAILURE_STR                                  \
    "Can not get SYM algorithm from request"
#define DC_REQUEST_ALGORITHM_GET_FAILURE_STR                                   \
    "Can not get DC algorithm from request"
/* errors below should never happen since they will occur when NULL parameter is
 * passed as a argument */
#define INVALID_LOGGER_HANDLE_STR "Can not get the logger handle"
#define BANK_AND_RING_GET_FAILURE_STR "Can not get bank and ring number"

/*
********************************************************************************
* Private functions
********************************************************************************
*/
#ifndef ICP_DC_ONLY
STATIC CpaBoolean LacLogger_IsBulkRequest(icp_qat_fw_comn_req_t *req)
{
    icp_qat_fw_comn_req_hdr_t *cmn_hdr = &req->comn_hdr;

    if (cmn_hdr->service_cmd_id == ICP_QAT_FW_LA_CMD_CIPHER ||
        cmn_hdr->service_cmd_id == ICP_QAT_FW_LA_CMD_CIPHER_HASH ||
        cmn_hdr->service_cmd_id == ICP_QAT_FW_LA_CMD_HASH_CIPHER ||
        cmn_hdr->service_cmd_id == ICP_QAT_FW_LA_CMD_AUTH ||
        cmn_hdr->service_cmd_id == ICP_QAT_FW_LA_CMD_CIPHER_PRE_COMP ||
        cmn_hdr->service_cmd_id == ICP_QAT_FW_LA_CMD_AUTH_PRE_COMP)
    {
        return CPA_TRUE;
    }

    return CPA_FALSE;
}

STATIC CpaStatus LacLogger_GetSymSGLData(icp_adf_dbg_content_desc_t *dbg_desc,
                                         icp_qat_fw_comn_req_t *qat_req)
{
    lac_sym_cookie_t *cookie;
    lac_sym_bulk_cookie_t *bulk_cookie;
    const CpaBufferList *src_list;
    CpaBufferList *dst_list;
    icp_qat_fw_comn_req_mid_t *comn_mid = &qat_req->comn_mid;
    void *opaque_data = (void *)(uintptr_t)comn_mid->opaque_data;

    if (QAT_COMN_PTR_TYPE_FLAT ==
        ICP_QAT_FW_COMN_PTR_TYPE_GET(qat_req->comn_hdr.comn_req_flags))
    {
        return CPA_STATUS_SUCCESS;
    }
    if (!opaque_data)
    {
        LAC_LOG_ERROR("Invalid request opaque_data");
        return CPA_STATUS_FAIL;
    }
    if (comn_mid->src_length > 0)
    {
        LAC_LOG_ERROR("Invalid src_length value for SGL");
        return CPA_STATUS_FAIL;
    }
    if (comn_mid->dst_length > 0)
    {
        LAC_LOG_ERROR("Invalid dst_length value for SGL");
        return CPA_STATUS_FAIL;
    }

    cookie = (lac_sym_cookie_t *)opaque_data;
    bulk_cookie = &cookie->u.bulkCookie;
    src_list = bulk_cookie->pSrcBuffer;
    dst_list = bulk_cookie->pDstBuffer;
    if (src_list)
    {
        dbg_desc->src_sgl =
            (icp_buffer_list_desc_t *)src_list->pPrivateMetaData;
        dbg_desc->src_sgl_size =
            sizeof(icp_buffer_list_desc_t) +
            src_list->numBuffers * sizeof(icp_flat_buffer_desc_t);
    }
    if (dst_list)
    {
        dbg_desc->dst_sgl =
            (icp_buffer_list_desc_t *)dst_list->pPrivateMetaData;
        dbg_desc->dst_sgl_size =
            sizeof(icp_buffer_list_desc_t) +
            dst_list->numBuffers * sizeof(icp_flat_buffer_desc_t);
    }

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus LacLogger_GetSymCyAlg(icp_adf_dbg_content_desc_t *dbg_desc,
                                       icp_qat_fw_comn_req_t *qat_req)
{
    lac_sym_cookie_t *cookie;
    lac_sym_bulk_cookie_t *bulk_cookie;
    lac_session_desc_t *session_desc;
    icp_qat_fw_comn_req_mid_t *comn_mid = &qat_req->comn_mid;

    if (LacLogger_IsBulkRequest(qat_req) == CPA_FALSE)
    {
        return CPA_STATUS_SUCCESS;
    }

    cookie = (lac_sym_cookie_t *)(uintptr_t)comn_mid->opaque_data;
    if (!cookie)
    {
        LAC_LOG_ERROR("SYM request opaque data is NULL");
        return CPA_STATUS_FAIL;
    }

    bulk_cookie = &cookie->u.bulkCookie;
    if (bulk_cookie->sessionCtx)
    {
        session_desc =
            (lac_session_desc_t *)*(void **)(bulk_cookie->sessionCtx);
        dbg_desc->content_desc.u.s.cipherAlg =
            (unsigned short)session_desc->cipherAlgorithm;
        dbg_desc->content_desc.u.s.hashAlg =
            (unsigned short)session_desc->hashAlgorithm;
    }

    return CPA_STATUS_SUCCESS;
}
#endif

STATIC CpaStatus LacLogger_GetDcAlg(icp_adf_dbg_content_desc_t *dbg_desc,
                                    icp_qat_fw_comn_req_t *qat_req)
{
    dc_compression_cookie_t *dc_cookie;
    dc_session_desc_t *dc_session;
    icp_qat_fw_comp_req_t *dc_req = (icp_qat_fw_comp_req_t *)qat_req;
    icp_qat_fw_comn_req_mid_t *comn_mid = &dc_req->comn_mid;

    dc_cookie = (dc_compression_cookie_t *)(uintptr_t)comn_mid->opaque_data;
    if (!dc_cookie)
    {
        LAC_LOG_ERROR("DC request opaque data is NULL");
        return CPA_STATUS_FAIL;
    }
    if (dc_cookie->pSessionHandle)
    {
        dc_session = (dc_session_desc_t *)*(void **)dc_cookie->pSessionHandle;
        dbg_desc->content_desc.u.s1.compType =
            (unsigned short)dc_session->compType;
        dbg_desc->content_desc.u.s1.huffType =
            (unsigned short)dc_session->huffType;
    }

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus LacLogger_GetDcSGLData(icp_adf_dbg_content_desc_t *dbg_desc,
                                        icp_qat_fw_comn_req_t *qat_req)
{
    dc_compression_cookie_t *cookie;
    const CpaBufferList *src_list;
    CpaBufferList *dst_list;
    icp_qat_fw_comp_req_t *comp_req = (icp_qat_fw_comp_req_t *)qat_req;
    icp_qat_fw_comn_req_mid_t *comn_mid = &comp_req->comn_mid;
    void *opaque_data = (void *)(uintptr_t)comn_mid->opaque_data;

    if (QAT_COMN_PTR_TYPE_FLAT ==
        ICP_QAT_FW_COMN_PTR_TYPE_GET(qat_req->comn_hdr.comn_req_flags))
    {
        return CPA_STATUS_SUCCESS;
    }
    if (!opaque_data)
    {
        LAC_LOG_ERROR("Invalid request opaque_data");
        return CPA_STATUS_FAIL;
    }
    if (comn_mid->src_length > 0)
    {
        LAC_LOG_ERROR("Invalid src_length value for SGL");
        return CPA_STATUS_FAIL;
    }
    if (comn_mid->dst_length > 0)
    {
        LAC_LOG_ERROR("Invalid dst_length value for SGL");
        return CPA_STATUS_FAIL;
    }

    cookie = (dc_compression_cookie_t *)opaque_data;
    src_list = (CpaBufferList *)cookie->pUserSrcBuff;
    dst_list = (CpaBufferList *)cookie->pUserDestBuff;
    if (src_list)
    {
        dbg_desc->src_sgl =
            (icp_buffer_list_desc_t *)src_list->pPrivateMetaData;
        dbg_desc->src_sgl_size =
            sizeof(icp_buffer_list_desc_t) +
            src_list->numBuffers * sizeof(icp_flat_buffer_desc_t);
    }
    if (dst_list)
    {
        dbg_desc->dst_sgl =
            (icp_buffer_list_desc_t *)dst_list->pPrivateMetaData;
        dbg_desc->dst_sgl_size =
            sizeof(icp_buffer_list_desc_t) +
            dst_list->numBuffers * sizeof(icp_flat_buffer_desc_t);
    }

    return CPA_STATUS_SUCCESS;
}

/*
********************************************************************************
* Public functions
********************************************************************************
*/
CpaBoolean LacLogger_IsEnabled(lac_comms_trans_handle trans_handle,
                               enum icp_adf_dbg_level log_level)
{
    icp_adf_dbg_handle_t *dbg_handle;

    if (CPA_STATUS_SUCCESS !=
        icp_adf_transGetLoggerHandle(trans_handle, &dbg_handle))
    {
        return CPA_FALSE;
    }

    return icp_adf_log_is_enabled(dbg_handle, log_level);
}

CpaStatus LacLogger_PrepFWReqTrad(lac_comms_trans_handle trans_handle,
                                  icp_adf_dbg_content_desc_t *dbg_desc,
                                  void *pqat_msg)
{
    CpaStatus status;
    icp_qat_fw_comn_req_t *qat_req;
    icp_qat_fw_comn_req_hdr_t *comn_hdr;

    LAC_CHECK_NULL_PARAM(dbg_desc);
    LAC_CHECK_NULL_PARAM(pqat_msg);

    /* Extracting common headers */
    qat_req = (icp_qat_fw_comn_req_t *)pqat_msg;
    comn_hdr = &qat_req->comn_hdr;
    /* Extracting basic data */
    dbg_desc->msg_type = (unsigned short)QATD_MSG_REQUEST;

    if (CPA_STATUS_SUCCESS != icp_adf_transGetBankAndRing(trans_handle,
                                                          &dbg_desc->bank,
                                                          &dbg_desc->ring))
    {
        LAC_LOG_ERROR(BANK_AND_RING_GET_FAILURE_STR);
        return CPA_STATUS_FAIL;
    }

    dbg_desc->msg = pqat_msg;

    if (CPA_STATUS_SUCCESS !=
        icp_adf_transGetMessageSize(trans_handle, &dbg_desc->msg_size))
    {
        LAC_LOG_ERROR("Can not get the request size");
        return CPA_STATUS_FAIL;
    }

#ifndef ICP_DC_ONLY
    /* SYMMETRIC */
    if (ICP_QAT_FW_COMN_REQ_CPM_FW_LA == comn_hdr->service_type)
    {
        status = LacLogger_GetSymSGLData(dbg_desc, pqat_msg);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Can not get SYM request SGL data");
            return status;
        }

        status = LacLogger_GetSymCyAlg(dbg_desc, pqat_msg);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR(SYM_REQUEST_ALGORITHM_GET_FAILURE_STR);
        }
        return status;
    }
#ifndef ASYM_NOT_SUPPORTED
    /* PKE - ASYMMETRIC */
    if (ICP_QAT_FW_COMN_REQ_CPM_FW_PKE == comn_hdr->service_type)
    {
        return CPA_STATUS_SUCCESS;
    }
#endif
#endif
    /* COMPRESSION */
    if (ICP_QAT_FW_COMN_REQ_CPM_FW_COMP == comn_hdr->service_type)
    {
        status = LacLogger_GetDcSGLData(dbg_desc, pqat_msg);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR("Can not get DC request SGL data");
            return status;
        }

        status = LacLogger_GetDcAlg(dbg_desc, pqat_msg);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR(DC_REQUEST_ALGORITHM_GET_FAILURE_STR);
        }
        return status;
    }

    if (ICP_QAT_FW_COMN_REQ_CPM_FW_COMP_CHAIN == comn_hdr->service_type)
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    return CPA_STATUS_SUCCESS;
}

#ifndef ICP_DC_ONLY
CpaStatus LacLogger_LogCyDpReq(lac_comms_trans_handle trans_handle,
                               void *pqat_msg)
{
    icp_qat_fw_comn_req_t *qat_req;
    icp_adf_dbg_handle_t *dbg_handle;
    icp_adf_dbg_content_desc_t dbg_desc = {0};

    LAC_CHECK_NULL_PARAM(pqat_msg);

    qat_req = (icp_qat_fw_comn_req_t *)pqat_msg;
    dbg_desc.msg_type = (unsigned short)QATD_MSG_REQUEST;
    dbg_desc.msg = pqat_msg;
    dbg_desc.msg_size = sizeof(icp_qat_fw_la_bulk_req_t);

    if (QAT_COMN_PTR_TYPE_SGL ==
        ICP_QAT_FW_COMN_PTR_TYPE_GET(qat_req->comn_hdr.comn_req_flags))
    {
        dbg_desc.src_phy_addr = qat_req->comn_mid.src_data_addr;
        dbg_desc.dst_phy_addr = qat_req->comn_mid.dest_data_addr;
    }
    if (CPA_STATUS_SUCCESS != LacLogger_GetSymCyAlg(&dbg_desc, qat_req))
    {
        LAC_LOG_ERROR(SYM_REQUEST_ALGORITHM_GET_FAILURE_STR);
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS != icp_adf_transGetBankAndRing(
                                  trans_handle, &dbg_desc.bank, &dbg_desc.ring))
    {
        LAC_LOG_ERROR(BANK_AND_RING_GET_FAILURE_STR);
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS !=
        icp_adf_transGetLoggerHandle(trans_handle, &dbg_handle))
    {
        LAC_LOG_ERROR(INVALID_LOGGER_HANDLE_STR);
        return CPA_STATUS_FAIL;
    }

    return icp_adf_log_req(dbg_handle, &dbg_desc);
}
#endif

CpaStatus LacLogger_LogDcDpReq(lac_comms_trans_handle trans_handle,
                               void *pqat_msg)
{
    icp_qat_fw_comn_req_t *qat_req;
    icp_adf_dbg_handle_t *dbg_handle;
    icp_adf_dbg_content_desc_t dbg_desc = {0};

    LAC_CHECK_NULL_PARAM(pqat_msg);

    qat_req = (icp_qat_fw_comn_req_t *)pqat_msg;
    dbg_desc.msg_type = (unsigned short)QATD_MSG_REQUEST;
    dbg_desc.msg = pqat_msg;
    dbg_desc.msg_size = sizeof(icp_qat_fw_la_bulk_req_t);

    if (QAT_COMN_PTR_TYPE_SGL ==
        ICP_QAT_FW_COMN_PTR_TYPE_GET(qat_req->comn_hdr.comn_req_flags))
    {
        dbg_desc.src_phy_addr = qat_req->comn_mid.src_data_addr;
        dbg_desc.dst_phy_addr = qat_req->comn_mid.dest_data_addr;
    }
    if (CPA_STATUS_SUCCESS != LacLogger_GetDcAlg(&dbg_desc, qat_req))
    {
        LAC_LOG_ERROR(DC_REQUEST_ALGORITHM_GET_FAILURE_STR);
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS != icp_adf_transGetBankAndRing(
                                  trans_handle, &dbg_desc.bank, &dbg_desc.ring))
    {
        LAC_LOG_ERROR(BANK_AND_RING_GET_FAILURE_STR);
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS !=
        icp_adf_transGetLoggerHandle(trans_handle, &dbg_handle))
    {
        LAC_LOG_ERROR(INVALID_LOGGER_HANDLE_STR);
        return CPA_STATUS_FAIL;
    }

    return icp_adf_log_req(dbg_handle, &dbg_desc);
}

CpaStatus LacLogger_LogApiCall(CpaInstanceHandle instanceHandle,
                               enum icp_adf_dbg_api_type api_type,
                               lac_dbg_op_data_comms op_data,
                               Cpa16U op_data_size)
{
    icp_comms_trans_handle trans_handle;
    icp_adf_dbg_handle_t *dbg_handle;
    icp_adf_dbg_content_desc_t dbg_desc;

    if (!op_data)
    {
        return CPA_STATUS_SUCCESS;
    }
    /* The API calls logging shares the same ring handle as QAT resposes */
    trans_handle =
        icp_adf_transGetHandleRx(instanceHandle, SAL_SERVICE_TYPE_CRYPTO_SYM);
    if (!trans_handle)
    {
        LAC_LOG_ERROR(
            "Instance handle does not contain valid transport handle");
        return CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS !=
        icp_adf_transGetLoggerHandle(trans_handle, &dbg_handle))
    {
        /* Do not report error because ring buffer may have Debuggability
         * disabled */
        return CPA_STATUS_SUCCESS;
    }
    if (CPA_FALSE == icp_adf_log_is_enabled(dbg_handle, QATD_LEVEL_API_CALLS))
    {
        return CPA_STATUS_SUCCESS;
    }

    osalMemSet(&dbg_desc, 0, sizeof(dbg_desc));
    if (CPA_STATUS_SUCCESS != icp_adf_transGetBankAndRing(
                                  trans_handle, &dbg_desc.bank, &dbg_desc.ring))
    {
        LAC_LOG_ERROR(BANK_AND_RING_GET_FAILURE_STR);
        return CPA_STATUS_FAIL;
    }

    dbg_desc.msg_type = QATD_MSG_APICALL;
    dbg_desc.api_type = api_type;
    dbg_desc.msg = (void *)op_data;
    dbg_desc.msg_size = op_data_size;

    return icp_adf_log_apicall(dbg_handle, &dbg_desc);
}

CpaStatus LacLogger_ErrRespNotify(lac_comms_trans_handle trans_handle)
{
    icp_adf_dbg_handle_t *dbg_handle;

    if (CPA_STATUS_SUCCESS !=
        icp_adf_transGetLoggerHandle(trans_handle, &dbg_handle))
    {
        LAC_LOG_ERROR(INVALID_LOGGER_HANDLE_STR);
        return CPA_STATUS_FAIL;
    }

    return icp_adf_log_err_resp_notify(dbg_handle);
}

CpaStatus LacLogger_PrivCleanupImpl(void *qat_msg)
{
    icp_qat_fw_comn_req_t *req;
    icp_qat_fw_comn_req_hdr_t *comn_hdr;
    icp_qat_fw_comn_req_hdr_cd_pars_t *cd_pars;

    LAC_CHECK_NULL_PARAM(qat_msg);

    req = (icp_qat_fw_comn_req_t *)qat_msg;
    comn_hdr = &req->comn_hdr;
    if (comn_hdr->service_type != ICP_QAT_FW_COMN_REQ_CPM_FW_LA)
    {
        return CPA_STATUS_SUCCESS;
    }
    if (!ICP_QAT_FW_COMN_PTR_TYPE_GET(comn_hdr->serv_specif_flags))
    {
        return CPA_STATUS_SUCCESS;
    }

    cd_pars = &req->cd_pars;
    cd_pars->s.content_desc_addr = 0;

    return CPA_STATUS_SUCCESS;
}