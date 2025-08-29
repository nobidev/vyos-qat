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
 * @file qat_dbg_fwaudit.cpp
 *
 * @description
 *        This file provides implementation of QAT firmware calls audit
 *        helpers functions.
 *
 ****************************************************************************/
/* System headers */
#include <stdio.h>

/* STL headers */
#include <iostream>
#include <vector>
#include <iterator>

/* Project headers */
#include "qat_dbg_fwaudit.h"
#include "cpa.h"
#include "adf_kernel_types.h"
#include "qat_dbg_user.h"
#include "qat_dbg_fwcalls.h"
#include "qat_dbg_utils.h"
#include "Osal.h"

/* FW headers */
#include "icp_qat_fw.h"
#include "icp_qat_fw_la.h"
#include "icp_qat_fw_pke.h"
#include "icp_qat_fw_comp.h"
#include "icp_buffer_desc.h"

/* API headers */
#include "cpa_cy_sym.h"
#include "icp_qat_hw.h"
#include "lac_sym_cipher_defs.h"

/*
*******************************************************************************
* Private definitions
*******************************************************************************
*/
#define QAT_DBG_ALGS_SYM_CY_OFFSET 1

struct qat_dbg_hw_cipher_info
{
    icp_qat_hw_cipher_algo_t algorithm;
    icp_qat_hw_cipher_mode_t mode;
};

/*
*******************************************************************************
* External variables
*******************************************************************************
*/
extern char gProcMmapFilePath[];

/*
*******************************************************************************
* Private global variables
*******************************************************************************
*/

/* translates CpaCySymCipherAlgorithm to string */
static const char *qatDbgAlgsSymCy[] = {
    QAT_DBG_INVALID_MAPPING_VAL,     "CPA_CY_SYM_CIPHER_NULL",
    "CPA_CY_SYM_CIPHER_ARC4",        "CPA_CY_SYM_CIPHER_AES_ECB",
    "CPA_CY_SYM_CIPHER_AES_CBC",     "CPA_CY_SYM_CIPHER_AES_CTR",
    "CPA_CY_SYM_CIPHER_AES_CCM",     "CPA_CY_SYM_CIPHER_AES_GCM",
    "CPA_CY_SYM_CIPHER_DES_ECB",     "CPA_CY_SYM_CIPHER_DES_CBC",
    "CPA_CY_SYM_CIPHER_3DES_ECB",    "CPA_CY_SYM_CIPHER_3DES_CBC",
    "CPA_CY_SYM_CIPHER_3DES_CTR",    "CPA_CY_SYM_CIPHER_KASUMI_F8",
    "CPA_CY_SYM_CIPHER_SNOW3G_UEA2", "CPA_CY_SYM_CIPHER_AES_F8",
    "CPA_CY_SYM_CIPHER_AES_XTS",     "CPA_CY_SYM_CIPHER_ZUC_EEA3",
    "CPA_CY_SYM_CIPHER_CHACHA",      "CPA_CY_SYM_CIPHER_SM4_ECB",
    "CPA_CY_SYM_CIPHER_SM4_CBC",     "CPA_CY_SYM_CIPHER_SM4_CTR"};
const size_t qatDbgAlgsSymCySize = QAT_DBG_ARRAY_SIZE(qatDbgAlgsSymCy);

static const struct qat_dbg_hw_cipher_info qatDbgCipherInfo[] = {
    /* CPA_CY_SYM_CIPHER_NULL */
    {
        ICP_QAT_HW_CIPHER_ALGO_NULL,
        ICP_QAT_HW_CIPHER_ECB_MODE,
    },
    /* CPA_CY_SYM_CIPHER_ARC4 */
    {
        ICP_QAT_HW_CIPHER_ALGO_ARC4,
        ICP_QAT_HW_CIPHER_ECB_MODE,
    },
    /* CPA_CY_SYM_CIPHER_AES_ECB */
    {
        ICP_QAT_HW_CIPHER_ALGO_AES128,
        ICP_QAT_HW_CIPHER_ECB_MODE,
    },
    /* CPA_CY_SYM_CIPHER_AES_CBC */
    {
        ICP_QAT_HW_CIPHER_ALGO_AES128,
        ICP_QAT_HW_CIPHER_CBC_MODE,
    },
    /* CPA_CY_SYM_CIPHER_AES_CTR */
    {
        ICP_QAT_HW_CIPHER_ALGO_AES128,
        ICP_QAT_HW_CIPHER_CTR_MODE,
    },
    /* CPA_CY_SYM_CIPHER_AES_CCM */
    {
        ICP_QAT_HW_CIPHER_ALGO_AES128,
        ICP_QAT_HW_CIPHER_CTR_MODE,
    },
    /* CPA_CY_SYM_CIPHER_AES_GCM */
    {
        ICP_QAT_HW_CIPHER_ALGO_AES128,
        ICP_QAT_HW_CIPHER_CTR_MODE,
    },
    /* CPA_CY_SYM_CIPHER_DES_ECB */
    {
        ICP_QAT_HW_CIPHER_ALGO_DES,
        ICP_QAT_HW_CIPHER_ECB_MODE,
    },
    /* CPA_CY_SYM_CIPHER_DES_CBC */
    {
        ICP_QAT_HW_CIPHER_ALGO_DES,
        ICP_QAT_HW_CIPHER_CBC_MODE,
    },
    /* CPA_CY_SYM_CIPHER_3DES_ECB */
    {
        ICP_QAT_HW_CIPHER_ALGO_3DES,
        ICP_QAT_HW_CIPHER_ECB_MODE,
    },
    /* CPA_CY_SYM_CIPHER_3DES_CBC */
    {
        ICP_QAT_HW_CIPHER_ALGO_3DES,
        ICP_QAT_HW_CIPHER_CBC_MODE,
    },
    /* CPA_CY_SYM_CIPHER_3DES_CTR */
    {
        ICP_QAT_HW_CIPHER_ALGO_3DES,
        ICP_QAT_HW_CIPHER_CTR_MODE,
    },
    /* CPA_CY_SYM_CIPHER_KASUMI_F8 */
    {
        ICP_QAT_HW_CIPHER_ALGO_KASUMI,
        ICP_QAT_HW_CIPHER_F8_MODE,
    },
    /* CPA_CY_SYM_CIPHER_SNOW3G_UEA2 */
    {
        ICP_QAT_HW_CIPHER_ALGO_SNOW_3G_UEA2,
        ICP_QAT_HW_CIPHER_ECB_MODE,
    },
    /* CPA_CY_SYM_CIPHER_AES_F8 */
    {
        ICP_QAT_HW_CIPHER_ALGO_AES128,
        ICP_QAT_HW_CIPHER_F8_MODE,
    },
    /* CPA_CY_SYM_CIPHER_AES_XTS */
    {
        ICP_QAT_HW_CIPHER_ALGO_AES128,
        ICP_QAT_HW_CIPHER_XTS_MODE,
    },
    /* CPA_CY_SYM_CIPHER_ZUC_EEA3 */
    {
        ICP_QAT_HW_CIPHER_ALGO_ZUC_3G_128_EEA3,
        ICP_QAT_HW_CIPHER_ECB_MODE,
    },
    /* CPA_CY_SYM_CIPHER_CHACHA */
    {ICP_QAT_HW_CIPHER_ALGO_CHACHA20_POLY1305, ICP_QAT_HW_CIPHER_AEAD_MODE},
    /* CPA_CY_SYM_CIPHER_SM4_ECB */
    {ICP_QAT_HW_CIPHER_ALGO_SM4, ICP_QAT_HW_CIPHER_ECB_MODE},
    /* CPA_CY_SYM_CIPHER_SM4_CBC */
    {ICP_QAT_HW_CIPHER_ALGO_SM4, ICP_QAT_HW_CIPHER_CBC_MODE},
    /* CPA_CY_SYM_CIPHER_SM4_CTR */
    {ICP_QAT_HW_CIPHER_ALGO_SM4, ICP_QAT_HW_CIPHER_CTR_MODE}};
const size_t qatDbgCipherInfoSize = QAT_DBG_ARRAY_SIZE(qatDbgCipherInfo);

/*
*******************************************************************************
* Private functions
*******************************************************************************
*/
/*
*******************************************************************************
* Symmetric cryptography getter functions
*******************************************************************************
*/
/*
 ******************************************************************
 * @ingroup qatDbg
 *        Translate cipher to algorithm id
 *
 * @description
 *        Translates by value array qatDbgCipherInfo to index in
 *        array qatDbgAlgsSymCy. The output index has the same
 *        value as CpaCySymCipherAlgorithm enum.
 *
 * @param[in]  cipherInfo  pointer to structure
 *                         qat_dbg_hw_cipher_info
 *
 * @retval index in qatDbgAlgsSymCy array or its size on failure
 *
 ******************************************************************
 */
static size_t qatDbgGetSymCyAlgId(qat_dbg_hw_cipher_info *cipherInfo)
{
    size_t limit = qatDbgCipherInfoSize;
    size_t i = 0;

    if (ICP_QAT_HW_CIPHER_ALGO_NULL == cipherInfo->algorithm)
    {
        return QAT_DBG_ALGS_SYM_CY_OFFSET;
    }
    if (cipherInfo->algorithm == ICP_QAT_HW_CIPHER_ALGO_AES192 ||
        cipherInfo->algorithm == ICP_QAT_HW_CIPHER_ALGO_AES256)
    {
        cipherInfo->algorithm = ICP_QAT_HW_CIPHER_ALGO_AES128;
    }

    for (i = 0; i < limit; i++)
    {
        if (qatDbgCipherInfo[i].algorithm == cipherInfo->algorithm &&
            qatDbgCipherInfo[i].mode == cipherInfo->mode)
        {
            return i + QAT_DBG_ALGS_SYM_CY_OFFSET;
        }
    }

    /* Algorithm not found */
    return i;
}

static size_t qatDbgGetSymCyAlgBlockSize(
    CpaCySymCipherAlgorithm cipherAlgorithm)
{
    if (LAC_CIPHER_IS_ARC4(cipherAlgorithm))
    {
        return LAC_CIPHER_ARC4_BLOCK_LEN_BYTES;
    }
    if (LAC_CIPHER_IS_AES(cipherAlgorithm) ||
        LAC_CIPHER_IS_AES_F8(cipherAlgorithm))
    {
        return ICP_QAT_HW_AES_BLK_SZ;
    }
    if (LAC_CIPHER_IS_DES(cipherAlgorithm))
    {
        return ICP_QAT_HW_DES_BLK_SZ;
    }
    if (LAC_CIPHER_IS_TRIPLE_DES(cipherAlgorithm))
    {
        return ICP_QAT_HW_3DES_BLK_SZ;
    }
    if (LAC_CIPHER_IS_KASUMI(cipherAlgorithm))
    {
        return ICP_QAT_HW_KASUMI_BLK_SZ;
    }
    if (LAC_CIPHER_IS_SNOW3G_UEA2(cipherAlgorithm))
    {
        return ICP_QAT_HW_SNOW_3G_BLK_SZ;
    }
    if (LAC_CIPHER_IS_ZUC_EEA3(cipherAlgorithm))
    {
        return ICP_QAT_HW_ZUC_3G_BLK_SZ;
    }
    if (LAC_CIPHER_IS_CHACHA(cipherAlgorithm))
    {
        return ICP_QAT_HW_CHACHAPOLY_BLK_SZ;
    }
    if (LAC_CIPHER_IS_SM4(cipherAlgorithm))
    {
        return ICP_QAT_HW_SM4_BLK_SZ;
    }
    if (LAC_CIPHER_IS_NULL(cipherAlgorithm))
    {
        return LAC_CIPHER_NULL_BLOCK_LEN_BYTES;
    }

    return 0;
}

static size_t qatDbgGetSymCySrcPacketSize(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_la_bulk_req_t *req =
        (icp_qat_fw_la_bulk_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_comn_req_mid_t *comnMid = &req->comn_mid;
    uint8_t *sglPtr = NULL;

    if (!msgHeader->msg_len)
    {
        return 0;
    }
    if (comnMid->src_length)
    {
        return comnMid->src_length;
    }
    if (!msgHeader->src_sgl_len)
    {
        return 0;
    }

    /* Calculate SGL size */
    sglPtr = QAT_DBG_GET_MSG_CONTENT(msgHeader) + msgHeader->msg_len;
    if (sglPtr)
    {
        /* Handling source SGL */
        icp_buffer_list_desc_t sgl = *((icp_buffer_list_desc_t *)sglPtr);
        size_t i = 0;
        size_t size = 0;

        for (i = 0; i < sgl.numBuffers; i++)
        {
            icp_flat_buffer_desc_t *flat =
                QAT_DBG_GET_SGL_FLAT_BUFFER(sglPtr, i);

            if (!flat)
            {
                continue;
            }

            size += flat->dataLenInBytes;
        }

        return size;
    }

    return 0;
}

/*
*******************************************************************************
* Physical addresses related functions
*******************************************************************************
*/
static CpaBoolean qatDbgHasReqSgl(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_comn_req_t *req =
        (icp_qat_fw_comn_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_comn_req_hdr_t *comnHeader = &req->comn_hdr;

    if (QAT_COMN_PTR_TYPE_SGL ==
        ICP_QAT_FW_COMN_PTR_TYPE_GET(comnHeader->comn_req_flags))
    {
        return CPA_TRUE;
    }

    return CPA_FALSE;
}

static void qatDbgAppendSglPointers(std::vector<qat_dbg_addr_range_t> *sglList,
                                    void *sglPtr)
{
    icp_buffer_list_desc_t sgl = *((icp_buffer_list_desc_t *)sglPtr);
    qat_dbg_addr_range_t addrEntry = {0};
    size_t i = 0;

    if (!sglPtr)
        return;

    for (i = 0; i < sgl.numBuffers; i++)
    {
        icp_flat_buffer_desc_t *flat = QAT_DBG_GET_SGL_FLAT_BUFFER(sglPtr, i);

        if (!flat)
        {
            continue;
        }

        addrEntry.start = flat->phyBuffer;
        addrEntry.size = flat->dataLenInBytes;
        addrEntry.end = addrEntry.start + addrEntry.size;
        sglList->push_back(addrEntry);
    }
}

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Extract all physical addresses from debug message
 *
 * @description
 *        Extract all physical addresses contained in given debug
 *        message. The addrList is always cleared at the beginning
 *        of this function. Independently of the return value, the
 *        addrList contains physical addresses ranges contained in
 *        the given debug message. The return value is used to
 *        indicate invalid SGL descriptors inside the message.
 *
 * @param[out]  addrList   reference to vector with storage element
 *                         of qat_dbg_addr_range_t struct
 * @param[in]   msgHeader  pointer to debug message
 *
 * @retval CPA_TRUE    SGL descriptors are valid in given debug
 *                     message
 * @retval CPA_FALSE   At least one SGL descriptor is invalid in
 *                     the given debug message
 *
 ******************************************************************
 */
static CpaBoolean qatDbgEntryExtractPhyAddresses(
    std::vector<qat_dbg_addr_range_t> &addrList,
    icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_comn_req_t *req =
        (icp_qat_fw_comn_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_comn_req_hdr_t *comnHeader = &req->comn_hdr;
    icp_qat_fw_comn_req_mid_t *comnMid = &req->comn_mid;
    qat_dbg_addr_range_t addrEntry = {0};
    CpaBoolean status = CPA_TRUE;

    addrList.clear();
    if (ICP_QAT_FW_COMN_REQ_CPM_FW_PKE == comnHeader->service_type)
    {
        icp_qat_fw_pke_request_t *pkeReq = (icp_qat_fw_pke_request_t *)req;
        icp_qat_fw_req_pke_mid_t *pkeMid = &pkeReq->pke_mid;

        addrEntry.start = pkeMid->src_data_addr;
        addrEntry.size = 0;
        addrEntry.end = addrEntry.start + addrEntry.size;
        addrList.push_back(addrEntry);

        addrEntry.start = pkeMid->dest_data_addr;
        addrEntry.size = 0;
        addrEntry.end = addrEntry.start + addrEntry.size;
        addrList.push_back(addrEntry);
    }
    else
    {
        addrEntry.start = comnMid->src_data_addr;
        addrEntry.size = comnMid->src_length;
        addrEntry.end = addrEntry.start + addrEntry.size;
        addrList.push_back(addrEntry);

        addrEntry.start = comnMid->dest_data_addr;
        addrEntry.size = comnMid->dst_length;
        addrEntry.end = addrEntry.start + addrEntry.size;
        addrList.push_back(addrEntry);
    }
    if (qatDbgHasReqSgl(msgHeader))
    {
        uint8_t *sglPtr =
            QAT_DBG_GET_MSG_CONTENT(msgHeader) + msgHeader->msg_len;

        if (!comnMid->src_length)
        {
            if (msgHeader->src_sgl_len)
            {
                qatDbgAppendSglPointers(&addrList, sglPtr);
            }
            else
            {
                status = CPA_FALSE;
            }
        }
        if (!comnMid->dst_length)
        {
            if (msgHeader->dst_sgl_len)
            {
                sglPtr += msgHeader->src_sgl_len;
                qatDbgAppendSglPointers(&addrList, sglPtr);
            }
            else
            {
                status = CPA_FALSE;
            }
        }
    }

    return status;
}

static size_t qatDbgCheckReqSgl(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_comn_req_t *req =
        (icp_qat_fw_comn_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_comn_req_mid_t *comnMid = &req->comn_mid;
    uint8_t *sglPtr = QAT_DBG_GET_MSG_CONTENT(msgHeader) + msgHeader->msg_len;
    size_t i = 0;
    size_t errors = 0;

    if (!qatDbgHasReqSgl(msgHeader))
    {
        return 0;
    }

    /* Handling SGL  */
    if (!comnMid->src_length)
    {
        if (!msgHeader->src_sgl_len)
        {
            std::cout << "ERROR: Missing SGL source in log entry." << std::endl;
            errors++;
        }
        else
        {
            /* Handling source SGL */
            icp_buffer_list_desc_t sgl = *((icp_buffer_list_desc_t *)sglPtr);

            for (i = 0; i < sgl.numBuffers; i++)
            {
                icp_flat_buffer_desc_t *flat =
                    QAT_DBG_GET_SGL_FLAT_BUFFER(sglPtr, i);

                if (!flat)
                {
                    std::cout << "ERROR: Empty source flat buffer in SGL."
                              << std::endl;
                    errors++;
                }
                else if (!flat->dataLenInBytes)
                {
                    std::cout << "ERROR: Empty destination flat buffer in SGL."
                              << std::endl;
                    errors++;
                }
            }
        }
        sglPtr += msgHeader->src_sgl_len;
    }
    if (!comnMid->dst_length)
    {
        if (!msgHeader->dst_sgl_len)
        {
            std::cout << "ERROR: Missing SGL destination in log entry."
                      << std::endl;
            errors++;
        }
        else
        {
            /* Handling destination SGL */
            icp_buffer_list_desc_t sgl = *((icp_buffer_list_desc_t *)sglPtr);

            for (i = 0; i < sgl.numBuffers; i++)
            {
                icp_flat_buffer_desc_t *flat =
                    QAT_DBG_GET_SGL_FLAT_BUFFER(sglPtr, i);

                if (!flat)
                {
                    std::cout << "\tERROR: Empty source flat buffer in SGL."
                              << std::endl;
                    errors++;
                }
                else if (!flat->dataLenInBytes)
                {
                    std::cout
                        << "\tERROR: Empty destination flat buffer in SGL."
                        << std::endl;
                    errors++;
                }
            }
        }
    }

    return errors;
}

/*
*******************************************************************************
* Requests lengths related functions
*******************************************************************************
*/
static CpaBoolean qatDbgIsReqCySymBulk(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_comn_req_t *req =
        (icp_qat_fw_comn_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_comn_req_hdr_t *comnHeader = &req->comn_hdr;

    if (ICP_QAT_FW_LA_CMD_CIPHER == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_CIPHER_HASH == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_HASH_CIPHER == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_CIPHER_PRE_COMP == comnHeader->service_cmd_id)
    {
        return CPA_TRUE;
    }

    return CPA_FALSE;
}

static size_t qatDbgCheckCySymReqLengths(icp_adf_dbg_entry_header_t *msgHeader)
{
    /* LW0-LW31 */
    icp_qat_fw_la_bulk_req_t *req =
        (icp_qat_fw_la_bulk_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    /* LWs 14-26 */
    icp_qat_fw_comn_req_rqpars_t *comnReqSpecifParams =
        &req->serv_specif_rqpars;
    icp_qat_fw_la_cipher_req_params_t *cipherReqParams = NULL;
    size_t cipherAlg = 0;
    size_t srcPktSize = 0;
    size_t reqBlockSize = 0;
    size_t errors = 0;

    /* Extracting algorithms */
    cipherAlg = msgHeader->content_desc.u.s.cipherAlg;

    /* Translating cipher algorithm number to value used by LAC */
    if (msgHeader->msg_type == QATD_MSG_REQUEST_DPDK)
    {
        qat_dbg_hw_cipher_info cipherInfo;

        osalMemSet(&cipherInfo, 0, sizeof(cipherInfo));
        cipherInfo.algorithm = (icp_qat_hw_cipher_algo_t)cipherAlg;
        cipherInfo.mode =
            (icp_qat_hw_cipher_mode_t)msgHeader->content_desc.u.s.cipherMode;
        cipherAlg = qatDbgGetSymCyAlgId(&cipherInfo);
    }

    /* Extracting and validating block size */
    reqBlockSize =
        qatDbgGetSymCyAlgBlockSize((CpaCySymCipherAlgorithm)cipherAlg);
    if (!reqBlockSize || cipherAlg >= qatDbgAlgsSymCySize)
    {
        std::cout << "ERROR: Unknown cipher algorithm (" << cipherAlg << ")"
                  << std::endl;
        return ++errors;
    }

    /* Extracting and validating source packet size */
    srcPktSize = qatDbgGetSymCySrcPacketSize(msgHeader);
    if (!srcPktSize)
    {
        std::cout << "ERROR: Incorrect source packet size: " << srcPktSize
                  << " for alg: " << qatDbgAlgsSymCy[cipherAlg] << std::endl;
        errors++;
    }

    /* Overall size check */
    cipherReqParams = (icp_qat_fw_la_cipher_req_params_t
                           *)((uint8_t *)comnReqSpecifParams +
                              ICP_QAT_FW_CIPHER_REQUEST_PARAMETERS_OFFSET);
    if ((cipherReqParams->cipher_length + cipherReqParams->cipher_offset) >
        srcPktSize)
    {
        std::cout << "ERROR: Cipher len + offset greater than src "
                  << "buffer packet len. Alg: " << qatDbgAlgsSymCy[cipherAlg]
                  << std::endl;
        errors++;
    }
    /* Alignment check */
    if (LAC_CIPHER_IS_ARC4(cipherAlg) || LAC_CIPHER_IS_CTR_MODE(cipherAlg) ||
        LAC_CIPHER_IS_F8_MODE(cipherAlg) ||
        LAC_CIPHER_IS_SNOW3G_UEA2(cipherAlg) ||
        LAC_CIPHER_IS_XTS_MODE(cipherAlg) || LAC_CIPHER_IS_CHACHA(cipherAlg) ||
        LAC_CIPHER_IS_ZUC_EEA3(cipherAlg) || LAC_CIPHER_IS_XTS_MODE(cipherAlg))
    {
        return errors;
    }
    if (cipherReqParams->cipher_length & (reqBlockSize - 1))
    {
        std::cout << "ERROR: Cipher data size must be block multiple"
                  << " (Cipher len:" << cipherReqParams->cipher_length << ", "
                  << "block size:" << reqBlockSize << ")"
                  << " for alg: " << qatDbgAlgsSymCy[cipherAlg] << std::endl;
        errors++;
    }

    return errors;
}

/*
*******************************************************************************
* Public functions
*******************************************************************************
*/
CpaBoolean qatDbgTestPhyAddrMap(icp_adf_dbg_entry_header_t *msgHeader)
{
    static std::vector<qat_dbg_addr_range_t> procAddrMap;
    static CpaBoolean mapLoaded = CPA_FALSE;
    std::vector<qat_dbg_addr_range_t> entryPhyAddresses;
    std::vector<qat_dbg_addr_range_t>::iterator reqIt;
    std::vector<qat_dbg_addr_range_t>::iterator procIt;

    if (mapLoaded)
    {
        /* Optimization - in case of empty file */
        if (procAddrMap.empty())
        {
            return CPA_TRUE;
        }
    }
    else
    {
        /* Load process mmaps file in case if is not loaded yet */
        FILE *fd = NULL;
        char *line = NULL;
        size_t allocLen = 0;
        ssize_t readLen = 0;
        qat_dbg_addr_range_t addrRange = {0};

        mapLoaded = CPA_TRUE;
        fd = fopen(gProcMmapFilePath, "r");
        if (!fd)
        {
            return CPA_TRUE;
        }

        while (-1 != (readLen = getline(&line, &allocLen, fd)))
        {
            unsigned long long int addr;

            osalMemSet(&addrRange, 0, sizeof(qat_dbg_addr_range_t));
            sscanf(line,
                   "%d:0x%llx:%llu\n",
                   &addrRange.pid,
                   &addr,
                   &addrRange.size);
            addrRange.start = addr;
            addrRange.end = addrRange.start + addrRange.size;
            procAddrMap.push_back(addrRange);
        }
        free(line);
        fclose(fd);
    }

    /* Extract all physical addresses from entry */
    (void)qatDbgEntryExtractPhyAddresses(entryPhyAddresses, msgHeader);
    for (reqIt = entryPhyAddresses.begin(); reqIt != entryPhyAddresses.end();
         ++reqIt)
    {
        qat_dbg_addr_range_t *reqAddr = &(*reqIt);
        size_t mapsCtr = 0;
        size_t inMapCtr = 0;

        for (procIt = procAddrMap.begin(); procIt != procAddrMap.end();
             ++procIt)
        {
            qat_dbg_addr_range_t *procRange = &(*procIt);

            if (procRange->pid != (pid_t)msgHeader->pid)
            {
                continue;
            }
            mapsCtr++;

            if (reqAddr->end >= reqAddr->start &&
                reqAddr->start >= procRange->start &&
                reqAddr->end < procRange->end)
            {
                inMapCtr++;
                break;
            }
        }
        if (mapsCtr && !inMapCtr)
        {
            if (!reqAddr->size)
            {
                std::cout << "ERROR: Physical address (0x" << std::hex
                          << reqAddr->start
                          << ") used in request is out of process pid: "
                          << std::dec << msgHeader->pid << " range."
                          << std::endl;
            }
            else
            {
                std::cout << "ERROR: Physical addresses range (0x" << std::hex
                          << reqAddr->start << "-"
                          << (reqAddr->start + reqAddr->size)
                          << ") used in request is out of  process pid: "
                          << std::dec << msgHeader->pid << " range."
                          << std::endl;
            }
            std::cout << "\tCheck " << gProcMmapFilePath
                      << " to see process physical addresses ranges."
                      << std::endl;

            return CPA_FALSE;
        }
    }

    return CPA_TRUE;
}

CpaBoolean qatDbgTestPhyAddrOverlap(icp_adf_dbg_entry_header_t *msgHeader)
{
    size_t i = 0;
    size_t j = 0;
    size_t count = 0;
    std::vector<qat_dbg_addr_range_t> entryPhyAddresses;

    if (!qatDbgEntryExtractPhyAddresses(entryPhyAddresses, msgHeader))
    {
        return CPA_FALSE;
    }

    count = entryPhyAddresses.size();
    for (i = 0; i < count; i++)
    {
        qat_dbg_addr_range_t *addr1 = &entryPhyAddresses[i];

        for (j = 0; j < count; j++)
        {
            qat_dbg_addr_range_t *addr2 = &entryPhyAddresses[j];

            /* Do not compare the same entries */
            if (i == j)
            {
                continue;
            }

            /* Check if addresses overlaps */
            /* Allow addresses to be the same for in-place operations */
            if (addr2->end > addr2->start && addr1->start > addr2->start &&
                addr1->start < addr2->end)
            {
                return CPA_FALSE;
            }
        }
    }

    return CPA_TRUE;
}

CpaBoolean qatDbgTestRespStatus(icp_adf_dbg_entry_header_t *msgHeader)
{
    uint8_t *entry = QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_la_resp_t *laResp = (icp_qat_fw_la_resp_t *)entry;
    icp_qat_fw_comn_resp_hdr_t *comnResp = &laResp->comn_resp;
    size_t errors = 0;

    if (QATD_MSG_RESPONSE != msgHeader->msg_type)
    {
        return CPA_TRUE;
    }
    if (ICP_QAT_FW_COMN_REQ_CPM_FW_PKE == comnResp->response_type)
    {
        icp_qat_fw_pke_resp_t *pkeResp = (icp_qat_fw_pke_resp_t *)entry;
        icp_qat_fw_resp_pke_hdr_t *pkeRespHeader = &pkeResp->pke_resp_hdr;
        icp_qat_fw_pke_resp_status_t *pkeRespStatus =
            &pkeRespHeader->resp_status;

        if (pkeRespStatus->comn_err_code)
        {
            errors++;
            std::cout << "WARNING: Incorrect response RCs. Response flags: 0x"
                      << std::hex << (int)pkeRespStatus->pke_resp_flags
                      << " error_code: 0x" << (int)pkeRespStatus->comn_err_code
                      << std::dec << std::endl;
        }
    }
    else if (ICP_QAT_FW_COMN_REQ_CPM_FW_COMP == comnResp->response_type)
    {
        icp_qat_fw_comp_resp_t *compResp = (icp_qat_fw_comp_resp_t *)entry;
        icp_qat_fw_comn_resp_hdr_t *compRespHeader = &compResp->comn_resp;

        if (compRespHeader->comn_error.s1.xlat_err_code ||
            compRespHeader->comn_error.s1.cmp_err_code)
        {
            errors++;
        }
        if (0 < errors)
        {
            std::cout << "WARNING: Incorrect response RCs. Status: "
                      << (int)comnResp->comn_status
                      << " Translator slice error_code: 0x" << std::hex
                      << (int)comnResp->comn_error.s1.xlat_err_code
                      << " Compression slice error_code: 0x"
                      << (int)comnResp->comn_error.s1.cmp_err_code << std::dec
                      << std::endl;
        }
    }
    else
    {
        if (comnResp->comn_error.s.comn_err_code)
        {
            errors++;
        }
        if (comnResp->comn_status)
        {
            errors++;
        }
        if (0 < errors)
        {
            std::cout << "WARNING: Incorrect response RCs. Status: "
                      << (int)comnResp->comn_status << " error_code: 0x"
                      << std::hex << (int)comnResp->comn_error.s.comn_err_code
                      << std::dec << std::endl;
        }
    }

    if (errors)
    {
        return CPA_FALSE;
    }

    return CPA_TRUE;
}

CpaBoolean qatDbgTestReqLengths(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_comn_req_t *req =
        (icp_qat_fw_comn_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_comn_req_hdr_t *comnHeader = &req->comn_hdr;

    if (ICP_QAT_FW_COMN_REQ_CPM_FW_LA == comnHeader->service_type)
    {
        if (qatDbgIsReqCySymBulk(msgHeader))
        {
            size_t errors = qatDbgCheckCySymReqLengths(msgHeader);

            if (errors > 0)
            {
                return CPA_FALSE;
            }
        }
    }

    return CPA_TRUE;
}

CpaBoolean qatDbgTestMsgHeader(icp_adf_dbg_entry_header_t *msgHeader)
{
    size_t errors = 0;

    if (QATD_MSG_REQUEST == msgHeader->msg_type ||
        QATD_MSG_REQUEST_DPDK == msgHeader->msg_type)
    {
        icp_qat_fw_comn_req_t *req =
            (icp_qat_fw_comn_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
        icp_qat_fw_comn_req_hdr_t *comnHeader = &req->comn_hdr;

        if (comnHeader->service_type >= qatDbgServiceIdsReqSize)
        {
            std::cout << QAT_DBG_INVALID_REQ_SERVICE_MAPPING_MSG << std::endl;
            errors++;
        }

        if (ICP_QAT_FW_COMN_REQ_CPM_FW_LA == comnHeader->service_type)
        {
            if (comnHeader->service_cmd_id >= qatDbgCmdIdsSymCySize)
            {
                std::cout << "ERROR: Unknown CY SYM Command ID" << std::endl;
                errors++;
            }
        }
        else if (ICP_QAT_FW_COMN_REQ_CPM_FW_COMP == comnHeader->service_type ||
                 ICP_QAT_FW_COMN_REQ_CPM_FW_COMP_CHAIN ==
                     comnHeader->service_type)
        {
            if (comnHeader->service_cmd_id >= qatDbgCmdIdsDcSize)
            {
                std::cout << "ERROR: Unknown DC Command ID" << std::endl;
                errors++;
            }
        }
        if (errors)
        {
            qatDbgHandleFwRequest(msgHeader);
        }
    }
    else if (QATD_MSG_RESPONSE == msgHeader->msg_type)
    {
        icp_qat_fw_comn_resp_t *resp =
            (icp_qat_fw_comn_resp_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
        icp_qat_fw_comn_resp_hdr_t *comnHeader = &resp->comn_hdr;

        if (comnHeader->service_id >= qatDbgServiceIdsRespSize)
        {
            std::cout << QAT_DBG_INVALID_RESP_SERVICE_MAPPING_MSG << std::endl;
            errors++;
        }
        if (comnHeader->response_type >= qatDbgServiceIdsReqSize)
        {
            std::cout << QAT_DBG_INVALID_REQ_SERVICE_MAPPING_MSG << std::endl;
            errors++;
        }
        if (ICP_QAT_FW_COMN_REQ_CPM_FW_LA == comnHeader->response_type)
        {
            if (comnHeader->cmd_id >= qatDbgCmdIdsSymCySize)
            {
                std::cout << QAT_DBG_INVALID_CMD_MAPPING_MSG << std::endl;
                errors++;
            }
        }
        else if (ICP_QAT_FW_COMN_REQ_CPM_FW_COMP == comnHeader->response_type ||
                 ICP_QAT_FW_COMN_REQ_CPM_FW_COMP_CHAIN ==
                     comnHeader->response_type)
        {
            if (comnHeader->cmd_id >= qatDbgCmdIdsDcSize)
            {
                std::cout << QAT_DBG_INVALID_CMD_MAPPING_MSG << std::endl;
                errors++;
            }
        }
        if (errors)
        {
            qatDbgHandleFwResponse(msgHeader);
        }
    }

    if (errors)
    {
        return CPA_FALSE;
    }

    return CPA_TRUE;
}

CpaBoolean qatDbgTestReqSgl(icp_adf_dbg_entry_header_t *msgHeader)
{
    size_t errors = qatDbgCheckReqSgl(msgHeader);

    if (errors > 0)
    {
        return CPA_FALSE;
    }

    return CPA_TRUE;
}