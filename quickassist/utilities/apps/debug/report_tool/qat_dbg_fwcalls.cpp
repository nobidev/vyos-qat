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
 * @file qat_dbg_fwcalls.cpp
 *
 * @description
 *        This file provides QAT firmware calls parsers utilities
 *        implementation.
 *
 ****************************************************************************/
/* System headers */
#include <iostream>

/* Project headers */
#include "qat_dbg_fwcalls.h"
#include "qat_dbg_utils.h"

/* FW headers */
#include "icp_qat_fw.h"
#include "icp_qat_fw_la.h"
#include "icp_qat_fw_pke.h"
#include "icp_qat_fw_comp.h"
#include "icp_qat_fw_mmp_ids.h"
#include "icp_buffer_desc.h"

/*
*******************************************************************************
* Private typedefs
*******************************************************************************
*/
struct qat_dbg_mmp_map_entry
{
    const char *name;
    unsigned int id;
};

/*
*******************************************************************************
* Exported variables
*******************************************************************************
*/
const char *qatDbgServiceIdsReq[] = {"ICP_QAT_FW_COMN_REQ_NULL",
                                     QAT_DBG_INVALID_MAPPING_VAL,
                                     QAT_DBG_INVALID_MAPPING_VAL,
                                     "ICP_QAT_FW_COMN_REQ_CPM_FW_PKE",
                                     "ICP_QAT_FW_COMN_REQ_CPM_FW_LA",
                                     QAT_DBG_INVALID_MAPPING_VAL,
                                     QAT_DBG_INVALID_MAPPING_VAL,
                                     "ICP_QAT_FW_COMN_REQ_CPM_FW_DMA",
                                     QAT_DBG_INVALID_MAPPING_VAL,
                                     "ICP_QAT_FW_COMN_REQ_CPM_FW_COMP",
                                     QAT_DBG_INVALID_MAPPING_VAL,
                                     "ICP_QAT_FW_COMN_REQ_CPM_FW_COMP_CHAIN"};
const size_t qatDbgServiceIdsReqSize = QAT_DBG_ARRAY_SIZE(qatDbgServiceIdsReq);

const char *qatDbgServiceIdsResp[] = {"ICP_QAT_FW_COMN_RESP_SERV_NULL",
                                      "ICP_QAT_FW_COMN_RESP_SERV_CPM_FW"};
const size_t qatDbgServiceIdsRespSize =
    QAT_DBG_ARRAY_SIZE(qatDbgServiceIdsResp);

const char *qatDbgCmdIdsDc[] = {"ICP_QAT_FW_COMP_CMD_STATIC",
                                "ICP_QAT_FW_COMP_CMD_DYNAMIC",
                                "ICP_QAT_FW_COMP_CMD_DECOMPRESS"};
const size_t qatDbgCmdIdsDcSize = QAT_DBG_ARRAY_SIZE(qatDbgCmdIdsDc);

const char *qatDbgCmdIdsSymCy[] = {
    "ICP_QAT_FW_LA_CMD_CIPHER",
    "ICP_QAT_FW_LA_CMD_AUTH",
    "ICP_QAT_FW_LA_CMD_CIPHER_HASH",
    "ICP_QAT_FW_LA_CMD_HASH_CIPHER",
    "ICP_QAT_FW_LA_CMD_TRNG_GET_RANDOM",
    "ICP_QAT_FW_LA_CMD_TRNG_TEST",
    "ICP_QAT_FW_LA_CMD_SSL3_KEY_DERIVE",
    "ICP_QAT_FW_LA_CMD_TLS_V1_1_KEY_DERIVE",
    "ICP_QAT_FW_LA_CMD_TLS_V1_2_KEY_DERIVE",
    "ICP_QAT_FW_LA_CMD_MGF1",
    "ICP_QAT_FW_LA_CMD_AUTH_PRE_COMP",
    "ICP_QAT_FW_LA_CMD_CIPHER_PRE_COMP",
    "ICP_QAT_FW_LA_CMD_HKDF_EXTRACT",
    "ICP_QAT_FW_LA_CMD_HKDF_EXPAND",
    "ICP_QAT_FW_LA_CMD_HKDF_EXTRACT_AND_EXPAND",
    "ICP_QAT_FW_LA_CMD_HKDF_EXPAND_LABEL",
    "ICP_QAT_FW_LA_CMD_HKDF_EXTRACT_AND_EXPAND_LABEL"};
const size_t qatDbgCmdIdsSymCySize = QAT_DBG_ARRAY_SIZE(qatDbgCmdIdsSymCy);

/*
*******************************************************************************
* Private variables
*******************************************************************************
*/
#define DEF_MMP_MAP_ENTRY(mmp)                                                 \
    {                                                                          \
#mmp, mmp                                                              \
    }
const struct qat_dbg_mmp_map_entry qatDbgMmpIdMap[] = {
    DEF_MMP_MAP_ENTRY(PKE_INIT),
    DEF_MMP_MAP_ENTRY(PKE_DH_G2_768),
    DEF_MMP_MAP_ENTRY(PKE_DH_768),
    DEF_MMP_MAP_ENTRY(PKE_DH_G2_1024),
    DEF_MMP_MAP_ENTRY(PKE_DH_1024),
    DEF_MMP_MAP_ENTRY(PKE_DH_G2_1536),
    DEF_MMP_MAP_ENTRY(PKE_DH_1536),
    DEF_MMP_MAP_ENTRY(PKE_DH_G2_2048),
    DEF_MMP_MAP_ENTRY(PKE_DH_2048),
    DEF_MMP_MAP_ENTRY(PKE_DH_G2_3072),
    DEF_MMP_MAP_ENTRY(PKE_DH_3072),
    DEF_MMP_MAP_ENTRY(PKE_DH_G2_4096),
    DEF_MMP_MAP_ENTRY(PKE_DH_4096),
    DEF_MMP_MAP_ENTRY(PKE_RSA_KP1_512),
    DEF_MMP_MAP_ENTRY(PKE_RSA_KP2_512),
    DEF_MMP_MAP_ENTRY(PKE_RSA_EP_512),
    DEF_MMP_MAP_ENTRY(PKE_RSA_DP1_512),
    DEF_MMP_MAP_ENTRY(PKE_RSA_DP2_512),
    DEF_MMP_MAP_ENTRY(PKE_RSA_KP1_1024),
    DEF_MMP_MAP_ENTRY(PKE_RSA_KP2_1024),
    DEF_MMP_MAP_ENTRY(PKE_RSA_EP_1024),
    DEF_MMP_MAP_ENTRY(PKE_RSA_DP1_1024),
    DEF_MMP_MAP_ENTRY(PKE_RSA_DP2_1024),
    DEF_MMP_MAP_ENTRY(PKE_RSA_KP1_1536),
    DEF_MMP_MAP_ENTRY(PKE_RSA_KP2_1536),
    DEF_MMP_MAP_ENTRY(PKE_RSA_EP_1536),
    DEF_MMP_MAP_ENTRY(PKE_RSA_DP1_1536),
    DEF_MMP_MAP_ENTRY(PKE_RSA_DP2_1536),
    DEF_MMP_MAP_ENTRY(PKE_RSA_KP1_2048),
    DEF_MMP_MAP_ENTRY(PKE_RSA_KP2_2048),
    DEF_MMP_MAP_ENTRY(PKE_RSA_EP_2048),
    DEF_MMP_MAP_ENTRY(PKE_RSA_DP1_2048),
    DEF_MMP_MAP_ENTRY(PKE_RSA_DP2_2048),
    DEF_MMP_MAP_ENTRY(PKE_RSA_KP1_3072),
    DEF_MMP_MAP_ENTRY(PKE_RSA_KP2_3072),
    DEF_MMP_MAP_ENTRY(PKE_RSA_EP_3072),
    DEF_MMP_MAP_ENTRY(PKE_RSA_DP1_3072),
    DEF_MMP_MAP_ENTRY(PKE_RSA_DP2_3072),
    DEF_MMP_MAP_ENTRY(PKE_RSA_KP1_4096),
    DEF_MMP_MAP_ENTRY(PKE_RSA_KP2_4096),
    DEF_MMP_MAP_ENTRY(PKE_RSA_EP_4096),
    DEF_MMP_MAP_ENTRY(PKE_RSA_DP1_4096),
    DEF_MMP_MAP_ENTRY(PKE_RSA_DP2_4096),
    DEF_MMP_MAP_ENTRY(PKE_GCD_PT_192),
    DEF_MMP_MAP_ENTRY(PKE_GCD_PT_256),
    DEF_MMP_MAP_ENTRY(PKE_GCD_PT_384),
    DEF_MMP_MAP_ENTRY(PKE_GCD_PT_512),
    DEF_MMP_MAP_ENTRY(PKE_GCD_PT_768),
    DEF_MMP_MAP_ENTRY(PKE_GCD_PT_1024),
    DEF_MMP_MAP_ENTRY(PKE_GCD_PT_1536),
    DEF_MMP_MAP_ENTRY(PKE_GCD_PT_2048),
    DEF_MMP_MAP_ENTRY(PKE_GCD_PT_3072),
    DEF_MMP_MAP_ENTRY(PKE_GCD_PT_4096),
    DEF_MMP_MAP_ENTRY(PKE_FERMAT_PT_160),
    DEF_MMP_MAP_ENTRY(PKE_FERMAT_PT_512),
    DEF_MMP_MAP_ENTRY(PKE_FERMAT_PT_L512),
    DEF_MMP_MAP_ENTRY(PKE_FERMAT_PT_768),
    DEF_MMP_MAP_ENTRY(PKE_FERMAT_PT_1024),
    DEF_MMP_MAP_ENTRY(PKE_FERMAT_PT_1536),
    DEF_MMP_MAP_ENTRY(PKE_FERMAT_PT_2048),
    DEF_MMP_MAP_ENTRY(PKE_FERMAT_PT_3072),
    DEF_MMP_MAP_ENTRY(PKE_FERMAT_PT_4096),
    DEF_MMP_MAP_ENTRY(PKE_MR_PT_160),
    DEF_MMP_MAP_ENTRY(PKE_MR_PT_512),
    DEF_MMP_MAP_ENTRY(PKE_MR_PT_768),
    DEF_MMP_MAP_ENTRY(PKE_MR_PT_1024),
    DEF_MMP_MAP_ENTRY(PKE_MR_PT_1536),
    DEF_MMP_MAP_ENTRY(PKE_MR_PT_2048),
    DEF_MMP_MAP_ENTRY(PKE_MR_PT_3072),
    DEF_MMP_MAP_ENTRY(PKE_MR_PT_4096),
    DEF_MMP_MAP_ENTRY(PKE_MR_PT_L512),
    DEF_MMP_MAP_ENTRY(PKE_LUCAS_PT_160),
    DEF_MMP_MAP_ENTRY(PKE_LUCAS_PT_512),
    DEF_MMP_MAP_ENTRY(PKE_LUCAS_PT_768),
    DEF_MMP_MAP_ENTRY(PKE_LUCAS_PT_1024),
    DEF_MMP_MAP_ENTRY(PKE_LUCAS_PT_1536),
    DEF_MMP_MAP_ENTRY(PKE_LUCAS_PT_2048),
    DEF_MMP_MAP_ENTRY(PKE_LUCAS_PT_3072),
    DEF_MMP_MAP_ENTRY(PKE_LUCAS_PT_4096),
    DEF_MMP_MAP_ENTRY(PKE_LUCAS_PT_L512),
    DEF_MMP_MAP_ENTRY(MATHS_MODEXP_L512),
    DEF_MMP_MAP_ENTRY(MATHS_MODEXP_L1024),
    DEF_MMP_MAP_ENTRY(MATHS_MODEXP_L1536),
    DEF_MMP_MAP_ENTRY(MATHS_MODEXP_L2048),
    DEF_MMP_MAP_ENTRY(MATHS_MODEXP_L2560),
    DEF_MMP_MAP_ENTRY(MATHS_MODEXP_L3072),
    DEF_MMP_MAP_ENTRY(MATHS_MODEXP_L3584),
    DEF_MMP_MAP_ENTRY(MATHS_MODEXP_L4096),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_ODD_L128),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_ODD_L192),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_ODD_L256),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_ODD_L384),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_ODD_L512),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_ODD_L768),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_ODD_L1024),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_ODD_L1536),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_ODD_L2048),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_ODD_L3072),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_ODD_L4096),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_EVEN_L128),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_EVEN_L192),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_EVEN_L256),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_EVEN_L384),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_EVEN_L512),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_EVEN_L768),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_EVEN_L1024),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_EVEN_L1536),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_EVEN_L2048),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_EVEN_L3072),
    DEF_MMP_MAP_ENTRY(MATHS_MODINV_EVEN_L4096),
    DEF_MMP_MAP_ENTRY(PKE_DSA_GEN_P_1024_160),
    DEF_MMP_MAP_ENTRY(PKE_DSA_GEN_G_1024),
    DEF_MMP_MAP_ENTRY(PKE_DSA_GEN_Y_1024),
    DEF_MMP_MAP_ENTRY(PKE_DSA_SIGN_R_1024_160),
    DEF_MMP_MAP_ENTRY(PKE_DSA_SIGN_S_160),
    DEF_MMP_MAP_ENTRY(PKE_DSA_SIGN_R_S_1024_160),
    DEF_MMP_MAP_ENTRY(PKE_DSA_VERIFY_1024_160),
    DEF_MMP_MAP_ENTRY(PKE_DSA_GEN_P_2048_224),
    DEF_MMP_MAP_ENTRY(PKE_DSA_GEN_Y_2048),
    DEF_MMP_MAP_ENTRY(PKE_DSA_SIGN_R_2048_224),
    DEF_MMP_MAP_ENTRY(PKE_DSA_SIGN_S_224),
    DEF_MMP_MAP_ENTRY(PKE_DSA_SIGN_R_S_2048_224),
    DEF_MMP_MAP_ENTRY(PKE_DSA_VERIFY_2048_224),
    DEF_MMP_MAP_ENTRY(PKE_DSA_GEN_P_2048_256),
    DEF_MMP_MAP_ENTRY(PKE_DSA_GEN_G_2048),
    DEF_MMP_MAP_ENTRY(PKE_DSA_SIGN_R_2048_256),
    DEF_MMP_MAP_ENTRY(PKE_DSA_SIGN_S_256),
    DEF_MMP_MAP_ENTRY(PKE_DSA_SIGN_R_S_2048_256),
    DEF_MMP_MAP_ENTRY(PKE_DSA_VERIFY_2048_256),
    DEF_MMP_MAP_ENTRY(PKE_DSA_GEN_P_3072_256),
    DEF_MMP_MAP_ENTRY(PKE_DSA_GEN_G_3072),
    DEF_MMP_MAP_ENTRY(PKE_DSA_GEN_Y_3072),
    DEF_MMP_MAP_ENTRY(PKE_DSA_SIGN_R_3072_256),
    DEF_MMP_MAP_ENTRY(PKE_DSA_SIGN_R_S_3072_256),
    DEF_MMP_MAP_ENTRY(PKE_DSA_VERIFY_3072_256),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_RS_GF2_L256),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_R_GF2_L256),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_S_GF2_L256),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_VERIFY_GF2_L256),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_RS_GF2_L512),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_R_GF2_L512),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_S_GF2_L512),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_VERIFY_GF2_L512),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_RS_GF2_571),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_S_GF2_571),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_R_GF2_571),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_VERIFY_GF2_571),
    DEF_MMP_MAP_ENTRY(MATHS_POINT_MULTIPLICATION_GF2_L256),
    DEF_MMP_MAP_ENTRY(MATHS_POINT_VERIFY_GF2_L256),
    DEF_MMP_MAP_ENTRY(MATHS_POINT_MULTIPLICATION_GF2_L512),
    DEF_MMP_MAP_ENTRY(MATHS_POINT_VERIFY_GF2_L512),
    DEF_MMP_MAP_ENTRY(MATHS_POINT_MULTIPLICATION_GF2_571),
    DEF_MMP_MAP_ENTRY(MATHS_POINT_VERIFY_GF2_571),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_R_GFP_L256),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_S_GFP_L256),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_RS_GFP_L256),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_VERIFY_GFP_L256),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_R_GFP_L512),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_S_GFP_L512),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_RS_GFP_L512),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_VERIFY_GFP_L512),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_R_GFP_521),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_S_GFP_521),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_SIGN_RS_GFP_521),
    DEF_MMP_MAP_ENTRY(PKE_ECDSA_VERIFY_GFP_521),
    DEF_MMP_MAP_ENTRY(MATHS_POINT_MULTIPLICATION_GFP_L256),
    DEF_MMP_MAP_ENTRY(MATHS_POINT_VERIFY_GFP_L256),
    DEF_MMP_MAP_ENTRY(MATHS_POINT_MULTIPLICATION_GFP_L512),
    DEF_MMP_MAP_ENTRY(MATHS_POINT_VERIFY_GFP_L512),
    DEF_MMP_MAP_ENTRY(MATHS_POINT_MULTIPLICATION_GFP_521),
    DEF_MMP_MAP_ENTRY(MATHS_POINT_VERIFY_GFP_521),
    DEF_MMP_MAP_ENTRY(POINT_MULTIPLICATION_C25519),
    DEF_MMP_MAP_ENTRY(GENERATOR_MULTIPLICATION_C25519),
    DEF_MMP_MAP_ENTRY(POINT_MULTIPLICATION_ED25519),
    DEF_MMP_MAP_ENTRY(GENERATOR_MULTIPLICATION_ED25519),
    DEF_MMP_MAP_ENTRY(POINT_MULTIPLICATION_C448),
    DEF_MMP_MAP_ENTRY(GENERATOR_MULTIPLICATION_C448),
    DEF_MMP_MAP_ENTRY(POINT_MULTIPLICATION_ED448),
    DEF_MMP_MAP_ENTRY(GENERATOR_MULTIPLICATION_ED448),
    DEF_MMP_MAP_ENTRY(PKE_LIVENESS),
    DEF_MMP_MAP_ENTRY(PKE_INTERFACE_SIGNATURE),
    DEF_MMP_MAP_ENTRY(PKE_INVALID_FUNC_ID)};
const size_t qatDbgMmpIdMapSize = QAT_DBG_ARRAY_SIZE(qatDbgMmpIdMap);

/*
*******************************************************************************
* Private functions
*******************************************************************************
*/
static const char *qatDbgGetTableMapping(const char **table,
                                         size_t tableSize,
                                         size_t index,
                                         const char *outOfRangeVal)
{
    if (index < tableSize)
    {
        return table[index];
    }
    else
    {
        return outOfRangeVal;
    }
}

#define QAT_DBG_GET_SERVICE(id)                                                \
    qatDbgGetTableMapping(qatDbgServiceIdsReq,                                 \
                          qatDbgServiceIdsReqSize,                             \
                          (id),                                                \
                          QAT_DBG_INVALID_REQ_SERVICE_MAPPING_MSG)
#define QAT_DBG_GET_RESP_SERVICE(id)                                           \
    qatDbgGetTableMapping(qatDbgServiceIdsResp,                                \
                          qatDbgServiceIdsRespSize,                            \
                          (id),                                                \
                          QAT_DBG_INVALID_RESP_SERVICE_MAPPING_MSG)
#define QAT_DBG_GET_DC_CMD(id)                                                 \
    qatDbgGetTableMapping(qatDbgCmdIdsDc,                                      \
                          qatDbgCmdIdsDcSize,                                  \
                          (id),                                                \
                          QAT_DBG_INVALID_CMD_MAPPING_MSG)
#define QAT_DBG_GET_SYM_CY_CMD(id)                                             \
    qatDbgGetTableMapping(qatDbgCmdIdsSymCy,                                   \
                          qatDbgCmdIdsSymCySize,                               \
                          (id),                                                \
                          QAT_DBG_INVALID_CMD_MAPPING_MSG)

static std::string qatDbgPkeFuncIdToName(unsigned int funcId)
{
    std::string name(QAT_DBG_INVALID_MAPPING_VAL);
    size_t i = 0;

    for (i = 0; i < qatDbgMmpIdMapSize; i++)
    {
        if (qatDbgMmpIdMap[i].id == funcId)
        {
            name = qatDbgMmpIdMap[i].name;
            break;
        }
    }

    return name;
}

/*
*******************************************************************************
* Symmetric cryptography debug dump related functions
*******************************************************************************
*/
static void qatDbgPrintSymCyCmdFlags(icp_adf_dbg_entry_header_t *msgHeader,
                                     size_t indentLevel = 0)
{
    icp_qat_fw_la_bulk_req_t *req =
        (icp_qat_fw_la_bulk_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_comn_req_hdr_t *comnHeader = &req->comn_hdr;
    icp_qat_fw_serv_specif_flags servSpecificFlags =
        comnHeader->serv_specif_flags;
    std::string prefix;

    qatDbgGetIndent(prefix, indentLevel);
    std::cout << prefix << "[1.0-1B] LA BULK (SYMMETRIC CRYPTO) COMMAND FLAGS ("
              << "0x" << std::hex << servSpecificFlags << ")" << std::dec
              << std::endl;
    qatDbgGetIndent(prefix, indentLevel + 1);
    /* bit 12 */
    std::cout << prefix << "[1.12]\tZUC_3G_PROTO"
              << ": " << ICP_QAT_FW_LA_ZUC_3G_PROTO_FLAG_GET(servSpecificFlags)
              << std::endl;
    /* bit 11 */
    std::cout << prefix << "[1.11]\tGCM_IV_LEN_FLAG"
              << ": " << ICP_QAT_FW_LA_GCM_IV_LEN_FLAG_GET(servSpecificFlags)
              << std::endl;
    /* bit 10 */
    // auth_rslt
    std::cout << prefix << "[1.10]\tDIGEST_IN_BUFFER"
              << ": " << ICP_QAT_FW_LA_DIGEST_IN_BUFFER_GET(servSpecificFlags)
              << std::endl;
    /* bit 7-9 */
    // proto flags
    std::cout << prefix << "[1.7-9]\tPROTO"
              << ": " << ICP_QAT_FW_LA_PROTO_GET(servSpecificFlags)
              << std::endl;
    /* bit 6 */
    // cmp auth
    std::cout << prefix << "[1.6]\tCMP_AUTH"
              << ": " << ICP_QAT_FW_LA_CMP_AUTH_GET(servSpecificFlags)
              << std::endl;
    /* bit 5 */
    // ret auth
    std::cout << prefix << "[1.5]\tRET_AUTH"
              << ": " << ICP_QAT_FW_LA_RET_AUTH_GET(servSpecificFlags)
              << std::endl;
    /* bit 4 */
    // Update state
    std::cout << prefix << "[1.4]\tUPDATE_STATE"
              << ": " << ICP_QAT_FW_LA_UPDATE_STATE_GET(servSpecificFlags)
              << std::endl;
    /* bit 3 */
    // Ciph/Auth
    std::cout << prefix << "[1.3]\tCIPH_AUTH_CFG_OFFSET_FLAG"
              << ": "
              << ICP_QAT_FW_LA_CIPH_AUTH_CFG_OFFSET_FLAG_GET(servSpecificFlags)
              << std::endl;
    /* bit 2 */
    std::cout << prefix << "[1.2]\tCIPH_IV_FLD_FLAG"
              << ": " << ICP_QAT_FW_LA_CIPH_IV_FLD_FLAG_GET(servSpecificFlags)
              << std::endl;
    /* bit 0-1 */
    std::cout << prefix << "[1.0-1]\tPARTIAL FLAGS"
              << ": " << ICP_QAT_FW_LA_PARTIAL_GET(servSpecificFlags);

    switch (ICP_QAT_FW_LA_PARTIAL_GET(servSpecificFlags))
    {
        case 0:
            std::cout << " (FULL)";
            break;
        case 1:
            std::cout << " (FIRST)";
            break;
        case 2:
            std::cout << " (FINAL)";
            break;
        case 3:
            std::cout << " (MIDDLE)";
            break;
        default:
            break;
    }
    std::cout << std::endl;
}

static void qatDbgPrintSymCyCdCtrlHeader(icp_adf_dbg_entry_header_t *msgHeader,
                                         size_t indentLevel = 0)
{
    icp_qat_fw_la_bulk_req_t *req =
        (icp_qat_fw_la_bulk_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_cipher_cd_ctrl_hdr_t *pCipherCdCtrlHdr =
        (icp_qat_fw_cipher_cd_ctrl_hdr_t *)&req->cd_ctrl;
    std::string prefix;

    qatDbgGetIndent(prefix, indentLevel);
    std::cout << prefix
              << "[27-28.0B] Cipher Request Control Header:" << std::endl;
    qatDbgGetIndent(prefix, indentLevel + 1);
    /* [27] */
    std::cout << prefix << "[27.0B]\tuint8_t::cipher_state_sz: "
              << (int)pCipherCdCtrlHdr->cipher_state_sz << std::endl;
    std::cout << prefix << "[27.1B]\tuint8_t::cipher_key_sz: "
              << (int)pCipherCdCtrlHdr->cipher_key_sz << std::endl;
    std::cout << prefix << "[27.2B]\tuint8_t::cipher_cfg_offset: "
              << (int)pCipherCdCtrlHdr->cipher_cfg_offset << std::endl;
    std::cout << prefix << "[27.3B]\tuint8_t::next_curr_id: 0x" << std::hex
              << (int)pCipherCdCtrlHdr->next_curr_id << std::dec
              << " (curr_id: " << ICP_QAT_FW_COMN_CURR_ID_GET(pCipherCdCtrlHdr)
              << ", next: " << ICP_QAT_FW_COMN_NEXT_ID_GET(pCipherCdCtrlHdr)
              << ")" << std::endl;
    /* [28.0B] */
    std::cout << prefix << "[28.0B]\tuint8_t::cipher_padding_sz: "
              << (int)pCipherCdCtrlHdr->cipher_padding_sz << std::endl;
}

static void qatDbgPrintSymCyReqParams(icp_adf_dbg_entry_header_t *msgHeader,
                                      size_t indentLevel = 0)
{
    icp_qat_fw_la_bulk_req_t *req =
        (icp_qat_fw_la_bulk_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    /* LW 14-26 */
    icp_qat_fw_comn_req_rqpars_t *comnReqParams = &req->serv_specif_rqpars;
    /* Common request service-specific parameter field */
    icp_qat_fw_la_cipher_req_params_t *pCipherReqParams =
        (icp_qat_fw_la_cipher_req_params_t
             *)((uint8_t *)comnReqParams +
                ICP_QAT_FW_CIPHER_REQUEST_PARAMETERS_OFFSET);
    std::string prefix;

    qatDbgGetIndent(prefix, indentLevel);
    std::cout << prefix << "[14-19] Cipher Request Parameters:" << std::endl;
    qatDbgGetIndent(prefix, indentLevel + 1);
    std::cout << prefix << "[14]\tuint32_t::cipher_offset: "
              << pCipherReqParams->cipher_offset << std::endl;
    std::cout << prefix << "[15]\tuint32_t::cipher_length: "
              << pCipherReqParams->cipher_length << std::endl;
    std::cout << prefix << "[16-17]\tuint64_t::cipher_IV_ptr: "
              << (void *)pCipherReqParams->u.s.cipher_IV_ptr << std::endl;
    std::cout << prefix << "[18-19]\tuint64_t::resrvd1: "
              << (void *)pCipherReqParams->u.s.resrvd1 << std::endl;
}

/*
*******************************************************************************
* Authentication debug dump related functions
*******************************************************************************
*/
static void qatDbgPrintAuthCdCtrlHeader(icp_adf_dbg_entry_header_t *msgHeader,
                                        size_t indentLevel = 0)
{
    icp_qat_fw_la_bulk_req_t *req =
        (icp_qat_fw_la_bulk_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_auth_cd_ctrl_hdr_t *pAuthReqCtrlHdr =
        (icp_qat_fw_auth_cd_ctrl_hdr_t *)&req->cd_ctrl;
    std::string prefix;

    qatDbgGetIndent(prefix, indentLevel);
    std::cout << prefix
              << "[27-31] Authentication Request Control Header:" << std::endl;
    qatDbgGetIndent(prefix, indentLevel + 1);
    /* [27] */
    std::cout << prefix << "[27]\tuint32_t::resrvd1: 0x" << std::hex
              << pAuthReqCtrlHdr->resrvd1 << std::endl;
    /* [28] */
    std::cout << prefix << "[28.0B]\tuint8_t::resrvd2: 0x" << std::hex
              << (int)pAuthReqCtrlHdr->resrvd2 << std::endl;
    std::cout << prefix << "[28.1B]\tuint8_t::hash_flags: 0x" << std::hex
              << (int)pAuthReqCtrlHdr->hash_flags << std::endl;
    std::cout << prefix << "[28.2B]\tuint8_t::hash_cfg_offset: " << std::dec
              << (int)pAuthReqCtrlHdr->hash_cfg_offset << std::endl;
    std::cout << prefix << "[28.3B]\tuint8_t::next_curr_id: 0x" << std::hex
              << (int)pAuthReqCtrlHdr->next_curr_id << std::dec
              << " (curr_id: " << ICP_QAT_FW_COMN_CURR_ID_GET(pAuthReqCtrlHdr)
              << ", next: " << ICP_QAT_FW_COMN_NEXT_ID_GET(pAuthReqCtrlHdr)
              << ")" << std::endl;
    /* [29] */
    std::cout << prefix << "[29.0B]\tuint8_t::resrvd3: 0x" << std::hex
              << (int)pAuthReqCtrlHdr->resrvd3 << std::dec << std::endl;
    std::cout << prefix << "[29.1B]\tuint8_t::outer_prefix_offset: "
              << (int)pAuthReqCtrlHdr->outer_prefix_offset << std::endl;
    std::cout << prefix << "[29.2B]\tuint8_t::final_sz: "
              << (int)pAuthReqCtrlHdr->final_sz << std::endl;
    std::cout << prefix << "[29.3B]\tuint8_t::inner_res_sz: "
              << (int)pAuthReqCtrlHdr->inner_res_sz << std::endl;
    /* [30] */
    std::cout << prefix << "[30.0B]\tuint8_t::resrvd4: 0x" << std::hex
              << (int)pAuthReqCtrlHdr->resrvd4 << std::dec << std::endl;
    std::cout << prefix << "[30.1B]\tuint8_t::inner_state1_sz: "
              << (int)pAuthReqCtrlHdr->inner_state1_sz << std::endl;
    std::cout << prefix << "[30.2B]\tuint8_t::inner_state2_offset: "
              << (int)pAuthReqCtrlHdr->inner_state2_offset << std::endl;
    std::cout << prefix << "[30.3B]\tuint8_t::inner_state2_sz: "
              << (int)pAuthReqCtrlHdr->inner_state2_sz << std::endl;
    /* [31] */
    std::cout << prefix << "[31.0B]\tuint8_t::outer_config_offset: "
              << (int)pAuthReqCtrlHdr->outer_config_offset << std::endl;
    std::cout << prefix << "[31.1B]\tuint8_t::outer_state1_sz: "
              << (int)pAuthReqCtrlHdr->outer_state1_sz << std::endl;
    std::cout << prefix << "[31.2B]\tuint8_t::outer_res_sz: "
              << (int)pAuthReqCtrlHdr->outer_res_sz << std::endl;
    std::cout << prefix << "[31.3B]\tuint8_t::outer_prefix_offset: "
              << (int)pAuthReqCtrlHdr->outer_prefix_offset << std::endl;
}

static void qatDbgPrintAuthReqParams(icp_adf_dbg_entry_header_t *msgHeader,
                                     size_t indentLevel = 0)
{
    icp_qat_fw_la_bulk_req_t *req =
        (icp_qat_fw_la_bulk_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    /* LW 20 - 26 */
    icp_qat_fw_la_auth_req_params_t *pAuthReqParams =
        (icp_qat_fw_la_auth_req_params_t
             *)((Cpa8U *)&(req->serv_specif_rqpars) +
                ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET);
    std::string prefix;

    qatDbgGetIndent(prefix, indentLevel);
    std::cout << prefix
              << "[20-26] Authentication Request Parameters:" << std::endl;
    qatDbgGetIndent(prefix, indentLevel + 1);
    std::cout << prefix
              << "[20]\tuint32_t::auth_off: " << pAuthReqParams->auth_off
              << std::endl;
    std::cout << prefix
              << "[21]\tuint32_t::auth_len: " << pAuthReqParams->auth_len
              << std::endl;
    /* [22-23] Authentication Partial State/Prefix/AAD Pointer */
    std::cout << prefix << "[22-23]\tuint64_t::aad_adr/APS: "
              << (void *)pAuthReqParams->u1.auth_partial_st_prefix << std::endl;
    /* [24-25] Authentication Result Pointer */
    std::cout << prefix << "[24-25]\tuint64_t::auth_res_addr: "
              << (void *)pAuthReqParams->auth_res_addr << std::endl;
    /* [26] Authentication Result */
    std::cout << prefix << "[26.0B]\tuint8_t::aad_sz/inner_prefix_sz: "
              << (int)pAuthReqParams->u2.inner_prefix_sz << std::endl;
    /* [26] resrvd1 */
    std::cout << prefix
              << "[26.1B]\tuint8_t::resrvd1: " << (int)pAuthReqParams->resrvd1
              << std::endl;
    /* [26] hash_state_sz */
    std::cout << prefix << "[26.2B]\tuint8_t::hash_state_sz: "
              << (int)pAuthReqParams->hash_state_sz << std::endl; // ?
    /* [26] auth_res_sz */
    std::cout << prefix << "[26.3B]\tuint8_t::auth_res_sz: "
              << (int)pAuthReqParams->auth_res_sz << std::endl;
}

/*
*******************************************************************************
* Key derivation function debug dump related functions
*******************************************************************************
*/
static void qatDbgPrintCyKeyGenSsl3ReqParams(
    icp_adf_dbg_entry_header_t *msgHeader,
    size_t indentLevel = 0)
{
    /* LW0-LW31 */
    icp_qat_fw_la_bulk_req_t *req =
        (icp_qat_fw_la_bulk_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    /* LW14-LW26 */
    icp_qat_fw_la_ssl3_req_params_t *ssl3ReqParams =
        (icp_qat_fw_la_ssl3_req_params_t *)&req->serv_specif_rqpars;
    /* LW14-LW15 */
    icp_qat_fw_la_key_gen_common_t *keygenComn = &ssl3ReqParams->keygen_comn;
    std::string prefix;

    qatDbgGetIndent(prefix, indentLevel);
    std::cout << prefix << "SSL3 Key Derive Request Parameters:" << std::endl;
    qatDbgGetIndent(prefix, indentLevel + 1);
    /* LW14.0B - LW14.1B */
    std::cout << prefix << "[14.0-1B]\tuint16_t::secret_lgth_ssl: "
              << keygenComn->u.secret_lgth_ssl << std::endl;
    /* LW14.2 */
    std::cout << prefix << "[14.2B]\tuint8_t::output_lgth_ssl: "
              << (int)keygenComn->u1.s1.output_lgth_ssl << std::endl;
    /* LW14.3 */
    std::cout << prefix << "[14.3B]\tuint8_t::label_lgth_ssl: "
              << (int)keygenComn->u1.s1.label_lgth_ssl << std::endl;
    /* LW15 */
    std::cout << prefix << "[15.0B]\tuint8_t::iter_count: "
              << (int)keygenComn->u2.iter_count << std::endl;
    /* Note that the only field in the Request Parameters Block that is used by
     * SSL3 is
     * the Inner Prefix / AAD Size field. The remaining areas of the Request
     * Parameters Block are reserved for SSL3.
     */
    /* [26] Authentication Result */
    std::cout << prefix << "[26.0B]\tuint8_t::aad_sz/inner_prefix_sz: "
              << ssl3ReqParams->u2.inner_prefix_sz << std::endl;
}

static void qatDbgPrintCyKeyGenTlsV11ReqParams(
    icp_adf_dbg_entry_header_t *msgHeader,
    size_t indentLevel = 0)
{
    /* LW0-LW31 */
    icp_qat_fw_la_bulk_req_t *req =
        (icp_qat_fw_la_bulk_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    /* LW14-LW26 */
    icp_qat_fw_la_tls_req_params_t *tlsReqParams =
        (icp_qat_fw_la_tls_req_params_t *)&req->serv_specif_rqpars;
    /* LW14-LW15 */
    icp_qat_fw_la_key_gen_common_t *keyGenComn = &tlsReqParams->keygen_comn;
    std::string prefix;

    qatDbgGetIndent(prefix, indentLevel);
    std::cout << prefix
              << "TLS V1.1 Key Derive Request Parameters:" << std::endl;
    qatDbgGetIndent(prefix, indentLevel + 1);
    /* LW14.0B - LW14.1B */
    std::cout << prefix << "[14.0-1B]\tuint16_t::secret_lgth_tls: "
              << keyGenComn->u.secret_lgth_tls << std::endl;
    /* LW14.2 */
    std::cout << prefix << "[14.2B]\tuint8_t::output_lgth_tls: "
              << (int)keyGenComn->u1.s3.output_lgth_tls << std::endl;
    /* LW14.3 */
    std::cout << prefix << "[14.3B]\tuint8_t::label_lgth_tls: "
              << (int)keyGenComn->u1.s3.label_lgth_tls << std::endl;
    /* LW15 */
    std::cout << prefix << "[15.0B]\tuint8_t::tls_seed_length: "
              << (int)keyGenComn->u2.tls_seed_length << std::endl;
}

static void qatDbgPrintCyKeyGenHKDFReqParams(
    icp_adf_dbg_entry_header_t *msgHeader,
    size_t indentLevel = 0)
{
    /* LW0-LW31 */
    icp_qat_fw_la_bulk_req_t *req =
        (icp_qat_fw_la_bulk_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    /* LW0-LW1 */
    icp_qat_fw_comn_req_hdr_t *comnHeader = &req->comn_hdr;
    /* LW14-LW26 */
    icp_qat_fw_la_tls_req_params_t *hkdfReqParams =
        (icp_qat_fw_la_tls_req_params_t *)&req->serv_specif_rqpars;
    /* LW14-LW15 */
    icp_qat_fw_la_key_gen_common_t *keyGenComn = &hkdfReqParams->keygen_comn;
    std::string prefix;

    qatDbgGetIndent(prefix, indentLevel);
    std::cout << prefix << "[14-15] HKDF Request Parameters:" << std::endl;
    qatDbgGetIndent(prefix, indentLevel + 1);
    /* LW14.0B - LW14.1B */
    std::cout << prefix << "[14.0-1B]\tuint16_t::secret_lgth_tls: "
              << keyGenComn->u.secret_lgth_tls << std::endl;
    if (ICP_QAT_FW_LA_CMD_HKDF_EXTRACT == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_HKDF_EXPAND == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_HKDF_EXTRACT_AND_EXPAND == comnHeader->service_cmd_id)
    {
        /* LW14.2 */
        std::cout << prefix << "[14.2B]\tuint8_t::rsrvd1: "
                  << (int)keyGenComn->u1.hkdf.rsrvd1 << std::endl;
        /* LW14.3 */
        std::cout << prefix << "[14.3B]\tuint8_t::info_length: "
                  << (int)keyGenComn->u1.hkdf.info_length << std::endl;
    }
    else if (ICP_QAT_FW_LA_CMD_HKDF_EXPAND_LABEL ==
                 comnHeader->service_cmd_id ||
             ICP_QAT_FW_LA_CMD_HKDF_EXTRACT_AND_EXPAND_LABEL ==
                 comnHeader->service_cmd_id)
    {
        /* LW14.2 */
        std::cout << prefix << "[14.2B]\tuint8_t::rsrvd1: "
                  << (int)keyGenComn->u1.hkdf_label.rsrvd1 << std::endl;
        /* LW14.3 */
        std::cout << prefix << "[14.3B]\tuint8_t::num_labels: "
                  << (int)keyGenComn->u1.hkdf_label.num_labels << std::endl;
    }
    /* LW15 */
    std::cout << prefix << "[15.0B]\tuint8_t::hkdf_ikm_length: "
              << (int)keyGenComn->u2.hkdf_ikm_length << std::endl;
    std::cout << prefix << "[15.1B]\tuint8_t::hkdf_num_sublabels: "
              << (int)keyGenComn->u3.hkdf_num_sublabels << std::endl;
}

/*
*******************************************************************************
* QAT requests common routines
*******************************************************************************
*/
static void qatDbgPrintReqHeader(icp_adf_dbg_entry_header_t *msgHeader,
                                 const char *service)
{
    Cpa16U bank = msgHeader->bank;
    Cpa16U ring = msgHeader->ring;
    std::string prefix;

    qatDbgGetIndent(prefix, 1);
    std::cout << prefix << "Entry [REQUEST " << service
              << "]: Time-stamp: " << qatDbgFormatTimestamp(msgHeader->ts)
              << std::endl;
    std::cout << prefix << "Bank: " << bank << " Ring: " << ring
              << " PID: " << msgHeader->pid << std::endl;
}

static void qatDbgPrintReqCd(icp_adf_dbg_entry_header_t *msgHeader,
                             size_t indentLevel = 0)
{
    /* LW0-LW31 */
    icp_qat_fw_la_bulk_req_t *req =
        (icp_qat_fw_la_bulk_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    /* LW2-LW5 */
    icp_qat_fw_comn_req_hdr_cd_pars_t *cdPars = &req->cd_pars;
    std::string prefix;

    qatDbgGetIndent(prefix, indentLevel);
    std::cout << prefix << "[2-3] Content Descriptor (CD) Param Pointer: "
              << (void *)cdPars->s.content_desc_addr << std::endl;
    std::cout << prefix << "[4.2B] Content Descriptor Param Size: "
              << (int)cdPars->s.content_desc_params_sz << " [Quad words]"
              << std::endl;
}

static void qatDbgPrintCommonReq(icp_adf_dbg_entry_header_t *msgHeader)
{
    /* LW0-LW31 */
    icp_qat_fw_comn_req_t *req =
        (icp_qat_fw_comn_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    /* LW0-LW1 */
    icp_qat_fw_comn_req_hdr_t *comnHeader = &req->comn_hdr;
    /* LW6-LW13 */
    icp_qat_fw_comn_req_mid_t *comnMid = &req->comn_mid;
    std::string prefix;
    std::string prefixSub;

    qatDbgPrintReqHeader(msgHeader, "UNKNOWN");
    qatDbgGetIndent(prefix, 2);
    qatDbgGetIndent(prefixSub, 3);
    std::cout << prefix
              << "[0.1B] command ID: " << (int)comnHeader->service_cmd_id
              << std::endl;
    std::cout << prefix << "[0.2B] Service type: "
              << QAT_DBG_GET_SERVICE(comnHeader->service_type) << " ["
              << (int)comnHeader->service_type << "]" << std::endl;
    /* Skip protocol specific flags */
    std::cout << prefix << "[1.2B] Common Request flags: 0x" << std::hex
              << (int)comnHeader->comn_req_flags << std::dec << std::endl;
    std::cout << prefixSub << " SGL["
              << ICP_QAT_FW_COMN_PTR_TYPE_GET(comnHeader->comn_req_flags) << "]"
              << " CD_IN ["
              << ICP_QAT_FW_COMN_CD_FLD_TYPE_GET(comnHeader->comn_req_flags)
              << "]"
              << " BNP ["
              << ICP_QAT_FW_COMN_BNP_ENABLED_GET(comnHeader->comn_req_flags)
              << "]" << std::endl;
    std::cout << prefix
              << "[1.3B] Extended Symmetric Crypto Command Flags: " << std::hex
              << (int)comnHeader->extended_serv_specif_flags << std::dec
              << std::endl;
    /* LW2 - LW5 */
    qatDbgPrintReqCd(msgHeader, 2);
    std::cout << prefix
              << "[6-7]\tOpaque Data: " << (void *)comnMid->opaque_data
              << std::endl;
    std::cout << prefix
              << "[8-9]\tSource phy_addr: " << (void *)comnMid->src_data_addr
              << std::endl;
    std::cout << prefix << "[10-11]\tDestination phy_addr: "
              << (void *)comnMid->dest_data_addr << std::endl;
    std::cout << prefix << "[12]\tSource length: " << comnMid->src_length
              << std::endl;
    std::cout << prefix << "[13]\tDestination length: " << comnMid->dst_length
              << std::endl;
    std::cout << prefix << "Request hex dump:" << std::endl;
    qatDbgHexDump(prefix, (uint8_t *)req, sizeof(icp_qat_fw_comn_req_t));
}

/*
*******************************************************************************
* QAT service-specific requests debug dump related functions
*******************************************************************************
*/
static void qatDbgPrintSymCyReq(icp_adf_dbg_entry_header_t *msgHeader)
{
    /* LW0-LW31 */
    icp_qat_fw_la_bulk_req_t *req =
        (icp_qat_fw_la_bulk_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    /* LW0-LW1 */
    icp_qat_fw_comn_req_hdr_t *comnHeader = &req->comn_hdr;
    /* LW6-LW13 */
    icp_qat_fw_comn_req_mid_t *comnMid = &req->comn_mid;
    const size_t indentLevel = 2;
    std::string prefix;
    std::string prefixSub;

    qatDbgPrintReqHeader(msgHeader, "SYM");
    qatDbgGetIndent(prefix, indentLevel);
    qatDbgGetIndent(prefixSub, indentLevel + 1);
    std::cout << prefix << "[0.1B] Crypto command ID: "
              << QAT_DBG_GET_SYM_CY_CMD(comnHeader->service_cmd_id) << " ["
              << (int)comnHeader->service_cmd_id << "]" << std::endl;
    std::cout << prefix << "[0.2B] Service type: "
              << QAT_DBG_GET_SERVICE(comnHeader->service_type) << " ["
              << (int)comnHeader->service_type << "]" << std::endl;
    /* LW1[0-1B] */
    qatDbgPrintSymCyCmdFlags(msgHeader, 2);
    std::cout << prefix << "[1.2B] Common Request flags: 0x" << std::hex
              << (int)comnHeader->comn_req_flags << std::dec << std::endl;
    std::cout << prefixSub << " SGL["
              << ICP_QAT_FW_COMN_PTR_TYPE_GET(comnHeader->comn_req_flags) << "]"
              << " CD_IN ["
              << ICP_QAT_FW_COMN_CD_FLD_TYPE_GET(comnHeader->comn_req_flags)
              << "]"
              << " BNP ["
              << ICP_QAT_FW_COMN_BNP_ENABLED_GET(comnHeader->comn_req_flags)
              << "]" << std::endl;
    std::cout << prefix
              << "[1.3B] Extended Symmetric Crypto Command Flags: " << std::hex
              << (int)comnHeader->extended_serv_specif_flags << std::dec
              << std::endl;
    /* LW2 - LW5 */
    qatDbgPrintReqCd(msgHeader, indentLevel);
    std::cout << prefix
              << "[6-7]\tOpaque Data: " << (void *)comnMid->opaque_data
              << std::endl;
    std::cout << prefix
              << "[8-9]\tSource phy_addr: " << (void *)comnMid->src_data_addr
              << std::endl;
    std::cout << prefix << "[10-11]\tDestination phy_addr: "
              << (void *)comnMid->dest_data_addr << std::endl;
    std::cout << prefix << "[12]\tSource length: " << comnMid->src_length
              << std::endl;
    std::cout << prefix << "[13]\tDestination length: " << comnMid->dst_length
              << std::endl;

    if (ICP_QAT_FW_LA_CMD_CIPHER == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_CIPHER_HASH == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_HASH_CIPHER == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_CIPHER_PRE_COMP == comnHeader->service_cmd_id)
    {
        qatDbgPrintSymCyReqParams(msgHeader, indentLevel);
        qatDbgPrintSymCyCdCtrlHeader(msgHeader, indentLevel);
    }
    if (ICP_QAT_FW_LA_CMD_AUTH == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_CIPHER_HASH == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_HASH_CIPHER == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_AUTH_PRE_COMP == comnHeader->service_cmd_id)
    {
        qatDbgPrintAuthReqParams(msgHeader, indentLevel);
        qatDbgPrintAuthCdCtrlHeader(msgHeader,
                                    indentLevel); // Auth/Hash control block
    }
    if (ICP_QAT_FW_LA_CMD_SSL3_KEY_DERIVE == comnHeader->service_cmd_id)
    {
        // SSL specific (LW14 + LW15.0B) + 26.1B
        qatDbgPrintCyKeyGenSsl3ReqParams(msgHeader, indentLevel);
        qatDbgPrintAuthCdCtrlHeader(msgHeader,
                                    indentLevel); // Auth/Hash control block
    }
    if (ICP_QAT_FW_LA_CMD_TLS_V1_1_KEY_DERIVE == comnHeader->service_cmd_id)
    {
        qatDbgPrintCyKeyGenTlsV11ReqParams(
            msgHeader,
            indentLevel); // TLS specific (LW14 + LW15.0B)
        qatDbgPrintAuthReqParams(msgHeader, indentLevel); // Auth Params
        qatDbgPrintAuthCdCtrlHeader(msgHeader,
                                    indentLevel); // Auth/Hash control block
    }
    if (ICP_QAT_FW_LA_CMD_TLS_V1_2_KEY_DERIVE == comnHeader->service_cmd_id)
    {
        /* Missing in documentation */
        qatDbgPrintCyKeyGenTlsV11ReqParams(
            msgHeader,
            indentLevel); // TLS specific (LW14 + LW15.0B)
        qatDbgPrintAuthReqParams(msgHeader, indentLevel); // Auth Params
        qatDbgPrintAuthCdCtrlHeader(msgHeader,
                                    indentLevel); // Auth/Hash control block
    }
    if (ICP_QAT_FW_LA_CMD_HKDF_EXTRACT == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_HKDF_EXPAND == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_HKDF_EXTRACT_AND_EXPAND ==
            comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_HKDF_EXPAND_LABEL == comnHeader->service_cmd_id ||
        ICP_QAT_FW_LA_CMD_HKDF_EXTRACT_AND_EXPAND_LABEL ==
            comnHeader->service_cmd_id)
    {
        qatDbgPrintCyKeyGenHKDFReqParams(msgHeader, indentLevel);
        qatDbgPrintAuthReqParams(msgHeader, indentLevel); // Auth Params
        qatDbgPrintAuthCdCtrlHeader(msgHeader,
                                    indentLevel); // Auth/Hash control block
    }
}

static void qatDbgPrintPkeReq(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_pke_request_t *pkeReq =
        (icp_qat_fw_pke_request_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_req_pke_hdr_t *pkeHeader = &pkeReq->pke_hdr;
    icp_qat_fw_req_pke_mid_t *pkeMid = &pkeReq->pke_mid;
    icp_qat_fw_req_hdr_pke_cd_pars_t *cdPars = NULL;
    std::string prefix;

    qatDbgPrintReqHeader(msgHeader, "PKE");
    qatDbgGetIndent(prefix, 2);
    std::cout << prefix << "[0.2B] Service Type: "
              << QAT_DBG_GET_SERVICE(pkeHeader->service_type) << "["
              << (int)pkeHeader->service_type << "] " << std::endl;
    std::cout << prefix << "[1.0-1B Common request flags: 0x" << std::hex
              << (int)pkeHeader->comn_req_flags << std::dec << std::endl;
    std::cout << prefix << "\tSGL["
              << ICP_QAT_FW_COMN_PTR_TYPE_GET(pkeHeader->comn_req_flags) << "]"
              << std::endl;
    /* Function ID extraction */
    cdPars = &pkeHeader->cd_pars;
    std::cout << prefix << "[5]\tFunctionality ID: "
              << qatDbgPkeFuncIdToName(cdPars->func_id) << " [0x" << std::hex
              << cdPars->func_id << "]" << std::endl;
    std::cout << prefix << "[6-7]\tOpaque Data: " << (void *)pkeMid->opaque_data
              << std::endl;
    std::cout << prefix
              << "[8-9]\tSource phy_addr: " << (void *)pkeMid->src_data_addr
              << std::endl;
    std::cout << prefix << "[10-11]\tDestination phy_addr: "
              << (void *)pkeMid->dest_data_addr << std::endl;
    std::cout << prefix << "[12.0B]\tOutput Param Count: " << std::dec
              << (int)pkeReq->output_param_count << std::endl;
    std::cout << prefix << "[12.1B]\tInput Param Count: "
              << (int)pkeReq->input_param_count << std::endl;
    std::cout << prefix << "[14-15]\tNext Request Address: 0x"
              << (void *)pkeReq->next_req_adr << std::dec << std::endl;
}

static void qatDbgPrintDcReq(icp_adf_dbg_entry_header_t *msgHeader)
{
    /* LW0 - LW31 */
    icp_qat_fw_comp_req_t *compReq =
        (icp_qat_fw_comp_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    /* LW0 - LW1 */
    icp_qat_fw_comn_req_hdr_t *comnHeader = &compReq->comn_hdr;
    /* LW2 - LW5 */
    icp_qat_fw_comp_req_hdr_cd_pars_t *cdPars = &compReq->cd_pars;
    /* LW6 - LW13 */
    icp_qat_fw_comn_req_mid_t *comnMid = &compReq->comn_mid;
    /* LW14 -  LW19 */
    icp_qat_fw_comp_req_params_t *compPars = &compReq->comp_pars;
    /* LW20 - LW21 */
    icp_qat_fw_xlt_req_params_t *xltPars = &compReq->u1.xlt_pars;
    /* LW24 - LW29 */
    icp_qat_fw_comp_cd_hdr_t *compCdCtrl = &compReq->comp_cd_ctrl;
    /* LW30 - LW31 */
    icp_qat_fw_xlt_cd_hdr_t *xltCdCtrl = &compReq->u2.xlt_cd_ctrl;
    const size_t indentLevel = 2;
    std::string prefix;
    std::string prefixSub;

    qatDbgPrintReqHeader(msgHeader, "DC");
    qatDbgGetIndent(prefix, indentLevel);
    qatDbgGetIndent(prefixSub, indentLevel + 1);
    std::cout << prefix << "[0.1B] Compression command ID: "
              << QAT_DBG_GET_DC_CMD(comnHeader->service_cmd_id) << "["
              << (int)comnHeader->service_cmd_id << "]" << std::endl;
    std::cout << prefix << "[0.2B] Service Type: "
              << QAT_DBG_GET_SERVICE(comnHeader->service_type) << "["
              << (int)comnHeader->service_type << "] " << std::endl;
    /* Compression flags */
    std::cout << prefix << "[1.0-1B] Compression command flags: 0x" << std::hex
              << comnHeader->serv_specif_flags << std::dec << std::endl;
    std::cout << prefixSub << "[1.2b] Stateful flag: "
              << ICP_QAT_FW_COMP_SESSION_TYPE_GET(comnHeader->serv_specif_flags)
              << std::endl;
    std::cout << prefixSub << "[1.3b] Auto Select Best flag: "
              << ICP_QAT_FW_COMP_AUTO_SELECT_BEST_GET(
                     comnHeader->serv_specif_flags)
              << std::endl;
    std::cout << prefixSub << "[1.4b] Enhanced Auto Select Best flags: "
              << ICP_QAT_FW_COMP_EN_ASB_GET(comnHeader->serv_specif_flags)
              << std::endl;
    std::cout << prefixSub << "[1.5b] Return disable Type0 header: "
              << ICP_QAT_FW_COMP_RET_UNCOMP_GET(comnHeader->serv_specif_flags)
              << std::endl;
    std::cout << prefixSub
              << "[1.7b] Disable Secure RAM use as intermediate buffer: "
              << ICP_QAT_FW_COMP_SECURE_RAM_USE_GET(
                     comnHeader->serv_specif_flags)
              << std::endl;
    /* Common request flags */
    std::cout << prefix << "[1.2-3B] Common request flags: 0x" << std::hex
              << (int)comnHeader->comn_req_flags << std::dec << " SGL["
              << ICP_QAT_FW_COMN_PTR_TYPE_GET(comnHeader->comn_req_flags) << "]"
              << " CD_IN ["
              << ICP_QAT_FW_COMN_CD_FLD_TYPE_GET(comnHeader->comn_req_flags)
              << "]"
              << " BNP ["
              << ICP_QAT_FW_COMN_BNP_ENABLED_GET(comnHeader->comn_req_flags)
              << "]" << std::endl;
    std::cout << prefix << "[2-3] Content desc address/Config: "
              << (void *)cdPars->s.content_desc_addr << std::endl;
    std::cout << prefix << "[4.3B] Content desc param size:"
              << (int)cdPars->s.content_desc_params_sz << std::endl;
    std::cout << prefix << "[6-7] Opaque data: " << (void *)comnMid->opaque_data
              << std::endl;
    std::cout << prefix
              << "[8-9] Source pointer: " << (void *)comnMid->src_data_addr
              << std::endl;
    std::cout << prefix << "[10-11] Destination pointer: "
              << (void *)comnMid->dest_data_addr << std::endl;
    std::cout << prefix << "[12] Source length: " << comnMid->src_length
              << std::endl;
    std::cout << prefix << "[13] Destination length: " << comnMid->dst_length
              << std::endl;
    std::cout << prefix << "[14] Compression length: " << compPars->comp_len
              << std::endl;
    std::cout << prefix
              << "[15] Output buffer size: " << compPars->out_buffer_sz
              << std::endl;
    std::cout << prefix << "[16] Initial CRC32: " << std::hex
              << compPars->crc.legacy.initial_crc32 << std::dec << std::endl;
    std::cout << prefix << "[17] Initial Adler: " << std::hex
              << compPars->crc.legacy.initial_adler << std::dec << std::endl;
    std::cout << prefix << "[16-17] CRC data addr: " << std::hex
              << compPars->crc.crc_data_addr << std::dec << std::endl;
    /* Request param flags */
    std::cout << prefix << "[18] Request param flags: 0x" << std::hex
              << compPars->req_par_flags << std::dec << std::endl;
    std::cout << prefixSub << " SOP:"
              << (int)ICP_QAT_FW_COMP_SOP_GET(compPars->req_par_flags)
              << std::endl;
    std::cout << prefixSub << " EOP:"
              << (int)ICP_QAT_FW_COMP_EOP_GET(compPars->req_par_flags)
              << std::endl;
    std::cout << prefixSub << " FINAL:"
              << (int)ICP_QAT_FW_COMP_BFINAL_GET(compPars->req_par_flags)
              << std::endl;
    std::cout << prefixSub << " CNV:"
              << (int)ICP_QAT_FW_COMP_CNV_GET(compPars->req_par_flags)
              << std::endl;
    std::cout << prefixSub << " CNVnR:"
              << (int)QAT_FIELD_GET(compPars->req_par_flags,
                                    ICP_QAT_FW_COMP_CNV_RECOVERY_BITPOS,
                                    1)
              << std::endl;
    /* LW19 - reserverd */
    /* LW20 - LW21 */
    std::cout << prefix << "[20-21] Intermediate buffer pointer: "
              << (void *)xltPars->inter_buff_ptr << std::endl;
    /* LW24 */
    std::cout << prefix << "[24.0-1B] RAM Bank Flags: 0x" << std::hex
              << compCdCtrl->ram_bank_flags << std::dec << std::endl;
    std::cout << prefix
              << "[24.2B] Comp cfg offset: " << (int)compCdCtrl->comp_cfg_offset
              << std::endl;
    std::cout << prefix << "[24.3B] Next/Curr ID: : 0x" << std::hex
              << (int)compCdCtrl->next_curr_id << std::dec
              << " (curr_id: " << ICP_QAT_FW_COMN_CURR_ID_GET(compCdCtrl)
              << ", next: " << ICP_QAT_FW_COMN_NEXT_ID_GET(compCdCtrl) << ")"
              << std::endl;
    std::cout << prefix << "[26-27] Compression State Pointer: "
              << (void *)compCdCtrl->comp_state_addr << std::endl;
    std::cout << prefix << "[28-29] RAM Bank Pointer: "
              << (void *)compCdCtrl->ram_banks_addr << std::endl;
    /* LW30 */
    std::cout << prefix << "[30.3B] XLT Next/Current ID: 0x" << std::hex
              << (int)xltCdCtrl->next_curr_id << std::dec
              << " (curr_id: " << ICP_QAT_FW_COMN_CURR_ID_GET(xltCdCtrl)
              << ", next: " << ICP_QAT_FW_COMN_NEXT_ID_GET(xltCdCtrl) << ")"
              << std::endl;
}

/*
*******************************************************************************
* QAT responses common routines
*******************************************************************************
*/
static void qatDbgPrintRespHeader(icp_adf_dbg_entry_header_t *msgHeader,
                                  const char *service)
{
    Cpa16U bank = msgHeader->bank;
    Cpa16U ring = msgHeader->ring;
    std::string prefix;

    qatDbgGetIndent(prefix, 1);
    std::cout << prefix << "Entry [RESPONSE " << service
              << "]: Time-stamp: " << qatDbgFormatTimestamp(msgHeader->ts)
              << std::endl;
    std::cout << prefix << "Bank: " << bank << " Ring: " << ring
              << " PID: " << msgHeader->pid << std::endl;
}

/*
*******************************************************************************
* QAT services responses debug dump related functions
*******************************************************************************
*/
static void qatDbgPrintPkeResp(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_pke_resp_t *pkeResp =
        (icp_qat_fw_pke_resp_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_resp_pke_hdr_t *pkeRespHeader = &pkeResp->pke_resp_hdr;
    icp_qat_fw_pke_resp_status_t *pkeRespStatus = &pkeRespHeader->resp_status;
    std::string prefix;

    qatDbgPrintRespHeader(msgHeader, "PKE");
    qatDbgGetIndent(prefix, 2);
    /* 0.3B (it's not described in documentation) */
    std::cout << prefix << "[1.0B] Common error code: "
              << (int)pkeRespStatus->comn_err_code << std::endl;
    std::cout << prefix << "[1.1B] PKE status flag: 0x" << std::hex
              << (int)pkeRespStatus->pke_resp_flags << std::dec << std::endl;
    std::cout << prefix << "[2-3] Opaque data: " << (void *)pkeResp->opaque_data
              << std::endl;
    std::cout << prefix
              << "[4-5] Source pointer: " << (void *)pkeResp->src_data_addr
              << std::endl;
    std::cout << prefix << "[6-7] Destination pointer: "
              << (void *)pkeResp->dest_data_addr << std::dec << std::endl;
}

/*
*******************************************************************************
* Public functions
*******************************************************************************
*/
void qatDbgHandleFwRequest(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_comn_req_t *req =
        (icp_qat_fw_comn_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_comn_req_hdr_t *comnHeader = &req->comn_hdr;
    uint8_t *sglPtr = NULL;
    size_t i = 0;
    std::string prefix;

    switch (comnHeader->service_type)
    {
        case ICP_QAT_FW_COMN_REQ_CPM_FW_LA:
            qatDbgPrintSymCyReq(msgHeader);
            break;
        case ICP_QAT_FW_COMN_REQ_CPM_FW_PKE:
            qatDbgPrintPkeReq(msgHeader);
            break;
        case ICP_QAT_FW_COMN_REQ_CPM_FW_COMP:
        case ICP_QAT_FW_COMN_REQ_CPM_FW_COMP_CHAIN:
            qatDbgPrintDcReq(msgHeader);
            break;
        default:
            qatDbgPrintCommonReq(msgHeader);
            break;
    }

    if (QAT_COMN_PTR_TYPE_FLAT ==
        ICP_QAT_FW_COMN_PTR_TYPE_GET(comnHeader->comn_req_flags))
    {
        return;
    }

    /* Handling SGL */
    qatDbgGetIndent(prefix, 2);
    sglPtr = QAT_DBG_GET_MSG_CONTENT(msgHeader) + msgHeader->msg_len;
    std::cout << prefix << "SGL Data:" << std::endl;

    if (0 < msgHeader->src_sgl_len)
    {
        /* Handling source SGL */
        icp_buffer_list_desc_t sgl = *((icp_buffer_list_desc_t *)sglPtr);

        std::cout << "\t\t\tSource SGL contains " << sgl.numBuffers
                  << " flat buffer(s):" << std::endl;
        for (i = 0; i < sgl.numBuffers; i++)
        {
            icp_flat_buffer_desc_t *flat =
                QAT_DBG_GET_SGL_FLAT_BUFFER(sglPtr, i);

            std::cout << "\t\t\t\t[" << i
                      << "] Flat buffer: len: " << flat->dataLenInBytes;
            std::cout << std::hex << " phy_addr: 0x" << flat->phyBuffer
                      << std::dec << std::endl;
        }
    }
    sglPtr += msgHeader->src_sgl_len;

    if (0 < msgHeader->dst_sgl_len)
    {
        /* Handling destination SGL */
        icp_buffer_list_desc_t sgl = *((icp_buffer_list_desc_t *)sglPtr);

        std::cout << "\t\t\tDestination SGL contains " << sgl.numBuffers
                  << " flat buffer(s):" << std::endl;
        for (i = 0; i < sgl.numBuffers; i++)
        {
            icp_flat_buffer_desc_t *flat =
                QAT_DBG_GET_SGL_FLAT_BUFFER(sglPtr, i);

            std::cout << "\t\t\t\t[" << i
                      << "] Flat buffer: len: " << flat->dataLenInBytes;
            std::cout << std::hex << " phy_addr: 0x" << flat->phyBuffer
                      << std::dec << std::endl;
        }
    }
}

void qatDbgHandleFwResponse(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_comn_resp_t *resp =
        (icp_qat_fw_comn_resp_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_comn_resp_hdr_t *comnHeader = &resp->comn_hdr;
    const int indentLevel = 2;
    std::string prefix;
    std::string prefixSub;

    /* Print header */
    switch (comnHeader->response_type)
    {
        case ICP_QAT_FW_COMN_REQ_CPM_FW_LA:
            qatDbgPrintRespHeader(msgHeader, "SYM");
            break;
        case ICP_QAT_FW_COMN_REQ_CPM_FW_PKE:
            qatDbgPrintPkeResp(msgHeader);
            return;
        case ICP_QAT_FW_COMN_REQ_CPM_FW_COMP:
        case ICP_QAT_FW_COMN_REQ_CPM_FW_COMP_CHAIN:
            qatDbgPrintRespHeader(msgHeader, "DC");
            break;
        default:
            qatDbgPrintRespHeader(msgHeader, "UNKNOWN");
            break;
    }

    qatDbgGetIndent(prefix, indentLevel);
    qatDbgGetIndent(prefixSub, indentLevel + 1);
    std::cout << prefix << "[0.1B] Service ID: "
              << QAT_DBG_GET_RESP_SERVICE(comnHeader->service_id) << " ["
              << (int)comnHeader->service_id << "]" << std::endl;
    std::cout << prefix << "[0.2B] Response type: "
              << QAT_DBG_GET_SERVICE(comnHeader->response_type) << " ["
              << (int)comnHeader->response_type << "]" << std::endl;
    std::cout << prefix << "[1.3B] Command ID: ";
    if (ICP_QAT_FW_COMN_REQ_CPM_FW_LA == comnHeader->response_type)
    {
        std::cout << QAT_DBG_GET_SYM_CY_CMD(comnHeader->cmd_id);
    }
    else if (ICP_QAT_FW_COMN_REQ_CPM_FW_COMP == comnHeader->response_type ||
             ICP_QAT_FW_COMN_REQ_CPM_FW_COMP_CHAIN == comnHeader->response_type)
    {
        std::cout << QAT_DBG_GET_DC_CMD(comnHeader->cmd_id);
    }
    else
    {
        std::cout << "UNKNOWN";
    }
    std::cout << " [" << (int)comnHeader->cmd_id << "]" << std::endl;
    std::cout << prefix << "[1.1B] Common error code: "
              << (int)comnHeader->comn_error.s.comn_err_code << std::endl;
    std::cout << prefix << "[1.2B] Common status flags: 0x" << std::hex
              << (int)comnHeader->comn_status << std::dec << std::endl;
    std::cout << prefixSub << " CRYPTO STAT FLAG: "
              << ICP_QAT_FW_COMN_RESP_CRYPTO_STAT_GET(comnHeader->comn_status)
              << std::endl;
    std::cout << prefixSub << " PKE STAT FLAG: "
              << ICP_QAT_FW_COMN_RESP_PKE_STAT_GET(comnHeader->comn_status)
              << std::endl;
    std::cout << prefixSub << " CMP STAT FLAG: "
              << ICP_QAT_FW_COMN_RESP_CMP_STAT_GET(comnHeader->comn_status)
              << std::endl;
    std::cout << prefixSub << " XLAT STAT FLAG: "
              << ICP_QAT_FW_COMN_RESP_XLAT_STAT_GET(comnHeader->comn_status)
              << std::endl;
    std::cout << prefixSub << " XLAT APPLIED STAT FLAG: "
              << ICP_QAT_FW_COMN_RESP_XLT_APPLIED_GET(comnHeader->comn_status)
              << std::endl;
    std::cout << prefixSub << " CMP EOF LAST BLK FLAG: "
              << ICP_QAT_FW_COMN_RESP_CMP_END_OF_LAST_BLK_FLAG_GET(
                     comnHeader->comn_status)
              << std::endl;
    std::cout << prefixSub << " UNSUPPORTED RQ STAT FLAG: "
              << ICP_QAT_FW_COMN_RESP_UNSUPPORTED_REQUEST_STAT_GET(
                     comnHeader->comn_status)
              << std::endl;
    std::cout << prefix << "[2-3] Opaque data: " << (void *)resp->opaque_data
              << std::endl;
}
