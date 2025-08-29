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
 * @file qat_dbg_apicalls.cpp
 *
 * @description
 *        This file provides implementation of QAT API calls
 *        parsers utility.
 *
 ****************************************************************************/
/* System headers */
#include <string>
#include <iostream>

/* Headers to parse opData for API calls */
#include "qat_dbg_apicalls.h"
#include "qat_dbg_utils.h"
#include "cpa.h"
#include "cpa_cy_sym.h"
#include "cpa_cy_sym_dp.h"
#include "cpa_cy_rsa.h"
#include "cpa_cy_prime.h"
#include "cpa_cy_key.h"
#include "cpa_cy_ecdsa.h"
#include "cpa_cy_ecdh.h"
#include "cpa_cy_ec.h"
#include "cpa_cy_ecsm2.h"
#include "cpa_cy_ln.h"
#include "cpa_cy_dsa.h"
#include "cpa_cy_dh.h"
#include "cpa_dc.h"
#include "cpa_dc_dp.h"
#include "cpa_dc_chain.h"
#include "cpa_dc_bp.h"

/*
*******************************************************************************
* Private definitions
*******************************************************************************
*/
#define QAT_DBG_PRINT_API_TYPE(apiType)                                        \
    std::cout << "\t\tOPData API call:: " #apiType << std::endl
#define QAT_DBG_PRINT_FLAT_BUFFER(opData, buffer)                              \
    do                                                                         \
    {                                                                          \
        std::cout << "\t\tCpaFlatBuffer::" #buffer << std::endl;               \
        std::cout << "\t\t\tdataLenInBytes : "                                 \
                  << (opData)->buffer.dataLenInBytes << std::endl;             \
        std::cout << "\t\t\tpData : " << std::hex                              \
                  << (void *)((opData)->buffer.pData) << std::dec              \
                  << std::endl;                                                \
    } while (0)
#define QAT_DBG_CASE_API(apiType)                                              \
    case apiType:                                                              \
        QAT_DBG_PRINT_API_TYPE(apiType)
/*
*******************************************************************************
* Private functions
*******************************************************************************
*/
static void qatDbgHandleCpaCySymOpData(icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCySymOpData *opData =
        (CpaCySymOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    std::cout << "\t\tCpaCySymSessionCtx::sessionCtx : " << opData->sessionCtx
              << std::endl;
    std::cout << "\t\tCpaCySymPacketType::packetType : " << opData->packetType
              << std::endl;
    std::cout << "\t\tCpa8U *::pIv : " << static_cast<void *>(opData->pIv)
              << std::endl;
    std::cout << "\t\tCpa32U::ivLenInBytes : " << opData->ivLenInBytes
              << std::endl;
    std::cout << "\t\tCpa32U::cryptoStartSrcOffsetInBytes : "
              << opData->cryptoStartSrcOffsetInBytes << std::endl;
    std::cout << "\t\tCpa32U::messageLenToCipherInBytes : "
              << opData->messageLenToCipherInBytes << std::endl;
    std::cout << "\t\tCpa32U::hashStartSrcOffsetInBytes : "
              << opData->hashStartSrcOffsetInBytes << std::endl;
    std::cout << "\t\tCpa32U::messageLenToHashInBytes : "
              << opData->messageLenToHashInBytes << std::endl;
    std::cout << "\t\tCpa8U *::pDigestResult : "
              << static_cast<void *>(opData->pDigestResult) << std::endl;
    std::cout << "\t\tCpa8U *::pAdditionalAuthData : "
              << static_cast<void *>(opData->pAdditionalAuthData) << std::endl;
}

static void qatDbgHandleCpaCySymDpOpData(icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCySymDpOpData *opData =
        (CpaCySymDpOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    std::cout << "\t\tCpa64U::reserved0 : " << opData->reserved0 << std::endl;
    std::cout << "\t\tCpa32U::cryptoStartSrcOffsetInBytes : "
              << opData->cryptoStartSrcOffsetInBytes << std::endl;
    std::cout << "\t\tCpa32U::messageLenToCipherInBytes : "
              << opData->messageLenToCipherInBytes << std::endl;
    std::cout << "\t\tCpaPhysicalAddr::iv : " << std::hex
              << (void *)(opData->iv) << std::dec << std::endl;
    std::cout << "\t\tCpa64U::reserved1 : " << opData->reserved1 << std::endl;
    std::cout << "\t\tCpa32U::hashStartSrcOffsetInBytes : "
              << opData->hashStartSrcOffsetInBytes << std::endl;
    std::cout << "\t\tCpa32U::messageLenToHashInBytes : "
              << opData->messageLenToHashInBytes << std::endl;
    std::cout << "\t\tCpaPhysicalAddr::additionalAuthData : " << std::hex
              << (void *)(opData->additionalAuthData) << std::dec << std::endl;
    std::cout << "\t\tCpaPhysicalAddr::digestResult : " << std::hex
              << (void *)(opData->digestResult) << std::dec << std::endl;
    std::cout << "\t\tCpaInstanceHandle::instanceHandle : "
              << opData->instanceHandle << std::endl;
    std::cout << "\t\tCpaCySymDpSessionCtx::sessionCtx : " << opData->sessionCtx
              << std::endl;
    std::cout << "\t\tCpa32U::ivLenInBytes : " << opData->ivLenInBytes
              << std::endl;
    std::cout << "\t\tCpaPhysicalAddr::srcBuffer : " << std::hex
              << (void *)(opData->srcBuffer) << std::dec << std::endl;
    std::cout << "\t\tCpa32U::srcBufferLen : " << opData->srcBufferLen
              << std::endl;
    std::cout << "\t\tCpaPhysicalAddr::dstBuffer : " << std::hex
              << (void *)(opData->dstBuffer) << std::dec << std::endl;
    std::cout << "\t\tCpa32U::dstBufferLen : " << opData->dstBufferLen
              << std::endl;
    std::cout << "\t\tCpaPhysicalAddr::thisPhys : " << std::hex
              << (void *)(opData->thisPhys) << std::dec << std::endl;
    std::cout << "\t\tCpa8U *::pIv : " << static_cast<void *>(opData->pIv)
              << std::endl;
    std::cout << "\t\tCpa8U *::pAdditionalAuthData : "
              << static_cast<void *>(opData->pAdditionalAuthData) << std::endl;
    std::cout << "\t\tvoid *::pCallbackTag : "
              << static_cast<void *>(opData->pCallbackTag) << std::endl;
}

static void qatDbgHandleCpaCyRsaKeyGenOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyRsaKeyGenOpData *opData =
        (CpaCyRsaKeyGenOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, prime1P);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, prime2Q);
    std::cout << "\t\tCpa32U::modulusLenInBytes : " << opData->modulusLenInBytes
              << std::endl;
    std::cout << "\t\tCpaCyRsaVersion::version : " << opData->version
              << std::endl;
    std::cout << "\t\tCpaCyRsaPrivateKeyRepType::privateKeyRepType : "
              << opData->privateKeyRepType << std::endl;
    QAT_DBG_PRINT_FLAT_BUFFER(opData, publicExponentE);
}

static void qatDbgHandleCpaCyRsaEncryptOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyRsaEncryptOpData *opData =
        (CpaCyRsaEncryptOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    std::cout << "\t\tCpaCyRsaPublicKey *::pPublicKey : "
              << static_cast<void *>(opData->pPublicKey) << std::endl;
    QAT_DBG_PRINT_FLAT_BUFFER(opData, inputData);
}

static void qatDbgHandleCpaCyRsaDecryptOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyRsaDecryptOpData *opData =
        (CpaCyRsaDecryptOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    std::cout << "\t\tCpaCyRsaPrivateKey *::pRecipientPrivateKey : "
              << static_cast<void *>(opData->pRecipientPrivateKey) << std::endl;
    QAT_DBG_PRINT_FLAT_BUFFER(opData, inputData);
}

static void qatDbgHandleCpaCyPrimeTestOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyPrimeTestOpData *opData =
        (CpaCyPrimeTestOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, primeCandidate);
    std::cout << "\t\tCpaBoolean::performGcdTest : " << opData->performGcdTest
              << std::endl;
    std::cout << "\t\tCpaBoolean::performFermatTest : "
              << opData->performFermatTest << std::endl;
    std::cout << "\t\tCpa32U::numMillerRabinRounds : "
              << opData->numMillerRabinRounds << std::endl;
    QAT_DBG_PRINT_FLAT_BUFFER(opData, millerRabinRandomInput);
    std::cout << "\t\tCpaBoolean::performLucasTest : "
              << opData->performLucasTest << std::endl;
}

static void qatDbgHandleCpaCyKeyGenSslOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyKeyGenSslOpData *opData =
        (CpaCyKeyGenSslOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    std::cout << "\t\tCpaCyKeySslOp::sslOp : " << opData->sslOp << std::endl;
    QAT_DBG_PRINT_FLAT_BUFFER(opData, secret);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, seed);
    std::cout << "\t\tCpa32U::generatedKeyLenInBytes : "
              << opData->generatedKeyLenInBytes << std::endl;
    QAT_DBG_PRINT_FLAT_BUFFER(opData, userLabel);
}

static void qatDbgHandleCpaCyKeyGenTlsOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyKeyGenTlsOpData *opData =
        (CpaCyKeyGenTlsOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    std::cout << "\t\tCpaCyKeyTlsOp::tlsOp : " << opData->tlsOp << std::endl;
    QAT_DBG_PRINT_FLAT_BUFFER(opData, secret);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, seed);
    std::cout << "\t\tCpa32U::generatedKeyLenInBytes : "
              << opData->generatedKeyLenInBytes << std::endl;
    QAT_DBG_PRINT_FLAT_BUFFER(opData, userLabel);
}

static void qatDbgHandleCpaCyKeyGenHKDFOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyKeyGenHKDFOpData *opData =
        (CpaCyKeyGenHKDFOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    std::string prefix("\t\t");

    std::cout << "\t\tCpaCyKeyHKDFOp::hkdfKeyOp : " << (int)opData->hkdfKeyOp
              << std::endl;
    std::cout << "\t\tCpa8U::secretLen : " << (int)opData->secretLen
              << std::endl;
    std::cout << "\t\tCpa8U::infoLen : " << (int)opData->infoLen << std::endl;
    std::cout << "\t\tCpa8U::seedLen : " << (int)opData->seedLen << std::endl;
    std::cout << "\t\tCpa8U::numLabels : " << (int)opData->numLabels
              << std::endl;

    if ((int)opData->secretLen)
    {
        std::cout << "\t\tCpa8U::secret (" << (int)opData->secretLen << ")"
                  << std::endl;
        qatDbgHexDump(
            prefix + "\t", opData->secret, CPA_CY_HKDF_KEY_MAX_SECRET_SZ);
    }
    if ((int)opData->seedLen)
    {
        std::cout << "\t\tCpa8U::seed (" << (int)opData->secretLen << ")"
                  << std::endl;
        qatDbgHexDump(prefix + "\t", opData->seed, CPA_CY_HKDF_KEY_MAX_HMAC_SZ);
    }
    if ((int)opData->infoLen)
    {
        std::cout << "\t\tCpa8U::info (" << (int)opData->infoLen << ")"
                  << std::endl;
        qatDbgHexDump(prefix + "\t", opData->info, CPA_CY_HKDF_KEY_MAX_INFO_SZ);
    }
    if ((int)opData->numLabels)
    {
        size_t i = 0;

        for (i = 0; i < (int)opData->numLabels; i++)
        {
            CpaCyKeyGenHKDFExpandLabel *label = &opData->label[i];

            std::cout << "\tCpaCyKeyGenHKDFExpandLabel::label[" << i
                      << "] LabelLen: " << (int)label->labelLen << std::endl;
            qatDbgHexDump(
                prefix + "\t", label->label, CPA_CY_HKDF_KEY_MAX_LABEL_SZ);
            std::cout << "\tCpaCyKeyGenHKDFExpandLabel::sublabelFlag : 0x"
                      << std::hex << (int)label->sublabelFlag << std::dec
                      << std::endl;
        }
    }
}

static void qatDbgHandleCpaCyKeyGenMgfOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyKeyGenMgfOpData *opData =
        (CpaCyKeyGenMgfOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, seedBuffer);
    std::cout << "\t\tCpa32U::maskLenInBytes : " << opData->maskLenInBytes
              << std::endl;
}

static void qatDbgHandleCpaCyKeyGenMgfOpDataExt(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyKeyGenMgfOpDataExt *opData =
        (CpaCyKeyGenMgfOpDataExt *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, baseOpData.seedBuffer);
    std::cout << "\t\tCpaCySymHashAlgorithm::hashAlgorithm : "
              << (int)opData->hashAlgorithm << std::endl;
}

static void qatDbgHandleCpaCyEcdsaSignROpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcdsaSignROpData *opData =
        (CpaCyEcdsaSignROpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, xg);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, yg);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, n);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, q);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, a);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, b);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, k);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcdsaSignSOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcdsaSignSOpData *opData =
        (CpaCyEcdsaSignSOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, m);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, d);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, r);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, k);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, n);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcdsaSignRSOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcdsaSignRSOpData *opData =
        (CpaCyEcdsaSignRSOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, xg);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, yg);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, n);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, q);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, a);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, b);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, k);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, m);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, d);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcdsaVerifyOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcdsaVerifyOpData *opData =
        (CpaCyEcdsaVerifyOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, xg);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, yg);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, n);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, q);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, a);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, b);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, m);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, r);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, s);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, xp);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, yp);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcdhPointMultiplyOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcdhPointMultiplyOpData *opData =
        (CpaCyEcdhPointMultiplyOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, k);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, xg);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, yg);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, a);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, b);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, q);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, h);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
    std::cout << "\t\tCpaBoolean::pointVerify : " << opData->pointVerify
              << std::endl;
}

static void qatDbgHandleCpaCyEcPointMultiplyOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcPointMultiplyOpData *opData =
        (CpaCyEcPointMultiplyOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, k);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, xg);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, yg);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, a);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, b);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, q);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, h);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcPointVerifyOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcPointVerifyOpData *opData =
        (CpaCyEcPointVerifyOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, xq);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, yq);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, q);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, a);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, b);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcMontEdwdsPointMultiplyOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcMontEdwdsPointMultiplyOpData *opData =
        (CpaCyEcMontEdwdsPointMultiplyOpData *)QAT_DBG_GET_MSG_CONTENT(
            msgHeader);

    std::cout << "\t\tCpaCyEcMontEdwdsCurveType::curveType : "
              << opData->curveType << std::endl;
    std::cout << "\t\tCpaBoolean::generator : " << opData->generator
              << std::endl;
    QAT_DBG_PRINT_FLAT_BUFFER(opData, k);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, x);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, y);
}

static void qatDbgHandleCpaCyEcsm2PointMultiplyOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcsm2PointMultiplyOpData *opData =
        (CpaCyEcsm2PointMultiplyOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, k);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, x);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, y);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcsm2GeneratorMultiplyOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcsm2GeneratorMultiplyOpData *opData =
        (CpaCyEcsm2GeneratorMultiplyOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, k);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcsm2PointVerifyOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcsm2PointVerifyOpData *opData =
        (CpaCyEcsm2PointVerifyOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, x);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, y);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcsm2SignOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcsm2SignOpData *opData =
        (CpaCyEcsm2SignOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, k);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, e);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, d);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcsm2VerifyOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcsm2VerifyOpData *opData =
        (CpaCyEcsm2VerifyOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, e);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, r);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, s);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, xP);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, yP);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcsm2EncryptOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcsm2EncryptOpData *opData =
        (CpaCyEcsm2EncryptOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, k);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, xP);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, yP);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcsm2DecryptOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcsm2DecryptOpData *opData =
        (CpaCyEcsm2DecryptOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, d);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, x1);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, y1);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcsm2KeyExPhase1OpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcsm2KeyExPhase1OpData *opData =
        (CpaCyEcsm2KeyExPhase1OpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, r);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandleCpaCyEcsm2KeyExPhase2OpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyEcsm2KeyExPhase2OpData *opData =
        (CpaCyEcsm2KeyExPhase2OpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, r);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, d);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, x1);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, x2);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, y2);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, xP);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, yP);
    std::cout << "\t\tCpaCyEcFieldType::fieldType : " << opData->fieldType
              << std::endl;
}

static void qatDbgHandlecpaCyLnModExpOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyLnModExpOpData *opData =
        (CpaCyLnModExpOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, modulus);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, base);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, exponent);
}

static void qatDbgHandlecpaCyLnModInvOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyLnModInvOpData *opData =
        (CpaCyLnModInvOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, A);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, B);
}

static void qatDbgHandleCpaCyDsaPParamGenOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyDsaPParamGenOpData *opData =
        (CpaCyDsaPParamGenOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, X);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, Q);
}

static void qatDbgHandleCpaCyDsaGParamGenOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyDsaGParamGenOpData *opData =
        (CpaCyDsaGParamGenOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, P);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, Q);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, H);
}

static void qatDbgHandleCpaCyDsaYParamGenOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyDsaYParamGenOpData *opData =
        (CpaCyDsaYParamGenOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, P);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, G);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, X);
}

static void qatDbgHandleCpaCyDsaRSignOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyDsaRSignOpData *opData =
        (CpaCyDsaRSignOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, P);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, Q);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, G);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, K);
}

static void qatDbgHandleCpaCyDsaSSignOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyDsaSSignOpData *opData =
        (CpaCyDsaSSignOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, Q);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, X);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, K);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, R);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, Z);
}

static void qatDbgHandleCpaCyDsaRSSignOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyDsaRSSignOpData *opData =
        (CpaCyDsaRSSignOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, P);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, Q);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, G);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, X);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, K);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, Z);
}

static void qatDbgHandleCpaCyDsaVerifyOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyDsaVerifyOpData *opData =
        (CpaCyDsaVerifyOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, P);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, Q);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, G);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, Y);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, Z);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, R);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, S);
}

static void qatDbgHandleCpaCyDhPhase1KeyGenOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyDhPhase1KeyGenOpData *opData =
        (CpaCyDhPhase1KeyGenOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, primeP);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, baseG);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, privateValueX);
}

static void qatDbgHandleCpaCyDhPhase2SecretKeyGenOpData(
    icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaCyDhPhase2SecretKeyGenOpData *opData =
        (CpaCyDhPhase2SecretKeyGenOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    QAT_DBG_PRINT_FLAT_BUFFER(opData, primeP);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, remoteOctetStringPV);
    QAT_DBG_PRINT_FLAT_BUFFER(opData, privateValueX);
}

static void qatDbgPrintCpaDcOpData(CpaDcOpData *opData, size_t indentLevel = 2)
{
    std::string prefix;
    std::string prefixSub;

    qatDbgGetIndent(prefix, indentLevel);
    qatDbgGetIndent(prefixSub, indentLevel + 1);

    std::cout << prefix << "CpaDcFlush::flushFlag : " << opData->flushFlag
              << std::endl;
    std::cout << prefix
              << "CpaBoolean::compressAndVerify : " << opData->compressAndVerify
              << std::endl;
    std::cout << prefix << "CpaBoolean::compressAndVerifyAndRecover : "
              << opData->compressAndVerifyAndRecover << std::endl;
    std::cout << prefix
              << "CpaBoolean::integrityCrcCheck : " << opData->integrityCrcCheck
              << std::endl;
    std::cout << prefix << "CpaBoolean::verifyHwIntegrityCrcs : "
              << opData->verifyHwIntegrityCrcs << std::endl;
    std::cout << prefix << "CpaDcSkipData::inputSkipData " << std::endl;
    std::cout << prefixSub
              << "CpaDcSkipMode::skipMode : " << opData->inputSkipData.skipMode
              << std::endl;
    std::cout << prefixSub
              << "Cpa32U::skipLength : " << opData->inputSkipData.skipLength
              << std::endl;
    std::cout << prefixSub
              << "Cpa32U::strideLength : " << opData->inputSkipData.strideLength
              << std::endl;
    std::cout << prefixSub << "Cpa32U::firstSkipOffset : "
              << opData->inputSkipData.firstSkipOffset << std::endl;
    std::cout << prefix << "CpaDcSkipData::outputSkipData " << std::endl;
    std::cout << prefixSub
              << "CpaDcSkipMode::skipMode : " << opData->outputSkipData.skipMode
              << std::endl;
    std::cout << prefixSub
              << "Cpa32U::skipLength : " << opData->outputSkipData.skipLength
              << std::endl;
    std::cout << prefixSub << "Cpa32U::strideLength : "
              << opData->outputSkipData.strideLength << std::endl;
    std::cout << prefixSub << "Cpa32U::firstSkipOffset : "
              << opData->outputSkipData.firstSkipOffset << std::endl;
    std::cout << prefix << "CpaCrcData*::pCrcData : "
              << static_cast<void *>(opData->pCrcData) << std::endl;
}

static void qatDbgHandleCpaDcOpData(icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaDcOpData *opData = (CpaDcOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    qatDbgPrintCpaDcOpData(opData);
}

static void qatDbgHandleCpaDcBatchOpData(icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaDcBatchOpData *opData =
        (CpaDcBatchOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    std::cout << "\t\tCpaDcOpData::opData : " << std::endl;
    qatDbgPrintCpaDcOpData(&opData->opData, 3);
    std::cout << "\t\tCpaBufferList::pSrcBuff : "
              << static_cast<void *>(opData->pSrcBuff) << std::endl;
    std::cout << "\t\tCpaBoolean::resetSessionState : "
              << opData->resetSessionState << std::endl;
}

static void qatDbgHandleCpaDcChainOpData(icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaDcChainOpData *opData =
        (CpaDcChainOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    CpaDcOpData *dcOpData = opData->pDcOp;

    std::cout << "\t\tCpaDcChainSessionType::opType : " << opData->opType
              << std::endl;
    std::cout << "\t\tCpaDcFlush::flushFlag : " << dcOpData->flushFlag
              << std::endl;
    std::cout << "\t\tCpaBoolean::compressAndVerify : "
              << dcOpData->compressAndVerify << std::endl;
    std::cout << "\t\tCpaBoolean::compressAndVerifyAndRecover : "
              << dcOpData->compressAndVerifyAndRecover << std::endl;
    std::cout << "\t\tCpaDcSkipData::inputSkipData " << std::endl;
    std::cout << "\t\t\tCpaDcSkipMode::skipMode : "
              << dcOpData->inputSkipData.skipMode << std::endl;
    std::cout << "\t\t\tCpa32U::skipLength : "
              << dcOpData->inputSkipData.skipLength << std::endl;
    std::cout << "\t\t\tCpa32U::strideLength : "
              << dcOpData->inputSkipData.strideLength << std::endl;
    std::cout << "\t\t\tCpa32U::firstSkipOffset : "
              << dcOpData->inputSkipData.firstSkipOffset << std::endl;
    std::cout << "\t\tCpaDcSkipData::outputSkipData " << std::endl;
    std::cout << "\t\t\tCpaDcSkipMode::skipMode : "
              << dcOpData->outputSkipData.skipMode << std::endl;
    std::cout << "\t\t\tCpa32U::skipLength : "
              << dcOpData->outputSkipData.skipLength << std::endl;
    std::cout << "\t\t\tCpa32U::strideLength : "
              << dcOpData->outputSkipData.strideLength << std::endl;
    std::cout << "\t\t\tCpa32U::firstSkipOffset : "
              << dcOpData->outputSkipData.firstSkipOffset << std::endl;
}

static void qatDbgHandleCpaDcDpOpData(icp_adf_dbg_entry_header_t *msgHeader)
{
    CpaDcDpOpData *opData = (CpaDcDpOpData *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    std::cout << "\t\tCpa64U::reserved0 : " << opData->reserved0 << std::endl;
    std::cout << "\t\tCpa32U::bufferLenToCompress : "
              << opData->bufferLenToCompress << std::endl;
    std::cout << "\t\tCpa32U::bufferLenForData : " << opData->bufferLenForData
              << std::endl;
    std::cout << "\t\tCpa64U::reserved1 : " << opData->reserved1 << std::endl;
    std::cout << "\t\tCpa64U::reserved2 : " << opData->reserved2 << std::endl;
    std::cout << "\t\tCpa64U::reserved3 : " << opData->reserved3 << std::endl;
    std::cout << "\t\tCpaDcRqResults::results " << std::endl;
    std::cout << "\t\t\tCpaDcReqStatus::status : " << opData->results.status
              << std::endl;
    std::cout << "\t\t\tCpa32U::produced : " << opData->results.produced
              << std::endl;
    std::cout << "\t\t\tCpa32U::consumed : " << opData->results.consumed
              << std::endl;
    std::cout << "\t\t\tCpaBoolean::endOfLastBlock : "
              << opData->results.endOfLastBlock << std::endl;
    std::cout << "\t\tCpaInstanceHandle::dcInstance : " << opData->dcInstance
              << std::endl;
    std::cout << "\t\tCpaDcSessionHandle::pSessionHandle : "
              << opData->pSessionHandle << std::endl;
    std::cout << "\t\tCpaPhysicalAddr::srcBuffer : " << std::hex
              << (void *)(opData->srcBuffer) << std::dec << std::endl;
    std::cout << "\t\tCpa32U::srcBufferLen : " << opData->srcBufferLen
              << std::endl;
    std::cout << "\t\tCpaPhysicalAddr::destBuffer : " << std::hex
              << (void *)(opData->destBuffer) << std::dec << std::endl;
    std::cout << "\t\tCpa32U::destBufferLen : " << opData->destBufferLen
              << std::endl;
    std::cout << "\t\tCpaDcSessionDir::sessDirection : "
              << opData->sessDirection << std::endl;
    std::cout << "\t\tCpaBoolean::compressAndVerify : "
              << opData->compressAndVerify << std::endl;
    std::cout << "\t\tCpaBoolean::compressAndVerifyAndRecover : "
              << opData->compressAndVerifyAndRecover << std::endl;
    std::cout << "\t\tCpaStatus::responseStatus : " << opData->responseStatus
              << std::endl;
    std::cout << "\t\tCpaPhysicalAddr::thisPhys : " << std::hex
              << (void *)(opData->thisPhys) << std::dec << std::endl;
    std::cout << "\t\tvoid *::pCallbackTag : "
              << static_cast<void *>(opData->pCallbackTag) << std::endl;
}

static void qatDbgHandleDpdkApiCall(icp_adf_dbg_entry_header_t *msgHeader)
{
    uint8_t *msg = NULL;
    uint8_t *miscPtr = NULL;
    size_t miscOffset = 0;
    std::string prefix("\t\t");

    if (msgHeader->msg_len)
    {
        msg = QAT_DBG_GET_MSG_CONTENT(msgHeader);
    }

    if (msgHeader->misc_len)
    {
        miscOffset = sizeof(icp_adf_dbg_entry_header_t) + msgHeader->msg_len +
                     msgHeader->src_sgl_len + msgHeader->dst_sgl_len;
        miscPtr = ((uint8_t *)msgHeader + miscOffset);
    }

    if (msgHeader->api_type == QATD_DPDK_SYM)
    {
        std::cout << prefix << "OPData API call:: QATD_DPDK_SYM" << std::endl;
        std::cout << prefix << "\trte_crypto_op:" << std::endl;
        qatDbgHexDump(prefix + "\t", msg, msgHeader->msg_len);
        if (miscPtr)
        {
            std::cout << prefix << "\tqat_sym_session:" << std::endl;
            qatDbgHexDump(prefix + "\t", miscPtr, msgHeader->misc_len);
        }
    }
    else if (msgHeader->api_type == QATD_DPDK_ASYM)
    {
        std::cout << prefix << "OPData API call:: QATD_DPDK_ASYM" << std::endl;
        std::cout << prefix << "\trte_crypto_op:" << std::endl;
        qatDbgHexDump(prefix + "\t", msg, msgHeader->msg_len);
        if (miscPtr)
        {
            std::cout << prefix << "\tqat_asym_session:" << std::endl;
            qatDbgHexDump(prefix + "\t", miscPtr, msgHeader->misc_len);
        }
    }
    else if (msgHeader->api_type == QATD_DPDK_COMP)
    {
        std::cout << prefix << "OPData API call:: QATD_DPDK_COMP" << std::endl;
        std::cout << prefix << "\trte_comp_op:" << std::endl;
        qatDbgHexDump(prefix + "\t", msg, msgHeader->msg_len);
        if (miscPtr)
        {
            std::cout << prefix << "\tqat_comp_xform:" << std::endl;
            qatDbgHexDump(prefix + "\t", miscPtr, msgHeader->misc_len);
        }
    }
}

static void qatDbgPrintApiCallHeader(icp_adf_dbg_entry_header_t *msgHeader)
{
    Cpa16U bank = msgHeader->bank;
    Cpa16U ring = msgHeader->ring;
    std::string prefix("\t");

    std::cout << prefix << "Entry [API_CALL]: Time-stamp: "
              << qatDbgFormatTimestamp(msgHeader->ts) << std::endl;
    std::cout << prefix << "Bank: " << bank << " Ring: " << ring
              << " PID: " << msgHeader->pid << std::endl;
}

/*
*******************************************************************************
* Public functions
*******************************************************************************
*/
void qatDbgHandleApiCall(icp_adf_dbg_entry_header_t *msgHeader)
{
    qatDbgPrintApiCallHeader(msgHeader);

    switch (msgHeader->api_type)
    {
        QAT_DBG_CASE_API(QATD_CPACYSYMOPDATA);
        qatDbgHandleCpaCySymOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYSYMDPOPDATA);
        qatDbgHandleCpaCySymDpOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYRSAKEYGENOPDATA);
        qatDbgHandleCpaCyRsaKeyGenOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYRSAENCRYPTOPDATA);
        qatDbgHandleCpaCyRsaEncryptOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYRSADECRYPTOPDATA);
        qatDbgHandleCpaCyRsaDecryptOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYPRIMETESTOPDATA);
        qatDbgHandleCpaCyPrimeTestOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYKEYGENSSLOPDATA);
        qatDbgHandleCpaCyKeyGenSslOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYKEYGENTLSOPDATA);
        qatDbgHandleCpaCyKeyGenTlsOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYKEYGENHKDFOPDATA);
        qatDbgHandleCpaCyKeyGenHKDFOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYKEYGENMGFOPDATA);
        qatDbgHandleCpaCyKeyGenMgfOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYKEYGENMGFOPDATAEXT);
        qatDbgHandleCpaCyKeyGenMgfOpDataExt(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECDSASIGNROPDATA);
        qatDbgHandleCpaCyEcdsaSignROpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECDSASIGNSOPDATA);
        qatDbgHandleCpaCyEcdsaSignSOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECDSASIGNRSOPDATA);
        qatDbgHandleCpaCyEcdsaSignRSOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECDSAVERIFYOPDATA);
        qatDbgHandleCpaCyEcdsaVerifyOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECDHPOINTMULTIPLYOPDATA);
        qatDbgHandleCpaCyEcdhPointMultiplyOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECPOINTMULTIPLYOPDATA);
        qatDbgHandleCpaCyEcPointMultiplyOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECPOINTVERIFYOPDATA);
        qatDbgHandleCpaCyEcPointVerifyOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECMONTEDWDSPOINTMULTIPLYOPDATA);
        qatDbgHandleCpaCyEcMontEdwdsPointMultiplyOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECSM2POINTMULTIPLYOPDATA);
        qatDbgHandleCpaCyEcsm2PointMultiplyOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECSM2GENERATORMULTIPLYOPDATA);
        qatDbgHandleCpaCyEcsm2GeneratorMultiplyOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECSM2POINTVERIFYOPDATA);
        qatDbgHandleCpaCyEcsm2PointVerifyOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECSM2SIGNOPDATA);
        qatDbgHandleCpaCyEcsm2SignOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECSM2VERIFYOPDATA);
        qatDbgHandleCpaCyEcsm2VerifyOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECSM2ENCRYPTOPDATA);
        qatDbgHandleCpaCyEcsm2EncryptOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECSM2DECRYPTOPDATA);
        qatDbgHandleCpaCyEcsm2DecryptOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECSM2KEYEXPHASE1OPDATA);
        qatDbgHandleCpaCyEcsm2KeyExPhase1OpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYECSM2KEYEXPHASE2OPDATA);
        qatDbgHandleCpaCyEcsm2KeyExPhase2OpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYLNMODEXPOPDATA);
        qatDbgHandlecpaCyLnModExpOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYLNMODINVOPDATA);
        qatDbgHandlecpaCyLnModInvOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYDSAPPARAMGENOPDATA);
        qatDbgHandleCpaCyDsaPParamGenOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYDSAGPARAMGENOPDATA);
        qatDbgHandleCpaCyDsaGParamGenOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYDSAYPARAMGENOPDATA);
        qatDbgHandleCpaCyDsaYParamGenOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYDSARSIGNOPDATA);
        qatDbgHandleCpaCyDsaRSignOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYDSASSIGNOPDATA);
        qatDbgHandleCpaCyDsaSSignOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYDSARSSIGNOPDATA);
        qatDbgHandleCpaCyDsaRSSignOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYDSAVERIFYOPDATA);
        qatDbgHandleCpaCyDsaVerifyOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYDHPHASE1KEYGENOPDATA);
        qatDbgHandleCpaCyDhPhase1KeyGenOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPACYDHPHASE2SECRETKEYGENOPDATA);
        qatDbgHandleCpaCyDhPhase2SecretKeyGenOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPADCOPDATA);
        qatDbgHandleCpaDcOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPADCBATCHOPDATA);
        qatDbgHandleCpaDcBatchOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPADCCHAINOPDATA);
        qatDbgHandleCpaDcChainOpData(msgHeader);
        break;
        QAT_DBG_CASE_API(QATD_CPADCDPOPDATA);
        qatDbgHandleCpaDcDpOpData(msgHeader);
        break;
        case QATD_DPDK_ASYM:
        case QATD_DPDK_SYM:
        case QATD_DPDK_COMP:
            qatDbgHandleDpdkApiCall(msgHeader);
            break;
        default:
            std::cout << "\t\tERROR: Unknown OPData type" << std::endl;
            break;
    }
}
