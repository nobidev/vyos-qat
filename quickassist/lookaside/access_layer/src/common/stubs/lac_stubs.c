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

/**
 *****************************************************************************
 *
 * @file lac_stubs.c
 *
 * @defgroup kernel stubs
 *
 * All PKE and KPT API won't be supported in kernel API
 *
 *****************************************************************************/

/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/

/* API Includes */
#include "cpa.h"
#include "cpa_cy_dh.h"
#include "cpa_cy_dsa.h"
#include "cpa_cy_ecdh.h"
#include "cpa_cy_ecdsa.h"
#include "cpa_cy_kpt.h"
#include "cpa_cy_ec.h"
#include "cpa_cy_prime.h"
#include "cpa_cy_rsa.h"
#include "cpa_cy_ln.h"
#include "cpa_dc_chain.h"
#include "icp_accel_devices.h"

/* Diffie Hellman */
CpaStatus cpaCyDhKeyGenPhase1(
    const CpaInstanceHandle instanceHandle,
    const CpaCyGenFlatBufCbFunc pDhPhase1Cb,
    void *pCallbackTag,
    const CpaCyDhPhase1KeyGenOpData *pPhase1KeyGenData,
    CpaFlatBuffer *pLocalOctetStringPV)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyDhKeyGenPhase2Secret(
    const CpaInstanceHandle instanceHandle,
    const CpaCyGenFlatBufCbFunc pDhPhase2Cb,
    void *pCallbackTag,
    const CpaCyDhPhase2SecretKeyGenOpData *pPhase2SecretKeyGenData,
    CpaFlatBuffer *pOctetStringSecretKey)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus CPA_DEPRECATED
cpaCyDhQueryStats(const CpaInstanceHandle instanceHandle,
                  struct _CpaCyDhStats *pDhStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyDhQueryStats64(const CpaInstanceHandle instanceHandle,
                              CpaCyDhStats64 *pDhStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

/* DSA */
CpaStatus cpaCyDsaGenPParam(const CpaInstanceHandle instanceHandle,
                            const CpaCyDsaGenCbFunc pCb,
                            void *pCallbackTag,
                            const CpaCyDsaPParamGenOpData *pOpData,
                            CpaBoolean *pProtocolStatus,
                            CpaFlatBuffer *pP)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyDsaGenGParam(const CpaInstanceHandle instanceHandle,
                            const CpaCyDsaGenCbFunc pCb,
                            void *pCallbackTag,
                            const CpaCyDsaGParamGenOpData *pOpData,
                            CpaBoolean *pProtocolStatus,
                            CpaFlatBuffer *pG)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyDsaGenYParam(const CpaInstanceHandle instanceHandle,
                            const CpaCyDsaGenCbFunc pCb,
                            void *pCallbackTag,
                            const CpaCyDsaYParamGenOpData *pOpData,
                            CpaBoolean *pProtocolStatus,
                            CpaFlatBuffer *pY)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyDsaSignR(const CpaInstanceHandle instanceHandle,
                        const CpaCyDsaGenCbFunc pCb,
                        void *pCallbackTag,
                        const CpaCyDsaRSignOpData *pOpData,
                        CpaBoolean *pProtocolStatus,
                        CpaFlatBuffer *pR)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyDsaSignS(const CpaInstanceHandle instanceHandle,
                        const CpaCyDsaGenCbFunc pCb,
                        void *pCallbackTag,
                        const CpaCyDsaSSignOpData *pOpData,
                        CpaBoolean *pProtocolStatus,
                        CpaFlatBuffer *pS)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyDsaSignRS(const CpaInstanceHandle instanceHandle,
                         const CpaCyDsaRSSignCbFunc pCb,
                         void *pCallbackTag,
                         const CpaCyDsaRSSignOpData *pOpData,
                         CpaBoolean *pProtocolStatus,
                         CpaFlatBuffer *pR,
                         CpaFlatBuffer *pS)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyDsaVerify(const CpaInstanceHandle instanceHandle,
                         const CpaCyDsaVerifyCbFunc pCb,
                         void *pCallbackTag,
                         const CpaCyDsaVerifyOpData *pOpData,
                         CpaBoolean *pVerifyStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus CPA_DEPRECATED
cpaCyDsaQueryStats(const CpaInstanceHandle instanceHandle,
                   struct _CpaCyDsaStats *pDsaStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyDsaQueryStats64(const CpaInstanceHandle instanceHandle,
                               CpaCyDsaStats64 *pDsaStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

/* ECDH */
CpaStatus cpaCyEcdhPointMultiply(const CpaInstanceHandle instanceHandle,
                                 const CpaCyEcdhPointMultiplyCbFunc pCb,
                                 void *pCallbackTag,
                                 const CpaCyEcdhPointMultiplyOpData *pOpData,
                                 CpaBoolean *pMultiplyStatus,
                                 CpaFlatBuffer *pXk,
                                 CpaFlatBuffer *pYk)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyEcdhQueryStats64(const CpaInstanceHandle instanceHandle,
                                CpaCyEcdhStats64 *pEcdhStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

/* ECDSA */
CpaStatus cpaCyEcdsaSignR(const CpaInstanceHandle instanceHandle,
                          const CpaCyEcdsaGenSignCbFunc pCb,
                          void *pCallbackTag,
                          const CpaCyEcdsaSignROpData *pOpData,
                          CpaBoolean *pSignStatus,
                          CpaFlatBuffer *pR)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyEcdsaSignS(const CpaInstanceHandle instanceHandle,
                          const CpaCyEcdsaGenSignCbFunc pCb,
                          void *pCallbackTag,
                          const CpaCyEcdsaSignSOpData *pOpData,
                          CpaBoolean *pSignStatus,
                          CpaFlatBuffer *pS)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyEcdsaSignRS(const CpaInstanceHandle instanceHandle,
                           const CpaCyEcdsaSignRSCbFunc pCb,
                           void *pCallbackTag,
                           const CpaCyEcdsaSignRSOpData *pOpData,
                           CpaBoolean *pSignStatus,
                           CpaFlatBuffer *pR,
                           CpaFlatBuffer *pS)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyEcdsaVerify(const CpaInstanceHandle instanceHandle,
                           const CpaCyEcdsaVerifyCbFunc pCb,
                           void *pCallbackTag,
                           const CpaCyEcdsaVerifyOpData *pOpData,
                           CpaBoolean *pVerifyStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyEcdsaQueryStats64(const CpaInstanceHandle instanceHandle,
                                 CpaCyEcdsaStats64 *pEcdsaStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

/* EC */
CpaStatus cpaCyEcPointMultiply(const CpaInstanceHandle instanceHandle,
                               const CpaCyEcPointMultiplyCbFunc pCb,
                               void *pCallbackTag,
                               const CpaCyEcPointMultiplyOpData *pOpData,
                               CpaBoolean *pMultiplyStatus,
                               CpaFlatBuffer *pXk,
                               CpaFlatBuffer *pYk)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyEcPointVerify(const CpaInstanceHandle instanceHandle,
                             const CpaCyEcPointVerifyCbFunc pCb,
                             void *pCallbackTag,
                             const CpaCyEcPointVerifyOpData *pOpData,
                             CpaBoolean *pVerifyStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyEcQueryStats64(const CpaInstanceHandle instanceHandle,
                              CpaCyEcStats64 *pEcStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyEcMontEdwdsPointMultiply(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointMultiplyCbFunc pCb,
    void *pCallbackTag,
    const CpaCyEcMontEdwdsPointMultiplyOpData *pOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pXk,
    CpaFlatBuffer *pYk)
{
    return CPA_STATUS_UNSUPPORTED;
}

/* Prime */
CpaStatus cpaCyPrimeTest(const CpaInstanceHandle instanceHandle,
                         const CpaCyPrimeTestCbFunc pCb,
                         void *pCallbackTag,
                         const CpaCyPrimeTestOpData *pOpData,
                         CpaBoolean *pTestPassed)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus CPA_DEPRECATED
cpaCyPrimeQueryStats(const CpaInstanceHandle instanceHandle,
                     struct _CpaCyPrimeStats *pPrimeStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyPrimeQueryStats64(const CpaInstanceHandle instanceHandle,
                                 CpaCyPrimeStats64 *pPrimeStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

/* RSA */
CpaStatus cpaCyRsaGenKey(const CpaInstanceHandle instanceHandle,
                         const CpaCyRsaKeyGenCbFunc pRsaKeyGenCb,
                         void *pCallbackTag,
                         const CpaCyRsaKeyGenOpData *pKeyGenOpData,
                         CpaCyRsaPrivateKey *pPrivateKey,
                         CpaCyRsaPublicKey *pPublicKey)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyRsaEncrypt(const CpaInstanceHandle instanceHandle,
                          const CpaCyGenFlatBufCbFunc pRsaEncryptCb,
                          void *pCallbackTag,
                          const CpaCyRsaEncryptOpData *pEncryptOpData,
                          CpaFlatBuffer *pOutputData)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyRsaDecrypt(const CpaInstanceHandle instanceHandle,
                          const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                          void *pCallbackTag,
                          const CpaCyRsaDecryptOpData *pDecryptOpData,
                          CpaFlatBuffer *pOutputData)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus CPA_DEPRECATED
cpaCyRsaQueryStats(const CpaInstanceHandle instanceHandle,
                   struct _CpaCyRsaStats *pRsaStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyRsaQueryStats64(const CpaInstanceHandle instanceHandle,
                               CpaCyRsaStats64 *pRsaStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

/* Large Number */
CpaStatus cpaCyLnModExp(const CpaInstanceHandle instanceHandle,
                        const CpaCyGenFlatBufCbFunc pLnModExpCb,
                        void *pCallbackTag,
                        const CpaCyLnModExpOpData *pLnModExpOpData,
                        CpaFlatBuffer *pResult)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyLnModInv(const CpaInstanceHandle instanceHandle,
                        const CpaCyGenFlatBufCbFunc pLnModInvCb,
                        void *pCallbackTag,
                        const CpaCyLnModInvOpData *pLnModInvOpData,
                        CpaFlatBuffer *pResult)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus CPA_DEPRECATED
cpaCyLnStatsQuery(const CpaInstanceHandle instanceHandle,
                  struct _CpaCyLnStats *pLnStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyLnStatsQuery64(const CpaInstanceHandle instanceHandle,
                              CpaCyLnStats64 *pLnStats)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaDcChainGetSessionSize(CpaInstanceHandle dcInstance,
                                   CpaDcChainOperations operation,
                                   Cpa8U numSessions,
                                   CpaDcChainSessionSetupData *pSessionData,
                                   Cpa32U *pSessionSize)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaDcChainInitSession(CpaInstanceHandle dcInstance,
                                CpaDcSessionHandle pSessionHandle,
                                CpaDcChainOperations operation,
                                Cpa8U numSessions,
                                CpaDcChainSessionSetupData *pSessionData,
                                CpaDcCallbackFn callbackFn)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaDcChainRemoveSession(const CpaInstanceHandle dcInstance,
                                  CpaDcSessionHandle pSessionHandle)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaDcChainResetSession(const CpaInstanceHandle dcInstance,
                                 CpaDcSessionHandle pSessionHandle)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaDcChainPerformOp(CpaInstanceHandle dcInstance,
                              CpaDcSessionHandle pSessionHandle,
                              CpaBufferList *pSrcBuff,
                              CpaBufferList *pDestBuff,
                              CpaDcChainOperations operation,
                              Cpa8U numOpDatas,
                              CpaDcChainOpData *pChainOpData,
                              CpaDcChainRqResults *pResults,
                              void *callbackTag)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyKptLoadKey(CpaInstanceHandle instanceHandle,
                CpaCyKptLoadKey *pSWK,
                CpaCyKptHandle *keyHandle,
                CpaCyKptKeyManagementStatus *pKptStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyKptQueryIssuingKeys(const CpaInstanceHandle instanceHandle_in,
                                   CpaFlatBuffer *pPublicX509IssueCert,
                                   CpaCyKptKeyManagementStatus *pKptStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyKptDeleteKey(CpaInstanceHandle instanceHandle,
                            CpaCyKptHandle keyHandle,
                            CpaCyKptKeyManagementStatus *pKptStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyKptRsaDecrypt(const CpaInstanceHandle instanceHandle,
                             const CpaCyGenFlatBufCbFunc pRsaDecryptCb,
                             void *pCallbackTag,
                             const CpaCyKptRsaDecryptOpData *pDecryptOpData,
                             CpaFlatBuffer *pOutputData,
                             CpaCyKptUnwrapContext *pKptUnwrapContext)

{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyEcGenericPointVerify(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointVerifyCbFunc pCb,
    void *pCallbackTag,
    const CpaCyEcGenericPointVerifyOpData *pOpData,
    CpaBoolean *pVerifyStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyEcGenericPointMultiply(
    const CpaInstanceHandle instanceHandle,
    const CpaCyEcPointMultiplyCbFunc pCb,
    void *pCallbackTag,
    const CpaCyEcGenericPointMultiplyOpData *pOpData,
    CpaBoolean *pMultiplyStatus,
    CpaFlatBuffer *pXk,
    CpaFlatBuffer *pYk)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyKptEcdsaSignRS(const CpaInstanceHandle instanceHandle,
                              const CpaCyEcdsaSignRSCbFunc pCb,
                              void *pCallbackTag,
                              const CpaCyKptEcdsaSignRSOpData *pOpData,
                              CpaBoolean *pSignStatus,
                              CpaFlatBuffer *pR,
                              CpaFlatBuffer *pS,
                              CpaCyKptUnwrapContext *pKptUnwrapContext)
{
    return CPA_STATUS_UNSUPPORTED;
}

CpaStatus cpaCyKptQueryDeviceCredentials(
    const CpaInstanceHandle instanceHandle,
    CpaCyKptValidationKey *pDevCredential,
    CpaCyKptKeyManagementStatus *pKptStatus)
{
    return CPA_STATUS_UNSUPPORTED;
}
