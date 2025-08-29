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
 * @file icp_sal_du.h
 *
 * @description
 *        This file includes device utilization APIs. It contains function
 *        prototypes for managing QAT device utilization on Intel(R)
 *        QuickAssist Technology.
 *
 ****************************************************************************/
#ifndef ICP_SAL_DU_H
#define ICP_SAL_DU_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 ******************************************************************
 * @ingroup SalUserDu
 *        Start the device utilization measurement
 *
 * @description
 *        This function is used to start the device utilization measurement
 *
 * @param[in]  pPf    Pointer to BDF address of physical function on which
 *                    to start the device utilization measurement
 *
 * @retval CPA_STATUS_SUCCESS         Operation successful
 * @retval CPA_STATUS_FAIL            Operation failed
 * @retval CPA_STATUS_INVALID_PARAM   Invalid/null arguments
 *
 ******************************************************************
 */
CpaStatus icp_sal_userDuStart(struct adf_pci_address *pPf);

/*
 ******************************************************************
 * @ingroup SalUserDu
 *        Stop the device utilization measurement
 *
 * @description
 *        This function is used to stop the device utilization measurement.
 *        Should typically be called some time(eg., 5-10 seconds)
 *        after starting device utilization measurement
 *
 * @param[in]  pPf    Pointer to BDF address of physical function on which
 *                    to stop the device utilization measurement
 *
 * @retval CPA_STATUS_SUCCESS         Operation successful
 * @retval CPA_STATUS_FAIL            Operation failed
 * @retval CPA_STATUS_INVALID_PARAM   Invalid/null arguments
 *
 ******************************************************************
 */
CpaStatus icp_sal_userDuStop(struct adf_pci_address *pPf);

/*
 ******************************************************************
 * @ingroup SalUserDu
 *        Query and get the overall device utilization for a
 *        specified service type
 *
 * @description
 *        This function is used to get the device utilization for
 *        a specified PF and service type, in SLA units.
 *        This data is reported based on the most recently completed
 *        iteration of device utilization, ie., between the last
 *        start and stop. If stop has never been called, the function
 *        will return CPA_STATUS_FAIL.
 *
 * @param[in]  pPf                 Pointer to BDF address of physical function
 * @param[in]  svcType             Svc service type - sym, asym or dc
 * @param[out] pCapacityInSlaUnit  Pointer to total capacity in sla units
 * @param[out] pUtilInSlaUnit      Pointer to utilization in sla units
 * @param[out] pUtilInPct          Pointer to utilization in percentage
 *
 * @retval CPA_STATUS_SUCCESS         Operation successful
 * @retval CPA_STATUS_FAIL            Operation failed
 * @retval CPA_STATUS_INVALID_PARAM   Invalid/null arguments
 *
 ******************************************************************
 */
CpaStatus icp_sal_userDuQuery(struct adf_pci_address *pPf,
                              enum adf_svc_type svcType,
                              Cpa32U *pCapacityInSlaUnit,
                              Cpa32U *pUtilInSlaUnit,
                              Cpa16U *pUtilInPct);

/*
 ******************************************************************
 * @ingroup SalUserDu
 *        Query and get the overall device utilization for a
 *        specified service type for virtual function
 *
 * @description
 *        This function is used to get the device utilization for
 *        a specified VF and service type, in SLA units.
 *        This data is reported based on the most recently completed
 *        iteration of device utilization, ie., between the last
 *        start and stop. If stop has never been called, the function
 *        will return CPA_STATUS_FAIL.
 *
 * @param[in]  pPf                  Pointer to BDF address of physical function
 * @param[in]  pVf                  Pointer to BDF address of virtual function
 * @param[in]  svcType              Svc service type - sym, asym or dc
 * @param[out] pSlaInSlaUnit   Pointer to total capacity in sla units
 * @param[out] pUtilInSlaUnit       Pointer to utilization in sla units
 * @param[out] pUtilInPct           Pointer to utilization in percentage
 *
 * @retval CPA_STATUS_SUCCESS         Operation successful
 * @retval CPA_STATUS_FAIL            Operation failed
 * @retval CPA_STATUS_INVALID_PARAM   Invalid/null arguments
 *
 ******************************************************************
 */
CpaStatus icp_sal_userDuQueryVf(struct adf_pci_address *pPf,
                                struct adf_pci_address *pVf,
                                enum adf_svc_type svcType,
                                Cpa32U *pSlaInSlaUnit,
                                Cpa32U *pUtilInSlaUnit,
                                Cpa16U *pUtilInPct);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif
