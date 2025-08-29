/***************************************************************************
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
 *  version: QAT.L.4.24.0-00005
 *
 ****************************************************************************/
/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/
#include "cpa.h"
#include "adf_kernel_types.h"
#include "icp_platform.h"
#include "adf_cfg_common.h"
#include "adf_du_user.h"
#include "icp_accel_devices.h"

static void du_user_copy(struct adf_pci_address *pTo,
                         struct adf_pci_address *pFrom)
{
    ICP_CHECK_FOR_NULL_PARAM_VOID(pTo);
    ICP_CHECK_FOR_NULL_PARAM_VOID(pFrom);

    pTo->domain_nr = pFrom->domain_nr;
    pTo->bus = pFrom->bus;
    pTo->dev = pFrom->dev;
    pTo->func = pFrom->func;
}

/*
 ******************************************************************
 * @ingroup du
 *        Execute I/O Ctl command
 *
 * @description
 *        This function is to execute the I/O ctl command.
 *
 * @param[in]      cmd       command to be executed
 * @param[in/out]  pArgs     pointer to the user argument structure
 *
 * @retval CPA_STATUS_SUCCESS    Operation successful
 * @retval CPA_STATUS_FAIL       Operation failed
 *
 ******************************************************************
 */
static CpaStatus du_user_ioctl(unsigned int cmd, void *pArgs)
{
    int fd;
    CpaStatus status = CPA_STATUS_SUCCESS;

    ICP_CHECK_FOR_NULL_PARAM(pArgs);

    fd = open(ADF_CTL_DEVICE_NAME, O_RDONLY);
    if (fd < 0)
    {
        ADF_ERROR("Failed to open device file %s\n", ADF_CTL_DEVICE_NAME);
        return CPA_STATUS_FAIL;
    }

    if (ioctl(fd, cmd, pArgs))
    {
        ADF_ERROR("Failed to execute ioctl command\n");
        status = CPA_STATUS_FAIL;
    }

    close(fd);
    return status;
}

CpaStatus icp_adf_userDuStart(struct adf_pci_address *pPf)
{
    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(pPf, CPA_STATUS_INVALID_PARAM);

    if (CPA_STATUS_SUCCESS != du_user_ioctl(IOCTL_DU_START, pPf))
    {
        ADF_ERROR("Failed to start device utilization\n");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus icp_adf_userDuStop(struct adf_pci_address *pPf)
{
    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(pPf, CPA_STATUS_INVALID_PARAM);

    if (CPA_STATUS_SUCCESS != du_user_ioctl(IOCTL_DU_STOP, pPf))
    {
        ADF_ERROR("Failed to stop device utilization\n");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus icp_adf_userDuQuery(struct adf_pci_address *pPf,
                              enum adf_svc_type svcType,
                              Cpa32U *pCapacityInSlaUnit,
                              Cpa32U *pUtilInSlaUnit,
                              Cpa16U *pUtilInPct)
{
    struct adf_user_du du;

    ICP_CHECK_FOR_NULL_PARAM(pPf);
    ICP_CHECK_FOR_NULL_PARAM(pCapacityInSlaUnit);
    ICP_CHECK_FOR_NULL_PARAM(pUtilInSlaUnit);
    ICP_CHECK_FOR_NULL_PARAM(pUtilInPct);

    du_user_copy(&du.pf_addr, pPf);
    du.svc_type = svcType;
    if (CPA_STATUS_SUCCESS != du_user_ioctl(IOCTL_DU_QUERY, &du))
    {
        ADF_ERROR("Failed to send device utilization query\n");
        return CPA_STATUS_FAIL;
    }

    *pCapacityInSlaUnit = du.slau_supported;
    *pUtilInSlaUnit = du.slau_utilized;

    *pUtilInPct = du.slau_util_percent;

    return CPA_STATUS_SUCCESS;
}

CpaStatus icp_adf_userDuQueryVf(struct adf_pci_address *pPf,
                                struct adf_pci_address *pVf,
                                enum adf_svc_type svcType,
                                Cpa32U *pSlaInSlaUnit,
                                Cpa32U *pUtilInSlaUnit,
                                Cpa16U *pUtilInPct)
{
    struct adf_user_du du;

    ICP_CHECK_FOR_NULL_PARAM(pPf);
    ICP_CHECK_FOR_NULL_PARAM(pVf);
    ICP_CHECK_FOR_NULL_PARAM(pSlaInSlaUnit);
    ICP_CHECK_FOR_NULL_PARAM(pUtilInSlaUnit);
    ICP_CHECK_FOR_NULL_PARAM(pUtilInPct);

    du_user_copy(&du.pf_addr, pPf);
    du_user_copy(&du.vf_addr, pVf);
    du.svc_type = svcType;
    if (CPA_STATUS_SUCCESS != du_user_ioctl(IOCTL_DU_QUERY_VF, &du))
    {
        ADF_ERROR("Failed to send device utilization query for VF\n");
        return CPA_STATUS_FAIL;
    }

    *pSlaInSlaUnit = du.slau_supported;
    *pUtilInSlaUnit = du.slau_utilized;

    *pUtilInPct = du.slau_util_percent;

    return CPA_STATUS_SUCCESS;
}
