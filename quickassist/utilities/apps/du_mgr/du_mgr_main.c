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
/*
 * This example shows how to use the driver ioctl interface for managing
 * the device-utilization feature
 *
 */
/*
*******************************************************************************
* Include public/global header files
*******************************************************************************
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/
#include "rl_utils.h"
#include "icp_sal_du.h"
#include "adf_du_user.h"

/* Argument related macros */
#define DU_MGR_MIN_USER_ARGS 3
#define DU_MGR_MAX_USER_ARGS 5
#define DU_MGR_ARGS_CMD 1
#define DU_MGR_ARGS_PCI_ADDR 2
#define DU_MGR_ARGS_PCI_ADDR_VF 3
#define DU_MGR_ARGS_SVC_TYPE 3
#define DU_MGR_ARGS_SVC_TYPE_VF 4
#define DU_MGR_ARGS_CNT_START 3
#define DU_MGR_ARGS_CNT_STOP 3
#define DU_MGR_ARGS_CNT_QUERY 4
#define DU_MGR_ARGS_CNT_QUERY_VF 5

/* DU commands */
static const char *pDuCommands[] = {"start",
                                    "stop",
                                    "query",
                                    "query_vf",
                                    "unknown"};

/* Enumeration for DU commands */
typedef enum du_mgr_cmd_s
{
    DU_MGR_CMD_START = 0,
    DU_MGR_CMD_STOP,
    DU_MGR_CMD_QUERY,
    DU_MGR_CMD_QUERY_VF,
    DU_MGR_CMD_UNKNOWN
} du_mgr_cmd_t;

/* Number of arguments for each commands*/
static int numOfArgCnt[] = {DU_MGR_ARGS_CNT_START,
                            DU_MGR_ARGS_CNT_STOP,
                            DU_MGR_ARGS_CNT_QUERY,
                            DU_MGR_ARGS_CNT_QUERY_VF};

/*
 ******************************************************************
 * @ingroup du
 *        Display command line argument help string.
 *
 * @description
 *        This function is used display the command line argument
 *        help string.
 *
 * @retval None
 *
 ******************************************************************
 */
static void duMgrPrintHelp(const Cpa8U *pExe)
{
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "\nDevice utilization tool to measure the utilization of ");
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "cryptographic\nservices on given physical or virtual function.\n");
    osalLog(OSAL_LOG_LVL_USER, OSAL_LOG_DEV_STDOUT, "\nUsage:\n");
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "\tStart or stop device measurement - ");
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "%s ( start | stop ) <pf_addr>\n",
            pExe);
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "\tQuery utilization for physical function - ");
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "%s query <pf_addr> <service>\n",
            pExe);
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "\tQuery utilization for virtual function - ");
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "%s query_vf <pf_addr> <vf_addr> <service>\n",
            pExe);
    osalLog(OSAL_LOG_LVL_USER, OSAL_LOG_DEV_STDOUT, "\nOptions:\n");
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "\tpf_addr     Physical address in domain_nr(optional):bus:device.function");
    osalLog(OSAL_LOG_LVL_USER, OSAL_LOG_DEV_STDOUT, "(xxxx:xx:xx.x) format\n");
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "\tvf_addr     Virtual address in domain_nr(optional):bus:device.function");
    osalLog(OSAL_LOG_LVL_USER, OSAL_LOG_DEV_STDOUT, "(xxxx:xx:xx.x) format\n");
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "\tservice     Asym(=0) or Sym(=1) cryptographic services\n");
    osalLog(OSAL_LOG_LVL_USER,
            OSAL_LOG_DEV_STDOUT,
            "\t            DC(=2) compression service\n");
}

/*
 ******************************************************************
 * @ingroup du
 *        Convert string to command type
 *
 * @description
 *        This function is to convert string to command type.
 *
 * @param[in]  pString     pointer to string
 *
 * @retval du_mgr_cmd_t        enum type of the command.
 *
 ******************************************************************
 */
static du_mgr_cmd_t duMgrStrToCmdType(Cpa8U *pString)
{
    int i;
    size_t stringLen = strnlen((const char *)pString, RL_MAX_CMD_STR_CHAR);

    for (i = DU_MGR_CMD_START; i < DU_MGR_CMD_UNKNOWN; i++)
    {
        if (stringLen != strnlen(pDuCommands[i], RL_MAX_CMD_STR_CHAR))
            continue;
        if (!strncmp((const char *)pString, pDuCommands[i], stringLen))
            return i;
    }
    return DU_MGR_CMD_UNKNOWN;
}

/*
 ******************************************************************
 * @ingroup du
 *        Parses input parameters for DU commands
 *
 * @description
 *        This function parses, validates and populates input parameters
 *        for all DU commands
 *
 * @param[in]   argc     number of arguments passed
 * @param[in]   argv     array of character pointers listing all the
 *                       arguments
 * @param[out]  du       pointer to struct adf_user_du
 * @param[out]  cmd      pointer to enum du_mgr_cmd_s
 *
 * @retval  CPA_STATUS_SUCCESS  Input parameters parsed and fetched successfully
 * @retval  CPA_STATUS_FAIL     Input parameters validation failed
 *
 ******************************************************************
 */
static CpaStatus duMgrParseInputParams(int argc,
                                       char **argv,
                                       struct adf_user_du *du,
                                       du_mgr_cmd_t *cmd)
{
    if (argc < DU_MGR_MIN_USER_ARGS || argc > DU_MGR_MAX_USER_ARGS)
    {
        return CPA_STATUS_FAIL;
    }

    /* validate PF pci address */
    if (rlStrToPciAddr(&du->pf_addr, (Cpa8U *)argv[DU_MGR_ARGS_PCI_ADDR]))
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDERR,
                "Incorrect pci address format");
        return CPA_STATUS_FAIL;
    }

    *cmd = duMgrStrToCmdType((Cpa8U *)argv[DU_MGR_ARGS_CMD]);
    if (DU_MGR_CMD_UNKNOWN == *cmd)
    {
        osalLog(OSAL_LOG_LVL_ERROR, OSAL_LOG_DEV_STDERR, "Invalid DU command");
        return CPA_STATUS_FAIL;
    }

    /* validate the number of arguments for the given command type */
    if (argc != numOfArgCnt[*cmd])
    {
        osalLog(OSAL_LOG_LVL_ERROR,
                OSAL_LOG_DEV_STDERR,
                "Invalid number of arguments\n");
        return CPA_STATUS_FAIL;
    }

    switch (*cmd)
    {
        case DU_MGR_CMD_START:
        case DU_MGR_CMD_STOP:
            /* do nothing */
            break;
        case DU_MGR_CMD_QUERY:
            /* validate svc type */
            if (CPA_STATUS_SUCCESS !=
                rlStrToSvc(&du->svc_type, (Cpa8U *)argv[DU_MGR_ARGS_SVC_TYPE]))
            {
                osalLog(OSAL_LOG_LVL_ERROR,
                        OSAL_LOG_DEV_STDERR,
                        "Missing/incorrect pf svc type");
                return CPA_STATUS_FAIL;
            }
            osalLog(OSAL_LOG_LVL_USER,
                    OSAL_LOG_DEV_STDOUT,
                    "[DevUtil]: Device:%.4x:%.2x:%.2x.%x\n",
                    du->pf_addr.domain_nr,
                    du->pf_addr.bus,
                    du->pf_addr.dev,
                    du->pf_addr.func);
            osalLog(OSAL_LOG_LVL_USER,
                    OSAL_LOG_DEV_STDOUT,
                    "[DevUtil]: Operation: %s\n",
                    argv[DU_MGR_ARGS_CMD]);
            break;
        case DU_MGR_CMD_QUERY_VF:
        {
            /* validate svc type and VF pci */
            if (CPA_STATUS_SUCCESS !=
                rlStrToSvc(&du->svc_type,
                           (Cpa8U *)argv[DU_MGR_ARGS_SVC_TYPE_VF]))
            {
                osalLog(OSAL_LOG_LVL_ERROR,
                        OSAL_LOG_DEV_STDERR,
                        "Missing/incorrect vf svc type");
                return CPA_STATUS_FAIL;
            }

            if (CPA_STATUS_SUCCESS !=
                rlStrToPciAddr(&du->vf_addr,
                               (Cpa8U *)argv[DU_MGR_ARGS_PCI_ADDR_VF]))
            {
                osalLog(OSAL_LOG_LVL_ERROR,
                        OSAL_LOG_DEV_STDERR,
                        "Incorrect vf pci address format");
                return CPA_STATUS_FAIL;
            }
            osalLog(OSAL_LOG_LVL_USER,
                    OSAL_LOG_DEV_STDOUT,
                    "[DevUtil]: Device:%.4x:%.2x:%.2x.%x\n",
                    du->vf_addr.domain_nr,
                    du->vf_addr.bus,
                    du->vf_addr.dev,
                    du->vf_addr.func);
            osalLog(OSAL_LOG_LVL_USER,
                    OSAL_LOG_DEV_STDOUT,
                    "[DevUtil]: Operation: %s\n",
                    argv[DU_MGR_ARGS_CMD]);
            break;
        }
        default:
        {
            return CPA_STATUS_FAIL;
        }
    }

    return CPA_STATUS_SUCCESS;
}

/*
 ******************************************************************
 * @ingroup du
 *        Execute DU command
 *
 * @description
 *        This function executes DU command
 *
 * @param[out]  du    pointer to struct adf_du
 * @param[out]  cmd   DU command type
 *
 * @retval  CPA_STATUS_SUCCESS    DU command executed successfully
 * @retval  CPA_STATUS_FAIL       Failed to execute DU command
 *
 ******************************************************************
 */
static CpaStatus duMgrRunDUCommand(struct adf_user_du *du, du_mgr_cmd_t cmd)
{
    switch (cmd)
    {
        case DU_MGR_CMD_START:
            if (CPA_STATUS_SUCCESS != icp_sal_userDuStart(&du->pf_addr))
            {
                osalLog(OSAL_LOG_LVL_ERROR,
                        OSAL_LOG_DEV_STDERR,
                        "Failed to start device utilization");
                return CPA_STATUS_FAIL;
            }
            break;
        case DU_MGR_CMD_STOP:
            if (CPA_STATUS_SUCCESS != icp_sal_userDuStop(&du->pf_addr))
            {
                osalLog(OSAL_LOG_LVL_ERROR,
                        OSAL_LOG_DEV_STDERR,
                        "Failed to stop device utilization");
                return CPA_STATUS_FAIL;
            }
            break;
        case DU_MGR_CMD_QUERY:
        {
            if (CPA_STATUS_SUCCESS !=
                icp_sal_userDuQuery(&du->pf_addr,
                                    du->svc_type,
                                    &du->slau_supported,
                                    &du->slau_utilized,
                                    &du->slau_util_percent))
            {
                osalLog(OSAL_LOG_LVL_ERROR,
                        OSAL_LOG_DEV_STDERR,
                        "Device query failed for pf");
                return CPA_STATUS_FAIL;
            }
            osalLog(OSAL_LOG_LVL_USER,
                    OSAL_LOG_DEV_STDOUT,
                    "[DevUtil]: SLA Total = %d, SLA Used = %d, "
                    "Utilization = %d%%\n",
                    du->slau_supported,
                    du->slau_utilized,
                    du->slau_util_percent);
            break;
        }
        case DU_MGR_CMD_QUERY_VF:
        {
            if (CPA_STATUS_SUCCESS !=
                icp_sal_userDuQueryVf(&du->pf_addr,
                                      &du->vf_addr,
                                      du->svc_type,
                                      &du->slau_supported,
                                      &du->slau_utilized,
                                      &du->slau_util_percent))
            {
                osalLog(OSAL_LOG_LVL_ERROR,
                        OSAL_LOG_DEV_STDERR,
                        "Device query failed for vf");
                return CPA_STATUS_FAIL;
            }
            osalLog(OSAL_LOG_LVL_USER,
                    OSAL_LOG_DEV_STDOUT,
                    "[DevUtil]: SLA Set = %d, SLA Used = %d, "
                    "Utilization = %d%%\n",
                    du->slau_supported,
                    du->slau_utilized,
                    du->slau_util_percent);
            break;
        }
        default:
            break;
    }

    return CPA_STATUS_SUCCESS;
}

/*
 ******************************************************************
 * @ingroup du
 *        Main function to execute the device utilization application
 *
 * @description
 *        This function is used to parse command line arguments
 *        and execute the commands on the given PF/VF device.
 *
 * @param[in]  argc  number of arguments passed
 * @param[in]  argv  array of character pointers listing all the
 *                   arguments
 *
 * @retval  0    Operation successful
 * @retval -1    Operation failed
 *
 ******************************************************************
 */
int main(int argc, char **argv)
{
    struct adf_user_du user_du = {{0, 0, 0, 0}, {0, 0, 0, 0}, ADF_SVC_NONE, 0, 0};
    du_mgr_cmd_t cmd = DU_MGR_CMD_UNKNOWN;

    if (CPA_STATUS_SUCCESS != duMgrParseInputParams(argc, argv, &user_du, &cmd))
    {
        duMgrPrintHelp((const Cpa8U *)argv[0]);
        return -1;
    }

    if (CPA_STATUS_SUCCESS != duMgrRunDUCommand(&user_du, cmd))
        return -1;

    return 0;
}
