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
 ***************************************************************************/
/****************************************************************************
 * @file qat_dbg_report.cpp
 *
 * @description
 *        This file provides QAT Debuggability report tool.
 *
 ****************************************************************************/
/* System headers */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

/* STL headers */
#include <iostream>
#include <iterator>
#include <map>

/* Project headers */
#include "adf_kernel_types.h"
#include "qat_dbg_user.h"
#include "qat_dbg_fwcalls.h"
#include "qat_dbg_fwaudit.h"
#include "qat_dbg_apicalls.h"
#include "qat_dbg_utils.h"
#include "Osal.h"

/* FW headers */
#include "icp_qat_fw.h"
#include "icp_qat_fw_la.h"
#include "icp_qat_fw_pke.h"
#include "icp_qat_fw_comp.h"
#include "icp_buffer_desc.h"

/*
*******************************************************************************
* Private definitions
*******************************************************************************
*/
#define STRLEN_CONST(str) (sizeof(str) - 1)
#define QAT_DBG_ENTRY_LOOKUP_LIMIT (1024)
#define QAT_DBG_RING_PREFIX "dbg_ring"
#define QAT_DBG_CRASH_DIR_PREFIX "qat_crash_dev_"
#define QAT_DBG_CONT_SYNC_FILE_PREFIX "data_inst_"
#define QAT_DBG_H_BAR                                                          \
    "========================================================================" \
    "==\n\n"
#define QAT_DBG_PROGRESS_BAR                                                   \
    "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
#define QAT_DBG_PROGRESS_BAR_WIDTH (60)
#define QAT_DBG_MAX_SCAN_LEN 1023
#define QAT_DBG_SCAN_STR2(x) #x
#define QAT_DBG_SCAN_STR(x) QAT_DBG_SCAN_STR2(x)
#define QAT_DBG_PCI_ADDR_FORMAT "%04x_%02x_%02x_%x"
#define QAT_DBG_PCI_ADDR_PARTS_NUM (4)

/*
*******************************************************************************
* Arguments related private definitions
*******************************************************************************
*/
#define QAT_DBG_OPT_MAX_NUM (5)
#define QAT_DBG_OPT_MAX_LEN (QAT_DBG_MAX_SCAN_LEN + 1)
#define QAT_DBG_CMD_MAX_LEN (32)
#define QAT_DBG_COMMAND_OPT_ARRAY_POS (0)
#define QAT_DBG_PATH_OPT_ARRAY_POS (1)
#define QAT_DBG_DEV_OPT_ARRAY_POS (2)
#define QAT_DBG_LAST_OPT_ARRAY_POS (3)
#define QAT_DBG_BDF_OPT_ARRAY_POS (4)
#define QAT_DBG_COMMAND_OPT_STR "command"
#define QAT_DBG_PATH_OPT_STR "path"
#define QAT_DBG_DEV_OPT_STR "dev"
#define QAT_DBG_LAST_OPT_STR "last"
#define QAT_DBG_BDF_OPT_STR "bdf"
#define QAT_DBG_COMMAND_OPT_DEF_VAL ""
#define QAT_DBG_PATH_OPT_DEF_VAL ""
#define QAT_DBG_DEV_OPT_DEF_VAL "-1"
#define QAT_DBG_LAST_OPT_DEF_VAL "-1"
#define QAT_DBG_BDF_OPT_DEF_VAL ""

/*
*******************************************************************************
* QAT debug report tool commands
*******************************************************************************
*/
#define QAT_DBG_CMD_DUMP "dump"
#define QAT_DBG_CMD_LIST "list"
#define QAT_DBG_CMD_AUDIT_PHY_ADDR "audit_phy_addresses"
#define QAT_DBG_AUDIT_RESP_RC "audit_ret_codes"
#define QAT_DBG_AUDIT_REQ_LENGTH "audit_fields_lengths"

/*
*******************************************************************************
* Private typedefs
*******************************************************************************
*/
typedef struct qatd_ring_desc qat_dbg_buffer_desc_t;
typedef struct qatd_ioctl_req qat_dbg_ioctl_req_t;
typedef unsigned long long int ull;
typedef std::multimap<ull, icp_adf_dbg_entry_header_t *>::iterator mmap_iter_t;
typedef std::multimap<ull, icp_adf_dbg_entry_header_t *>::reverse_iterator
    mmap_reviter_t;

typedef struct qat_dbg_option_s
{
    const char key[QAT_DBG_OPT_MAX_LEN];
    char value[QAT_DBG_OPT_MAX_LEN];
    bool specified;
} qat_dbg_option_t;

typedef struct qatd_ioctl_bsf2id_req qat_dbg_pci_addr_t;

/*
*******************************************************************************
* Global variables used by other files
*******************************************************************************
*/
char gWorkDir[QATD_MAX_FILE_NAME];
int gDevId;
qat_dbg_pci_addr_t gDevPciAddr = {0};
char gProcMmapFilePath[QATD_MAX_FILE_NAME * 2] = {0};

/*
*******************************************************************************
* Private variables
*******************************************************************************
*/
const char *pQatDbgDescriptions[] = {
    "Lists collected entries from directory <path> (optionally limited to the "
    "last several packets restricted by <last> entities).",
    "Physical addresses audit from directory <path>.",
    "Lists all responses with return codes other than 0 with matched request "
    "from directory <path>.",
    "Firmware requests fields lengths audit from directory <path>.",
    "Dumps content of debug buffers for device <dev>|<bdf> to crash "
    "directory."};

static std::multimap<ull, icp_adf_dbg_entry_header_t *> tsEntryMap;
static std::multimap<ull, icp_adf_dbg_entry_header_t *> cookieEntryMap;
static bool useCrashPath;

/*
*******************************************************************************
* Basic printing functions
*******************************************************************************
*/
static void qatDbgPrintHelp()
{
    std::cout << "\nQAT debug utility. Usage:\n";
    std::cout << "\tqat_dbg_report command=<command> [path=<path>] "
                 "[dev=<dev>]|[bdf=<bdf>] [last=<last>]\n";
    std::cout << "\nContinous sync logs analysis requires device to be "
                 "specified by using <dev> or <bdf> option.\n";
    std::cout << "<command> may be one of following:\n";
    std::cout << "\t[" << QAT_DBG_CMD_LIST << "]:\n\t\t"
              << pQatDbgDescriptions[0] << "\n";
    std::cout << "\t[" << QAT_DBG_CMD_AUDIT_PHY_ADDR << "]:\n\t\t"
              << pQatDbgDescriptions[1] << "\n";
    std::cout << "\t[" << QAT_DBG_AUDIT_RESP_RC << "]:\n\t\t"
              << pQatDbgDescriptions[2] << "\n";
    std::cout << "\t[" << QAT_DBG_AUDIT_REQ_LENGTH << "]:\n\t\t"
              << pQatDbgDescriptions[3] << "\n";
    std::cout << "\t[" << QAT_DBG_CMD_DUMP << "]:\n\t\t"
              << pQatDbgDescriptions[4] << "\n"
              << std::endl;
}

static void qatDbgPrintProgress(float percentage)
{
    int val = (int)(percentage * 100);
    int lPad = (int)(percentage * QAT_DBG_PROGRESS_BAR_WIDTH);
    int rPad = QAT_DBG_PROGRESS_BAR_WIDTH - lPad;

    fprintf(
        stderr, "\r%3d%% [%.*s%*s]", val, lPad, QAT_DBG_PROGRESS_BAR, rPad, "");
    fflush(stderr);
}

/*
 ******************************************************************
 * @ingroup qatDbg
 *        Increment and show audit progress
 *
 * @description
 *        This macro increments \p current variable and prints
 *        audit progress based on its value to stdout.
 *
 * @param[in] current  integer variable which represents current
 *                     iteration
 * @param[in] max      integer value which represents maximum
 *                     number of iterations
 *
 * @retval none
 *
 ******************************************************************
 */
#define QAT_DBG_INC_AUDIT_PROGRESS(current, max)                               \
    do                                                                         \
    {                                                                          \
        if (!((current)++ % 100))                                              \
        {                                                                      \
            qatDbgPrintProgress((float)(current) / (float)(max));              \
        }                                                                      \
    } while (0)

static void qatDbgParseAndPrintMsg(icp_adf_dbg_entry_header_t *msgHeader)
{
    switch (msgHeader->msg_type)
    {
        case QATD_MSG_REQUEST:
        case QATD_MSG_REQUEST_DPDK:
            qatDbgHandleFwRequest(msgHeader);
            break;
        case QATD_MSG_RESPONSE:
            qatDbgHandleFwResponse(msgHeader);
            break;
        case QATD_MSG_APICALL:
            qatDbgHandleApiCall(msgHeader);
            break;
        default:
            std::cout << "ERROR: Unknown message." << std::endl;
            break;
    }
}

/*
*******************************************************************************
* Debug entries related routines
*******************************************************************************
*/
static CpaBoolean qatDbgAreEntriesEqual(icp_adf_dbg_entry_header_t *e1,
                                        icp_adf_dbg_entry_header_t *e2)
{
    if (!e1 || !e2)
    {
        return CPA_FALSE;
    }
    if (e1->msg_type != e2->msg_type)
    {
        return CPA_FALSE;
    }
    if (e1->api_type != e2->api_type)
    {
        return CPA_FALSE;
    }
    if (e1->ts != e2->ts)
    {
        return CPA_FALSE;
    }
    if (e1->pid != e2->pid)
    {
        return CPA_FALSE;
    }
    if (e1->content_desc.u.s.cipherAlg != e2->content_desc.u.s.cipherAlg)
    {
        return CPA_FALSE;
    }
    if (e1->content_desc.u.s.cipherMode != e2->content_desc.u.s.cipherMode)
    {
        return CPA_FALSE;
    }
    if (e1->content_desc.u.s.hashAlg != e2->content_desc.u.s.hashAlg)
    {
        return CPA_FALSE;
    }
    if (e1->content_desc.u.s.hashMode != e2->content_desc.u.s.hashMode)
    {
        return CPA_FALSE;
    }
    if (e1->ring != e2->ring)
    {
        return CPA_FALSE;
    }
    if (e1->bank != e2->bank)
    {
        return CPA_FALSE;
    }

    return CPA_TRUE;
}

static CpaBoolean qatDbgIsEntryValid(icp_adf_dbg_entry_header_t *msgHeader)
{
    if (QATD_MSG_PREAMBLE != msgHeader->preamble)
    {
        return CPA_FALSE;
    }
    if (QATD_MSG_APICALL < msgHeader->msg_type)
    {
        return CPA_FALSE;
    }

    return CPA_TRUE;
}

static ull qatDbgGetEntryCookieId(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_comn_req_t *req = NULL;
    icp_qat_fw_comn_resp_t *resp = NULL;

    switch (msgHeader->msg_type)
    {
        case QATD_MSG_REQUEST:
        case QATD_MSG_REQUEST_DPDK:
            req = (icp_qat_fw_comn_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

            return req->comn_mid.opaque_data;
        case QATD_MSG_RESPONSE:
            resp = (icp_qat_fw_comn_resp_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

            return resp->opaque_data;
        case QATD_MSG_APICALL:
            return 0;
        default:
            return 0;
    }
}

/*
*******************************************************************************
* QAT requests common utilities
*******************************************************************************
*/
static Cpa8U qatDbgGetReqType(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_comn_req_t *req =
        (icp_qat_fw_comn_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);

    return req->comn_hdr.service_type;
}

/*
*******************************************************************************
* QAT ring debug related routines
*******************************************************************************
*/
static void qatDbgRecoverEntry(
    icp_adf_dbg_entry_header_t *msgHeader,
    size_t msgSize,
    std::multimap<ull, icp_adf_dbg_entry_header_t *> *entriesTsMap,
    std::multimap<ull, icp_adf_dbg_entry_header_t *> *entriesCookieMap)
{
    std::pair<mmap_iter_t, mmap_iter_t> result;
    mmap_iter_t its;
    int caught = 0;

    /* Check if elements with same ts exists */
    result = entriesTsMap->equal_range((ull)msgHeader->ts);
    for (its = result.first; its != result.second; ++its)
    {
        icp_adf_dbg_entry_header_t *entry = its->second;

        if (qatDbgAreEntriesEqual(msgHeader, entry))
        {
            /* We have same entry already indexed */
            caught++;
            break;
        }
    }
    if (!caught)
    {
        /* Copy msg */
        icp_adf_dbg_entry_header_t *entry =
            (icp_adf_dbg_entry_header_t *)malloc(msgSize);

        osalMemCopy(entry, (void *)msgHeader, msgSize);
        /* Insert message into multimap */
        entriesTsMap->insert(std::pair<ull, icp_adf_dbg_entry_header_t *>(
            (ull)msgHeader->ts, entry));
        entriesCookieMap->insert(std::pair<ull, icp_adf_dbg_entry_header_t *>(
            qatDbgGetEntryCookieId(msgHeader), entry));
    }
}

static void qatDbgRecoverRing(
    qat_dbg_buffer_desc_t *ringDesc,
    std::multimap<ull, icp_adf_dbg_entry_header_t *> *entriesTsMap,
    std::multimap<ull, icp_adf_dbg_entry_header_t *> *entriesCookieMap)
{
    size_t i = 0;
    size_t readOverlaps = 0;
    size_t found = 0;
    size_t loopLimit = 0;
    icp_adf_dbg_entry_header_t *msgHeader = NULL;
    size_t msgSize = 0;
    uint8_t *ptr = NULL;
    uint8_t *startPtr = (uint8_t *)ringDesc;
    uint8_t *startDataPtr = startPtr + sizeof(qat_dbg_buffer_desc_t);
    uint8_t *headPtr = startDataPtr + ringDesc->head;
    uint8_t *tailPtr = startDataPtr + ringDesc->tail;
    uint8_t *endPtr = NULL;

    if (ringDesc->end)
    {
        endPtr = startDataPtr + ringDesc->end;
    }
    else
    {
        endPtr = startPtr + ringDesc->ring_size;
    }

    loopLimit = ringDesc->ring_size / sizeof(icp_adf_dbg_entry_header_t);
    if (ringDesc->tail > 0)
    {
        ptr = startDataPtr;
        for (i = 0; i < loopLimit; i++)
        {
            msgHeader = (icp_adf_dbg_entry_header_t *)ptr;
            msgSize = QAT_DBG_GET_MSG_SIZE(msgHeader);

            if (qatDbgIsEntryValid(msgHeader))
            {
                qatDbgRecoverEntry(
                    msgHeader, msgSize, entriesTsMap, entriesCookieMap);
            }
            else
            {
                break;
            }

            ptr += msgSize;
            if (ptr >= tailPtr)
            {
                break;
            }
        }
    }

    /* Attempt to find first entry behind head */
    ptr = headPtr;
    for (i = 0; i < QAT_DBG_ENTRY_LOOKUP_LIMIT; i++)
    {
        if (ptr >= endPtr)
            break;

        if (qatDbgIsEntryValid((icp_adf_dbg_entry_header_t *)ptr))
        {
            found++;
            break;
        }
        ptr += sizeof(icp_adf_dbg_entry_header_t);
    }
    if (!found)
    {
        return;
    }

    for (i = 0, readOverlaps = 0; i < loopLimit; i++)
    {
        msgHeader = (icp_adf_dbg_entry_header_t *)ptr;
        msgSize = QAT_DBG_GET_MSG_SIZE(msgHeader);
        uint8_t *nextPtr = ptr + msgSize;

        if (nextPtr >= endPtr)
        {
            if (!i)
            {
                break;
            }
            ptr = startDataPtr;
            readOverlaps++;
            continue;
        }
        /* Detect whole loop */
        if (0 < readOverlaps && ptr >= tailPtr)
        {
            break;
        }
        if (QATD_MSG_PREAMBLE != msgHeader->preamble)
        {
            if (1 < readOverlaps)
            {
                break;
            }
            ptr = startDataPtr;
            readOverlaps++;
            continue;
        }

        qatDbgRecoverEntry(msgHeader, msgSize, entriesTsMap, entriesCookieMap);

        if (headPtr > tailPtr && nextPtr >= endPtr)
        {
            break;
        }
        if (tailPtr > headPtr && nextPtr >= tailPtr)
        {
            break;
        }

        ptr = nextPtr;
    }
}

static void qatDbgTraverseRing(
    qat_dbg_buffer_desc_t *ringDesc,
    std::multimap<ull, icp_adf_dbg_entry_header_t *> *entriesTsMap,
    std::multimap<ull, icp_adf_dbg_entry_header_t *> *entriesCookieMap)
{
    size_t i = 0;
    size_t limit = 0;
    size_t readOverlaps = 0;
    uint8_t *startPtr = NULL;
    uint8_t *startDataPtr = NULL;
    uint8_t *headPtr = NULL;
    uint8_t *tailPtr = NULL;
    uint8_t *endPtr = NULL;
    uint8_t *ptr = NULL;

    if (!ringDesc || (!ringDesc->log_entries && !ringDesc->overlaps))
    {
        return;
    }

    startPtr = (uint8_t *)ringDesc;
    startDataPtr = startPtr + sizeof(qat_dbg_buffer_desc_t);
    headPtr = startDataPtr + ringDesc->head;
    tailPtr = startDataPtr + ringDesc->tail;
    if (headPtr == tailPtr)
    {
        qatDbgRecoverRing(ringDesc, entriesTsMap, entriesCookieMap);
        return;
    }

    if (ringDesc->end)
    {
        endPtr = startDataPtr + ringDesc->end;
    }
    else
    {
        endPtr = startPtr + ringDesc->ring_size;
    }

    ptr = tailPtr;
    if (tailPtr >= endPtr)
    {
        ptr = startDataPtr;
    }

    /* Theoretical maximum number messages in ring */
    limit = ringDesc->ring_size / sizeof(icp_adf_dbg_entry_header_t);
    for (i = 0, readOverlaps = 0; i < limit; i++)
    {
        icp_adf_dbg_entry_header_t *msgHeader =
            (icp_adf_dbg_entry_header_t *)ptr;
        size_t msgSize = 0;
        uint8_t *bottomPtr = NULL;
        icp_adf_dbg_entry_header_t *entry = NULL;
        ull cookieId = 0;

        if (!msgHeader)
        {
            break;
        }
        msgSize = QAT_DBG_GET_MSG_SIZE(msgHeader);
        bottomPtr = ptr + msgSize;
        /* OK */
        if (bottomPtr >= endPtr)
        {
            ptr = startDataPtr;
            readOverlaps++;
            continue;
        }
        /* Detect whole loop */
        if (0 < readOverlaps && ptr >= tailPtr)
        {
            break;
        }
        if (QATD_MSG_PREAMBLE != msgHeader->preamble)
        {
            if (1 < readOverlaps)
            {
                break;
            }
            ptr = startDataPtr;
            readOverlaps++;
            continue;
        }

        /* Copy msg */
        entry = (icp_adf_dbg_entry_header_t *)malloc(msgSize);
        osalMemCopy(entry, (void *)msgHeader, msgSize);
        /* Insert message into multimap */
        entriesTsMap->insert(std::pair<ull, icp_adf_dbg_entry_header_t *>(
            (ull)msgHeader->ts, entry));
        cookieId = qatDbgGetEntryCookieId(msgHeader);
        if (cookieId)
        {
            entriesCookieMap->insert(
                std::pair<ull, icp_adf_dbg_entry_header_t *>(cookieId, entry));
        }
        if (headPtr > tailPtr && bottomPtr >= headPtr)
        {
            break;
        }

        ptr = bottomPtr;
    }
    qatDbgRecoverRing(ringDesc, entriesTsMap, entriesCookieMap);
}

/*
*******************************************************************************
* Debug logs related routines
*******************************************************************************
*/
static void qatDbgTraverseLogFile(icp_adf_dbg_entry_header_t *firstEntry,
                                  size_t fileSize)
{
    icp_adf_dbg_entry_header_t *msgHeader = NULL;
    icp_adf_dbg_entry_header_t *entry = NULL;
    size_t msgSize = 0;
    uint8_t *startPtr = (uint8_t *)firstEntry;
    uint8_t *endPtr = (uint8_t *)startPtr + fileSize;
    uint8_t *ptr = startPtr;
    uint8_t *bottomPtr = NULL;

    while (1)
    {
        msgHeader = (icp_adf_dbg_entry_header_t *)ptr;

        if (!msgHeader)
        {
            break;
        }
        if (QATD_MSG_PREAMBLE != msgHeader->preamble)
        {
            break;
        }
        msgSize = sizeof(icp_adf_dbg_entry_header_t) + msgHeader->msg_len +
                  msgHeader->src_sgl_len + msgHeader->dst_sgl_len +
                  msgHeader->misc_len;
        bottomPtr = ptr + msgSize;
        if (bottomPtr > endPtr)
        {
            break;
        }

        entry = msgHeader;
        /* Insert message into multimap */
        tsEntryMap.insert(std::pair<ull, icp_adf_dbg_entry_header_t *>(
            (ull)msgHeader->ts, entry));
        if (QATD_MSG_APICALL != msgHeader->msg_type)
        {
            cookieEntryMap.insert(std::pair<ull, icp_adf_dbg_entry_header_t *>(
                qatDbgGetEntryCookieId(msgHeader), entry));
        }
        ptr = bottomPtr;
    }
}

/*
*******************************************************************************
* Debug logs filesystem related functions
*******************************************************************************
*/
static CpaStatus qatDbgGetDevIdFromPath(char *path, int *devId)
{
    char *dirName;
    int rc;

    if (!path || !devId)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    dirName = basename(path);
    if (!dirName)
    {
        return CPA_STATUS_FAIL;
    }

    rc = sscanf(dirName, QAT_DBG_CRASH_DIR_PREFIX "%d_", devId);
    if (rc <= 0 || *devId < 0)
    {
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

static CpaStatus qatDbgGetDevBdfFromPath(char *path,
                                         qat_dbg_pci_addr_t *pPciAddr)
{
    char *dirName;
    int rc;

    if (!path || !pPciAddr)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    dirName = basename(path);
    if (!dirName)
    {
        return CPA_STATUS_FAIL;
    }

    /* Get the BDF which was used to create crash logs */
    rc = sscanf(dirName,
                QAT_DBG_CRASH_DIR_PREFIX "%*d_%4x_%2hhx_%2hhx_%1hhx_",
                &pPciAddr->domain,
                &pPciAddr->bus,
                &pPciAddr->dev,
                &pPciAddr->func);
    if (rc < QAT_DBG_PCI_ADDR_PARTS_NUM || pPciAddr->domain < 0)
    {
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

static CpaBoolean qatDbgMatchFileFilter(char *filename,
                                        const char *prefix,
                                        const char *filter)
{
    int len = 0;
    char *start = NULL;

    len = strlen(prefix);
    if (strncmp(filename, prefix, len))
    {
        return CPA_FALSE;
    }
    if (filter)
    {
        start = strchr(&filename[len], '_');
        if (!start)
        {
            return CPA_FALSE;
        }
        if (strncmp(start, filter, strlen(filter)))
        {
            return CPA_FALSE;
        }
    }

    return CPA_TRUE;
}

static CpaStatus qatDbgIndexCrashDir()
{
    DIR *dir = NULL;
    struct dirent *dirEntry = NULL;
    int fd = -1;
    int status = 0;
    struct stat fileStat = {0};
    char fileFilterProcMap[QATD_MAX_FILE_NAME] = {0};
    char fileFilterBDF[QATD_MAX_FILE_NAME] = {0};
    char fullPath[QATD_MAX_FILE_NAME * 2] = {0};
    qat_dbg_buffer_desc_t *ringDesc = NULL;

    dir = opendir(gWorkDir);
    if (!dir)
    {
        printf("ERROR: Unable to open directory: %s\n", gWorkDir);
        return CPA_STATUS_FAIL;
    }

    snprintf(fileFilterProcMap,
             sizeof(fileFilterProcMap),
             "%s%02d",
             QATD_PROC_MMAP_FILE_NAME,
             gDevId);
    snprintf(fileFilterBDF,
             sizeof(fileFilterBDF),
             "_" QAT_DBG_PCI_ADDR_FORMAT,
             gDevPciAddr.domain,
             gDevPciAddr.bus,
             gDevPciAddr.dev,
             gDevPciAddr.func);

    std::cout << "\n" << QAT_DBG_H_BAR << "Building index..." << std::endl;
    while ((dirEntry = readdir(dir)) != NULL)
    {
        /* Set processes memory map file path if found */
        if ((gDevPciAddr.domain >= 0 &&
             qatDbgMatchFileFilter(
                 dirEntry->d_name, QATD_PROC_MMAP_FILE_NAME, fileFilterBDF)) ||
            qatDbgMatchFileFilter(dirEntry->d_name, fileFilterProcMap, NULL))
        {
            snprintf(gProcMmapFilePath,
                     sizeof(gProcMmapFilePath),
                     "%s/%s",
                     gWorkDir,
                     dirEntry->d_name);
        }
        if (!qatDbgMatchFileFilter(dirEntry->d_name, QAT_DBG_RING_PREFIX, NULL))
        {
            continue;
        }

        osalMemSet(fullPath, 0, sizeof(fullPath));
        snprintf(
            fullPath, sizeof(fullPath), "%s/%s", gWorkDir, dirEntry->d_name);
        fd = open((const char *)fullPath, O_RDWR);
        if (fd < 0)
        {
            std::cout << "ERROR: Unable to open file " << fullPath << std::endl;
            continue;
        }

        status = stat((const char *)fullPath, &fileStat);
        if (0 != status || 0 >= fileStat.st_size)
        {
            close(fd);
            continue;
        }

        ringDesc = (qat_dbg_buffer_desc_t *)mmap(
            0, fileStat.st_size, PROT_READ, MAP_SHARED | MAP_LOCKED, fd, 0);
        if (MAP_FAILED == ringDesc)
        {
            std::cout << "ERROR: Unable to mmap file " << fullPath << std::endl;
            close(fd);
            continue;
        }

        qatDbgTraverseRing(ringDesc, &tsEntryMap, &cookieEntryMap);
        munmap(ringDesc, fileStat.st_size);
        close(fd);
    }
    closedir(dir);
    std::cout << "DONE\n"
              << "\tOverall indexed " << tsEntryMap.size() << " msgs."
              << std::endl;

    return CPA_STATUS_SUCCESS;
}

static CpaStatus qatDbgIndexContSyncData()
{
    DIR *dir = NULL;
    struct dirent *dirEntry = NULL;
    int fd = -1;
    int status = 0;
    struct stat fileStat = {0};
    char fullPath[QATD_MAX_FILE_NAME * 2] = {0};
    char fileFilter[QATD_MAX_FILE_NAME] = {0};
    char fileFilterProcMap[QATD_MAX_FILE_NAME] = {0};
    char fileFilterBDF[QATD_MAX_FILE_NAME] = {0};
    icp_adf_dbg_entry_header_t *firstEntry = NULL;

    dir = opendir(gWorkDir);
    if (!dir)
    {
        printf("ERROR: Unable to open directory: %s\n", gWorkDir);
        return CPA_STATUS_FAIL;
    }

    snprintf(fileFilter,
             sizeof(fileFilter),
             "%s%02d",
             QAT_DBG_CONT_SYNC_FILE_PREFIX,
             gDevId);
    snprintf(fileFilterProcMap,
             sizeof(fileFilterProcMap),
             "%s%02d",
             QATD_PROC_MMAP_FILE_NAME,
             gDevId);
    snprintf(fileFilterBDF,
             sizeof(fileFilterBDF),
             "_" QAT_DBG_PCI_ADDR_FORMAT,
             gDevPciAddr.domain,
             gDevPciAddr.bus,
             gDevPciAddr.dev,
             gDevPciAddr.func);

    std::cout << "\n" << QAT_DBG_H_BAR << "Building index..." << std::endl;
    while ((dirEntry = readdir(dir)))
    {
        if (gDevPciAddr.domain >= 0)
        {
            /* Set processes memory map file path if found */
            if (qatDbgMatchFileFilter(
                    dirEntry->d_name, QATD_PROC_MMAP_FILE_NAME, fileFilterBDF))
            {
                snprintf(gProcMmapFilePath,
                         sizeof(gProcMmapFilePath),
                         "%s/%s",
                         gWorkDir,
                         dirEntry->d_name);
            }
            /* While building index, take files that comply with provided BDF
             * only */
            if (!qatDbgMatchFileFilter(dirEntry->d_name,
                                       QAT_DBG_CONT_SYNC_FILE_PREFIX,
                                       fileFilterBDF))
            {
                continue;
            }
        }
        else
        {
            /* Set processes memory map file path if found */
            if (qatDbgMatchFileFilter(
                    dirEntry->d_name, fileFilterProcMap, NULL))
            {
                snprintf(gProcMmapFilePath,
                         sizeof(gProcMmapFilePath),
                         "%s/%s",
                         gWorkDir,
                         dirEntry->d_name);
            }
            /* While building index, take files that comply with device id only
             */
            if (!qatDbgMatchFileFilter(dirEntry->d_name, fileFilter, NULL))
            {
                continue;
            }
        }

        osalMemSet(fullPath, 0, sizeof(fullPath));
        snprintf(
            fullPath, sizeof(fullPath), "%s/%s", gWorkDir, dirEntry->d_name);
        fd = open((const char *)fullPath, O_RDWR);
        if (fd < 0)
        {
            std::cout << "ERROR: Unable to open file " << fullPath << std::endl;
            continue;
        }

        status = stat((const char *)fullPath, &fileStat);
        if (0 != status || 0 >= fileStat.st_size)
        {
            close(fd);
            continue;
        }

        firstEntry = (icp_adf_dbg_entry_header_t *)mmap(
            0, fileStat.st_size, PROT_READ, MAP_SHARED | MAP_LOCKED, fd, 0);
        if (MAP_FAILED == firstEntry)
        {
            std::cout << "ERROR: Unable to mmap file " << fullPath << std::endl;
            close(fd);
            continue;
        }

        qatDbgTraverseLogFile(firstEntry, fileStat.st_size);
        /* No unmap and close since entries are not copied */
    }
    closedir(dir);
    std::cout << "DONE\n"
              << "\tOverall indexed " << tsEntryMap.size() << " msgs."
              << std::endl;

    return CPA_STATUS_SUCCESS;
}

/*
*******************************************************************************
* Built index summary printing function
*******************************************************************************
*/
static void qatDbgPrintIndexSummary()
{
    Cpa8U reqType = 0;
    Cpa32U reqSym = 0;
    Cpa32U reqPke = 0;
    Cpa32U reqDc = 0;
    Cpa32U reqCtr = 0;
    Cpa32U respCtr = 0;
    Cpa32U apiCall = 0;
    mmap_reviter_t last = tsEntryMap.rbegin();

    for (; last != tsEntryMap.rend(); ++last)
    {
        icp_adf_dbg_entry_header_t *msg = last->second;
        if (QATD_MSG_PREAMBLE != msg->preamble)
        {
            continue;
        }
        switch (msg->msg_type)
        {
            case QATD_MSG_REQUEST:
            case QATD_MSG_REQUEST_DPDK:
                reqCtr++;
                reqType = qatDbgGetReqType(msg);
                switch (reqType)
                {
                    case ICP_QAT_FW_COMN_REQ_CPM_FW_LA:
                        reqSym++;
                        break;
                    case ICP_QAT_FW_COMN_REQ_CPM_FW_PKE:
                        reqPke++;
                        break;
                    case ICP_QAT_FW_COMN_REQ_CPM_FW_COMP:
                        reqDc++;
                        break;
                    default:
                        break;
                }
                break;
            case QATD_MSG_RESPONSE:
                respCtr++;
                break;
            case QATD_MSG_APICALL:
                apiCall++;
                break;
            default:
                break;
        }
    }
    std::cout << "\t\tRequests: " << reqCtr << " (Sym:" << reqSym
              << ", PKE:" << reqPke << ", DC:" << reqDc
              << ")\n\t\tResponses:" << respCtr << "\n\t\tAPI calls:" << apiCall
              << " \n"
              << QAT_DBG_H_BAR << std::endl;
}

/*
*******************************************************************************
* Audits routines
*******************************************************************************
*/
/*
 ******************************************************************
 * @ingroup qatDbg
 *        Audit QAT cryptographic request
 *
 * @description
 *        This macro performs audit on given QAT CY request,
 *        prints founded issues to the stdout and stores issues
 *        number in \p errorCnt variable.
 *
 * @param[in]  pMid      pointer to QAT CY request. It can be
 *                       pointer to icp_qat_fw_req_pke_mid_t or
 *                       icp_qat_fw_comn_req_hdr_t structure for
 *                       ASYM and SYM requests respectively
 * @param[in]  header    pointer to debug entry header structure
 *                       of type icp_adf_dbg_entry_header_t
 * @param[out] errorCnt  pointer to integer variable which will be
 *                       set to a number of issues founded by this
 *                       macro call
 * @param[in]  checkSGL  boolean value which determines if the
 *                       SGLs should be checked in given request
 *
 * @retval none
 *
 ******************************************************************
 */
#define QAT_DBG_AUDIT_CY_REQUEST(pMid, header, errorCnt, checkSGL)             \
    do                                                                         \
    {                                                                          \
        /* Check against null src address */                                   \
        if (!(pMid)->src_data_addr)                                            \
        {                                                                      \
            std::cout << "ERROR: physical destination address null."           \
                      << std::endl;                                            \
            *(errorCnt) += 1;                                                  \
        }                                                                      \
        /* Check against null dst address */                                   \
        if (!(pMid)->dest_data_addr)                                           \
        {                                                                      \
            std::cout << "ERROR: physical source address null." << std::endl;  \
            *(errorCnt) += 1;                                                  \
        }                                                                      \
        if (!qatDbgTestMsgHeader((header)))                                    \
        {                                                                      \
            *(errorCnt) += 1;                                                  \
        }                                                                      \
        if ((checkSGL) && !qatDbgTestReqSgl((header)))                         \
        {                                                                      \
            std::cout << "ERROR: SGL audit failed - check entry below."        \
                      << std::endl;                                            \
            *(errorCnt) += 1;                                                  \
        }                                                                      \
        if (!qatDbgTestPhyAddrOverlap((header)))                               \
        {                                                                      \
            std::cout << "ERROR: address overlapping audit failed - check "    \
                         "entry below."                                        \
                      << std::endl;                                            \
            *(errorCnt) += 1;                                                  \
        }                                                                      \
        if (!qatDbgTestPhyAddrMap((header)))                                   \
        {                                                                      \
            std::cout << "ERROR: User process memory regions audit failed"     \
                      << " - check entry below." << std::endl;                 \
            *(errorCnt) += 1;                                                  \
        }                                                                      \
    } while (0)

static int qatDbgParseAndAuditPkeReq(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_pke_request_t *pkeReq =
        (icp_qat_fw_pke_request_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_req_pke_mid_t *pMid = &pkeReq->pke_mid;
    int errors = 0;

    QAT_DBG_AUDIT_CY_REQUEST(pMid, msgHeader, &errors, CPA_FALSE);

    return errors;
}

static int qatDbgParseAndAuditCySymReq(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_comn_req_t *req =
        (icp_qat_fw_comn_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_comn_req_mid_t *pMid = &req->comn_mid;
    int errors = 0;

    QAT_DBG_AUDIT_CY_REQUEST(pMid, msgHeader, &errors, CPA_TRUE);

    return errors;
}

static int qatDbgParseAndAuditReq(icp_adf_dbg_entry_header_t *msgHeader)
{
    icp_qat_fw_comn_req_t *req =
        (icp_qat_fw_comn_req_t *)QAT_DBG_GET_MSG_CONTENT(msgHeader);
    icp_qat_fw_comn_req_hdr_t *comnHdr = &req->comn_hdr;
    int errors = 0;

    switch (comnHdr->service_type)
    {
        case ICP_QAT_FW_COMN_REQ_CPM_FW_LA:
        case ICP_QAT_FW_COMN_REQ_CPM_FW_COMP:
        case ICP_QAT_FW_COMN_REQ_CPM_FW_COMP_CHAIN:
            errors += qatDbgParseAndAuditCySymReq(msgHeader);
            break;
        case ICP_QAT_FW_COMN_REQ_CPM_FW_PKE:
            errors += qatDbgParseAndAuditPkeReq(msgHeader);
            break;
        default:
            std::cout << "WARNING: Unknown Service Type ("
                      << (int)comnHdr->service_type << ")." << std::endl;
            errors++;
    }

    if (0 < errors)
    {
        qatDbgParseAndPrintMsg(msgHeader);
        std::cout << QAT_DBG_H_BAR << std::endl;
    }

    return errors;
}

static void qatDbgAuditPhyAddresses()
{
    int entries = tsEntryMap.size();
    mmap_reviter_t last = tsEntryMap.rbegin();
    int errorCtr = 0;
    int ctr = 0;

    std::cout << QAT_DBG_H_BAR
              << "\nQAT Physical addresses - audit in progress ...\n"
              << std::endl;

    for (; last != tsEntryMap.rend(); ++last)
    {
        icp_adf_dbg_entry_header_t *msg = last->second;

        if (QATD_MSG_REQUEST != msg->msg_type &&
            QATD_MSG_REQUEST_DPDK != msg->msg_type)
        {
            continue;
        }
        if (0 <
            qatDbgParseAndAuditReq((icp_adf_dbg_entry_header_t *)last->second))
        {
            errorCtr++;
        }
        QAT_DBG_INC_AUDIT_PROGRESS(ctr, entries);
    }
    qatDbgPrintProgress((float)1);
    if (!errorCtr)
    {
        std::cout << "\nChecked " << std::dec << tsEntryMap.size()
                  << " records. No issues found." << std::endl;
    }
    else
    {
        std::cout << "\nChecked " << std::dec << tsEntryMap.size()
                  << " records. Found " << errorCtr << " issue(s)."
                  << std::endl;
    }
}

static void qatDbgAuditResponse()
{
    mmap_reviter_t last = tsEntryMap.rbegin();
    int entries = tsEntryMap.size();
    int errorCtr = 0;
    int ctr = 0;

    std::cout << QAT_DBG_H_BAR
              << "\nQAT Response return codes audit in progress ...\n\n"
              << std::endl;
    for (; last != tsEntryMap.rend(); ++last)
    {
        icp_adf_dbg_entry_header_t *resp = last->second;

        if (QATD_MSG_RESPONSE != resp->msg_type)
        {
            continue;
        }
        if (!qatDbgTestMsgHeader(resp))
        {
            errorCtr++;
        }
        if (!qatDbgTestRespStatus(resp))
        {
            icp_adf_dbg_entry_header_t *foundReq = NULL;
            ull tsDiff = 0;
            ull minTsDiff = 0;
            std::pair<mmap_iter_t, mmap_iter_t> result;
            mmap_iter_t it;

            errorCtr++;
            qatDbgParseAndPrintMsg(resp);
            /* Atempt to match with request by Cookie Id */
            result = cookieEntryMap.equal_range(qatDbgGetEntryCookieId(resp));
            /* Iterate all request with same cookie */
            for (it = result.first; it != result.second; ++it)
            {
                icp_adf_dbg_entry_header_t *req = it->second;

                if (QATD_MSG_REQUEST != req->msg_type &&
                    QATD_MSG_REQUEST_DPDK != req->msg_type)
                {
                    continue;
                }
                /* Response should occur after request */
                if (req->ts > resp->ts)
                {
                    continue;
                }
                /* Find response which have the lowest timestamp difference with
                 * request */
                tsDiff = resp->ts - req->ts;
                if (!minTsDiff)
                {
                    minTsDiff = tsDiff;
                    foundReq = req;
                }
                else
                {
                    if (tsDiff < minTsDiff)
                    {
                        minTsDiff = tsDiff;
                        foundReq = req;
                    }
                }
            }
            if (foundReq)
            {
                qatDbgParseAndPrintMsg(foundReq);
            }
            else
            {
                std::cout << "WARNING: Unable to find corresponding request."
                          << std::endl;
            }

            std::cout << QAT_DBG_H_BAR << std::endl;
        }
        QAT_DBG_INC_AUDIT_PROGRESS(ctr, entries);
    }
    qatDbgPrintProgress((float)1);
    if (!errorCtr)
    {
        std::cout << "\nChecked " << std::dec << tsEntryMap.size()
                  << " records. No issues found." << std::endl;
    }
    else
    {
        std::cout << "\nChecked " << std::dec << tsEntryMap.size()
                  << " records. Found " << errorCtr << " issue(s)."
                  << std::endl;
    }
}

static void qatDbgAuditCipherLengths()
{
    int entries = tsEntryMap.size();
    mmap_reviter_t last = tsEntryMap.rbegin();
    int errorCtr = 0;
    int ctr = 0;

    std::cout << QAT_DBG_H_BAR
              << "\nQAT request fields length - audit in progress..."
              << std::endl;
    for (; last != tsEntryMap.rend(); ++last)
    {
        icp_adf_dbg_entry_header_t *msg = last->second;

        if (QATD_MSG_REQUEST != msg->msg_type &&
            QATD_MSG_REQUEST_DPDK != msg->msg_type)
        {
            continue;
        }
        if (!qatDbgTestMsgHeader(msg))
        {
            errorCtr++;
        }
        if (!qatDbgTestReqLengths(msg))
        {
            errorCtr++;
            qatDbgParseAndPrintMsg(msg);
            std::cout << QAT_DBG_H_BAR << std::endl;
        }

        QAT_DBG_INC_AUDIT_PROGRESS(ctr, entries);
    }
    qatDbgPrintProgress((float)1);

    if (!errorCtr)
    {
        std::cout << "\nChecked " << std::dec << tsEntryMap.size()
                  << " records. No issues found." << std::endl;
    }
    else
    {
        std::cout << "\nChecked " << std::dec << tsEntryMap.size()
                  << " records. Found " << errorCtr << " issue(s)."
                  << std::endl;
    }
}

/*
*******************************************************************************
* QAT debug report tool commands handlers
*******************************************************************************
*/
static void qatDbgCmdListEntries(int entriesDisplayLimit)
{
    icp_adf_dbg_entry_header_t *req = NULL;
    mmap_reviter_t last = tsEntryMap.rbegin();
    int ctr = 0;

    std::cout << QAT_DBG_H_BAR;
    for (ctr = 0; last != tsEntryMap.rend(); ++last)
    {
        if (0 <= entriesDisplayLimit && ctr >= entriesDisplayLimit)
        {
            break;
        }
        req = last->second;
        qatDbgParseAndPrintMsg(req);
        std::cout << QAT_DBG_H_BAR << std::endl;
        ctr++;
    }
}

static CpaStatus qatDbgCmdSendCrashDump()
{
    int fd = -1;
    int ret = -1;
    qat_dbg_ioctl_req_t req = {0};
    CpaStatus status = CPA_STATUS_FAIL;

    fd = open(QATD_DEVICE_FILENAME, O_RDWR | O_NDELAY);
    if (fd <= 0)
    {
        std::cout << "ERROR: No file desc for QAT debug device." << std::endl;
        return CPA_STATUS_FAIL;
    }

    if (gDevPciAddr.domain < 0)
    {
        /* Dump explicitly by dev id, as it was provided */
        req.instance_id = gDevId;
    }
    else
    {
        /* Dump by BDF, as BDF was provided */
        /* Translate BDF to accel_id */
        ret = ioctl(fd, IOCTL_QATD_BSF_TO_ID, &gDevPciAddr);
        if (ret || CPA_STATUS_SUCCESS != gDevPciAddr.request_result)
        {
            goto on_exit;
        }

        req.instance_id = gDevPciAddr.device_id;
    }

    std::cout << "Sending crash request for device " << req.instance_id
              << " to QAT debug." << std::endl;

    ret = ioctl(fd, IOCTL_QATD_CRASH_DUMP, &req);
    if (ret || CPA_STATUS_SUCCESS != req.request_result)
    {
        std::cout << "ERROR: ioctl failed." << std::endl;
        goto on_exit;
    }

    status = CPA_STATUS_SUCCESS;
on_exit:
    close(fd);

    return status;
}

static CpaStatus qatDbgRunCommand(const char *command, int entriesDisplayLimit)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (!strncmp(command, QAT_DBG_CMD_DUMP, QAT_DBG_CMD_MAX_LEN))
    {
        status = qatDbgCmdSendCrashDump();
        if (!status)
        {
            std::cout << "Crash dump request sent." << std::endl;
        }
        else
        {
            std::cout << "Failed to send crash dump request." << std::endl;
        }

        return status;
    }
    else if (!strncmp(command, QAT_DBG_CMD_LIST, QAT_DBG_CMD_MAX_LEN) ||
             !strncmp(
                 command, QAT_DBG_CMD_AUDIT_PHY_ADDR, QAT_DBG_CMD_MAX_LEN) ||
             !strncmp(command, QAT_DBG_AUDIT_RESP_RC, QAT_DBG_CMD_MAX_LEN) ||
             !strncmp(command, QAT_DBG_AUDIT_REQ_LENGTH, QAT_DBG_CMD_MAX_LEN))
    {
        if (useCrashPath)
        {
            status = qatDbgIndexCrashDir();
        }
        else
        {
            status = qatDbgIndexContSyncData();
        }
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }

        qatDbgPrintIndexSummary();
        if (!strncmp(command, QAT_DBG_CMD_LIST, QAT_DBG_CMD_MAX_LEN))
        {
            qatDbgCmdListEntries(entriesDisplayLimit);
            return CPA_STATUS_SUCCESS;
        }
        if (!strncmp(command, QAT_DBG_CMD_AUDIT_PHY_ADDR, QAT_DBG_CMD_MAX_LEN))
        {
            qatDbgAuditPhyAddresses();
            return CPA_STATUS_SUCCESS;
        }
        if (!strncmp(command, QAT_DBG_AUDIT_RESP_RC, QAT_DBG_CMD_MAX_LEN))
        {
            qatDbgAuditResponse();
            return CPA_STATUS_SUCCESS;
        }
        if (!strncmp(command, QAT_DBG_AUDIT_REQ_LENGTH, QAT_DBG_CMD_MAX_LEN))
        {
            qatDbgAuditCipherLengths();
            return CPA_STATUS_SUCCESS;
        }
    }

    return CPA_STATUS_FAIL;
}

/*
*******************************************************************************
* QAT debug report tool input parameters related function
*******************************************************************************
*/
static CpaStatus qatDbgParseInputParams(int argc,
                                        char **argv,
                                        size_t optionsNum,
                                        qat_dbg_option_t *options)
{
    char value[QAT_DBG_OPT_MAX_LEN] = {0};
    char key[QAT_DBG_OPT_MAX_LEN] = {0};
    char command[QAT_DBG_CMD_MAX_LEN] = {0};
    int argIndex = 1;
    size_t optIndex = 0;
    size_t argsParsed = 0;
    int rc = 0;

    /* Domain will equal -1 if BDF is not specified */
    gDevPciAddr.domain = -1;
    /* By default search for cont-sync logs */
    useCrashPath = false;

    while (argIndex < argc)
    {
        if (argv[argIndex])
        {
            osalMemSet(key, 0, sizeof(key));
            osalMemSet(value, 0, sizeof(value));
            if (QAT_DBG_OPT_MAX_LEN <=
                strnlen(argv[argIndex], QAT_DBG_OPT_MAX_LEN))
            {
                std::cout << "Argument " << argIndex
                          << " exceeds permitted length" << std::endl;
                return CPA_STATUS_FAIL;
            }
            sscanf(argv[argIndex],
                   "%" QAT_DBG_SCAN_STR(
                       QAT_DBG_MAX_SCAN_LEN) "[^'=']="
                                             "%" QAT_DBG_SCAN_STR(
                                                 QAT_DBG_MAX_SCAN_LEN) "s",
                   key,
                   value);
            for (optIndex = 0; optIndex < optionsNum; optIndex++)
            {
                if (!strncmp(key, options[optIndex].key, QAT_DBG_OPT_MAX_LEN) &&
                    *value)
                {
                    strncpy(
                        options[optIndex].value, value, QAT_DBG_OPT_MAX_LEN);
                    options[optIndex].specified = true;
                    argsParsed++;
                }
            }
        }
        argIndex++;
    }

    if (!argsParsed)
    {
        return CPA_STATUS_FAIL;
    }
    if (options[QAT_DBG_DEV_OPT_ARRAY_POS].specified &&
        options[QAT_DBG_BDF_OPT_ARRAY_POS].specified)
    {
        std::cout << "ERROR: Device identifier and BDF provided. Only one "
                     "option should be used!"
                  << std::endl;
        return CPA_STATUS_FAIL;
    }
    strncpy(command,
            options[QAT_DBG_COMMAND_OPT_ARRAY_POS].value,
            QAT_DBG_CMD_MAX_LEN);

    /* Check audit and list arguments */
    if (!strncmp(command, QAT_DBG_CMD_LIST, QAT_DBG_CMD_MAX_LEN) ||
        !strncmp(command, QAT_DBG_CMD_AUDIT_PHY_ADDR, QAT_DBG_CMD_MAX_LEN) ||
        !strncmp(command, QAT_DBG_AUDIT_RESP_RC, QAT_DBG_CMD_MAX_LEN) ||
        !strncmp(command, QAT_DBG_AUDIT_REQ_LENGTH, QAT_DBG_CMD_MAX_LEN))
    {
        /* Path is mandatory */
        if (!options[QAT_DBG_PATH_OPT_ARRAY_POS].specified)
        {
            std::cout << "ERROR: Path to crash-dump or cont-sync directory is "
                         "missing in arguments!"
                      << std::endl;
            return CPA_STATUS_FAIL;
        }
    }

    /* Device id is optional when analyzing crash path */
    if (!options[QAT_DBG_DEV_OPT_ARRAY_POS].specified &&
        !options[QAT_DBG_BDF_OPT_ARRAY_POS].specified &&
        options[QAT_DBG_PATH_OPT_ARRAY_POS].specified &&
        strncmp(command, QAT_DBG_CMD_DUMP, QAT_DBG_CMD_MAX_LEN))
    {
        /* Set device identifier basing on path */
        do
        {
            if (CPA_STATUS_SUCCESS ==
                qatDbgGetDevBdfFromPath(
                    options[QAT_DBG_PATH_OPT_ARRAY_POS].value, &gDevPciAddr))
            {
                break;
            }
            if (CPA_STATUS_SUCCESS !=
                qatDbgGetDevIdFromPath(
                    options[QAT_DBG_PATH_OPT_ARRAY_POS].value, &gDevId))
            {
                std::cout << "ERROR: Device identifier cannot be found from "
                             "specified path!"
                          << std::endl;

                return CPA_STATUS_FAIL;
            }
        } while (0);

        useCrashPath = true;
    }
    else if (options[QAT_DBG_BDF_OPT_ARRAY_POS].specified)
    {
        /* User is allowed to provide BDF in a format of XXXX_BB_DD_F as well as
         * XXXX:BB:DD.F */
        rc = sscanf(options[QAT_DBG_BDF_OPT_ARRAY_POS].value,
                    "%4x%*[:_]%2hhx%*[:_]%2hhx%*[._]%1hhx",
                    &gDevPciAddr.domain,
                    &gDevPciAddr.bus,
                    &gDevPciAddr.dev,
                    &gDevPciAddr.func);
        if (rc < QAT_DBG_PCI_ADDR_PARTS_NUM || gDevPciAddr.domain < 0)
        {
            std::cout << "ERROR: Given BDF is invalid!" << std::endl;
            return CPA_STATUS_FAIL;
        }
    }
    else if (options[QAT_DBG_DEV_OPT_ARRAY_POS].specified)
    {
        gDevId = atoi(options[QAT_DBG_DEV_OPT_ARRAY_POS].value);
        if (gDevId < 0)
        {
            std::cout << "ERROR: Provided device ID is incorrect!" << std::endl;
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        std::cout << "ERROR: Device ID is missing in arguments!" << std::endl;
        return CPA_STATUS_FAIL;
    }

    strncpy(gWorkDir,
            options[QAT_DBG_PATH_OPT_ARRAY_POS].value,
            sizeof(gWorkDir) - 1);
    gWorkDir[sizeof(gWorkDir) - 1] = 0;

    return CPA_STATUS_SUCCESS;
}

/*
*******************************************************************************
* Main
*******************************************************************************
*/
int main(int argc, char *argv[])
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    char command[QAT_DBG_CMD_MAX_LEN] = {0};
    int last = 0;
    qat_dbg_option_t optArray[QAT_DBG_OPT_MAX_NUM] = {
        {QAT_DBG_COMMAND_OPT_STR, QAT_DBG_COMMAND_OPT_DEF_VAL, false},
        {QAT_DBG_PATH_OPT_STR, QAT_DBG_PATH_OPT_DEF_VAL, false},
        {QAT_DBG_DEV_OPT_STR, QAT_DBG_DEV_OPT_DEF_VAL, false},
        {QAT_DBG_LAST_OPT_STR, QAT_DBG_LAST_OPT_DEF_VAL, false},
        {QAT_DBG_BDF_OPT_STR, QAT_DBG_BDF_OPT_DEF_VAL, false}};

    status = qatDbgParseInputParams(argc, argv, QAT_DBG_OPT_MAX_NUM, optArray);
    if (CPA_STATUS_SUCCESS != status)
    {
        qatDbgPrintHelp();
        return -1;
    }

    strncpy(command,
            optArray[QAT_DBG_COMMAND_OPT_ARRAY_POS].value,
            QAT_DBG_CMD_MAX_LEN);
    last = atoi(optArray[QAT_DBG_LAST_OPT_ARRAY_POS].value);
    status = qatDbgRunCommand(command, last);
    if (CPA_STATUS_SUCCESS != status)
    {
        qatDbgPrintHelp();
        return -1;
    }

    return 0;
}
