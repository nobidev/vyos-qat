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
 * @file icp_adf_dbg_log.h
 *
 * @description
 *      This file contains the QAT debug logger utilities.
 *
 *****************************************************************************/
#ifndef ICP_ADF_DBG_LOG_H_
#define ICP_ADF_DBG_LOG_H_

#include "cpa.h"

/*
*******************************************************************************
* Public definitions
*******************************************************************************
*/
#define QATD_DEVICE_FILENAME "/dev/qat_debug"
#define QATD_PROC_MMAP_FILE_NAME "proc.mmaps.dev"
#define QATD_MSG_PREAMBLE 0xacc00cca

#define QATD_DAEMON_KEY 0xACC0107
#define QATD_IPC_MSGTYPE 1
#define QATD_IPC_PERM 0666
#define QATD_PUT_MSG_RING_FULL CPA_STATUS_RETRY

/*
*******************************************************************************
* Public typedefs
*******************************************************************************
*/
typedef void *(*icp_adf_dbg_phys2virt_callback)(CpaPhysicalAddr);
typedef int (*icp_adf_dbg_priv_cleanup_callback)(void *);

/*
*******************************************************************************
* Public structures
*******************************************************************************
*/
/* IPC queue message struct with imposed layout */
typedef struct icp_adf_dbg_sync_msg_s
{
    long msg_type;
    unsigned int buffer_id;
} icp_adf_dbg_sync_msg_t;

typedef struct icp_adf_dbg_dev_handle_s
{
    /* QAT Device ID */
    Cpa32U accel_id;
    /* File descriptor */
    int fd;
    /* Timestamp when last message was stored on any debug ring buffer */
    volatile Cpa64S last_msg_ts;
} icp_adf_dbg_dev_handle_t;

typedef struct icp_adf_dbg_handle_s
{
    icp_adf_dbg_dev_handle_t *dev_handle;
    /* Debuggability feature enable inidcator */
    Cpa32S qat_dbg_enabled;
    /* Debuggability log level */
    Cpa32U qat_dbg_level;
    /* Size of mapped debug buffer */
    Cpa32U qat_dbg_buffer_size;
    /* Pointer to mapped debug buffer */
    void *qat_dbg_buffer_desc;
    /* IPC message queue identifier */
    int qat_dbg_daemon_msgq_id;
    /* Mutex for locking when API calls logging is enabled */
    void *resp_api_lock;
    /* Virtual to physical callback */
    icp_adf_dbg_phys2virt_callback qat_dbg_phys2virt_client_cb;
    /* Private data cleanup from debug sideband copy of request data callback */
    icp_adf_dbg_priv_cleanup_callback qat_dbg_priv_cleanup_cb;
    /* Current message timestamp */
    Cpa64U msg_ts;
} icp_adf_dbg_handle_t;

typedef struct icp_adf_dbg_hw_config_s
{
    union {
        struct
        {
            Cpa16U cipherAlg;
            Cpa16U cipherMode;
            Cpa16U hashAlg;
            Cpa16U hashMode;
        } s;
        struct
        {
            Cpa16U compType;
            Cpa16U huffType;
            Cpa16U hash_algo;
        } s1;
    } u;
} __attribute__((packed, aligned(4))) icp_adf_dbg_hw_config_t;

typedef struct icp_adf_dbg_entry_header_s
{
    Cpa32U preamble;
    /* Timestamp */
    Cpa64U ts;
    /* Bank number */
    Cpa16U bank;
    /* Ring number */
    Cpa16U ring;
    /* PID */
    Cpa32U pid;
    /* Message type: FW REQ, FW RESP, APICALL */
    Cpa16U msg_type;
    /* API Call */
    Cpa16U api_type;
    /* Session data */
    icp_adf_dbg_hw_config_t content_desc;
    /* Message length */
    Cpa16U msg_len;
    /* Source buffer SGL length */
    Cpa16U src_sgl_len;
    /* Destination buffer SGL length */
    Cpa16U dst_sgl_len;
    /* Miscellaneous data length */
    Cpa16U misc_len;
} __attribute__((packed, aligned(4))) icp_adf_dbg_entry_header_t;

typedef struct icp_adf_dbg_content_desc_s
{
    /* Message type: FW REQ, FW RESP, APICALL */
    Cpa16U msg_type;
    /* API Call */
    Cpa16U api_type;
    /* Msg */
    void *msg;
    /* Message size */
    Cpa16U msg_size;
    /* Source SGL pointer */
    void *src_sgl;
    /* Source buffer SGL size */
    Cpa16U src_sgl_size;
    /* Source buffer SGL physical address */
    Cpa64U src_phy_addr;
    /* Destination SGL pointer */
    void *dst_sgl;
    /* Destination buffer SGL size */
    Cpa16U dst_sgl_size;
    /* Destination buffer SGL physical address */
    Cpa64U dst_phy_addr;
    /* Bank number */
    Cpa16U bank;
    /* Ring number */
    Cpa16U ring;
    /* Misc */
    void *misc;
    /* Misc size */
    Cpa16U misc_size;
    /* Session data */
    icp_adf_dbg_hw_config_t content_desc;
} icp_adf_dbg_content_desc_t;

/* Verbosity level */
enum icp_adf_dbg_level
{
    /* Collect no data */
    QATD_LEVEL_NO_COLLECT = 0,
    /* Collect only API calls */
    QATD_LEVEL_API_CALLS,
    /* Collect FW requests & responses only */
    QATD_LEVEL_FW_CALLS,
    /* Collect all above */
    QATD_LEVEL_ALL
};

/* Type of logged message */
enum icp_adf_dbg_message_type
{
    QATD_MSG_REQUEST = 0,
    QATD_MSG_REQUEST_DPDK,
    QATD_MSG_RESPONSE,
    QATD_MSG_APICALL
};

/* QAT API calls opaque data enumeration */
enum icp_adf_dbg_api_type
{
    QATD_CPACYDHPHASE1KEYGENOPDATA = 0,
    QATD_CPACYDHPHASE2SECRETKEYGENOPDATA,
    QATD_CPACYDRBGGENOPDATA,
    QATD_CPACYDRBGRESEEDOPDATA,
    QATD_CPACYDSAGPARAMGENOPDATA,
    QATD_CPACYDSAPPARAMGENOPDATA,
    QATD_CPACYDSARSIGNOPDATA,
    QATD_CPACYDSARSSIGNOPDATA,
    QATD_CPACYDSASSIGNOPDATA,
    QATD_CPACYDSAVERIFYOPDATA,
    QATD_CPACYDSAYPARAMGENOPDATA,
    QATD_CPACYECDHPOINTMULTIPLYOPDATA,
    QATD_CPACYECDSASIGNROPDATA,
    QATD_CPACYECDSASIGNRSOPDATA,
    QATD_CPACYECDSASIGNSOPDATA,
    QATD_CPACYECDSAVERIFYOPDATA,
    QATD_CPACYECPOINTMULTIPLYOPDATA,
    QATD_CPACYECPOINTVERIFYOPDATA,
    QATD_CPACYECMONTEDWDSPOINTMULTIPLYOPDATA,
    QATD_CPACYECSM2POINTMULTIPLYOPDATA,
    QATD_CPACYECSM2GENERATORMULTIPLYOPDATA,
    QATD_CPACYECSM2POINTVERIFYOPDATA,
    QATD_CPACYECSM2SIGNOPDATA,
    QATD_CPACYECSM2VERIFYOPDATA,
    QATD_CPACYECSM2ENCRYPTOPDATA,
    QATD_CPACYECSM2DECRYPTOPDATA,
    QATD_CPACYECSM2KEYEXPHASE1OPDATA,
    QATD_CPACYECSM2KEYEXPHASE2OPDATA,
    QATD_CPACYKEYGENMGFOPDATA,
    QATD_CPACYKEYGENMGFOPDATAEXT,
    QATD_CPACYKEYGENSSLOPDATA,
    QATD_CPACYKEYGENTLSOPDATA,
    QATD_CPACYKEYGENHKDFOPDATA,
    QATD_CPACYLNMODEXPOPDATA,
    QATD_CPACYLNMODINVOPDATA,
    QATD_CPACYNRBGOPDATA,
    QATD_CPACYPRIMETESTOPDATA,
    QATD_CPACYRANDGENOPDATA,
    QATD_CPACYRANDSEEDOPDATA,
    QATD_CPACYRSADECRYPTOPDATA,
    QATD_CPACYRSAENCRYPTOPDATA,
    QATD_CPACYRSAKEYGENOPDATA,
    QATD_CPACYSYMDPOPDATA,
    QATD_CPACYSYMOPDATA,
    QATD_CPADCBATCHOPDATA,
    QATD_CPADCCHAINOPDATA,
    QATD_CPADCDPOPDATA,
    QATD_CPADCOPDATA,
    QATD_DPDK_SYM,
    QATD_DPDK_ASYM,
    QATD_DPDK_COMP
};

/*
*******************************************************************************
* Public functions
*******************************************************************************
*/
/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Check if QAT Debuggablity feature is enabled
 *
 * @description
 *      This function checks if for given \p handle the requested
 *      Debuggability logging level provided in \p level argument
 *      is enabled.
 *
 * @param[in]  handle  Pointer to Debuggability handle
 * @param[in]  level   Debug level
 *
 * @retval CPA_TRUE   Requested debug level is enabled for given
 *                    Debuggability handle
 * @retval CPA_FALSE  Requested debug level is disabled for given
 *                    Debuggability or invalid arguments provided
 *
 ******************************************************************
 */
CpaBoolean icp_adf_log_is_enabled(icp_adf_dbg_handle_t *handle,
                                  enum icp_adf_dbg_level level);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Log QAT request
 *
 * @description
 *      This function performs logging of QAT request described by
 *      debug content descriptor into debug ring buffers. The debug
 *      ring buffer is acquired automatically if required.
 *
 * @param[in]  handle           Pointer to Debuggability handle
 * @param[in]  db_content_desc  Pointer to debug content descriptor
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_FAIL           Failed to log the request
 * @retval CPA_STATUS_RETRY          All debug buffers are being
 *                                   synchronized with persistent
 *                                   storage and the request has
 *                                   not been stored in any of them
 * @retval CPA_STATUS_SUCCESS        Request stored successfully or
 *                                   skipped due to configuration:
 *                                   logging disabled or other log
 *                                   level than requests is
 *                                   configured
 ******************************************************************
 */
CpaStatus icp_adf_log_req(icp_adf_dbg_handle_t *handle,
                          icp_adf_dbg_content_desc_t *db_content_desc);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Log QAT response
 *
 * @description
 *      This function performs logging of QAT response into debug
 *      ring buffers. The debug ring buffer is acquired
 *      automatically if required.
 *
 * @param[in]  handle    Pointer to Debuggability handle
 * @param[in]  bank      Bank number of the response
 * @param[in]  ring      Ring number of the response
 * @param[in]  msg       Pointer to QAT response
 * @param[in]  msg_size  Size of QAT response pointed by msg
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_FAIL           Failed to log the response
 * @retval CPA_STATUS_FATAL          Failed to lock response/API
 *                                   call mutex
 * @retval CPA_STATUS_RETRY          All debug buffers are being
 *                                   synchronized with persistent
 *                                   storage and the response
 *                                   has not been stored in any
 *                                   of them
 * @retval CPA_STATUS_SUCCESS        Response stored successfully
 *                                   or skipped due to
 *                                   configuration: logging
 *                                   disabled or other log level
 *                                   than responses is configured
 ******************************************************************
 */
CpaStatus icp_adf_log_resp(icp_adf_dbg_handle_t *handle,
                           Cpa16U bank,
                           Cpa16U ring,
                           void *msg,
                           Cpa16U msg_size);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Log QAT API call
 *
 * @description
 *      This function performs logging of QAT API call described by
 *      debug content descriptor into debug ring buffers. The debug
 *      ring buffer is acquired automatically if required.
 *
 * @param[in]  handle           Pointer to Debuggability handle
 * @param[in]  db_content_desc  Pointer to debug content descriptor
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_FAIL           Failed to log the API call
 * @retval CPA_STATUS_FATAL          Failed to lock response/API
 *                                   call mutex
 * @retval CPA_STATUS_RETRY          All debug buffers are being
 *                                   synchronized with persistent
 *                                   storage and the API call
 *                                   has not been stored in any
 *                                   of them
 * @retval CPA_STATUS_SUCCESS        API call stored successfully
 *                                   or skipped due to
 *                                   configuration: logging
 *                                   disabled or other log level
 *                                   than API calls is configured
 ******************************************************************
 */
CpaStatus icp_adf_log_apicall(icp_adf_dbg_handle_t *handle,
                              icp_adf_dbg_content_desc_t *db_content_desc);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Set physical to virtual addresses translation callback
 *
 * @description
 *      This function sets provided by user callback for
 *      translating physical to virtual addresses. The callback
 *      will be used for Data Plane API requests with SGL
 *      provided.
 *
 * @param[in]  handle                  Pointer to Debuggability
 *                                     handle
 * @param[in]  qat_dbg_user_phys2virt  Function which will be
 *                                     translating physical
 *                                     addresses to virtual ones
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_SUCCESS        User callback set successfully
 ******************************************************************
 */
CpaStatus icp_adf_log_set_phys_to_virt_cb(
    icp_adf_dbg_handle_t *handle,
    icp_adf_dbg_phys2virt_callback qat_dbg_user_phys2virt);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Set private data clean up callback
 *
 * @description
 *      This function set callback which is going to be executed to
 *      clean up sensitive content from QAT firmware requests before
 *      they will be stored in debug ring buffers.
 *
 * @param[in]  handle                   Pointer to Debuggability
 *                                      handle
 * @param[in]  qat_dbg_priv_cleanup_cb  Clean up callback
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_SUCCESS        Callback set successfully
 ******************************************************************
 */
CpaStatus icp_adf_log_set_priv_cleanup_cb(
    icp_adf_dbg_handle_t *handle,
    icp_adf_dbg_priv_cleanup_callback qat_dbg_priv_cleanup_cb);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Inform Debuggability about QAT error response
 *
 * @description
 *      This function is used to notify Debuggability about error
 *      response form QAT. An ioctl to Debuggability character
 *      device is performed for storing running processes memory
 *      map purpose.
 *
 * @param[in]  handle  Pointer to Debuggability handle
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_FAIL           Failed to perform ioctl
 * @retval CPA_STATUS_SUCCESS        Notification sent successfully
 ******************************************************************
 */
CpaStatus icp_adf_log_err_resp_notify(icp_adf_dbg_handle_t *handle);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Initialize QAT Debuggability
 *
 * @description
 *      Initialize QAT Debuggability for given device.
 *
 * @param[in]  dev_handle  Pointer to Debuggability device handle
 * @param[in]  accel_id    Accelerator id
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_FAIL           Initialization failed
 * @retval CPA_STATUS_SUCCESS        Initialization succeeded
 ******************************************************************
 */
CpaStatus icp_adf_log_init_device(icp_adf_dbg_dev_handle_t *dev_handle,
                                  Cpa32U accel_id);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Reinitialize QAT Debuggability
 *
 * @description
 *      Reinitialize QAT Debuggability for given device.
 *
 * @param[in]  dev_handle  Pointer to Debuggability device handle
 * @param[in]  accel_id    Accelerator id
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_FAIL           Reinitialization failed
 * @retval CPA_STATUS_SUCCESS        Reinitialization succeeded
 ******************************************************************
 */
CpaStatus icp_adf_log_reinit_device(icp_adf_dbg_dev_handle_t *dev_handle,
                                    Cpa32U accel_id);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Initialize QAT Debuggability for physical device
 *
 * @description
 *      Initialize QAT Debuggability for given physical device
 *      identified by VF domain and bus.
 *
 * @param[in]  dev_handle  Pointer to Debuggability device handle
 * @param[in]  domain      PCI domain
 * @param[in]  bus         PCI bus
 * @param[in]  dev         PCI device (slot)
 * @param[in]  func        PCI function
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_FAIL           Initialization failed
 * @retval CPA_STATUS_SUCCESS        Initialization succeeded
 ******************************************************************
 */
CpaStatus icp_adf_log_init_device_vf(icp_adf_dbg_dev_handle_t *dev_handle,
                                     Cpa32U domain,
                                     Cpa8U bus,
                                     Cpa8U dev,
                                     Cpa8U func);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Deinitialize QAT Debuggability
 *
 * @description
 *      Deinitialize QAT Debuggability for given device.
 *
 * @param[in]  dev_handle  Pointer to Debuggability device handle
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_FAIL           Deinitialization failed
 * @retval CPA_STATUS_SUCCESS        Deinitialization succeeded
 ******************************************************************
 */
CpaStatus icp_adf_log_release_device(icp_adf_dbg_dev_handle_t *dev_handle);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Initialize QAT Debuggability handle
 *
 * @description
 *      Initialize QAT Debuggability handle for given device.
 *
 * @param[in]  dev_handle  Pointer to Debuggability device handle
 * @param[in]  handle      Pointer to Debuggability handle
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_FAIL           Initialization failed
 * @retval CPA_STATUS_SUCCESS        Initialization succeeded
 ******************************************************************
 */
CpaStatus icp_adf_log_init_handle(icp_adf_dbg_dev_handle_t *dev_handle,
                                  icp_adf_dbg_handle_t *handle);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Reinitialize QAT Debuggability handle
 *
 * @description
 *      Reinitialize QAT Debuggability handle for given device.
 *
 * @param[in]  dev_handle  Pointer to Debuggability device handle
 * @param[in]  handle      Pointer to Debuggability handle
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_FAIL           Reinitialization failed
 * @retval CPA_STATUS_SUCCESS        Reinitialization succeeded
 ******************************************************************
 */
CpaStatus icp_adf_log_reinit_handle(icp_adf_dbg_dev_handle_t *dev_handle,
                                    icp_adf_dbg_handle_t *handle);

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Deinitialize QAT Debuggability handle
 *
 * @description
 *      Deinitialize QAT Debuggability handle for given device.
 *
 * @param[in]  handle      Pointer to Debuggability handle
 *
 * @retval CPA_STATUS_INVALID_PARAM  Invalid arguments provided
 * @retval CPA_STATUS_FAIL           Deinitialization failed
 * @retval CPA_STATUS_SUCCESS        Deinitialization succeeded
 ******************************************************************
 */
CpaStatus icp_adf_log_release_handle(icp_adf_dbg_handle_t *handle);
#endif /* ICP_ADF_DBG_LOG_H_ */
