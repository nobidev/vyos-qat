/******************************************************************************
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
 *****************************************************************************/
/******************************************************************************
 * @file icp_adf_dbg_log.c
 *
 * @description
 *      This file contains implementation of the QAT debug logger utilities.
 *
 *****************************************************************************/

/* System headers */
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>

/* Project headers */
#include "icp_adf_dbg_log.h"
#include "Osal.h"
#include "adf_kernel_types.h"
#include "qat_dbg_user.h"
#include "qae_mem.h"
#include "icp_platform.h"

/* Type definitions */
typedef struct qatd_ring_desc adf_dbg_buffer_desc_t;
typedef struct qatd_ioctl_req qatd_ioctl_req_t;

/*
*******************************************************************************
* Private definitions
*******************************************************************************
*/
#define QAT_DBG_BUFFERS_FULL_MSG_DEBOUNCE_NS 30000000000LL

/*
*******************************************************************************
* Private functions
*******************************************************************************
*/
STATIC pid_t get_pid(void)
{
    static volatile pid_t cached_value = -1;

    if (cached_value < 0)
        cached_value = getpid();

    return cached_value;
}

/*
 ******************************************************************
 * @ingroup qat_dbg
 *      Perform a ioctl call to qat_debug device
 *
 * @description
 *      This macro validates required input arguments, performs
 *      ioctl syscall to Debuggability character device, and
 *      validates the call return code.
 *
 * @context
 *      Should be called from function which returns variable of
 *      type CpaStatus
 *
 * @param[in] dev_handle  pointer to Debuggability device handle
 *                        of type icp_adf_dbg_dev_handle_t
 * @param[in] request     ioctl request
 * @param[in] param       pointer to qatd_ioctl_req_t structure
 *                        which will be passed as ioctl argument
 *
 * @retval none
 *
 ******************************************************************
 */
#define ADF_LOG_REQUEST(dev_handle, request, param)                            \
    do                                                                         \
    {                                                                          \
        int fd;                                                                \
                                                                               \
        ICP_CHECK_FOR_NULL_PARAM(dev_handle);                                  \
        if ((fd = (dev_handle)->fd) < 0)                                       \
        {                                                                      \
            ADF_ERROR("No file descriptor for ring\n");                        \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
        if (ioctl(fd, (request), (param)))                                     \
        {                                                                      \
            ADF_ERROR(#request " ioctl failed\n");                             \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
                                                                               \
        return CPA_STATUS_SUCCESS;                                             \
    } while (0)

STATIC CpaStatus dbg_log_buffer_acquire(icp_adf_dbg_dev_handle_t *dev_handle,
                                        qatd_ioctl_req_t *req)
{
    ADF_LOG_REQUEST(dev_handle, IOCTL_QATD_BUFFER_REQ, req);
}

STATIC CpaStatus dbg_log_buffer_release(icp_adf_dbg_dev_handle_t *dev_handle,
                                        qatd_ioctl_req_t *req)
{
    ADF_LOG_REQUEST(dev_handle, IOCTL_QATD_BUFFER_RELEASE, req);
}

STATIC CpaStatus dbg_log_buffer_swap(icp_adf_dbg_dev_handle_t *dev_handle,
                                     qatd_ioctl_req_t *req)
{
    ADF_LOG_REQUEST(dev_handle, IOCTL_QATD_SYNC_REQ, req);
}

STATIC CpaStatus dbg_log_get_status(icp_adf_dbg_dev_handle_t *dev_handle,
                                    qatd_ioctl_req_t *req)
{
    ADF_LOG_REQUEST(dev_handle, IOCTL_QATD_STATUS, req);
}

STATIC CpaStatus dbg_log_err_resp_notify(icp_adf_dbg_dev_handle_t *dev_handle,
                                         qatd_ioctl_req_t *req)
{
    ADF_LOG_REQUEST(dev_handle, IOCTL_QATD_ERR_RESP, req);
}

STATIC CpaStatus adf_log_daemon_init(icp_adf_dbg_handle_t *handle,
                                     enum qatd_sync_mode sync_mode)
{
    /* This is an internal function - input parameters are checked by caller */
    if (sync_mode == QATD_SYNC_CONT)
    {
        handle->qat_dbg_daemon_msgq_id =
            msgget(QATD_DAEMON_KEY + handle->dev_handle->accel_id,
                   QATD_IPC_PERM | IPC_CREAT);
        if (handle->qat_dbg_daemon_msgq_id < 0)
        {
            ADF_ERROR("Unable to create sync daemon queue\n");
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        handle->qat_dbg_daemon_msgq_id = -1;
    }

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus adf_log_daemon_notify(icp_adf_dbg_handle_t *handle,
                                       unsigned int buffer_id)
{
    /* This is an internal function - input parameters are checked by caller */
    if (handle->qat_dbg_daemon_msgq_id >= 0)
    {
        /* In case of cont-sync enabled */
        int status;
        icp_adf_dbg_sync_msg_t message;

        message.msg_type = QATD_IPC_MSGTYPE;
        message.buffer_id = buffer_id;
        /* Argument msgsz should not include size of field mtype in struct
         * msgbuf */
        status = msgsnd(handle->qat_dbg_daemon_msgq_id,
                        &message,
                        sizeof(message) - sizeof(message.msg_type),
                        0);
        if (status < 0)
        {
            return CPA_STATUS_RETRY;
        }
    }

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus adf_log_phys_to_virt_SGL(icp_adf_dbg_dev_handle_t *dev_handle,
                                          CpaPhysicalAddr src_phys,
                                          CpaPhysicalAddr dst_phys,
                                          void **src_virt,
                                          void **dst_virt)
{
    /* This is an internal function - input parameters are checked by caller */
    void *src_virt_addr;
    void *dst_virt_addr;

    src_virt_addr = qaePhysToVirtNUMA(src_phys);
    dst_virt_addr = qaePhysToVirtNUMA(dst_phys);
    if (!src_virt_addr || !dst_virt_addr)
    {
        return CPA_STATUS_FAIL;
    }

    *src_virt = src_virt_addr;
    *dst_virt = dst_virt_addr;

    return CPA_STATUS_SUCCESS;
}

STATIC OSAL_INLINE CpaStatus
adf_log_handle_new_buffer(icp_adf_dbg_handle_t *handle,
                          struct qatd_ioctl_req *req)
{
    /* This is an internal function - input parameters are checked by caller */
    adf_dbg_buffer_desc_t *dbg_buffer_desc;
    icp_adf_dbg_dev_handle_t *dev_handle;

    dev_handle = handle->dev_handle;

    if (CPA_STATUS_SUCCESS != req->request_result)
    {
        Cpa64S last_msg_ts;

        last_msg_ts =
            __sync_lock_test_and_set(&dev_handle->last_msg_ts, handle->msg_ts);
        if (last_msg_ts != 0)
        {
            /* Limit number of error messages per device */
            return (-EAGAIN == req->request_result) ? CPA_STATUS_RETRY
                                                    : CPA_STATUS_FAIL;
        }
        switch (req->request_result)
        {
            case -EAGAIN:
                ADF_PRINT("Debug buffers are full for device %u. Check DEBUG "
                          "configuration and qat_dbg_sync_deamon state\n",
                          dev_handle->accel_id);
                return CPA_STATUS_RETRY;
            case -ENOMEM:
                ADF_ERROR("Not enough debug buffers configured for device %u. "
                          "Check DEBUG configuration\n",
                          dev_handle->accel_id);
                return CPA_STATUS_FAIL;
            case -EBUSY:
                ADF_ERROR("Device %u is in reset\n", dev_handle->accel_id);
                return CPA_STATUS_RESTARTING;
            default:
                ADF_ERROR("Buffer sync request for device %u failed\n",
                          dev_handle->accel_id);
                return CPA_STATUS_FAIL;
        }
    }

    handle->qat_dbg_buffer_size = req->buffer_sz;
    dbg_buffer_desc =
        (adf_dbg_buffer_desc_t *)ICP_MMAP(0,
                                          handle->qat_dbg_buffer_size,
                                          PROT_READ | PROT_WRITE,
                                          MAP_SHARED | MAP_LOCKED,
                                          dev_handle->fd,
                                          req->buffer_addr);
    if (MAP_FAILED == dbg_buffer_desc)
    {
        CpaStatus status;

        ADF_ERROR("Memory map failed\n");
        status = dbg_log_buffer_release(dev_handle, req);
        if (CPA_STATUS_SUCCESS != status ||
            CPA_STATUS_SUCCESS != req->request_result)
        {
            ADF_ERROR("Sending buffer release request failed\n");
        }

        handle->qat_dbg_buffer_desc = NULL;

        return CPA_STATUS_FAIL;
    }
    handle->qat_dbg_buffer_desc = dbg_buffer_desc;

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus adf_log_init_buffer(icp_adf_dbg_handle_t *handle)
{
    /* This is an internal function - input parameters are checked by caller */
    CpaStatus status;
    qatd_ioctl_req_t req = { 0 };

    req.instance_id = handle->dev_handle->accel_id;
    status = dbg_log_buffer_acquire(handle->dev_handle, &req);
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("Sending buffer acquire request failed\n");
        return CPA_STATUS_FAIL;
    }
    /* Do not check req->request_result here */

    return adf_log_handle_new_buffer(handle, &req);
}

STATIC OSAL_INLINE CpaStatus
adf_log_prepare_buffer_release(icp_adf_dbg_handle_t *handle,
                               struct qatd_ioctl_req *req)
{
    /* This is an internal function - input parameters are checked by caller */
    CpaStatus status;

    if (!handle->qat_dbg_buffer_desc)
    {
        return CPA_STATUS_RESOURCE;
    }

    req->buffer_id =
        ((adf_dbg_buffer_desc_t *)handle->qat_dbg_buffer_desc)->buffer_id;
    status = adf_log_daemon_notify(handle, req->buffer_id);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    status = (long int)ICP_MUNMAP(handle->qat_dbg_buffer_desc,
                                  handle->qat_dbg_buffer_size);
    if (status)
    {
        ADF_ERROR("Memory unmap failed\n");
        return CPA_STATUS_FAIL;
    }

    handle->qat_dbg_buffer_desc = NULL;
    req->instance_id = handle->dev_handle->accel_id;

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus adf_log_release_buffer(icp_adf_dbg_handle_t *handle)
{
    CpaStatus status;
    qatd_ioctl_req_t req = { 0 };

    ICP_CHECK_FOR_NULL_PARAM(handle);
    ICP_CHECK_FOR_NULL_PARAM(handle->dev_handle);

    status = adf_log_prepare_buffer_release(handle, &req);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    status = dbg_log_buffer_release(handle->dev_handle, &req);
    if (CPA_STATUS_SUCCESS != status ||
        CPA_STATUS_SUCCESS != req.request_result)
    {
        ADF_ERROR("Sending buffer release request failed\n");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus adf_log_swap_buffer(icp_adf_dbg_handle_t *handle)
{
    /* This is an internal function - input parameters are checked by caller */
    CpaStatus status;
    qatd_ioctl_req_t req = { 0 };

    status = adf_log_prepare_buffer_release(handle, &req);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    status = dbg_log_buffer_swap(handle->dev_handle, &req);
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("Sending buffer swap request failed\n");
        return CPA_STATUS_FAIL;
    }
    /* Do not check req->request_result here */

    return adf_log_handle_new_buffer(handle, &req);
}

STATIC CpaStatus adf_log_put_msg(struct icp_adf_dbg_handle_s *handle,
                                 struct icp_adf_dbg_entry_header_s *header,
                                 CpaBoolean clean_cd,
                                 uint8_t *in_buf,
                                 uint32_t msg_size,
                                 uint8_t *src_sgl,
                                 uint32_t src_sgl_size,
                                 uint8_t *dst_sgl,
                                 uint32_t dst_sgl_size,
                                 uint8_t *misc,
                                 uint32_t misc_size)
{
    /* This is an internal function - input parameters are checked by caller */
    unsigned int ring_size, new_head, orig_head, entire_msg_size;
    struct qatd_ring_desc *buffer_desc;
    uint8_t *target_addr;
    Cpa64S timestamp;

    buffer_desc = handle->qat_dbg_buffer_desc;
    entire_msg_size = sizeof(struct icp_adf_dbg_entry_header_s) + msg_size +
                      src_sgl_size + dst_sgl_size + misc_size;
    orig_head = buffer_desc->head;
    new_head = buffer_desc->head + entire_msg_size;

    if (buffer_desc->ring_size <= sizeof(struct qatd_ring_desc))
    {
        return QATD_PUT_MSG_RING_FULL;
    }

    ring_size = buffer_desc->ring_size - sizeof(struct qatd_ring_desc);
    if (new_head > ring_size)
    {
        /* Check if there is enough space in tail */
        if (buffer_desc->tail > 0)
        {
            /* There is some space in the bottom of buffer */
            new_head = entire_msg_size;
            if (new_head >= buffer_desc->tail)
            {
                return QATD_PUT_MSG_RING_FULL;
            }

            buffer_desc->end = orig_head;
            orig_head = 0;
            buffer_desc->overlaps++;
            buffer_desc->log_entries = 0;
        }
        else
        {
            return QATD_PUT_MSG_RING_FULL;
        }
    }
    else if (buffer_desc->head < buffer_desc->tail &&
             new_head >= buffer_desc->tail)
    {
        return QATD_PUT_MSG_RING_FULL;
    }

    buffer_desc->log_entries++;
    buffer_desc->log_entries_all++;
    buffer_desc->last_ts = header->ts;
    header->msg_len = msg_size;
    header->src_sgl_len = src_sgl_size;
    header->dst_sgl_len = dst_sgl_size;
    header->misc_len = misc_size;

    target_addr =
        (uint8_t *)buffer_desc + sizeof(struct qatd_ring_desc) + orig_head;

    /* Copy header */
    memcpy(target_addr, header, sizeof(struct icp_adf_dbg_entry_header_s));
    target_addr += sizeof(struct icp_adf_dbg_entry_header_s);
    /* Copy content */
    memcpy(target_addr, in_buf, msg_size);
    if (clean_cd)
    {
        if (handle->qat_dbg_priv_cleanup_cb)
        {
            handle->qat_dbg_priv_cleanup_cb(target_addr);
        }
    }

    target_addr += msg_size;

    /* Copy SGLs */
    if (src_sgl && src_sgl_size > 0)
    {
        memcpy(target_addr, src_sgl, src_sgl_size);
        target_addr += src_sgl_size;
    }
    if (dst_sgl && dst_sgl_size > 0)
    {
        memcpy(target_addr, dst_sgl, dst_sgl_size);
        target_addr += dst_sgl_size;
    }
    /* Copy misc */
    if (misc && misc_size > 0)
    {
        memcpy(target_addr, misc, misc_size);
    }

    buffer_desc->head = new_head;

    timestamp =
        (Cpa64S)osalAtomicGet((OsalAtomic *)&(handle->dev_handle->last_msg_ts));
    if (timestamp != 0 && ((Cpa64S)handle->msg_ts - timestamp) >=
                              QAT_DBG_BUFFERS_FULL_MSG_DEBOUNCE_NS)
    {
        osalAtomicSet(0, (OsalAtomic *)&(handle->dev_handle->last_msg_ts));
    }

    return CPA_STATUS_SUCCESS;
}

STATIC OSAL_INLINE CpaStatus
adf_log_put_msg_wrapper(struct icp_adf_dbg_handle_s *handle,
                        struct icp_adf_dbg_entry_header_s *header,
                        CpaBoolean clean_cd,
                        struct icp_adf_dbg_content_desc_s *dbg_content_desc)
{
    /* This is an internal function - input parameters are checked by caller */
    CpaStatus status;

    /* Should never happen */
    if (!handle->qat_dbg_buffer_desc)
    {
        ADF_ERROR("Debug buffer pointer is NULL\n");
        return CPA_STATUS_RESOURCE;
    }
    /* Put message and SGLs to debug buffers */
    status = adf_log_put_msg(handle,
                             header,
                             clean_cd,
                             dbg_content_desc->msg,
                             dbg_content_desc->msg_size,
                             dbg_content_desc->src_sgl,
                             dbg_content_desc->src_sgl_size,
                             dbg_content_desc->dst_sgl,
                             dbg_content_desc->dst_sgl_size,
                             dbg_content_desc->misc,
                             dbg_content_desc->misc_size);

    if (QATD_PUT_MSG_RING_FULL == status)
    {
        status = adf_log_swap_buffer(handle);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }

        status = adf_log_put_msg(handle,
                                 header,
                                 clean_cd,
                                 dbg_content_desc->msg,
                                 dbg_content_desc->msg_size,
                                 dbg_content_desc->src_sgl,
                                 dbg_content_desc->src_sgl_size,
                                 dbg_content_desc->dst_sgl,
                                 dbg_content_desc->dst_sgl_size,
                                 dbg_content_desc->misc,
                                 dbg_content_desc->misc_size);
        if (CPA_STATUS_SUCCESS != status)
        {
            ADF_ERROR("Putting message on debug ring failed\n");
            return status;
        }
    }

    return status;
}

STATIC CpaStatus
icp_adf_log_msg(struct icp_adf_dbg_handle_s *handle,
                struct icp_adf_dbg_content_desc_s *dbg_content_desc,
                CpaBoolean clean_cd)
{
    CpaStatus status;
    struct icp_adf_dbg_entry_header_s header = { 0 };

    ICP_CHECK_FOR_NULL_PARAM(handle);
    ICP_CHECK_FOR_NULL_PARAM(handle->dev_handle);
    ICP_CHECK_FOR_NULL_PARAM(dbg_content_desc);

    if (handle->dev_handle->fd < 0 || !handle->qat_dbg_enabled)
    {
        return CPA_STATUS_SUCCESS;
    }

    if (QATD_LEVEL_ALL != handle->qat_dbg_level)
    {
        if (QATD_LEVEL_FW_CALLS == handle->qat_dbg_level &&
            QATD_MSG_APICALL == dbg_content_desc->msg_type)
        {
            return CPA_STATUS_SUCCESS;
        }
        if (QATD_LEVEL_API_CALLS == handle->qat_dbg_level &&
            QATD_MSG_APICALL != dbg_content_desc->msg_type)
        {
            return CPA_STATUS_SUCCESS;
        }
        if (!handle->qat_dbg_level)
        {
            return CPA_STATUS_SUCCESS;
        }
    }

    handle->msg_ts = osalTimestampGetNs();
    /* Lazy init */
    if (!handle->qat_dbg_buffer_desc)
    {
        status = adf_log_init_buffer(handle);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
    }

    header.preamble = QATD_MSG_PREAMBLE;
    header.msg_type = dbg_content_desc->msg_type;
    header.api_type = dbg_content_desc->api_type;
    header.ts = handle->msg_ts;
    header.pid = get_pid();
    header.content_desc = dbg_content_desc->content_desc;
    header.bank = dbg_content_desc->bank;
    header.ring = dbg_content_desc->ring;

    if (dbg_content_desc->src_phy_addr && dbg_content_desc->src_sgl_size == 0 &&
        dbg_content_desc->dst_phy_addr && dbg_content_desc->dst_sgl_size == 0)
    {
        CpaPhysBufferList *srcSgl;
        CpaPhysBufferList *dstSgl;

        if (handle->qat_dbg_phys2virt_client_cb)
        {
            srcSgl = (CpaPhysBufferList *)handle->qat_dbg_phys2virt_client_cb(
                dbg_content_desc->src_phy_addr);
            if (srcSgl)
            {
                dbg_content_desc->src_sgl = srcSgl;
            }
            dstSgl = (CpaPhysBufferList *)handle->qat_dbg_phys2virt_client_cb(
                dbg_content_desc->dst_phy_addr);
            if (dstSgl)
            {
                dbg_content_desc->dst_sgl = dstSgl;
            }
        }
        else
        {
            status = adf_log_phys_to_virt_SGL(handle->dev_handle,
                                              dbg_content_desc->src_phy_addr,
                                              dbg_content_desc->dst_phy_addr,
                                              &dbg_content_desc->src_sgl,
                                              &dbg_content_desc->dst_sgl);
            if (CPA_STATUS_SUCCESS != status)
            {
                ADF_ERROR("Translating physical to virtual address failed\n");
                /* Store in the logs given invalid address */
                srcSgl = NULL;
                dstSgl = NULL;
            }
            else
            {
                srcSgl = (CpaPhysBufferList *)dbg_content_desc->src_sgl;
                dstSgl = (CpaPhysBufferList *)dbg_content_desc->dst_sgl;
            }
        }

        if (srcSgl)
        {
            dbg_content_desc->src_sgl_size =
                sizeof(CpaPhysBufferList) +
                srcSgl->numBuffers * sizeof(CpaPhysFlatBuffer);
        }
        if (dstSgl)
        {
            dbg_content_desc->dst_sgl_size =
                sizeof(CpaPhysBufferList) +
                dstSgl->numBuffers * sizeof(CpaPhysFlatBuffer);
        }
    }

    return adf_log_put_msg_wrapper(handle, &header, clean_cd, dbg_content_desc);
}

STATIC void icp_adf_log_reset_handle(icp_adf_dbg_handle_t *handle)
{
    /* This is an internal function - input parameters are checked by caller */
    handle->dev_handle = NULL;
    handle->qat_dbg_enabled = 0;
    handle->qat_dbg_level = 0;
    handle->qat_dbg_buffer_size = 0;
    handle->qat_dbg_buffer_desc = NULL;
    handle->qat_dbg_daemon_msgq_id = -1;

    if (handle->resp_api_lock)
    {
        (void)osalMutexDestroy((OsalMutex *)&handle->resp_api_lock);
        ICP_FREE(handle->resp_api_lock);
    }

    handle->qat_dbg_phys2virt_client_cb = NULL;
    handle->qat_dbg_priv_cleanup_cb = NULL;
}

STATIC CpaStatus
icp_adf_log_init_handle_int(icp_adf_dbg_dev_handle_t *dev_handle,
                            icp_adf_dbg_handle_t *handle,
                            CpaBoolean reinit)
{
    CpaStatus status;
    qatd_ioctl_req_t req = { 0 };

    ICP_CHECK_FOR_NULL_PARAM(dev_handle);
    ICP_CHECK_FOR_NULL_PARAM(handle);
    /* Logging module not present */
    if (dev_handle->fd < 0)
    {
        return CPA_STATUS_FAIL;
    }

    req.instance_id = dev_handle->accel_id;
    status = dbg_log_get_status(dev_handle, &req);

    if (CPA_STATUS_SUCCESS != status ||
        CPA_STATUS_SUCCESS != req.request_result)
    {
        ADF_ERROR("Failed to send status request\n");
        goto on_error;
    }

    handle->dev_handle = dev_handle;
    handle->qat_dbg_enabled = req.status;
    handle->qat_dbg_level = req.debug_level;
    handle->qat_dbg_buffer_size = 0;
    handle->qat_dbg_buffer_desc = NULL;
    handle->msg_ts = 0;

    if (CPA_FALSE == reinit)
    {
        handle->qat_dbg_phys2virt_client_cb = NULL;
        handle->qat_dbg_priv_cleanup_cb = NULL;
        handle->resp_api_lock = NULL;
    }
    if (QATD_LEVEL_ALL == handle->qat_dbg_level ||
        QATD_LEVEL_API_CALLS == handle->qat_dbg_level)
    {
        /* API calls are used in Traditional API which is thread safe */
        if (handle->resp_api_lock)
        {
            (void)osalMutexDestroy((OsalMutex *)&handle->resp_api_lock);
            ICP_FREE(handle->resp_api_lock);
        }
        if (OSAL_STATUS_SUCCESS !=
            osalMutexInit((OsalMutex *)&handle->resp_api_lock))
        {
            ADF_ERROR("Failed to init Osal mutex\n");
            goto on_error;
        }
    }

    status = adf_log_daemon_init(handle, req.sync_mode);
    if (CPA_STATUS_SUCCESS != status)
        goto on_error;

    return CPA_STATUS_SUCCESS;

on_error:
    icp_adf_log_reset_handle(handle);

    return CPA_STATUS_FAIL;
}

/*
*******************************************************************************
* Public functions
*******************************************************************************
*/
CpaBoolean icp_adf_log_is_enabled(icp_adf_dbg_handle_t *handle,
                                  enum icp_adf_dbg_level log_level)
{
    if (!handle)
    {
        return CPA_FALSE;
    }
    if (log_level == handle->qat_dbg_level || QATD_LEVEL_ALL == log_level ||
        QATD_LEVEL_ALL == handle->qat_dbg_level)
    {
        return CPA_TRUE;
    }

    return CPA_FALSE;
}

CpaStatus icp_adf_log_req(icp_adf_dbg_handle_t *handle,
                          icp_adf_dbg_content_desc_t *dbg_content_desc)
{
    return icp_adf_log_msg(handle, dbg_content_desc, CPA_TRUE);
}

CpaStatus icp_adf_log_apicall(icp_adf_dbg_handle_t *handle,
                              icp_adf_dbg_content_desc_t *db_content_desc)
{
    CpaStatus status;

    ICP_CHECK_FOR_NULL_PARAM(handle);

    if (OSAL_STATUS_SUCCESS !=
        osalMutexLock((OsalMutex *)&handle->resp_api_lock, OSAL_WAIT_FOREVER))
    {
        return CPA_STATUS_FATAL;
    }
    status = icp_adf_log_msg(handle, db_content_desc, CPA_FALSE);
    osalMutexUnlock((OsalMutex *)&handle->resp_api_lock);

    return status;
}

CpaStatus icp_adf_log_resp(icp_adf_dbg_handle_t *handle,
                           Cpa16U bank,
                           Cpa16U ring,
                           void *msg,
                           Cpa16U msg_size)
{
    CpaStatus status;
    icp_adf_dbg_entry_header_t header = { 0 };
    icp_adf_dbg_content_desc_t dbg_content_desc = { 0 };

    ICP_CHECK_FOR_NULL_PARAM(handle);
    ICP_CHECK_FOR_NULL_PARAM(handle->dev_handle);

    if (handle->dev_handle->fd < 0 || !handle->qat_dbg_enabled)
    {
        return CPA_STATUS_SUCCESS;
    }
    if (handle->resp_api_lock)
    {
        if (OSAL_STATUS_SUCCESS !=
            osalMutexLock((OsalMutex *)&handle->resp_api_lock,
                          OSAL_WAIT_FOREVER))
        {
            return CPA_STATUS_FATAL;
        }
    }

    handle->msg_ts = osalTimestampGetNs();
    /* Lazy init */
    if (!handle->qat_dbg_buffer_desc)
    {
        status = adf_log_init_buffer(handle);
        if (CPA_STATUS_SUCCESS != status)
        {
            goto on_exit;
        }
    }

    header.preamble = QATD_MSG_PREAMBLE;
    header.msg_type = QATD_MSG_RESPONSE;
    header.ts = handle->msg_ts;
    header.pid = get_pid();
    header.bank = bank;
    header.ring = ring;

    dbg_content_desc.msg = msg;
    dbg_content_desc.msg_size = msg_size;

    status =
        adf_log_put_msg_wrapper(handle, &header, CPA_FALSE, &dbg_content_desc);

on_exit:
    if (handle->resp_api_lock)
    {
        osalMutexUnlock((OsalMutex *)&handle->resp_api_lock);
    }

    return status;
}

/*
*******************************************************************************
* External callback setup functions
*******************************************************************************
*/
CpaStatus icp_adf_log_set_phys_to_virt_cb(
    icp_adf_dbg_handle_t *handle,
    icp_adf_dbg_phys2virt_callback qat_dbg_user_phys2virt)
{
    ICP_CHECK_FOR_NULL_PARAM(handle);

    handle->qat_dbg_phys2virt_client_cb = qat_dbg_user_phys2virt;

    return CPA_STATUS_SUCCESS;
}

CpaStatus icp_adf_log_set_priv_cleanup_cb(
    icp_adf_dbg_handle_t *handle,
    icp_adf_dbg_priv_cleanup_callback qat_dbg_priv_cleanup_cb)
{
    ICP_CHECK_FOR_NULL_PARAM(handle);

    handle->qat_dbg_priv_cleanup_cb = qat_dbg_priv_cleanup_cb;

    return CPA_STATUS_SUCCESS;
}

/*
*******************************************************************************
* Initialization and Deinitialization routines
*******************************************************************************
*/
CpaStatus icp_adf_log_init_handle(icp_adf_dbg_dev_handle_t *dev_handle,
                                  icp_adf_dbg_handle_t *handle)
{
    return icp_adf_log_init_handle_int(dev_handle, handle, CPA_FALSE);
}

CpaStatus icp_adf_log_reinit_handle(icp_adf_dbg_dev_handle_t *dev_handle,
                                    icp_adf_dbg_handle_t *handle)
{
    return icp_adf_log_init_handle_int(dev_handle, handle, CPA_TRUE);
}

CpaStatus icp_adf_log_release_handle(icp_adf_dbg_handle_t *handle)
{
    CpaStatus status;

    ICP_CHECK_FOR_NULL_PARAM(handle);

    status = adf_log_release_buffer(handle);
    icp_adf_log_reset_handle(handle);

    return status;
}

CpaStatus icp_adf_log_init_device(icp_adf_dbg_dev_handle_t *dev_handle,
                                  Cpa32U accel_id)
{
    ICP_CHECK_FOR_NULL_PARAM(dev_handle);

    dev_handle->fd = open(QATD_DEVICE_FILENAME, O_RDWR | O_NDELAY);
    if (dev_handle->fd < 0)
    {
        return CPA_STATUS_FAIL;
    }
    dev_handle->accel_id = accel_id;
    dev_handle->last_msg_ts = 0;

    return CPA_STATUS_SUCCESS;
}

CpaStatus icp_adf_log_reinit_device(icp_adf_dbg_dev_handle_t *dev_handle,
                                    Cpa32U accel_id)
{
    CpaStatus status;

    status = icp_adf_log_release_device(dev_handle);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    return icp_adf_log_init_device(dev_handle, accel_id);
}

CpaStatus icp_adf_log_init_device_vf(icp_adf_dbg_dev_handle_t *dev_handle,
                                     Cpa32U domain,
                                     Cpa8U bus,
                                     Cpa8U dev,
                                     Cpa8U func)
{
    CpaStatus status;
    struct qatd_ioctl_bsf2id_req bsf_req = { 0 };

    ICP_CHECK_FOR_NULL_PARAM(dev_handle);

    dev_handle->fd = open(QATD_DEVICE_FILENAME, O_RDWR | O_NDELAY);
    if (dev_handle->fd < 0)
    {
        return CPA_STATUS_FAIL;
    }

    /* Translate BDF to accel_id */
    bsf_req.domain = domain;
    bsf_req.bus = bus;
    bsf_req.dev = dev;
    bsf_req.func = func;

    status = ioctl(dev_handle->fd, IOCTL_QATD_BSF_TO_ID, &bsf_req);
    if (status || CPA_STATUS_SUCCESS != bsf_req.request_result)
    {
        close(dev_handle->fd);
        return CPA_STATUS_FAIL;
    }

    dev_handle->accel_id = bsf_req.device_id;
    dev_handle->last_msg_ts = 0;

    return CPA_STATUS_SUCCESS;
}

CpaStatus icp_adf_log_release_device(icp_adf_dbg_dev_handle_t *dev_handle)
{
    ICP_CHECK_FOR_NULL_PARAM(dev_handle);

    if (dev_handle->fd >= 0)
    {
        close(dev_handle->fd);
        dev_handle->fd = -1;
    }

    dev_handle->accel_id = -1;

    return CPA_STATUS_SUCCESS;
}

CpaStatus icp_adf_log_err_resp_notify(icp_adf_dbg_handle_t *handle)
{
    CpaStatus status;
    icp_adf_dbg_dev_handle_t *dev_handle;
    qatd_ioctl_req_t req = { 0 };

    ICP_CHECK_FOR_NULL_PARAM(handle);
    dev_handle = handle->dev_handle;
    ICP_CHECK_FOR_NULL_PARAM(dev_handle);

    if (dev_handle->fd < 0 || !handle->qat_dbg_enabled)
    {
        return CPA_STATUS_SUCCESS;
    }

    req.instance_id = dev_handle->accel_id;
    status = dbg_log_err_resp_notify(dev_handle, &req);
    if (CPA_STATUS_SUCCESS != status ||
        CPA_STATUS_SUCCESS != req.request_result)
    {
        ADF_ERROR("Sending error response notification failed\n");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}