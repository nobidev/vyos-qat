// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2015 - 2021 Intel Corporation */
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include "adf_accel_devices.h"
#include "adf_common_drv.h"
#include "icp_qat_fw_init_admin.h"
#include "adf_heartbeat.h"
#include "adf_cfg.h"

/* Keep version number in range 0-255 */
#define ADF_CONST_TABLE_VERSION (1)

/*
 * This table content is auto-generated.
 * Do not change manually - use the original source to regenerate on any
 * changes. This table must remain backwardly compatible within a silicon
 * generation. Extensions to the table are allowed within a generation. In
 * such a case:
 * - the table must remain backwardly compatible - i.e. descriptors built by
 * an older SAL must continue to work
 * - corresponding meta-data must be added to the capabilities infrastructure,
 * with code building descriptors based on that new extension checking the
 * capabilities.
 * If a non-backwardly-compatible table is needed for a new silicon generation,
 * then generation-specific tables should be created, i.e. the table for
 * previous generations must always remain backwardly compatible after the
 * first driver for that generation is released.
 */
static const u8 const_tab[1024] __aligned(1024) = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x02, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x13, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
0x54, 0x32, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab,
0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0,
0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc1, 0x05, 0x9e,
0xd8, 0x36, 0x7c, 0xd5, 0x07, 0x30, 0x70, 0xdd, 0x17, 0xf7, 0x0e, 0x59, 0x39,
0xff, 0xc0, 0x0b, 0x31, 0x68, 0x58, 0x15, 0x11, 0x64, 0xf9, 0x8f, 0xa7, 0xbe,
0xfa, 0x4f, 0xa4, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae,
0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f,
0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19, 0x05,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0xcb, 0xbb, 0x9d, 0x5d, 0xc1, 0x05, 0x9e, 0xd8, 0x62, 0x9a, 0x29,
0x2a, 0x36, 0x7c, 0xd5, 0x07, 0x91, 0x59, 0x01, 0x5a, 0x30, 0x70, 0xdd, 0x17,
0x15, 0x2f, 0xec, 0xd8, 0xf7, 0x0e, 0x59, 0x39, 0x67, 0x33, 0x26, 0x67, 0xff,
0xc0, 0x0b, 0x31, 0x8e, 0xb4, 0x4a, 0x87, 0x68, 0x58, 0x15, 0x11, 0xdb, 0x0c,
0x2e, 0x0d, 0x64, 0xf9, 0x8f, 0xa7, 0x47, 0xb5, 0x48, 0x1d, 0xbe, 0xfa, 0x4f,
0xa4, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb,
0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94,
0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51, 0x0e, 0x52,
0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13,
0x7e, 0x21, 0x79, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x18,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x01, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x15, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x02, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x14, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x02,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x24, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25,
0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x01, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x01,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x2B, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#define ADF_ADMIN_POLL_MIN_DELAY_US 20
#define ADF_ADMIN_POLL_MAX_DELAY_US (1000 * 1000)

int adf_put_admin_msg_sync(struct adf_accel_dev *accel_dev, u32 ae,
			   void *in, void *out)
{
	struct adf_admin_comms *admin = accel_dev->admin;
	int offset = ae * ADF_ADMINMSG_LEN * 2;
	void __iomem *mailbox = admin->mailbox_addr;
	int mb_offset = ae * ADF_MAILBOX_STRIDE;
	unsigned long delay = ADF_ADMIN_POLL_MIN_DELAY_US;
	int received;
	struct icp_qat_fw_init_admin_req *request = in;

	mutex_lock(&admin->lock);

	if (ADF_CSR_RD(mailbox, mb_offset) == 1) {
		mutex_unlock(&admin->lock);
		return -EAGAIN;
	}

	memcpy((u8 *)admin->virt_addr + offset, in, ADF_ADMINMSG_LEN);
	ADF_CSR_WR(mailbox, mb_offset, 1);
	received = 0;

	do {
		usleep_range(delay, delay * 2);
		delay *= 2;
		if (ADF_CSR_RD(mailbox, mb_offset) == 0) {
			received = 1;
			break;
		}
	} while (delay < ADF_ADMIN_POLL_MAX_DELAY_US);

	/* Response received from admin message, we can now
	 * make response data available in "out" parameter.
	 */
	if (received)
		memcpy(out, (u8 *)admin->virt_addr + offset +
		       ADF_ADMINMSG_LEN, ADF_ADMINMSG_LEN);
	else
		dev_err(&GET_DEV(accel_dev),
			"Failed to send admin msg %d to accelerator %d\n",
			request->cmd_id, ae);

	mutex_unlock(&admin->lock);
	return received ? 0 : -EFAULT;
}
EXPORT_SYMBOL_GPL(adf_put_admin_msg_sync);

static inline int adf_set_dc_ibuf(struct adf_accel_dev *accel_dev,
				  struct icp_qat_fw_init_admin_req *req)
{
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
	unsigned long ibuf_size = 0;

	if (!adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC,
				     ADF_INTER_BUF_SIZE, val)) {
		if (kstrtoul(val, 0, &ibuf_size))
			return -EFAULT;
	}

	if ((ibuf_size != 32) && (ibuf_size != 64))
		ibuf_size = 64;

	req->ibuf_size_in_kb = ibuf_size;

	return 0;
}

int adf_send_admin(struct adf_accel_dev *accel_dev,
		   struct icp_qat_fw_init_admin_req *req,
		   struct icp_qat_fw_init_admin_resp *resp,
		   unsigned long ae_mask)
{
	int i;

	for_each_set_bit(i, &ae_mask, GET_MAX_ACCELENGINES(accel_dev)) {
		if (adf_put_admin_msg_sync(accel_dev, i, req, resp) ||
		    resp->status)
			return -EFAULT;
	}

	return 0;
}

static int adf_init_me(struct adf_accel_dev *accel_dev)
{
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp resp;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	u32 ae_mask = hw_device->ae_mask;

	memset(&req, 0, sizeof(req));
	req.cmd_id = ICP_QAT_FW_INIT_ME;

	if (adf_set_dc_ibuf(accel_dev, &req))
		return -EFAULT;

	if (accel_dev->aram_info) {
		req.init_cfg_sz = sizeof(*accel_dev->aram_info);
		req.init_cfg_ptr = accel_dev->admin->aram_map_phys_addr;
	}
	if (adf_send_admin(accel_dev, &req, &resp, ae_mask))
		return -EFAULT;

	return 0;
}

static int adf_get_dc_capabilities(struct adf_accel_dev *accel_dev,
				   u32 *capabilities)
{
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp resp;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	unsigned long ae_mask = hw_device->ae_mask;
	unsigned char i;

	memset(&req, 0, sizeof(req));
	req.cmd_id = ICP_QAT_FW_COMP_CAPABILITY_GET;

	/* Loop through all AE's to check any one AE supports
	 * dc Extended features
	 */
	for_each_set_bit(i, &ae_mask, GET_MAX_ACCELENGINES(accel_dev)) {
		memset(&resp, 0, sizeof(resp));
		if (!adf_put_admin_msg_sync(accel_dev, i, &req, &resp) &&
		    !resp.status) {
			if (resp.extended_features != 0) {
				*capabilities = resp.extended_features;
				break;
			}
		} else {
			return -EFAULT;
		}
	}

	return 0;
}

static int adf_set_heartbeat_timer(struct adf_accel_dev *accel_dev)
{
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp resp;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	u32 ae_mask = hw_device->ae_mask;

	memset(&req, 0, sizeof(req));
	req.cmd_id = ICP_QAT_FW_HEARTBEAT_TIMER_SET;
	req.hb_cfg_ptr = accel_dev->admin->phy_hb_addr;
	if (adf_get_hb_timer(accel_dev, &req.heartbeat_ticks))
		return -EINVAL;

	if (adf_send_admin(accel_dev, &req, &resp, ae_mask))
		return -EFAULT;

	return 0;
}

static int adf_set_fw_constants(struct adf_accel_dev *accel_dev)
{
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp resp;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	u32 ae_mask = hw_device->ae_mask;

	memset(&req, 0, sizeof(req));
	req.cmd_id = ICP_QAT_FW_CONSTANTS_CFG;

	req.init_cfg_sz = sizeof(const_tab);
	req.init_cfg_ptr = accel_dev->admin->const_tbl_addr;

	dev_dbg(&GET_DEV(accel_dev), "QAT constants table version=%u\n",
		adf_get_const_table_version());

	if (adf_send_admin(accel_dev, &req, &resp, ae_mask))
		return -EFAULT;

	return 0;
}

static int adf_get_fw_status(struct adf_accel_dev *accel_dev,
			     u8 *major, u8 *minor, u8 *patch)
{
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp resp;
	u32 ae_mask = 1;

	memset(&req, 0, sizeof(req));
	req.cmd_id = ICP_QAT_FW_STATUS_GET;

	if (adf_send_admin(accel_dev, &req, &resp, ae_mask))
		return -EFAULT;

	*major = resp.version_major_num;
	*minor = resp.version_minor_num;
	*patch = resp.version_patch_num;

	return 0;
}

int adf_get_fw_timestamp(struct adf_accel_dev *accel_dev, u64 *timestamp)
{
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp rsp;
	unsigned int ae_mask = 1;

	if (!accel_dev || !timestamp)
		return -EFAULT;

	memset(&req, 0, sizeof(req));
	req.cmd_id = ICP_QAT_FW_TIMER_GET;

	if (adf_send_admin(accel_dev, &req, &rsp, ae_mask))
		return -EFAULT;

	*timestamp = rsp.timestamp;
	return 0;
}

/**
 * adf_send_admin_init() - Function sends init message to FW
 * @accel_dev: Pointer to acceleration device.
 *
 * Function sends admin init message to the FW
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_send_admin_init(struct adf_accel_dev *accel_dev)
{
	u32 dc_capabilities = 0;
	int ret;

	ret = adf_get_dc_capabilities(accel_dev, &dc_capabilities);
	if (ret) {
		dev_err(&GET_DEV(accel_dev), "Cannot get dc capabilities\n");
		return ret;
	}
	accel_dev->hw_device->extended_dc_capabilities = dc_capabilities;

	ret = adf_set_heartbeat_timer(accel_dev);
	if (ret) {
		if (ret == -EINVAL) {
			dev_err(&GET_DEV(accel_dev),
				"Cannot set heartbeat timer\n");
			return ret;
		}
		dev_err(&GET_DEV(accel_dev), "Heartbeat is not supported\n");
	}

	ret = adf_get_fw_status(accel_dev,
				&accel_dev->fw_versions.fw_version_major,
				&accel_dev->fw_versions.fw_version_minor,
				&accel_dev->fw_versions.fw_version_patch);
	if (ret) {
		dev_err(&GET_DEV(accel_dev), "Cannot get fw version\n");
		return ret;
	}

	dev_dbg(&GET_DEV(accel_dev), "FW version: %d.%d.%d\n",
		accel_dev->fw_versions.fw_version_major,
		accel_dev->fw_versions.fw_version_minor,
		accel_dev->fw_versions.fw_version_patch);

	ret = adf_set_fw_constants(accel_dev);
	if (ret) {
		dev_err(&GET_DEV(accel_dev), "Cannot set fw constants\n");
		return ret;
	}

	ret = adf_init_me(accel_dev);
	if (ret)
		dev_err(&GET_DEV(accel_dev), "Cannot init AE\n");

	return ret;
}
EXPORT_SYMBOL_GPL(adf_send_admin_init);

int adf_init_admin_comms(struct adf_accel_dev *accel_dev)
{
	struct adf_admin_comms *admin;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_bar *pmisc =
		&GET_BARS(accel_dev)[hw_data->get_misc_bar_id(hw_data)];
	void __iomem *csr = pmisc->virt_addr;
	struct adf_admin_info admin_csrs_info;
	u32 mailbox_offset, adminmsg_u, adminmsg_l;
	void __iomem *mailbox;
	u64 reg_val;

	admin = kzalloc_node(sizeof(*accel_dev->admin), GFP_KERNEL,
			     dev_to_node(&GET_DEV(accel_dev)));
	if (!admin)
		return -ENOMEM;
	admin->virt_addr = dma_alloc_coherent(&GET_DEV(accel_dev), PAGE_SIZE,
					      &admin->phy_addr, GFP_KERNEL);
	if (!admin->virt_addr) {
		dev_err(&GET_DEV(accel_dev), "Failed to allocate dma buff\n");
		kfree(admin);
		return -ENOMEM;
	}

	admin->virt_tbl_addr = dma_alloc_coherent(&GET_DEV(accel_dev),
						  PAGE_SIZE,
						  &admin->const_tbl_addr,
						  GFP_KERNEL);
	if (!admin->virt_tbl_addr) {
		dev_err(&GET_DEV(accel_dev), "Failed to allocate const_tbl\n");
		dma_free_coherent(&GET_DEV(accel_dev), PAGE_SIZE,
				  admin->virt_addr, admin->phy_addr);
		kfree(admin);
		return -ENOMEM;
	}

	memcpy(admin->virt_tbl_addr, const_tab, sizeof(const_tab));

	/* DMA ARAM address map */
	if (accel_dev->aram_info) {
		admin->aram_map_phys_addr =
			 dma_map_single(&GET_DEV(accel_dev),
					accel_dev->aram_info,
					sizeof(*accel_dev->aram_info),
					DMA_TO_DEVICE);

		if (unlikely(dma_mapping_error(&GET_DEV(accel_dev),
					       admin->aram_map_phys_addr)
						  )) {
			dma_free_coherent(&GET_DEV(accel_dev), PAGE_SIZE,
					  admin->virt_addr, admin->phy_addr);
			dma_free_coherent(&GET_DEV(accel_dev), PAGE_SIZE,
					  admin->virt_tbl_addr,
					  admin->const_tbl_addr);
			kfree(admin);
			return -ENOMEM;
		}
	}

	admin->virt_hb_addr = dma_alloc_coherent(&GET_DEV(accel_dev),
						 PAGE_SIZE,
						 &admin->phy_hb_addr,
						 GFP_KERNEL);
	if (!admin->virt_hb_addr) {
		dev_err(&GET_DEV(accel_dev), "Failed to allocate hb stats\n");
		dma_free_coherent(&GET_DEV(accel_dev), PAGE_SIZE,
				  admin->virt_addr, admin->phy_addr);
		dma_free_coherent(&GET_DEV(accel_dev), PAGE_SIZE,
				  admin->virt_tbl_addr, admin->const_tbl_addr);
		dma_unmap_single(&GET_DEV(accel_dev),
				 admin->aram_map_phys_addr,
				 sizeof(*accel_dev->aram_info),
				 DMA_TO_DEVICE);
		kfree(admin);
		return -ENOMEM;
	}

	hw_data->get_admin_info(&admin_csrs_info);
	mailbox_offset = admin_csrs_info.mailbox_offset;
	mailbox = (void __iomem *)((uintptr_t)csr + mailbox_offset);
	adminmsg_u = admin_csrs_info.admin_msg_ur;
	adminmsg_l = admin_csrs_info.admin_msg_lr;
	reg_val = (u64)admin->phy_addr;
	dev_dbg(&GET_DEV(accel_dev),
		"DMA table address 0x%llx\n",
		admin->aram_map_phys_addr);
	ADF_CSR_WR(csr, adminmsg_u, reg_val >> 32);
	ADF_CSR_WR(csr, adminmsg_l, reg_val);
	mutex_init(&admin->lock);
	admin->mailbox_addr = mailbox;
	accel_dev->admin = admin;
	return 0;
}
EXPORT_SYMBOL_GPL(adf_init_admin_comms);

u8 adf_get_const_table_version(void)
{
	return ADF_CONST_TABLE_VERSION;
}

void adf_exit_admin_comms(struct adf_accel_dev *accel_dev)
{
	struct adf_admin_comms *admin = accel_dev->admin;

	if (!admin)
		return;

	if (admin->virt_addr)
		dma_free_coherent(&GET_DEV(accel_dev), PAGE_SIZE,
				  admin->virt_addr, admin->phy_addr);
	if (admin->virt_tbl_addr)
		dma_free_coherent(&GET_DEV(accel_dev), PAGE_SIZE,
				  admin->virt_tbl_addr, admin->const_tbl_addr);

	if (admin->virt_hb_addr)
		dma_free_coherent(&GET_DEV(accel_dev), PAGE_SIZE,
				  admin->virt_hb_addr, admin->phy_hb_addr);


	mutex_destroy(&admin->lock);
	kfree(admin);
	accel_dev->admin = NULL;
}
EXPORT_SYMBOL_GPL(adf_exit_admin_comms);

int adf_get_services_enabled(struct adf_accel_dev *accel_dev,
			     u16 *ring_to_svc_map)
{
	int ret = 0;
	ret = adf_cfg_get_services_enabled(accel_dev, ring_to_svc_map);
	return ret;
}
EXPORT_SYMBOL_GPL(adf_get_services_enabled);


static void adf_set_arb_mapping(struct adf_accel_dev *accel_dev,
				struct icp_qat_fw_init_admin_req *req)
{
	u16 arb = 0, i = 0,
	    ring_to_svc_map = GET_HW_DATA(accel_dev)->ring_to_svc_map;

	for (i = 0; i < ADF_CFG_NUM_SERVICES; i++) {
		switch (GET_SRV_TYPE(ring_to_svc_map, i)) {
		case CRYPTO:
			req->pke_svc_arb_map |= BIT(arb);
			arb++;
			req->bulk_crypto_svc_arb_map |= BIT(arb);
			i++;
			break;
		case ASYM:
			req->pke_svc_arb_map |= BIT(arb);
			break;
		case SYM:
			req->bulk_crypto_svc_arb_map |= BIT(arb);
			break;
		case COMP:
			req->compression_svc_arb_map |= BIT(arb);
			break;
		}
		arb++;
	}
}

/*
 * adf_send_rl_init() - Function sends rate limiting init message to firmware
 * @accel_dev: Pointer to acceleration device which runs SLA.
 * @period: Rate limiting period.
 * @me_nr: Number of accel engines
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_send_rl_init(struct adf_accel_dev *accel_dev, u32 period, u8 me_nr)
{
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp rsp;

	memset(&req, 0, sizeof(req));
	req.cmd_id = ICP_QAT_FW_RL_INIT;

	adf_set_arb_mapping(accel_dev, &req);

	req.rl_period = period;
	req.config = 1;
	req.num_me = me_nr;
	if (adf_send_admin(accel_dev, &req, &rsp, 1))
		return -EFAULT;

	return 0;
}

/*
 * adf_send_rl_exit() - Function sends rate limiting disable message to firmware
 * @accel_dev: Pointer to acceleration device which runs SLA.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_send_rl_exit(struct adf_accel_dev *accel_dev)
{
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp rsp;

	memset(&req, 0, sizeof(req));
	req.cmd_id = ICP_QAT_FW_RL_INIT;

	/* RL_INIT message with 0s is re-used to disable RL */
	if (adf_send_admin(accel_dev, &req, &rsp, 1))
		return -EFAULT;

	return 0;
}

/*
 * adf_send_set_sla() - Function sends SLA config message
 * @accel_dev: Pointer to acceleration device
 * @vf_id: VF number
 * @service_id: Type of the service
 * @credit_per_sla: SLA ticks
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_send_set_sla(struct adf_accel_dev *accel_dev, u8 vf_id,
		     u8 service_id, u32 credit_per_sla)
{
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp rsp;

	memset(&req, 0, sizeof(req));
	req.cmd_id = ICP_QAT_FW_RL_SLA_CONFIG;
	req.credit_per_sla = credit_per_sla;
	req.service_id = service_id;
	req.vf_id = vf_id;

	if (adf_send_admin(accel_dev, &req, &rsp, 1))
		return -EFAULT;

	return 0;
}

/*
 * adf_send_du_start() - Function sends start message for Device Utilization
 * @accel_dev: Pointer to acceleration device which runs DU.
 *
 * Function starts Device Utilization in FW.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_send_du_start(struct adf_accel_dev *accel_dev)
{
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp rsp;

	memset(&req, 0, sizeof(req));
	req.cmd_id = ICP_QAT_FW_RL_DU_START;

	return adf_send_admin(accel_dev, &req, &rsp, 1);
}

/*
 * adf_send_du_stop () - Function sends stop message for Device Utilization.
 * It is advised that the user selects the time interval of 1-5sec before
 * initiating the adf_send_du_stop for to allow the firmware to collect
 * enough data.
 *
 * @accel_dev: Pointer to acceleration device which runs DU.
 *
 * Function stop measurements of DU in FW, and get results.
 * NOTE: This function is meant to be called by device specific code.
 * The size of 'du_table->dma_addr' varies based on the device,
 * thus it is the caller's responsibility to provide correct allocated memory.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_send_du_stop(struct adf_accel_dev *accel_dev)
{
	struct icp_qat_fw_init_admin_req req;
	struct icp_qat_fw_init_admin_resp rsp;
	struct adf_dev_util_table *du_table = &accel_dev->du_table;

	memset(&req, 0, sizeof(req));
	req.cmd_id = ICP_QAT_FW_RL_DU_STOP;
	req.cfg_ptr = du_table->dma_addr;

	if (adf_send_admin(accel_dev, &req, &rsp, 1))
		return -EFAULT;

	du_table->total_util = rsp.total_du_time;

	return 0;
}
