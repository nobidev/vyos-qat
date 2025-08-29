// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2015 - 2021 Intel Corporation */

#include <linux/delay.h>
#include <linux/sched.h>
#include "adf_uio_control.h"
#include "adf_accel_devices.h"
#include "adf_transport_access_macros.h"
#include "adf_common_drv.h"
#include "adf_uio_cleanup.h"

#define     ADF_RING_EMPTY_MAX_RETRY 15
#define     ADF_RING_EMPTY_RETRY_DELAY 2

struct bundle_orphan_ring {
	unsigned long  tx_mask;
	unsigned long  rx_mask;
	unsigned long  asym_mask;
	void __iomem   *csr_base;
};

/*
*    if orphan->tx_mask does not match with orphan->rx_mask
*/
static void check_orphan_ring(struct bundle_orphan_ring *orphan,
			      struct adf_hw_device_data *hw_data)
{
	int i;
	int tx_rx_gap = hw_data->tx_rx_gap;
	u8 num_rings_per_bank = hw_data->num_rings_per_bank;
	void __iomem *csr_base = orphan->csr_base;

	for (i = 0; i < num_rings_per_bank; i++) {
		if (test_bit(i, &orphan->tx_mask)) {
			int rx_ring = i + tx_rx_gap;

			if (!test_bit(rx_ring, &orphan->rx_mask)) {
				__clear_bit(i, &orphan->tx_mask);

				/* clean up this tx ring  */
				WRITE_CSR_RING_CONFIG(csr_base, 0, i, 0);
				WRITE_CSR_RING_BASE(csr_base, 0, i, 0);
			}

		} else if (test_bit(i, &orphan->rx_mask)) {
			int tx_ring = i - tx_rx_gap;

			if (!test_bit(tx_ring, &orphan->tx_mask)) {
				__clear_bit(i, &orphan->rx_mask);

				/* clean up this rx ring */
				WRITE_CSR_RING_CONFIG(csr_base, 0, i, 0);
				WRITE_CSR_RING_BASE(csr_base, 0, i, 0);
			}
		}
	}
}

static int get_orphan_bundle(struct uio_info *info,
			     struct adf_uio_control_accel *accel,
			     struct bundle_orphan_ring **orphan)
{
	int i;
	int ret = 0;
	void __iomem *csr_base;
	unsigned long tx_mask;
	unsigned long asym_mask;
	struct adf_accel_dev *accel_dev = accel->accel_dev;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u8 num_rings_per_bank = hw_data->num_rings_per_bank;
	struct bundle_orphan_ring *orphan_bundle;
	uint64_t base;
	struct list_head *entry;
	struct qat_uio_bundle_dev *priv = info->priv;
	struct adf_uio_control_bundle *bundle = priv->bundle;
	struct adf_uio_instance_rings *instance_rings;
	uint16_t ring_mask = 0;

	orphan_bundle = kzalloc(sizeof(*orphan_bundle), GFP_KERNEL);
	if (!orphan_bundle)
		return -ENOMEM;

	csr_base = info->mem[0].internal_addr;
	orphan_bundle->csr_base = csr_base;

	orphan_bundle->tx_mask = 0;
	orphan_bundle->rx_mask = 0;
	tx_mask = accel_dev->hw_device->tx_rings_mask;
	asym_mask = accel_dev->hw_device->asym_rings_mask;

	/* Get ring mask for this process. */
	mutex_lock(&bundle->list_lock);
	list_for_each(entry, &bundle->list) {
		instance_rings = list_entry(entry,
					    struct adf_uio_instance_rings,
					    list);
		if (instance_rings->user_pid == current->tgid) {
			ring_mask = instance_rings->ring_mask;
			break;
		}
	}
	mutex_unlock(&bundle->list_lock);

	for (i = 0; i < num_rings_per_bank; i++) {
		base = READ_CSR_RING_BASE(csr_base, 0, i);

		if (!base)
			continue;
		if (!(ring_mask & 1 << i))
			continue; /* Not reserved for this process. */

		if (test_bit(i, &tx_mask))
			__set_bit(i, &orphan_bundle->tx_mask);
		else
			__set_bit(i, &orphan_bundle->rx_mask);

		if (test_bit(i, &asym_mask))
			__set_bit(i, &orphan_bundle->asym_mask);
	}

	if (orphan_bundle->tx_mask || orphan_bundle->rx_mask)
		check_orphan_ring(orphan_bundle, hw_data);

	*orphan = orphan_bundle;

	return ret;
}

static void put_orphan_bundle(struct bundle_orphan_ring *bundle)
{
	if (!bundle)
		return;

	kfree(bundle);
}

/* cleanup all ring  */
static void cleanup_all_ring(struct adf_uio_control_accel *accel,
			     struct bundle_orphan_ring *orphan)
{
	int i;
	void __iomem *csr_base = orphan->csr_base;
	unsigned long  mask = orphan->rx_mask | orphan->tx_mask;
	struct adf_accel_dev *accel_dev = accel->accel_dev;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u8 num_rings_per_bank = hw_data->num_rings_per_bank;

	for (i = 0; i < num_rings_per_bank; i++) {
		if (!test_bit(i, &mask))
			continue;

		WRITE_CSR_RING_CONFIG(csr_base, 0, i, 0);
		WRITE_CSR_RING_BASE(csr_base, 0, i, 0);
	}
}

/*
 * Return true, if number of messages in tx ring is equal to number
 * of messages in corresponding rx ring, else false.
 */
static bool is_all_resp_recvd(struct bundle_orphan_ring *bundle,
			      const u8 num_rings_per_bank)
{
	u32 rx_tail = 0, tx_head = 0, rx_ring_msg_offset = 0,
	    tx_ring_msg_offset = 0, tx_rx_offset = num_rings_per_bank / 2,
	    idx = 0, retry = 0, delay = ADF_RING_EMPTY_RETRY_DELAY;

	do {
		for_each_set_bit(idx, &bundle->tx_mask, tx_rx_offset) {
			rx_tail = READ_CSR_RING_TAIL(bundle->csr_base, 0,
						     (idx + tx_rx_offset));
			tx_head = READ_CSR_RING_HEAD(bundle->csr_base, 0, idx);

			/*
			 * Normalize messages in tx rings to match rx ring
			 * message size, i.e., size of response message(32).
			 * Asym messages are 64 bytes each, so right shift
			 * by 1 to normalize to 32. Sym and compression
			 * messages are 128 bytes each, so right shift by 2
			 * to normalize to 32.
			 */
			if (bundle->asym_mask & (1 << idx))
				tx_ring_msg_offset = (tx_head >> 1);
			else
				tx_ring_msg_offset = (tx_head >> 2);

			rx_ring_msg_offset = rx_tail;

			if (tx_ring_msg_offset != rx_ring_msg_offset)
				break;
		}
		if (idx == tx_rx_offset)
			/* All Tx and Rx ring message counts match */
			return true;

		msleep(delay);
		delay *= 2;
	} while (++retry < ADF_RING_EMPTY_MAX_RETRY);

	return false;
}

static bool bundle_need_cleanup(struct uio_info *info,
				const u8 num_rings_per_bank)
{
	int i;
	void __iomem *csr_base = info->mem[0].internal_addr;

	for (i = 0; i < num_rings_per_bank; i++) {
		if (READ_CSR_RING_BASE(csr_base, 0, i))
			return true;
	}

	return false;
}

static void cleanup_orphan_ring(struct bundle_orphan_ring *orphan,
				struct adf_uio_control_accel *accel)
{
	struct adf_accel_dev *accel_dev = accel->accel_dev;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u8 number_rings_per_bank = hw_data->num_rings_per_bank;

	/* disable the interrupt */
	WRITE_CSR_INT_COL_EN(orphan->csr_base, 0, 0);

	/*
	 * wait firmware finish the in-process ring
	 * 1. disable all tx rings
	 * 2. check if all responses are received
	 * 3. reset all rings
	 */
	adf_disable_ring_arb(orphan->csr_base, orphan->tx_mask);

	if (!is_all_resp_recvd(orphan, number_rings_per_bank)) {
		dev_err(&GET_DEV(accel_dev), "Failed to clean up orphan rings\n");
		return;
	}

	/*
	 * When the execution reaches here, it is assumed that
	 * there is no inflight request in the rings and that
	 * there is no in-process ring.
	 */
	cleanup_all_ring(accel, orphan);
	pr_debug("QAT: orphan rings cleaned\n");
}

void adf_uio_do_cleanup_orphan(struct uio_info *info,
			       struct adf_uio_control_accel *accel)
{
	int ret;
	struct bundle_orphan_ring *orphan = NULL;
	struct adf_accel_dev *accel_dev = accel->accel_dev;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u8 number_rings_per_bank = hw_data->num_rings_per_bank;
	struct qat_uio_bundle_dev *priv = info->priv;
	struct adf_uio_control_bundle *bundle = priv->bundle;
	struct adf_uio_instance_rings *instance_rings, *tmp;
	int pid_found = 0;

	if (!bundle_need_cleanup(info, number_rings_per_bank))
		goto release;

	ret = get_orphan_bundle(info, accel, &orphan);
	if (ret < 0) {
		dev_err(&GET_DEV(accel_dev),
			"get orphan ring failed to cleanup bundle\n");
		return;
	}

	if (!orphan->tx_mask && !orphan->rx_mask)
		goto out;

	dev_warn(&GET_DEV(accel_dev), "Process %d %s exit with orphan rings\n",
		 current->tgid, current->comm);
	/*
	 * If the device is in reset phase, we do not need to clean the ring
	 * here since we have disabled BME and will clean the ring in
	 * stop/shutdown stage.
	 */
	if (!test_bit(ADF_STATUS_RESTARTING, &accel_dev->status))
		cleanup_orphan_ring(orphan, accel);
out:
	put_orphan_bundle(orphan);
release:
	/*
	 * If the user process died without releasing the rings
	 * then force a release here.
	*/
	mutex_lock(&bundle->list_lock);
	list_for_each_entry_safe(instance_rings, tmp, &bundle->list, list) {
		if (instance_rings->user_pid == current->tgid) {
			pid_found = 1;
			break;
		}
	}
	mutex_unlock(&bundle->list_lock);

	if (pid_found) {
		mutex_lock(&bundle->lock);
		bundle->rings_used &= ~instance_rings->ring_mask;
		mutex_unlock(&bundle->lock);
	}
}
