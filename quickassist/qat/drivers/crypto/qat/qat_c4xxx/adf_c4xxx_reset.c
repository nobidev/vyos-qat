// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2017 - 2021 Intel Corporation */

#include "adf_c4xxx_reset.h"

static void adf_check_uncorr_status(struct adf_accel_dev *accel_dev)
{
	u32 aer_offset, reg_val = 0;
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);

	aer_offset = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ERR);
	if (!aer_offset) {
		dev_err(&pdev->dev,
			"Unable to find AER capability of the device\n");
	}
	pci_cfg_access_lock(pdev);
	pci_read_config_dword(pdev, aer_offset + PCI_ERR_UNCOR_STATUS,
			      &reg_val);
	pci_cfg_access_unlock(pdev);
	if (reg_val & PCIE_C4XXX_VALID_ERR_MASK) {
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable error occurred during reset\n");
		dev_err(&GET_DEV(accel_dev),
			"Error code value: 0x%04x\n", reg_val);
	}
}

static int adf_c4xxx_notify_reset(struct adf_accel_dev *accel_dev)
{
	u32 iosfsb_status;
	u32 iosfsb_port_cmd;
	u32 retries = ADF_C4XXX_IA2IOSFSB_POLLING_COUNT;
	void __iomem *csr_base =
		(&GET_BARS(accel_dev)[ADF_C4XXX_PMISC_BAR])->virt_addr;

	/* Check for pending IOSF-SB transactions */
	while (ADF_CSR_RD(csr_base, ADF_C4XXX_IA2IOSFSB_STATUS) &
	       ADF_C4XXX_IA2IOSFSB_STATUS_PEND) {
		if (retries--) {
			msleep(ADF_C4XXX_IA2IOSFSB_POLLING_INTERVAL);
			continue;
		}
		dev_err(&GET_DEV(accel_dev),
			"Pending IOSF-SB requests! Notification cancelled\n");
		return -EFAULT;
	}

	/* Setup port ID */
	iosfsb_port_cmd = ADF_C4XXX_GET_PORT_CMD(ADF_C4XXX_ETH_PORT_ID);
	ADF_CSR_WR(csr_base, ADF_C4XXX_IA2IOSFSB_PORTCMD, iosfsb_port_cmd);

	/* Setup register lower address */
	ADF_CSR_WR(csr_base, ADF_C4XXX_IA2IOSFSB_LOADD, 0);

	/* Setup register upper address and BAR index */
	ADF_CSR_WR(csr_base, ADF_C4XXX_IA2IOSFSB_HIADD, 0);

	/* Setup reset event in IA2IOSFSB_DATA[0...1] */
	ADF_CSR_WR(csr_base, ADF_C4XXX_IA2IOSFSB_DATA(0),
		   ADF_C4XXX_IOSFSB_RESET_EVENT);
	ADF_CSR_WR(csr_base, ADF_C4XXX_IA2IOSFSB_DATA(1), 0);

	/* Trigger IOSF-SB operation */
	ADF_CSR_WR(csr_base, ADF_C4XXX_IA2IOSFSB_KHOLE,
		   ADF_C4XXX_IOSFSB_TRIGGER);

	msleep(ADF_C4XXX_IA2IOSFSB_POLLING_INTERVAL);
	iosfsb_status = ADF_CSR_RD(csr_base, ADF_C4XXX_IA2IOSFSB_STATUS);
	if (iosfsb_status & ADF_C4XXX_IA2IOSFSB_STATUS_RTS) {
		dev_info(&GET_DEV(accel_dev),
			 "Post inline reset over IOSF-SB transaction\n");
		return -EFAULT;
	}
	dev_info(&GET_DEV(accel_dev),
		 "Successful inline reset over IOSF-SB transaction\n");
	return 0;
}

void adf_notify_and_wait_ethernet(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	u32 retries = 0;

	hw_device->reset_ack = false;

	if (adf_c4xxx_notify_reset(accel_dev))
		return;

	/* Wait for acknowledgment */
	do {
		msleep(ADF_C4XXX_ETH_ACK_POLLING_INTERVAL);
		/* Check if interrupt has happened */
		if (hw_device->reset_ack) {
			dev_info(&GET_DEV(accel_dev),
				 "Reset acknowledged by Ethernet driver\n");
			return;
		}
		retries++;
	} while (retries < ADF_C4XXX_MAX_ETH_ACK_ATTEMPT);

	if (retries >= ADF_C4XXX_MAX_ETH_ACK_ATTEMPT)
		dev_warn(&GET_DEV(accel_dev),
			 "Reset is not acknowledged by Ethernet driver\n");
}

void adf_dev_pre_reset_c4xxx(struct adf_accel_dev *accel_dev)
{
	dev_dbg(&GET_DEV(accel_dev), "Performing pre reset save\n");
	adf_dev_pre_reset(accel_dev);
}
EXPORT_SYMBOL_GPL(adf_dev_pre_reset_c4xxx);

void adf_dev_post_reset_c4xxx(struct adf_accel_dev *accel_dev)
{
	dev_dbg(&GET_DEV(accel_dev), "Performing post reset restore\n");
	adf_dev_post_reset(accel_dev);

	adf_check_uncorr_status(accel_dev);
}
EXPORT_SYMBOL_GPL(adf_dev_post_reset_c4xxx);

bool get_eth_doorbell_msg_c4xxx(struct adf_accel_dev *accel_dev)
{
	void __iomem *csr =
		(&GET_BARS(accel_dev)[ADF_C4XXX_PMISC_BAR])->virt_addr;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	u32 errsou11 = ADF_CSR_RD(csr, ADF_C4XXX_ERRSOU11);
	unsigned long doorbell_int = ADF_CSR_RD(csr,
						ADF_C4XXX_ETH_DOORBELL_INT);
	u32 eth_doorbell_reg[ADF_C4XXX_NUM_ETH_DOORBELL_REGS] = {0};
	bool handled = false;
	u32 data_reg;
	u8 i;

	/* Reset cannot be acknowledged until the reset */
	hw_device->reset_ack = false;

	/* Check if doorbell interrupt occurred. */
	if (errsou11 & ADF_C4XXX_DOORBELL_INT_SRC) {
		/* Decode doorbell messages from ethernet device */
		for_each_set_bit(i, &doorbell_int,
				 ADF_C4XXX_NUM_ETH_DOORBELL_REGS) {
			data_reg = ADF_C4XXX_ETH_DOORBELL(i);
			eth_doorbell_reg[i] = ADF_CSR_RD(csr, data_reg);
			dev_info(&GET_DEV(accel_dev),
				 "Receives Doorbell message(0x%08x)\n",
				 eth_doorbell_reg[i]);
		}
		/* Only need to check PF0 */
		if (eth_doorbell_reg[0] == ADF_C4XXX_IOSFSB_RESET_ACK) {
			dev_info(&GET_DEV(accel_dev),
				 "Receives pending reset ACK\n");
			hw_device->reset_ack = true;
		}
		/* Clear the interrupt source */
		ADF_CSR_WR(csr, ADF_C4XXX_ETH_DOORBELL_INT,
			   ADF_C4XXX_ETH_DOORBELL_MASK);
		handled = true;
	}

	return handled;
}

inline void adf_reset_hw_units_c4xxx(struct adf_accel_dev *accel_dev)
{
	void __iomem *pmisc =
		(&GET_BARS(accel_dev)[ADF_C4XXX_PMISC_BAR])->virt_addr;

	u32 global_clk_enable = ADF_C4XXX_GLOBAL_CLK_ENABLE_GENERIC_ARAM |
				ADF_C4XXX_GLOBAL_CLK_ENABLE_GENERIC_ICI_ENABLE |
				ADF_C4XXX_GLOBAL_CLK_ENABLE_GENERIC_ICE_ENABLE;

	u32 ixp_reset_generic = ADF_C4XXX_IXP_RESET_GENERIC_ARAM |
				ADF_C4XXX_IXP_RESET_GENERIC_INLINE_EGRESS |
				ADF_C4XXX_IXP_RESET_GENERIC_INLINE_INGRESS;

	/* To properly reset each of the units driver must:
	 * 1)Call out resetactive state using ixp reset generic
	 *   register;
	 * 2)Disable generic clock;
	 * 3)Take device out of reset by clearing ixp reset
	 *   generic register;
	 * 4)Re-enable generic clock;
	 */
	ADF_CSR_WR(pmisc, ADF_C4XXX_IXP_RESET_GENERIC, ixp_reset_generic);
	ADF_CSR_WR(pmisc, ADF_C4XXX_GLOBAL_CLK_ENABLE_GENERIC,
		   ADF_C4XXX_GLOBAL_CLK_ENABLE_GENERIC_DISABLE_ALL);
	ADF_CSR_WR(pmisc, ADF_C4XXX_IXP_RESET_GENERIC,
		   ADF_C4XXX_IXP_RESET_GENERIC_OUT_OF_RESET_TRIGGER);
	ADF_CSR_WR(pmisc, ADF_C4XXX_GLOBAL_CLK_ENABLE_GENERIC,
		   global_clk_enable);
}
