// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2015 - 2021 Intel Corporation */
#include "adf_accel_devices.h"
#include "adf_common_drv.h"
#include "adf_cfg_common.h"
#include "adf_transport_internal.h"
#include "adf_gen2_hw_data.h"

#include "icp_qat_hw.h"
#include <linux/mutex.h>
#define ADF_ARB_REG_SIZE 0x4
#define ADF_ARB_WTR_SIZE 0x20
#define ADF_ARB_REG_SLOT 0x1000
#define ADF_ARB_WTR_OFFSET 0x010
#define ADF_ARB_RO_EN_OFFSET 0x090
#define ADF_ARB_RINGSRVARBEN_OFFSET 0x19C

#define READ_CSR_ARB_RINGSRVARBEN(csr_addr, index) \
	ADF_CSR_RD(csr_addr, ADF_ARB_RINGSRVARBEN_OFFSET + \
	(ADF_ARB_REG_SLOT * index))

static DEFINE_MUTEX(csr_arb_lock);
#define WRITE_CSR_ARB_SARCONFIG(csr_addr, csr_offset, index, value) \
	ADF_CSR_WR(csr_addr, (csr_offset) + \
	(ADF_ARB_REG_SIZE * (index)), value)

#define WRITE_CSR_ARB_WRK_2_SER_MAP(csr_addr, csr_offset, \
	wrk_to_ser_map_offset, index, value) \
	ADF_CSR_WR(csr_addr, ((csr_offset) + (wrk_to_ser_map_offset)) + \
	(ADF_ARB_REG_SIZE * (index)), value)

#define WRITE_CSR_ARB_DBG_RST_ARB(csr_addr, csr_offset, \
	dbg_rst_arb_offset, value) \
	ADF_CSR_WR(csr_addr, ((csr_offset) + (dbg_rst_arb_offset)), value)

#ifdef QAT_HB_FAIL_SIM
void adf_write_csr_arb_wrk_2_ser_map(void *csr_addr, u32 csr_offset,
				     u32 wrk_to_ser_map_offset,
				     size_t index, u32 value)
{
	WRITE_CSR_ARB_WRK_2_SER_MAP(csr_addr, csr_offset,
				    wrk_to_ser_map_offset,
				    index, value);
}
#endif

int adf_init_arb(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_arb_info info;
	void __iomem *csr = accel_dev->transport->banks[0].csr_addr;
	u32 arb_cfg = 0x1U << 31 | 0x4 << 4 | 0x1;
	u32 arb;

	if (!hw_data->get_arb_info)
		return -EFAULT;

	hw_data->get_arb_info(&info);

	/* Reset DBG_RST_ARB before configuring arb service */
	WRITE_CSR_ARB_DBG_RST_ARB(csr, info.arbiter_offset,
				  info.dbg_rst_arb_offset, 1);
	WRITE_CSR_ARB_DBG_RST_ARB(csr, info.arbiter_offset,
				  info.dbg_rst_arb_offset, 0);

	/* Service arb configured for 32 bytes responses and
	 * ring flow control check enabled. */
	for (arb = 0; arb < ADF_ARB_NUM; arb++)
		WRITE_CSR_ARB_SARCONFIG(csr, info.arbiter_offset,
					arb, arb_cfg);

	return 0;
}
EXPORT_SYMBOL_GPL(adf_init_arb);

void adf_update_ring_arb(struct adf_etr_ring_data *ring)
{
	WRITE_CSR_ARB_RINGSRVARBEN(ring->bank->csr_addr,
				   ring->bank->bank_number,
				   ring->bank->ring_mask & 0xFF);
}

void adf_enable_ring_arb(void *csr_addr, unsigned int mask)
{
	u32 arbenable;
	mutex_lock(&csr_arb_lock);
	arbenable = READ_CSR_ARB_RINGSRVARBEN(csr_addr, 0);
	arbenable |= mask & 0xFF;
	WRITE_CSR_ARB_RINGSRVARBEN(csr_addr, 0, arbenable);
	mutex_unlock(&csr_arb_lock);
}

void adf_disable_ring_arb(void *csr_addr, unsigned int mask)
{
	u32 arbenable;
	mutex_lock(&csr_arb_lock);
	arbenable = READ_CSR_ARB_RINGSRVARBEN(csr_addr, 0);
	arbenable &= ~mask & 0xFF;
	WRITE_CSR_ARB_RINGSRVARBEN(csr_addr, 0, arbenable);
	mutex_unlock(&csr_arb_lock);
}


void adf_exit_arb(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_arb_info info;
	void __iomem *csr;
	unsigned int i;

	csr = accel_dev->transport->banks[0].csr_addr;

	if (!hw_data->get_arb_info)
		return;

	hw_data->get_arb_info(&info);

	/* Reset arbiter configuration */
	for (i = 0; i < ADF_ARB_NUM; i++)
		WRITE_CSR_ARB_SARCONFIG(csr,
					info.arbiter_offset, i, 0);
}
EXPORT_SYMBOL_GPL(adf_exit_arb);

void adf_disable_arb(struct adf_accel_dev *accel_dev)
{
	void __iomem *csr;
	unsigned int i;

	if (!accel_dev->transport)
		return;

	dev_info(&GET_DEV(accel_dev), "Disable arbiter.\n");

	csr = accel_dev->transport->banks[0].csr_addr;

	/* Disable arbitration on all rings */
	for (i = 0; i < GET_MAX_BANKS(accel_dev); i++)
		WRITE_CSR_ARB_RINGSRVARBEN(csr, i, 0);
}
EXPORT_SYMBOL_GPL(adf_disable_arb);
