// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2017, 2019 - 2021 Intel Corporation */
#include "adf_dev_err.h"

struct reg_info {
	size_t	offs;
	char	*name;
};

static struct reg_info adf_err_regs[] = {
	{ADF_ERRSOU0, "ERRSOU0"},
	{ADF_ERRSOU1, "ERRSOU1"},
	{ADF_ERRSOU3, "ERRSOU3"},
	{ADF_ERRSOU4, "ERRSOU4"},
	{ADF_ERRSOU5, "ERRSOU5"},
	{ADF_ERRMSK0, "ERRMSK0"},
	{ADF_ERRMSK1, "ERRMSK1"},
	{ADF_ERRMSK3, "ERRMSK3"},
	{ADF_ERRMSK4, "ERRMSK4"},
	{ADF_ERRMSK5, "ERRMSK5"},
	{ADF_RICPPINTCTL, "RICPPINTCTL"},
	{ADF_RICPPINTSTS, "RICPPINTSTS"},
	{ADF_RIERRPUSHID, "RIERRPUSHID"},
	{ADF_RIERRPULLID, "RIERRPULLID"},
	{ADF_CPP_CFC_ERR_STATUS, "CPP_CFC_ERR_STATUS"},
	{ADF_CPP_CFC_ERR_PPID, "CPP_CFC_ERR_PPID"},
	{ADF_PDTCRTHRESH, "PDTCRTHRESH"},
	{ADF_TICPPINTCTL, "TICPPINTCTL"},
	{ADF_TICPPINTSTS, "TICPPINTSTS"},
	{ADF_TIERRPUSHID, "TIERRPUSHID"},
	{ADF_TIERRPULLID, "TIERRPULLID"},
	{ADF_SECRAMUERR, "SECRAMUERR"},
	{ADF_SECRAMUERRAD, "SECRAMUERRAD"},
	{ADF_CPPMEMTGTERR, "CPPMEMTGTERR"},
	{ADF_ERRPPID, "ERRPPID"},
	{ADF_TIMISCCTL, "TIMISCCTL"},
	{ADF_TIMISCSTS, "TIMISCSTS"},
	{ADF_TIERRPPID, "TIERRPPID"},
	{ADF_TINPDBGSTSR, "TINPDBGSTSR"},
	{ADF_TIPDBGSTSR, "TIPDBGSTSR"},
	{ADF_TICDBGSTSR, "TICDBGSTSR"},
	{ADF_TIICDBGSTSR, "TIICDBGSTSR"},
	{ADF_ADMINMSGSTSR, "ADMINMSGSTSR"},
	{ADF_SECRAMERR, "SECRAMERR"},
	{ADF_SECRAMERRAD, "ADF_SECRAMERRAD"},
	{ADF_EPERRLOG, "EPERRLOG"},
};

static u32 adf_get_wqstat(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_WQSTAT(dev));
}

static u32 adf_get_intmaskssm(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_INTMASKSSM(dev));
}

static u32 adf_get_intstatsssm(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_INTSTATSSM(dev));
}

static u32 adf_get_pperr(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_PPERR(dev));
}

static u32 adf_get_pperrid(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_PPERRID(dev));
}

static u32 adf_get_uerrssmsh(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_UERRSSMSH(dev));
}

static u32 adf_get_uerrssmshad(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_UERRSSMSHAD(dev));
}

static u32 adf_get_cerrssmmmp0(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CERRSSMMMP(dev, 0));
}

static u32 adf_get_cerrssmmmp1(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CERRSSMMMP(dev, 1));
}

static u32 adf_get_cerrssmmmp2(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CERRSSMMMP(dev, 2));
}

static u32 adf_get_cerrssmmmp3(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CERRSSMMMP(dev, 3));
}

static u32 adf_get_cerrssmmmp4(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CERRSSMMMP(dev, 4));
}

static u32 adf_get_cerrssmmmpad0(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CERRSSMMMPAD(dev, 0));
}

static u32 adf_get_cerrssmmmpad1(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CERRSSMMMPAD(dev, 1));
}

static u32 adf_get_cerrssmmmpad2(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CERRSSMMMPAD(dev, 2));
}

static u32 adf_get_cerrssmmmpad3(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CERRSSMMMPAD(dev, 3));
}

static u32 adf_get_cerrssmmmpad4(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CERRSSMMMPAD(dev, 4));
}

static u32 adf_get_uerrssmmmp0(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_UERRSSMMMP(dev, 0));
}

static u32 adf_get_uerrssmmmp1(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_UERRSSMMMP(dev, 1));
}

static u32 adf_get_uerrssmmmp2(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_UERRSSMMMP(dev, 2));
}

static u32 adf_get_uerrssmmmp3(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_UERRSSMMMP(dev, 3));
}

static u32 adf_get_uerrssmmmp4(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_UERRSSMMMP(dev, 4));
}

static u32 adf_get_uerrssmmmpad0(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_UERRSSMMMPAD(dev, 0));
}

static u32 adf_get_uerrssmmmpad1(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_UERRSSMMMPAD(dev, 1));
}

static u32 adf_get_uerrssmmmpad2(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_UERRSSMMMPAD(dev, 2));
}

static u32 adf_get_uerrssmmmpad3(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_UERRSSMMMPAD(dev, 3));
}

static u32 adf_get_uerrssmmmpad4(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_UERRSSMMMPAD(dev, 4));
}

static u32 adf_get_exprpssmcmp0(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_EXPRPSSMCMP(dev, 0));
}

static u32 adf_get_exprpssmcmp1(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_EXPRPSSMCMP(dev, 1));
}

static u32 adf_get_exprpssmxlt0(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_EXPRPSSMXLT(dev, 0));
}

static u32 adf_get_exprpssmxlt1(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_EXPRPSSMXLT(dev, 1));
}

static u32 adf_get_ustore_error_status(void __iomem *pmisc_bar_addr,
				       size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_USTORE_ERROR_STATUS(dev));
}

static u32 adf_get_reg_error_status(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_REG_ERROR_STATUS(dev));
}

static u32 adf_get_active_ctx_status(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_ACTIVE_CTX_STS(dev));
}

static u32 adf_get_indirect_ctx_status(void __iomem *pmisc_bar_addr,
				       size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_INDIRECT_CTX_STS(dev));
}

static u32 adf_get_ctx_enables_status(void __iomem *pmisc_bar_addr,
				      size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CTX_ENABLES(dev));
}

static u32 adf_get_misc_control_status(void __iomem *pmisc_bar_addr,
				       size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_MISC_CONTROL(dev));
}

static u32 adf_get_local_csr_status(void __iomem *pmisc_bar_addr,
				    size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_LOCAL_CSR_STATUS(dev));
}

static u32 adf_get_active_ctx_sig_events(void __iomem *pmisc_bar_addr,
					 size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_ACTIVE_CTX_SIG_EVENTS(dev));
}

static u32 adf_get_indirect_ctx_sig_events(void __iomem *pmisc_bar_addr,
					   size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_INDIRECT_CTX_SIG_EVENTS(dev));
}

static u32 adf_get_active_ctx_wakeup_events(void __iomem *pmisc_bar_addr,
					    size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_ACTIVE_CTX_WAKEUP_EVENTS(dev));
}

static u32 adf_get_indirect_ctx_wakeup_events(void __iomem *pmisc_bar_addr,
					      size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_INDIRECT_CTX_WAKEUP_EVENTS(dev));
}

static u32 adf_get_slicepowerdown(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_SLICEPWRDOWN(dev));
}

static u32 adf_get_cpm_slice_status(void __iomem *pmisc_bar_addr,
				    size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CPM_SLICE_STATUS(dev));
}

static u32 adf_get_cpminstid(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_CPMINSTID(dev));
}

static u32 adf_get_shintmaskssm(void __iomem *pmisc_bar_addr, size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_SHINTMASKSSM(dev));
}

static u32 adf_get_slicehangstatus(void __iomem *pmisc_bar_addr,
				   size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_SLICEHANGSTATUS(dev));
}

static u32 adf_get_softerrorparity(void __iomem *pmisc_bar_addr,
				   size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_SOFTERRORPARITY(dev));
}

static u32 adf_get_ssmsofterrorparitymask(void __iomem *pmisc_bar_addr,
					  size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_SSMSOFTERRORPARITYMASK(dev));
}

static u32 adf_get_ssmomethsts(void __iomem *pmisc_bar_addr,
			       size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_SSMOMETHSTS(dev));
}

static u32 adf_get_ssmemethsts(void __iomem *pmisc_bar_addr,
			       size_t dev)
{
	return ADF_CSR_RD(pmisc_bar_addr, ADF_SSMEMETHSTS(dev));
}

struct reg_array_info {
	u32	(*read)(void __iomem *, size_t);
	char	*name;
};

static struct reg_array_info adf_dev_gen2_err_regs[] = {
	{adf_get_softerrorparity, "SOFTERRORPARITY"},
	{adf_get_ssmsofterrorparitymask, "SSMSOFTERRORPARITYMASK"},
	{adf_get_ssmomethsts, "SSMOMETHSTS"},
	{adf_get_ssmemethsts, "SSMEMETHSTS"},
	{adf_get_shintmaskssm, "SHINTMASKSSM"},
	{adf_get_slicehangstatus, "SLICEHANGSTATUS"},
};

static struct reg_array_info adf_accel_err_regs[] = {
	{adf_get_wqstat, "WQSTAT"},
	{adf_get_intmaskssm, "INTMASKSSM"},
	{adf_get_intstatsssm, "INTSTATSSM"},
	{adf_get_pperr, "PPERR"},
	{adf_get_pperrid, "PPERRID"},
	{adf_get_uerrssmsh, "UERRSSMSH"},
	{adf_get_uerrssmshad, "UERRSSMSHAD"},
	{adf_get_cerrssmmmp0, "CERRSSMMMP0"},
	{adf_get_cerrssmmmp1, "CERRSSMMMP1"},
	{adf_get_cerrssmmmp2, "CERRSSMMMP2"},
	{adf_get_cerrssmmmp3, "CERRSSMMMP3"},
	{adf_get_cerrssmmmp4, "CERRSSMMMP4"},
	{adf_get_cerrssmmmpad0, "CERRSSMMMPAD0"},
	{adf_get_cerrssmmmpad1, "CERRSSMMMPAD1"},
	{adf_get_cerrssmmmpad2, "CERRSSMMMPAD2"},
	{adf_get_cerrssmmmpad3, "CERRSSMMMPAD3"},
	{adf_get_cerrssmmmpad4, "CERRSSMMMPAD4"},
	{adf_get_uerrssmmmp0, "UERRSSMMMP0"},
	{adf_get_uerrssmmmp1, "UERRSSMMMP1"},
	{adf_get_uerrssmmmp2, "UERRSSMMMP2"},
	{adf_get_uerrssmmmp3, "UERRSSMMMP3"},
	{adf_get_uerrssmmmp4, "UERRSSMMMP4"},
	{adf_get_uerrssmmmpad0, "UERRSSMMMPAD0"},
	{adf_get_uerrssmmmpad1, "UERRSSMMMPAD1"},
	{adf_get_uerrssmmmpad2, "UERRSSMMMPAD2"},
	{adf_get_uerrssmmmpad3, "UERRSSMMMPAD3"},
	{adf_get_uerrssmmmpad4, "UERRSSMMMPAD4"},
	{adf_get_exprpssmcmp0, "EXPRPSSMCMP0"},
	{adf_get_exprpssmcmp1, "EXPRPSSMCMP1"},
	{adf_get_exprpssmxlt0, "EXPRPSSMXLT0"},
	{adf_get_exprpssmxlt1, "EXPRPSSMXLT1"},
	{adf_get_ustore_error_status, "USTORE_ERROR_STATUS"},
	{adf_get_reg_error_status, "REG_ERROR_STATUS"},
	{adf_get_ctx_enables_status, "CTX_ENABLES"},
	{adf_get_active_ctx_status, "ACTIVE_CTX_STS"},
	{adf_get_indirect_ctx_status, "INDIRECT_CTX_STS"},
	{adf_get_active_ctx_sig_events, "ACTIVE_CTX_SIG_EVENTS"},
	{adf_get_indirect_ctx_sig_events, "INDIRECT_CTX_SIG_EVENTS"},
	{adf_get_active_ctx_wakeup_events, "ACTIVE_CTX_WAKEUP_EVENTS"},
	{adf_get_indirect_ctx_wakeup_events, "INDIRECT_CTX_WAKEUP_EVENTS"},
	{adf_get_misc_control_status, "MISC_CONTROL"},
	{adf_get_local_csr_status, "LOCAL_CSR_STATUS"},
	{adf_get_slicepowerdown, "SLICEPWRDOWN"},
	{adf_get_cpm_slice_status, "CPM_SLICE_STATUS"},
	{adf_get_cpminstid, "CPMINSTID"},
};

static char adf_printf_buf[128] = {0};
static size_t adf_printf_len;

static void adf_print_flush(struct adf_accel_dev *accel_dev)
{
	if (adf_printf_len > 0) {
		dev_err(&GET_DEV(accel_dev), "%.128s\n", adf_printf_buf);
		adf_printf_len = 0;
	}
}

static void adf_print_reg(struct adf_accel_dev *accel_dev,
			  const char *name, size_t idx, u32 val)
{
	adf_printf_len += snprintf(&adf_printf_buf[adf_printf_len],
			sizeof(adf_printf_buf) - adf_printf_len,
			"%s[%zu],%.8x,", name, idx, val);

	if (adf_printf_len >= 80)
		adf_print_flush(accel_dev);
}

static void adf_print_pcie_config_space(struct adf_accel_dev *accel_dev)
{
	int i;
	unsigned int val;
	struct pci_dev *pdev = accel_dev->accel_pci_dev.pci_dev;

	/* Report out entire PCI configuration space */
	for (i = 0; i < ADF_PCI_CFG_EXP_SZ; i += 4) {
		pci_read_config_dword(pdev, i, &val);
		dev_err(&GET_DEV(accel_dev),
			"PCI Config[0x%03X] 0x%08X\n", i, val);
	}
}

void adf_print_gen2_err_registers(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_bar *misc_bar =
		&GET_BARS(accel_dev)[hw_data->get_misc_bar_id(hw_data)];
	void __iomem *csr = misc_bar->virt_addr;
	size_t i;
	u32 val;

	for (i = 0; i < ARRAY_SIZE(adf_dev_gen2_err_regs); ++i) {
		size_t accel;

		for_each_set_bit(accel, &hw_data->accel_mask,
				 hw_data->num_accel) {
			val = adf_dev_gen2_err_regs[i].read(csr, accel);

			adf_print_reg(accel_dev, adf_dev_gen2_err_regs[i].name,
				      accel, val);
		}
	}
}
EXPORT_SYMBOL_GPL(adf_print_gen2_err_registers);

void adf_print_err_registers(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_bar *misc_bar =
		&GET_BARS(accel_dev)[hw_data->get_misc_bar_id(hw_data)];
	void __iomem *csr = misc_bar->virt_addr;
	size_t i;
	u32 val;

	for (i = 0; i < ARRAY_SIZE(adf_err_regs); ++i) {
		val = ADF_CSR_RD(csr, adf_err_regs[i].offs);

		adf_print_reg(accel_dev, adf_err_regs[i].name, 0, val);
	}

	for (i = 0; i < ARRAY_SIZE(adf_accel_err_regs); ++i) {
		size_t accel;

		for_each_set_bit(accel, &hw_data->accel_mask,
				 hw_data->num_accel) {
			val = adf_accel_err_regs[i].read(csr, accel);

			adf_print_reg(accel_dev, adf_accel_err_regs[i].name,
				      accel, val);
		}
	}
	adf_print_flush(accel_dev);
	adf_print_pcie_config_space(accel_dev);
}
EXPORT_SYMBOL_GPL(adf_print_err_registers);

void adf_clear_uncorrectable_error_regs(struct adf_accel_dev *accel_dev)
{
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);

	/* Clear uncorrectable error status, error first, error next
	 * error registers
	 */
	pci_write_config_dword(pdev, ADF_PFIEERRUNCSTSR, 0xFFFF);
	pci_write_config_dword(pdev, ADF_PFIEERRUNCFER, 0xFFFF);
	pci_write_config_dword(pdev, ADF_PFIEERRUNCNER, 0xFFFF);
}
EXPORT_SYMBOL_GPL(adf_clear_uncorrectable_error_regs);

static void adf_log_slice_hang(struct adf_accel_dev *accel_dev,
			       u8 accel_num, char *unit_name, u8 unit_number)
{
	dev_err(&GET_DEV(accel_dev),
		"SliceHang detected in %s%u unit of accel%u\n",
		unit_name, unit_number, accel_num);
}

bool adf_handle_slice_hang(struct adf_accel_dev *accel_dev,
			   u8 accel_num,
			   void __iomem *csr,
			   u32 slice_hang_offset)
{
	u32 slice_hang = ADF_CSR_RD(csr, slice_hang_offset);

	if (!slice_hang)
		return false;

	if (slice_hang & ADF_SLICE_HANG_AUTH0_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "Auth", 0);
	if (slice_hang & ADF_SLICE_HANG_AUTH1_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "Auth", 1);
	if (slice_hang & ADF_SLICE_HANG_AUTH2_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "Auth", 2);
	if (slice_hang & ADF_SLICE_HANG_CPHR0_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "Cipher", 0);
	if (slice_hang & ADF_SLICE_HANG_CPHR1_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "Cipher", 1);
	if (slice_hang & ADF_SLICE_HANG_CPHR2_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "Cipher", 2);
	if (slice_hang & ADF_SLICE_HANG_CMP0_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "Comp", 0);
	if (slice_hang & ADF_SLICE_HANG_CMP1_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "Comp", 1);
	if (slice_hang & ADF_SLICE_HANG_XLT0_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "Xlator", 0);
	if (slice_hang & ADF_SLICE_HANG_XLT1_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "Xlator", 1);
	if (slice_hang & ADF_SLICE_HANG_MMP0_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "MMP", 0);
	if (slice_hang & ADF_SLICE_HANG_MMP1_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "MMP", 1);
	if (slice_hang & ADF_SLICE_HANG_MMP2_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "MMP", 2);
	if (slice_hang & ADF_SLICE_HANG_MMP3_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "MMP", 3);
	if (slice_hang & ADF_SLICE_HANG_MMP4_MASK)
		adf_log_slice_hang(accel_dev, accel_num, "MMP", 4);

	/* Clear the associated interrupt */
	ADF_CSR_WR(csr, slice_hang_offset, slice_hang);

	return true;
}
EXPORT_SYMBOL_GPL(adf_handle_slice_hang);

/**
 * adf_check_slice_hang() - Check slice hang status
 * @accel_dev: Pointer to adf_accel_dev structure
 *
 * Return: true if a slice hange interrupt is serviced..
 */
bool adf_check_slice_hang(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_bar *misc_bar =
		&GET_BARS(accel_dev)[hw_data->get_misc_bar_id(hw_data)];
	void __iomem *csr = misc_bar->virt_addr;
	u32 errsou3 = ADF_CSR_RD(csr, ADF_ERRSOU3);
	u32 errsou5 = ADF_CSR_RD(csr, ADF_ERRSOU5);
	u32 offset;
	u32 accel_num;
	bool handled = false;
	u32 errsou[] = {errsou3, errsou3, errsou5, errsou5, errsou5};
	u32 mask[] = {ADF_EMSK3_CPM0_MASK,
		      ADF_EMSK3_CPM1_MASK,
		      ADF_EMSK5_CPM2_MASK,
		      ADF_EMSK5_CPM3_MASK,
		      ADF_EMSK5_CPM4_MASK};

	for_each_set_bit(accel_num, &hw_data->accel_mask,
			 hw_data->num_accel) {
		if (accel_num >= ARRAY_SIZE(errsou)) {
			dev_err(&GET_DEV(accel_dev),
				"Invalid accel_num %d.\n", accel_num);
			break;
		}

		if (errsou[accel_num] & mask[accel_num]) {
			if (ADF_CSR_RD(csr, ADF_INTSTATSSM(accel_num)) &
				       ADF_INTSTATSSM_SHANGERR) {
				offset = ADF_SLICEHANGSTATUS(accel_num);
				handled |= adf_handle_slice_hang(accel_dev,
								 accel_num,
								 csr,
								 offset);
			}
		}
	}

	return handled;
}
EXPORT_SYMBOL_GPL(adf_check_slice_hang);
