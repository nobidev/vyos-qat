// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2017 - 2021 Intel Corporation */

#include "adf_c4xxx_ras.h"
#include <linux/sysfs.h>
#include <linux/pci.h>
#include <linux/bitops.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include "adf_accel_devices.h"
#include "adf_c4xxx_hw_data.h"
#include "adf_dev_err.h"


/* Protects access to RAS CSRs */
static spinlock_t ras_csr_lock;

static ssize_t ras_correctable_show(struct device *dev,
				    struct device_attribute *dev_attr,
				    char *buf)
{
	struct adf_accel_dev *accel_dev = pci_get_drvdata(to_pci_dev(dev));
	struct attribute *attr = &dev_attr->attr;
	unsigned long counter;

	if (!strcmp(attr->name, "ras_correctable")) {
		counter = atomic_read(&accel_dev->ras_counters[ADF_RAS_CORR]);
	} else {
		dev_err(&GET_DEV(accel_dev), "Unknown attribute %s\n",
			attr->name);
		return -EFAULT;
	}

	return scnprintf(buf, PAGE_SIZE, "%ld\n", counter);
}

static ssize_t ras_uncorrectable_show(struct device *dev,
				      struct device_attribute *dev_attr,
				      char *buf)
{
	struct adf_accel_dev *accel_dev = pci_get_drvdata(to_pci_dev(dev));
	struct attribute *attr = &dev_attr->attr;
	unsigned long counter;

	if (!strcmp(attr->name, "ras_uncorrectable")) {
		counter =
		atomic_read(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL]);
	} else {
		dev_err(&GET_DEV(accel_dev), "Unknown attribute %s\n",
			attr->name);
		return -EFAULT;
	}

	return scnprintf(buf, PAGE_SIZE, "%ld\n", counter);
}

static ssize_t ras_fatal_show(struct device *dev,
			      struct device_attribute *dev_attr, char *buf)
{
	struct adf_accel_dev *accel_dev = pci_get_drvdata(to_pci_dev(dev));
	struct attribute *attr = &dev_attr->attr;
	unsigned long counter;

	if (!strcmp(attr->name, "ras_fatal")) {
		counter =
		atomic_read(&accel_dev->ras_counters[ADF_RAS_UNCORR_FATAL]);
	} else {
		dev_err(&GET_DEV(accel_dev), "Unknown attribute %s\n",
			attr->name);
		return -EFAULT;
	}

	return scnprintf(buf, PAGE_SIZE, "%ld\n", counter);
}

DEVICE_ATTR_RO(ras_correctable);
DEVICE_ATTR_RO(ras_uncorrectable);
DEVICE_ATTR_RO(ras_fatal);

static ssize_t ras_reset_store(struct device *dev,
			       struct device_attribute *dev_attr,
			       const char *buf, size_t count)
{
	struct adf_accel_dev *accel_dev = pci_get_drvdata(to_pci_dev(dev));
	struct attribute *attr = &dev_attr->attr;

	if (!strcmp(attr->name, "ras_reset")) {
		if (buf[0] != '0' || count != 2)
			return -EINVAL;

		atomic_set
		(&accel_dev->ras_counters[ADF_RAS_CORR], 0);
		atomic_set
		(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL], 0);
		atomic_set
		(&accel_dev->ras_counters[ADF_RAS_UNCORR_FATAL], 0);
	} else {
		dev_err(&GET_DEV(accel_dev), "Unknown attribute %s\n",
			attr->name);
		return -EFAULT;
	}

	return count;
}

DEVICE_ATTR_WO(ras_reset);

int adf_init_ras_c4xxx(struct adf_accel_dev *accel_dev)
{
	int i;
	int err = 0;

	spin_lock_init(&ras_csr_lock);

	accel_dev->ras_counters = kcalloc(ADF_RAS_ERRORS,
					  sizeof(*accel_dev->ras_counters),
					  GFP_KERNEL);
	if (!accel_dev->ras_counters)
		return -ENOMEM;

	for (i = 0; i < ADF_RAS_ERRORS; ++i)
		atomic_set(&accel_dev->ras_counters[i], 0);
	pci_set_drvdata(accel_to_pci_dev(accel_dev), accel_dev);

	err = device_create_file(&GET_DEV(accel_dev), &dev_attr_ras_correctable);
	if (err) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to create device attribute ras_correctable\n");
		goto exit_init;
	}

	err = device_create_file(&GET_DEV(accel_dev), &dev_attr_ras_uncorrectable);
	if (err) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to create device attribute ras_uncorrectable\n");
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_correctable);
		goto exit_init;
	}

	err = device_create_file(&GET_DEV(accel_dev), &dev_attr_ras_fatal);
	if (err) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to create device attribute ras_fatal\n");
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_correctable);
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_uncorrectable);
		goto exit_init;
	}

	err = device_create_file(&GET_DEV(accel_dev), &dev_attr_ras_reset);
	if (err) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to create device attribute ras_reset\n");
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_correctable);
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_uncorrectable);
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_fatal);
		goto exit_init;
	}

exit_init:
	if (err != 0) {
		kfree(accel_dev->ras_counters);
		accel_dev->ras_counters = NULL;
	}

	return err;
}

void adf_exit_ras_c4xxx(struct adf_accel_dev *accel_dev)
{
	if (accel_dev->ras_counters) {
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_correctable);
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_uncorrectable);
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_fatal);
		device_remove_file(&GET_DEV(accel_dev), &dev_attr_ras_reset);
		kfree(accel_dev->ras_counters);
		accel_dev->ras_counters = NULL;
	}
}

static inline void adf_log_source_iastatssm(struct adf_accel_dev *accel_dev,
					    void __iomem *pmisc,
					    u32 iastatssm,
					    u32 accel_num)
{
	if (iastatssm & ADF_C4XXX_IASTATSSM_UERRSSMSH_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable error shared memory detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_CERRSSMSH_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Correctable error shared memory detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_UERRSSMMMP0_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable error MMP0 detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_CERRSSMMMP0_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Correctable error MMP0 detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_UERRSSMMMP1_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable error MMP1 detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_CERRSSMMMP1_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Correctable error MMP1 detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_UERRSSMMMP2_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable error MMP2 detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_CERRSSMMMP2_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Correctable error MMP2 detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_UERRSSMMMP3_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable error MMP3 detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_CERRSSMMMP3_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Correctable error MMP3 detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_UERRSSMMMP4_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable error MMP4 detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_CERRSSMMMP4_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Correctable error MMP4 detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_PPERR_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable error Push or Pull detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_CPPPAR_ERR_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable CPP parity error detected in accel: %u\n",
			accel_num);

	if (iastatssm & ADF_C4XXX_IASTATSSM_RFPAR_ERR_MASK)
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable SSM RF parity error detected in accel: %u\n",
			accel_num);
}

static inline void adf_clear_source_statssm(struct adf_accel_dev *accel_dev,
					    void __iomem *pmisc,
					    u32 statssm, u32 accel_num)
{
	if (statssm & ADF_C4XXX_IASTATSSM_UERRSSMSH_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_C4XXX_UERRSSMSH(accel_num),
				      ADF_C4XXX_UERRSSMSH_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_CERRSSMSH_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_C4XXX_CERRSSMSH(accel_num),
				      ADF_C4XXX_CERRSSMSH_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_UERRSSMMMP0_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_C4XXX_UERRSSMMMP(accel_num, 0),
				      ~ADF_C4XXX_UERRSSMMMP_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_CERRSSMMMP0_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_C4XXX_CERRSSMMMP(accel_num, 0),
				      ~ADF_C4XXX_CERRSSMMMP_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_UERRSSMMMP1_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_C4XXX_UERRSSMMMP(accel_num, 1),
				      ~ADF_C4XXX_UERRSSMMMP_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_CERRSSMMMP1_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_C4XXX_CERRSSMMMP(accel_num, 1),
				      ~ADF_C4XXX_CERRSSMMMP_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_UERRSSMMMP2_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_C4XXX_UERRSSMMMP(accel_num, 2),
				      ~ADF_C4XXX_UERRSSMMMP_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_CERRSSMMMP2_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_C4XXX_CERRSSMMMP(accel_num, 2),
				      ~ADF_C4XXX_CERRSSMMMP_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_UERRSSMMMP3_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_C4XXX_UERRSSMMMP(accel_num, 3),
				      ~ADF_C4XXX_UERRSSMMMP_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_CERRSSMMMP3_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_C4XXX_CERRSSMMMP(accel_num, 3),
				      ~ADF_C4XXX_CERRSSMMMP_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_UERRSSMMMP4_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_C4XXX_UERRSSMMMP(accel_num, 4),
				      ~ADF_C4XXX_UERRSSMMMP_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_CERRSSMMMP4_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_C4XXX_CERRSSMMMP(accel_num, 4),
				      ~ADF_C4XXX_CERRSSMMMP_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_PPERR_MASK)
		adf_csr_fetch_and_and(pmisc,
				      ADF_PPERR(accel_num),
				      ~ADF_C4XXX_PPERR_INTS_CLEAR_MASK);

	if (statssm & ADF_C4XXX_IASTATSSM_RFPAR_ERR_MASK)
		adf_csr_fetch_and_or(pmisc,
				     ADF_C4XXX_SSMSOFTERRORPARITY(accel_num),
				     0UL);

	if (statssm & ADF_C4XXX_IASTATSSM_CPPPAR_ERR_MASK)
		adf_csr_fetch_and_or(pmisc,
				     ADF_C4XXX_SSMCPPERR(accel_num),
				     0UL);
}

static inline void adf_process_errsou8(struct adf_accel_dev *accel_dev,
				       void __iomem *pmisc)
{
	int i;
	u32 mecorrerr = ADF_CSR_RD(pmisc, ADF_C4XXX_HI_ME_COR_ERRLOG);
	const unsigned long tmp_mecorrerr = mecorrerr;

	/* For each correctable error in ME increment RAS counter */
	for_each_set_bit(i, &tmp_mecorrerr,
			 ADF_C4XXX_HI_ME_COR_ERRLOG_SIZE_IN_BITS) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_CORR]);
		dev_err(&GET_DEV(accel_dev),
			"Correctable error detected in AE%d\n", i);
	}

	/* Clear interrupt from errsou8 (RW1C) */
	ADF_CSR_WR(pmisc, ADF_C4XXX_HI_ME_COR_ERRLOG, mecorrerr);
}

static inline void adf_ae_uncorr_err(struct adf_accel_dev *accel_dev,
				     void __iomem *pmisc)
{
	int i;
	u32 me_uncorr_err = ADF_CSR_RD(pmisc, ADF_C4XXX_HI_ME_UNCERR_LOG);
	const unsigned long tmp_me_uncorr_err = me_uncorr_err;

	/* For each uncorrectable fatal error in AE increment RAS error
	 * counter.
	 */
	for_each_set_bit(i, &tmp_me_uncorr_err,
			 ADF_C4XXX_HI_ME_UNCOR_ERRLOG_BITS) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_FATAL]);
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable error detected in AE%d\n", i);
	}

	/* Clear interrupt from me_uncorr_err (RW1C) */
	ADF_CSR_WR(pmisc, ADF_C4XXX_HI_ME_UNCERR_LOG, me_uncorr_err);
}

static inline void adf_ri_mem_par_err(struct adf_accel_dev *accel_dev,
				      void __iomem *pmisc,
				      bool *reset_required)
{
	u32 ri_mem_par_err_sts = 0;
	u32 ri_mem_par_err_ferr = 0;

	ri_mem_par_err_sts = ADF_CSR_RD(pmisc,
					ADF_C4XXX_RI_MEM_PAR_ERR_STS);

	ri_mem_par_err_ferr = ADF_CSR_RD(pmisc,
					 ADF_C4XXX_RI_MEM_PAR_ERR_FERR);

	if (ri_mem_par_err_sts & ADF_C4XXX_RI_MEM_PAR_ERR_STS_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL]);
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable RI memory parity error detected.\n");
	}

	if (ri_mem_par_err_sts & ADF_C4XXX_RI_MEM_MSIX_TBL_INT_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_FATAL]);
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable fatal MSIX table parity error detected.\n");
		*reset_required = true;
	}

	dev_err(&GET_DEV(accel_dev),
		"ri_mem_par_err_sts=0x%X\tri_mem_par_err_ferr=%u\n",
		ri_mem_par_err_sts, ri_mem_par_err_ferr);

	ADF_CSR_WR(pmisc, ADF_C4XXX_RI_MEM_PAR_ERR_STS,
		   ri_mem_par_err_sts);
}

static inline void adf_ti_mem_par_err(struct adf_accel_dev *accel_dev,
				      void __iomem *pmisc)
{
	u32 ti_mem_par_err_sts0 = 0;
	u32 ti_mem_par_err_sts1 = 0;
	u32 ti_mem_par_err_ferr = 0;

	ti_mem_par_err_sts0 = ADF_CSR_RD(pmisc,
					 ADF_C4XXX_TI_MEM_PAR_ERR_STS0);
	ti_mem_par_err_sts1 = ADF_CSR_RD(pmisc,
					 ADF_C4XXX_TI_MEM_PAR_ERR_STS1);
	ti_mem_par_err_ferr =
		ADF_CSR_RD(pmisc,
			   ADF_C4XXX_TI_MEM_PAR_ERR_FIRST_ERROR);

	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_FATAL]);
	ti_mem_par_err_sts1 &= ADF_C4XXX_TI_MEM_PAR_ERR_STS1_MASK;

	dev_err(&GET_DEV(accel_dev),
		"Uncorrectable TI memory parity error detected.\n");
	dev_err(&GET_DEV(accel_dev),
		"ti_mem_par_err_sts0=0x%X\tti_mem_par_err_sts1=0x%X\t"
		"ti_mem_par_err_ferr=0x%X\n", ti_mem_par_err_sts0,
		ti_mem_par_err_sts1, ti_mem_par_err_ferr);

	ADF_CSR_WR(pmisc, ADF_C4XXX_TI_MEM_PAR_ERR_STS0,
		   ti_mem_par_err_sts0);
	ADF_CSR_WR(pmisc, ADF_C4XXX_TI_MEM_PAR_ERR_STS1,
		   ti_mem_par_err_sts1);
}

static inline void adf_log_fatal_cmd_par_err(struct adf_accel_dev *accel_dev,
					     char *err_type)
{
	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_FATAL]);
	dev_err(&GET_DEV(accel_dev),
		"Fatal error detected: %s command parity\n",
		err_type);
}

static inline void adf_host_cpp_par_err(struct adf_accel_dev *accel_dev,
					void __iomem *pmisc)
{
	u32 host_cpp_par_err = 0;

	host_cpp_par_err = ADF_CSR_RD(pmisc,
				      ADF_C4XXX_HI_CPP_AGENT_CMD_PAR_ERR_LOG);

	if (host_cpp_par_err & ADF_C4XXX_TI_CMD_PAR_ERR)
		adf_log_fatal_cmd_par_err(accel_dev, "TI");

	if (host_cpp_par_err & ADF_C4XXX_RI_CMD_PAR_ERR)
		adf_log_fatal_cmd_par_err(accel_dev, "RI");

	if (host_cpp_par_err & ADF_C4XXX_ICI_CMD_PAR_ERR)
		adf_log_fatal_cmd_par_err(accel_dev, "ICI");

	if (host_cpp_par_err & ADF_C4XXX_ICE_CMD_PAR_ERR)
		adf_log_fatal_cmd_par_err(accel_dev, "ICE");

	if (host_cpp_par_err & ADF_C4XXX_ARAM_CMD_PAR_ERR)
		adf_log_fatal_cmd_par_err(accel_dev, "ARAM");

	if (host_cpp_par_err & ADF_C4XXX_CFC_CMD_PAR_ERR)
		adf_log_fatal_cmd_par_err(accel_dev, "CFC");

	if (ADF_C4XXX_SSM_CMD_PAR_ERR(host_cpp_par_err))
		adf_log_fatal_cmd_par_err(accel_dev, "SSM");

	/* Clear interrupt from host_cpp_par_err (RW1C) */
	ADF_CSR_WR(pmisc, ADF_C4XXX_HI_CPP_AGENT_CMD_PAR_ERR_LOG,
		   host_cpp_par_err);
}

static inline void adf_process_errsou9(struct adf_accel_dev *accel_dev,
				       void __iomem *pmisc, u32 errsou,
				       bool *reset_required)
{
	if (errsou & ADF_C4XXX_ME_UNCORR_ERROR) {
		adf_ae_uncorr_err(accel_dev, pmisc);

		/* Notify caller that function level reset is required. */
		*reset_required = true;
	}

	if (errsou & ADF_C4XXX_CPP_CMD_PAR_ERR) {
		adf_host_cpp_par_err(accel_dev, pmisc);
		*reset_required = true;
	}

	/* RI memory parity errors are uncorrectable non-fatal errors
	 * with exception of bit 22 MSIX table parity error, which should
	 * be treated as fatal error, followed by device restart.
	 */
	if (errsou & ADF_C4XXX_RI_MEM_PAR_ERR)
		adf_ri_mem_par_err(accel_dev, pmisc, reset_required);

	if (errsou & ADF_C4XXX_TI_MEM_PAR_ERR) {
		adf_ti_mem_par_err(accel_dev, pmisc);
		*reset_required = true;
	}
}

static inline void adf_process_spp_par_err(struct adf_accel_dev *accel_dev,
					   void __iomem *pmisc, u32 accel,
					   bool *reset_required)
{
	/* All SPP parity errors are treated as uncorrectable fatal errors */
	atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_FATAL]);
	*reset_required = true;
	dev_err(&GET_DEV(accel_dev),
		"Uncorrectable fatal SPP parity error detected\n");
}

static inline void adf_process_statssm(struct adf_accel_dev *accel_dev,
				       void __iomem *pmisc, u32 accel,
				       bool *reset_required)
{
	u32 i;
	u32 statssm = ADF_CSR_RD(pmisc, ADF_INTSTATSSM(accel));
	u32 iastatssm = ADF_CSR_RD(pmisc, ADF_C4XXX_IAINTSTATSSM(accel));
	bool type;
	const unsigned long tmp_iastatssm = iastatssm;

	/* First collect all errors */
	for_each_set_bit(i, &tmp_iastatssm,
			 ADF_C4XXX_IASTATSSM_BITS) {
		if (i == ADF_C4XXX_IASTATSSM_SLICE_HANG_ERR_BIT) {
		/* Slice Hang error is being handled in
		 * separate function adf_check_slice_hang_c4xxx(),
		 * which also increments RAS counters for
		 * SliceHang error.
		 */
			continue;
		}
		if (i == ADF_C4XXX_IASTATSSM_SPP_PAR_ERR_BIT) {
			adf_process_spp_par_err(accel_dev, pmisc, accel,
						reset_required);
			continue;
		}

		type = (i % 2) ? ADF_RAS_CORR : ADF_RAS_UNCORR_NONFATAL;
		if (i == ADF_C4XXX_IASTATSSM_CPP_PAR_ERR_BIT)
			type = ADF_RAS_UNCORR_NONFATAL;

		atomic_inc(&accel_dev->ras_counters[type]);
	}

	/* If iastatssm is set, we need to log the error */
	if (iastatssm & ADF_C4XXX_IASTATSSM_MASK)
		adf_log_source_iastatssm(accel_dev, pmisc, iastatssm, accel);
	/* If statssm is set, we need to clear the error sources */
	if (statssm & ADF_C4XXX_IASTATSSM_MASK)
		adf_clear_source_statssm(accel_dev, pmisc, statssm, accel);
}

/**
 * adf_check_slice_hang_c4xxx() - Check SliceHang status for C4XXX device
 * @accel_dev:  Pointer to acceleration device.
 *
 * Return: true if a SliceHang error source was cleared.
 */
static void adf_check_slice_hang_c4xxx(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	struct adf_bar *misc_bar =
		&GET_BARS(accel_dev)[hw_device->get_misc_bar_id(hw_device)];
	void __iomem *csr = misc_bar->virt_addr;
	u32 slice_hang_offset;
	u32 ia_slice_hang_offset;
	u32 fw_irq_source;
	u32 ia_irq_source;
	u32 accel_num;
	u32 errsou10 = ADF_CSR_RD(csr, ADF_C4XXX_ERRSOU10);
	unsigned long accel_mask = hw_device->accel_mask;

	for_each_set_bit(accel_num, &accel_mask, ADF_C4XXX_MAX_ACCELERATORS) {
		if (!(errsou10 & ADF_C4XXX_IRQ_SRC_MASK(accel_num)))
			continue;

		fw_irq_source = ADF_CSR_RD(csr, ADF_INTSTATSSM(accel_num));
		ia_irq_source =
			ADF_CSR_RD(csr, ADF_C4XXX_IAINTSTATSSM(accel_num));
		ia_slice_hang_offset =
				ADF_C4XXX_IASLICEHANGSTATUS_OFFSET(accel_num);

		/* FW did not clear SliceHang error, IA logs and clears
		 * the error
		 */
		if ((fw_irq_source & ADF_INTSTATSSM_SHANGERR) &&
		    (ia_irq_source & ADF_INTSTATSSM_SHANGERR)) {
			slice_hang_offset =
				ADF_C4XXX_SLICEHANGSTATUS_OFFSET(accel_num);

			/* Bring hung slice out of reset */
			adf_csr_fetch_and_and(csr, slice_hang_offset,
					      ADF_C4XXX_CLEAR_FW_SLICE_HANG);

			/* Log SliceHang error and clear an error source */
			adf_handle_slice_hang(accel_dev, accel_num, csr,
					      ia_slice_hang_offset);

			atomic_inc
			(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL]);
		}
		/* FW cleared SliceHang, IA only logs an error */
		else if (!(fw_irq_source & ADF_INTSTATSSM_SHANGERR) &&
			 (ia_irq_source & ADF_INTSTATSSM_SHANGERR)) {
			/* Log SliceHang error and clear an error source */
			adf_handle_slice_hang(accel_dev, accel_num, csr,
					      ia_slice_hang_offset);

			atomic_inc
			(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL]);
		}
	}
}

static inline void adf_process_errsou10(struct adf_accel_dev *accel_dev,
					void __iomem *pmisc, u32 errsou,
					u32 num_accels, bool *reset_required)
{
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	struct adf_bar *misc_bar =
		&GET_BARS(accel_dev)[hw_device->get_misc_bar_id(hw_device)];
	void __iomem *csr = misc_bar->virt_addr;
	int accel = 0;
	const unsigned long tmp_errsou = errsou;

	unsigned long irq_flags;

	/* Handle SliceHang as part of RAS for C4XXX devices. */
	adf_check_slice_hang_c4xxx(accel_dev);

	for_each_set_bit(accel, &tmp_errsou, num_accels) {
		adf_process_statssm(accel_dev, pmisc, accel, reset_required);

		/* Clear the associated IA interrupt for current accel.
		 * IAINTSTATSSM is RW register and should be updated and
		 * cleared in one place.
		 */
		spin_lock_irqsave(&ras_csr_lock, irq_flags);
		adf_csr_fetch_and_and(csr,
				      ADF_C4XXX_IAINTSTATSSM(accel),
				      0);
		spin_unlock_irqrestore(&ras_csr_lock, irq_flags);
	}
}

/* ERRSOU 11 */
static inline void adf_ti_misc_err(struct adf_accel_dev *accel_dev,
				   void __iomem *pmisc)
{
	u32 ti_misc_sts = 0;
	u32 err_type = 0;

	ti_misc_sts = ADF_CSR_RD(pmisc, ADF_C4XXX_TI_MISC_STS);
	dev_dbg(&GET_DEV(accel_dev), "ti_misc_sts = 0x%X\n", ti_misc_sts);

	if (ti_misc_sts & ADF_C4XXX_TI_MISC_ERR_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL]);

		/* If TI misc error occurred then check its type */
		err_type = ADF_C4XXX_GET_TI_MISC_ERR_TYPE(ti_misc_sts);
		if (err_type == ADF_C4XXX_TI_BME_RESP_ORDER_ERR) {
			dev_err(&GET_DEV(accel_dev),
				"Uncorrectable non-fatal BME response order error.\n");

		} else if (err_type == ADF_C4XXX_TI_RESP_ORDER_ERR) {
			dev_err(&GET_DEV(accel_dev),
				"Uncorrectable non-fatal response order error.\n");
		}

		/* Clear the interrupt and allow the next error to be
		 * logged.
		 */
		ADF_CSR_WR(pmisc, ADF_C4XXX_TI_MISC_STS, BIT(0));
	}
}

static inline void adf_ri_push_pull_par_err(struct adf_accel_dev *accel_dev,
					    void __iomem *pmisc)
{
	u32 ri_cpp_int_sts = 0;
	u32 err_clear_mask = 0;

	ri_cpp_int_sts = ADF_CSR_RD(pmisc, ADF_C4XXX_RI_CPP_INT_STS);
	dev_dbg(&GET_DEV(accel_dev), "ri_cpp_int_sts = 0x%X\n", ri_cpp_int_sts);

	if (ri_cpp_int_sts & ADF_C4XXX_RI_CPP_INT_STS_PUSH_ERR) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL]);
		dev_err(&GET_DEV(accel_dev),
			"CPP%d: Uncorrectable non-fatal RI push error detected.\n",
			ADF_C4XXX_GET_CPP_BUS_FROM_STS(ri_cpp_int_sts));

		err_clear_mask |= ADF_C4XXX_RI_CPP_INT_STS_PUSH_ERR;
	}

	if (ri_cpp_int_sts & ADF_C4XXX_RI_CPP_INT_STS_PULL_ERR) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL]);
		dev_err(&GET_DEV(accel_dev),
			"CPP%d: Uncorrectable non-fatal RI pull error detected.\n",
			ADF_C4XXX_GET_CPP_BUS_FROM_STS(ri_cpp_int_sts));

		err_clear_mask |= ADF_C4XXX_RI_CPP_INT_STS_PULL_ERR;
	}

	/* Clear the interrupt for handled errors and allow the next error
	 * to be logged.
	 */
	ADF_CSR_WR(pmisc, ADF_C4XXX_RI_CPP_INT_STS, err_clear_mask);
}

static inline void adf_ti_push_pull_par_err(struct adf_accel_dev *accel_dev,
					    void __iomem *pmisc)
{
	u32 ti_cpp_int_sts = 0;
	u32 err_clear_mask = 0;

	ti_cpp_int_sts = ADF_CSR_RD(pmisc, ADF_C4XXX_TI_CPP_INT_STS);
	dev_dbg(&GET_DEV(accel_dev), "ti_cpp_int_sts = 0x%X\n", ti_cpp_int_sts);

	if (ti_cpp_int_sts & ADF_C4XXX_TI_CPP_INT_STS_PUSH_ERR) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL]);
		dev_err(&GET_DEV(accel_dev),
			"CPP%d: Uncorrectable non-fatal TI push error detected.\n",
			ADF_C4XXX_GET_CPP_BUS_FROM_STS(ti_cpp_int_sts));

		err_clear_mask |= ADF_C4XXX_TI_CPP_INT_STS_PUSH_ERR;
	}

	if (ti_cpp_int_sts & ADF_C4XXX_TI_CPP_INT_STS_PULL_ERR) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL]);
		dev_err(&GET_DEV(accel_dev),
			"CPP%d: Uncorrectable non-fatal TI pull error detected.\n",
			ADF_C4XXX_GET_CPP_BUS_FROM_STS(ti_cpp_int_sts));

		err_clear_mask |= ADF_C4XXX_TI_CPP_INT_STS_PULL_ERR;
	}

	/* Clear the interrupt for handled errors and allow the next error
	 * to be logged.
	 */
	ADF_CSR_WR(pmisc, ADF_C4XXX_TI_CPP_INT_STS, err_clear_mask);
}

static inline void adf_aram_corr_err(struct adf_accel_dev *accel_dev,
				     void __iomem *aram_base_addr)
{
	u32 aram_cerr = 0;

	aram_cerr = ADF_CSR_RD(aram_base_addr, ADF_C4XXX_ARAMCERR);
	dev_dbg(&GET_DEV(accel_dev), "aram_cerr = 0x%X\n", aram_cerr);

	if (aram_cerr & ADF_C4XXX_ARAM_CORR_ERR_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_CORR]);
		dev_err(&GET_DEV(accel_dev),
			"Correctable ARAM error detected.\n");
	}

	/* Clear correctable ARAM error interrupt. */
	ADF_C4XXX_CLEAR_CSR_BIT(aram_cerr, 0);
	ADF_CSR_WR(aram_base_addr, ADF_C4XXX_ARAMCERR, aram_cerr);
}

static inline void adf_aram_uncorr_err(struct adf_accel_dev *accel_dev,
				       void __iomem *aram_base_addr)
{
	u32 aram_uerr = 0;

	aram_uerr = ADF_CSR_RD(aram_base_addr, ADF_C4XXX_ARAMUERR);
	dev_dbg(&GET_DEV(accel_dev), "aram_uerr = 0x%X\n", aram_uerr);

	if (aram_uerr & ADF_C4XXX_ARAM_UNCORR_ERR_MASK) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL]);
		dev_err(&GET_DEV(accel_dev),
			"Uncorrectable non-fatal ARAM error detected.\n");
	}

	/* Clear uncorrectable ARAM error interrupt. */
	ADF_C4XXX_CLEAR_CSR_BIT(aram_uerr, 0);
	ADF_CSR_WR(aram_base_addr, ADF_C4XXX_ARAMUERR, aram_uerr);
}

static inline void adf_ti_pull_par_err(struct adf_accel_dev *accel_dev,
				       void __iomem *pmisc)
{
	u32 ti_cpp_int_sts = 0;

	ti_cpp_int_sts = ADF_CSR_RD(pmisc, ADF_C4XXX_TI_CPP_INT_STS);
	dev_dbg(&GET_DEV(accel_dev), "ti_cpp_int_sts = 0x%X\n", ti_cpp_int_sts);

	if (ti_cpp_int_sts & ADF_C4XXX_TI_CPP_INT_STS_PUSH_DATA_PAR_ERR) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL]);
		dev_err(&GET_DEV(accel_dev),
			"CPP%d: Uncorrectable non-fatal TI pull data parity error detected.\n",
			ADF_C4XXX_GET_CPP_BUS_FROM_STS(ti_cpp_int_sts));
	}

	/* Clear the interrupt and allow the next error to be logged. */
	ADF_CSR_WR(pmisc, ADF_C4XXX_TI_CPP_INT_STS,
		   ADF_C4XXX_TI_CPP_INT_STS_PUSH_DATA_PAR_ERR);
}

static inline void adf_ri_push_par_err(struct adf_accel_dev *accel_dev,
				       void __iomem *pmisc)
{
	u32 ri_cpp_int_sts = 0;

	ri_cpp_int_sts = ADF_CSR_RD(pmisc, ADF_C4XXX_RI_CPP_INT_STS);
	dev_dbg(&GET_DEV(accel_dev), "ri_cpp_int_sts = 0x%X\n", ri_cpp_int_sts);

	if (ri_cpp_int_sts & ADF_C4XXX_RI_CPP_INT_STS_PUSH_DATA_PAR_ERR) {
		atomic_inc(&accel_dev->ras_counters[ADF_RAS_UNCORR_NONFATAL]);
		dev_err(&GET_DEV(accel_dev),
			"CPP%d: Uncorrectable non-fatal RI push data parity error detected.\n",
			ADF_C4XXX_GET_CPP_BUS_FROM_STS(ri_cpp_int_sts));
	}

	/* Clear the interrupt and allow the next error to be logged. */
	ADF_CSR_WR(pmisc, ADF_C4XXX_RI_CPP_INT_STS,
		   ADF_C4XXX_RI_CPP_INT_STS_PUSH_DATA_PAR_ERR);
}


static inline void adf_process_errsou11(struct adf_accel_dev *accel_dev,
					void __iomem *pmisc, u32 errsou,
					bool *reset_required)
{
	void __iomem *aram_base_addr =
			(&GET_BARS(accel_dev)[ADF_C4XXX_SRAM_BAR])->virt_addr;

	if (errsou & ADF_C4XXX_TI_MISC)
		adf_ti_misc_err(accel_dev, pmisc);

	if (errsou & ADF_C4XXX_RI_PUSH_PULL_PAR_ERR)
		adf_ri_push_pull_par_err(accel_dev, pmisc);

	if (errsou & ADF_C4XXX_TI_PUSH_PULL_PAR_ERR)
		adf_ti_push_pull_par_err(accel_dev, pmisc);

	if (errsou & ADF_C4XXX_ARAM_CORR_ERR)
		adf_aram_corr_err(accel_dev, aram_base_addr);

	if (errsou & ADF_C4XXX_ARAM_UNCORR_ERR)
		adf_aram_uncorr_err(accel_dev, aram_base_addr);

	if (errsou & ADF_C4XXX_TI_PULL_PAR_ERR)
		adf_ti_pull_par_err(accel_dev, pmisc);

	if (errsou & ADF_C4XXX_RI_PUSH_PAR_ERR)
		adf_ri_push_par_err(accel_dev, pmisc);

}

bool adf_ras_interrupts_c4xxx(struct adf_accel_dev *accel_dev,
			      bool *reset_required)
{
	u32 errsou = 0;
	bool handled = false;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 num_accels = hw_data->get_num_accels(hw_data);
	void __iomem *pmisc =
		(&GET_BARS(accel_dev)[ADF_C4XXX_PMISC_BAR])->virt_addr;

	if (unlikely(!reset_required)) {
		dev_err(&GET_DEV(accel_dev),
			"Invalid pointer reset_required\n");
		return false;
	}

	/* errsou8 */
	errsou = ADF_CSR_RD(pmisc, ADF_C4XXX_ERRSOU8);
	if (errsou & ADF_C4XXX_ERRSOU8_MECORR_MASK) {
		adf_process_errsou8(accel_dev, pmisc);
		handled = true;
	}

	/* errsou9 */
	errsou = ADF_CSR_RD(pmisc, ADF_C4XXX_ERRSOU9);
	if (errsou & ADF_C4XXX_ERRSOU9_ERROR_MASK) {
		adf_process_errsou9(accel_dev, pmisc, errsou, reset_required);
		handled = true;
	}

	/* errsou10 */
	errsou = ADF_CSR_RD(pmisc, ADF_C4XXX_ERRSOU10);
	if (errsou & ADF_C4XXX_ERRSOU10_RAS_MASK) {
		adf_process_errsou10(accel_dev, pmisc, errsou, num_accels,
				     reset_required);
		handled = true;
	}

	/* errsou11 */
	errsou = ADF_CSR_RD(pmisc, ADF_C4XXX_ERRSOU11);
	if (errsou & ADF_C4XXX_ERRSOU11_ERROR_MASK) {
		adf_process_errsou11(accel_dev, pmisc, errsou, reset_required);
		handled = true;
	}

	return handled;
}

void adf_enable_ras_c4xxx(struct adf_accel_dev *accel_dev)
{
	void __iomem *csr = NULL;
	struct adf_hw_device_data *hw_device = accel_dev->hw_device;
	u32 accel;
	unsigned long accel_mask;

	csr = (&GET_BARS(accel_dev)[ADF_C4XXX_PMISC_BAR])->virt_addr;
	accel_mask = hw_device->accel_mask;

	for_each_set_bit(accel, &accel_mask, ADF_C4XXX_MAX_ACCELERATORS) {
		ADF_CSR_WR(csr, ADF_C4XXX_GET_SSMFEATREN_OFFSET(accel),
			   ADF_C4XXX_SSMFEATREN_VAL);
	}
}
