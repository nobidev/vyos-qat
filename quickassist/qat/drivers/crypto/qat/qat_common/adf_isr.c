// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2015 - 2021 Intel Corporation */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include "adf_accel_devices.h"
#include "adf_common_drv.h"
#include "adf_cfg.h"
#include "adf_cfg_strings.h"
#include "adf_cfg_common.h"
#include "adf_transport_access_macros.h"
#include "adf_transport_internal.h"
#include "adf_dev_err.h"

#define ADF_PF_RESP_WQ "adf_pf_resp_wq_"

static int adf_enable_msix(struct adf_accel_dev *accel_dev)
{
	struct adf_accel_pci *pci_dev_info = &accel_dev->accel_pci_dev;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 msix_num_entries = 1;

	/* If SR-IOV is disabled, add entries for each bank */
	if (!accel_dev->pf.vf_info) {
		int i;

		msix_num_entries += hw_data->num_banks;
		for (i = 0; i < msix_num_entries; i++)
			pci_dev_info->msix_entries.entries[i].entry = i;
	} else {
		pci_dev_info->msix_entries.entries[0].entry =
			hw_data->num_banks;
	}

	if (pci_enable_msix_exact(pci_dev_info->pci_dev,
				  pci_dev_info->msix_entries.entries,
				  msix_num_entries)) {
		dev_err(&GET_DEV(accel_dev), "Failed to enable MSI-X IRQ(s)\n");
		return -EFAULT;
	}
	return 0;
}

static void adf_disable_msix(struct adf_accel_pci *pci_dev_info)
{
	pci_disable_msix(pci_dev_info->pci_dev);
}

static irqreturn_t adf_msix_isr_bundle(int irq, void *bank_ptr)
{
	struct adf_etr_bank_data *bank = bank_ptr;
	struct adf_accel_dev *accel_dev = bank->accel_dev;

	WRITE_CSR_INT_FLAG_AND_COL(bank->csr_addr, bank->bank_number, 0);
	queue_work(accel_dev->pf.resp_wq, &bank->resp_handler_wq);
	return IRQ_HANDLED;
}

#ifdef CONFIG_PCI_IOV
static bool adf_handle_vf2pf_int(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_bar *pmisc =
		&GET_BARS(accel_dev)[hw_data->get_misc_bar_id(hw_data)];
	void __iomem *pmisc_bar_addr = pmisc->virt_addr;
	u8 i;
	u32 vf_mask_sets[ADF_MAX_VF2PF_SET];
	bool irq_handled = false;

	spin_lock(&accel_dev->vf2pf_csr_lock);
	hw_data->process_and_get_vf2pf_int(pmisc_bar_addr, vf_mask_sets);
	spin_unlock(&accel_dev->vf2pf_csr_lock);

	for (i = 0; i < ARRAY_SIZE(vf_mask_sets); i++) {
		struct adf_accel_vf_info *vf_info;
		u32 j = 0;
		const unsigned long vf_mask_set = vf_mask_sets[i];

		if (!vf_mask_sets[i])
			continue;

		/*
		 * Handle VF2PF interrupt unless the VF is malicious and
		 * is attempting to flood the host OS with VF2PF interrupts.
		 */
		for_each_set_bit(j, &vf_mask_set,
				 (sizeof(vf_mask_sets[i]) * BITS_PER_BYTE)) {
			vf_info = accel_dev->pf.vf_info +
					j + ADF_VF2PF_SET_OFFSET(i);

			if (!__ratelimit(&vf_info->vf2pf_ratelimit)) {
				dev_info(&GET_DEV(accel_dev),
					 "Too many ints from VF%d\n",
					  vf_info->vf_nr + 1);
				continue;
			}

			adf_vf2pf_handler(vf_info);
			irq_handled = true;
		}
	}
	return irq_handled;
}
#endif

static irqreturn_t adf_msix_isr_ae(int irq, void *dev_ptr)
{
	struct adf_accel_dev *accel_dev = dev_ptr;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	bool reset_required = false;
	bool irq_handled = false;

#ifdef CONFIG_PCI_IOV
	/* If SR-IOV is enabled (vf_info is non-NULL), check for VF->PF ints */
	if (accel_dev->pf.vf_info)
		if (adf_handle_vf2pf_int(accel_dev))
			irq_handled = true;
#endif /* CONFIG_PCI_IOV */


	if (hw_data->check_uncorrectable_error &&
			hw_data->check_uncorrectable_error(accel_dev)) {
		if (hw_data->print_err_registers)
			hw_data->print_err_registers(accel_dev);
		if (hw_data->disable_error_interrupts)
			hw_data->disable_error_interrupts(accel_dev);

		if (adf_notify_fatal_error(accel_dev))
			dev_err(&GET_DEV(accel_dev),
				"Couldn't notify fatal error\n");

		irq_handled = true;
	}

	if (hw_data->ras_interrupts &&
	    hw_data->ras_interrupts(accel_dev, &reset_required)) {
		if (reset_required)
			if (adf_notify_fatal_error(accel_dev))
				dev_err(&GET_DEV(accel_dev),
					"Couldn't notify fatal error\n");

		irq_handled = true;
	}

#ifdef QAT_DBG
	if (hw_data->check_slice_hang && hw_data->check_slice_hang(accel_dev)) {
		if (adf_notify_err_resp(accel_dev))
			dev_err(&GET_DEV(accel_dev),
				"Couldn't notify error response\n");
		irq_handled = true;
	}
#else
	if (hw_data->check_slice_hang && hw_data->check_slice_hang(accel_dev))
		irq_handled = true;
#endif

	if (irq_handled)
		return IRQ_HANDLED;

	dev_dbg(&GET_DEV(accel_dev), "qat_dev%d spurious AE interrupt\n",
		accel_dev->accel_id);

	return IRQ_NONE;
}

static int adf_request_irqs(struct adf_accel_dev *accel_dev)
{
	struct adf_accel_pci *pci_dev_info = &accel_dev->accel_pci_dev;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_irq *irqs = pci_dev_info->msix_entries.irqs;
	struct msix_entry *msixe = pci_dev_info->msix_entries.entries;
	struct adf_etr_data *etr_data = accel_dev->transport;
	int ret = 0;
	u8 i = 0;
	char *name;

	/* Request msix irq for all banks unless SR-IOV enabled */
	if (!accel_dev->pf.vf_info) {
		char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
		unsigned long num_kernel_inst = hw_data->num_banks;

		if (adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC,
					    ADF_FIRST_USER_BUNDLE, val) == 0) {
			if (kstrtoul(val, 10, &num_kernel_inst))
				return -1;
		}

		for (i = 0; i < num_kernel_inst; i++) {
			struct adf_etr_bank_data *bank = &etr_data->banks[i];
			unsigned int cpu, cpus = num_online_cpus();

			name = irqs[i].name;
			snprintf(name, ADF_MAX_MSIX_VECTOR_NAME,
				 "qat%d-bundle%d", accel_dev->accel_id, i);
			ret = request_irq(msixe[i].vector,
					  adf_msix_isr_bundle, 0, name, bank);
			if (ret) {
				dev_err(&GET_DEV(accel_dev),
					"failed to enable irq %d for %s\n",
					msixe[i].vector, name);
				return ret;
			}

			cpu = ((accel_dev->accel_id * hw_data->num_banks) +
			       i) % cpus;
			irq_set_affinity_hint(msixe[i].vector,
					      get_cpu_mask(cpu));
			irqs[i].enabled = true;
		}
	i = hw_data->num_banks;
	}

	/* Request msix irq for AE */
	name = irqs[i].name;
	snprintf(name, ADF_MAX_MSIX_VECTOR_NAME,
		 "qat%d-ae-cluster", accel_dev->accel_id);
	ret = request_irq(msixe[i].vector, adf_msix_isr_ae, 0, name, accel_dev);
	if (ret) {
		dev_err(&GET_DEV(accel_dev),
			"failed to enable irq %d, for %s\n",
			msixe[i].vector, name);
		return ret;
	}
	irqs[i].enabled = true;
	return ret;
}

static void adf_free_irqs(struct adf_accel_dev *accel_dev)
{
	struct adf_accel_pci *pci_dev_info = &accel_dev->accel_pci_dev;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	struct adf_irq *irqs = pci_dev_info->msix_entries.irqs;
	struct msix_entry *msixe = pci_dev_info->msix_entries.entries;
	struct adf_etr_data *etr_data = accel_dev->transport;
	int i = 0;

	if (pci_dev_info->msix_entries.num_entries > 1) {
		char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
		unsigned long num_kernel_inst = hw_data->num_banks;

		if (adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC,
					    ADF_FIRST_USER_BUNDLE, val) == 0) {
			if (kstrtoul(val, 10, &num_kernel_inst))
				return;
		}

		for (i = 0; i < num_kernel_inst; i++) {
			if (irqs[i].enabled) {
				irq_set_affinity_hint(msixe[i].vector, NULL);
				free_irq(msixe[i].vector, &etr_data->banks[i]);
			}
		}
	i = hw_data->num_banks;
	}
	if (irqs[i].enabled) {
		irq_set_affinity_hint(msixe[i].vector, NULL);
		free_irq(msixe[i].vector, accel_dev);
	}
}

static int adf_isr_alloc_msix_entry_table(struct adf_accel_dev *accel_dev)
{
	struct adf_irq *irqs;
	struct msix_entry *entries;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 msix_num_entries = 1;

	/* If SR-IOV is disabled (vf_info is NULL), add entries for each bank */
	if (!accel_dev->pf.vf_info)
		msix_num_entries += hw_data->num_banks;

	entries = kzalloc_node(msix_num_entries * sizeof(*entries),
			       GFP_KERNEL, dev_to_node(&GET_DEV(accel_dev)));
	if (!entries)
		return -ENOMEM;

	irqs = kzalloc_node(msix_num_entries * sizeof(*irqs),
			    GFP_KERNEL, dev_to_node(&GET_DEV(accel_dev)));
	if (!irqs) {
		kfree(entries);
		return -ENOMEM;
	}
	accel_dev->accel_pci_dev.msix_entries.num_entries = msix_num_entries;
	accel_dev->accel_pci_dev.msix_entries.entries = entries;
	accel_dev->accel_pci_dev.msix_entries.irqs = irqs;
	return 0;
}

static void adf_isr_free_msix_entry_table(struct adf_accel_dev *accel_dev)
{
	kfree(accel_dev->accel_pci_dev.msix_entries.entries);
	kfree(accel_dev->accel_pci_dev.msix_entries.irqs);
	accel_dev->accel_pci_dev.msix_entries.entries = NULL;
	accel_dev->accel_pci_dev.msix_entries.irqs = NULL;
}

static int adf_setup_bh(struct adf_accel_dev *accel_dev)
{
	struct adf_etr_data *priv_data = accel_dev->transport;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	int i;

	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
	unsigned long num_kernel_inst = hw_data->num_banks;
	char wq_name[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};

	snprintf(wq_name, sizeof(wq_name), "%s%d",
		 ADF_PF_RESP_WQ, accel_dev->accel_id);

	accel_dev->pf.resp_wq = alloc_workqueue
		(wq_name, WQ_HIGHPRI | WQ_MEM_RECLAIM, 1);
	if (!accel_dev->pf.resp_wq)
		return -ENOMEM;
	if (adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC,
				    ADF_FIRST_USER_BUNDLE, val) == 0) {
		if (kstrtoul(val, 10, &num_kernel_inst))
			return -1;
	}

	for (i = 0; i < num_kernel_inst; i++)
		INIT_WORK
			(&priv_data->banks[i].resp_handler_wq,
			adf_response_handler_wq);
	return 0;
}

static void adf_cleanup_bh(struct adf_accel_dev *accel_dev)
{
	if (accel_dev->pf.resp_wq) {
		destroy_workqueue(accel_dev->pf.resp_wq);
		accel_dev->pf.resp_wq = NULL;
	}
}

/**
 * adf_isr_resource_free() - Free IRQ for acceleration device
 * @accel_dev:  Pointer to acceleration device.
 *
 * Function frees interrupts for acceleration device.
 */
void adf_isr_resource_free(struct adf_accel_dev *accel_dev)
{
	adf_free_irqs(accel_dev);
	adf_cleanup_bh(accel_dev);
	adf_disable_msix(&accel_dev->accel_pci_dev);
	adf_isr_free_msix_entry_table(accel_dev);
}
EXPORT_SYMBOL_GPL(adf_isr_resource_free);

/**
 * adf_isr_resource_alloc() - Allocate IRQ for acceleration device
 * @accel_dev:  Pointer to acceleration device.
 *
 * Function allocates interrupts for acceleration device.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_isr_resource_alloc(struct adf_accel_dev *accel_dev)
{
	int ret;

	ret = adf_isr_alloc_msix_entry_table(accel_dev);
	if (ret)
		return ret;
	if (adf_enable_msix(accel_dev))
		goto free_msix;

	/* If SR-IOV is disabled (vf_info is NULL), setup BH for each bank */
	if (!accel_dev->pf.vf_info)
		if (adf_setup_bh(accel_dev))
			goto disable_msix;

	if (adf_request_irqs(accel_dev))
		goto cleanup_bh;

	return 0;

cleanup_bh:
	adf_cleanup_bh(accel_dev);

disable_msix:
	adf_disable_msix(&accel_dev->accel_pci_dev);

free_msix:
	adf_isr_free_msix_entry_table(accel_dev);

	return -EFAULT;
}
EXPORT_SYMBOL_GPL(adf_isr_resource_alloc);
