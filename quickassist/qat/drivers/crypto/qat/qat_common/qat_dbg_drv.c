// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2021 - 2022 Intel Corporation */

/***************************************************************************
 * @file qat_dbg_drv.c
 *
 * This file provides Linux kernel QAT debug implementation.
 *
 ***************************************************************************/

/* System headers */
#include <linux/version.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/pci.h>

/* Project headers */
#include "adf_accel_devices.h"
#include "adf_cfg.h"
#include "adf_cfg_common.h"
#include "adf_common_drv.h"
#include "qat_dbg.h"
#include "qat_dbg_phy_map.h"

#define QATD_DEVICE_NAME "qat_debug"

static int qat_dbg_dev_open(struct inode *inodep, struct file *filep);
static ssize_t qat_dbg_dev_read(struct file *filep, char __user  *buff,
				size_t len, loff_t *off);
static int qat_dbg_dev_release(struct inode *inodep, struct file *filep);
static int qat_dbg_dev_mmap(struct file *filp, struct vm_area_struct *vma);
static long qat_dbg_dev_ioctl(struct file *fp, uint32_t cmd, unsigned long arg);

static const struct file_operations qat_dbg_fops = {
	.owner = THIS_MODULE,
	.mmap = qat_dbg_dev_mmap,
	.unlocked_ioctl = qat_dbg_dev_ioctl,
	.compat_ioctl = qat_dbg_dev_ioctl,
	.open = qat_dbg_dev_open,
	.read = qat_dbg_dev_read,
	.release = qat_dbg_dev_release,
};

struct qatd_drv_info {
	unsigned int major;
	struct cdev drv_cdev;
	struct class *drv_class;
} MY_PACKED;

static struct qatd_drv_info qatd_drv;

static int qat_dbg_dev_open(struct inode *inodep, struct file *filep)
{
	return qat_dbg_open_handler();
}

static ssize_t qat_dbg_dev_read(struct file *filep, char __user  *buff,
				size_t len, loff_t *off)
{
	return qat_dbg_phy_map_read(buff, len, off);
}

static int qat_dbg_dev_release(struct inode *inodep, struct file *filep)
{
	int pid;

	pid = (int)task_tgid_vnr(current);

	return qat_dbg_release_handler(pid);
}

/**
 * qat_dbg_dev_mmap() - Mmap debuggability device
 * @filp: pointer to a file.
 * @vma: pointer to virtual memory area.
 *
 * Function remaps page frame number associated to ring buffer allowing access
 * to that buffer from userspace.
 *
 * Return: 0 on success, error code otherwise
 */
static int qat_dbg_dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret = 0;
	struct page *page = NULL;
	struct qatd_ring_desc *ring;
	unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);
	unsigned int buffer_idx = vma->vm_pgoff & QATD_BUFFER_ID_MASK;
	unsigned int dbg_inst_idx = vma->vm_pgoff >> QATD_POOL_SIZE_SHIFT;

	if (vma->vm_start > vma->vm_end)
		return -EINVAL;

	ret = qat_dbg_mmap_handler(buffer_idx, dbg_inst_idx, size, &ring);
	if (ret)
		return ret;

	page = virt_to_page((unsigned long)ring);
	ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(page), size,
			      vma->vm_page_prot);

	return ret;
}

/**
 * qat_dbg_dev_handle_buffer_request() - Handle debug device buffer request
 * @arg: Request from userspace.
 *
 * Function handles debuggability device buffer request from userspace.
 *
 * Return: 0 on success, error code otherwise
 */
static int qat_dbg_dev_handle_buffer_request(unsigned long arg)
{
	int ret = 0;
	struct qatd_ioctl_req req = { 0 };

	ret = copy_from_user(&req, (struct qatd_ioctl_req *)arg, sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy from user\n");
		return -EFAULT;
	}

	req.request_result = qat_dbg_handle_buffer_request(&req);
	
	ret = copy_to_user((struct qatd_ioctl_req *)arg, &req, sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy to user\n");
		return -EFAULT;
	}

	return ret;
}

/**
 * qat_dbg_dev_handle_status_request()- Handle debug device status request
 * @arg: Request from userspace.
 *
 * Function handles debuggability device status request from userspace.
 *
 * Return: 0 on success, error code otherwise
 */
static int qat_dbg_dev_handle_status_request(unsigned long arg)
{
	int ret = 0;
	struct qatd_ioctl_req req = { 0 };

	ret = copy_from_user(&req, (struct qatd_ioctl_req *)arg, sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy from user\n");
		return -EFAULT;
	}

	req.request_result = qat_dbg_handle_status_request(&req);

	ret = copy_to_user((struct qatd_ioctl_req *)arg, &req, sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy to user\n");
		return -EFAULT;
	}

	return ret;
}

/**
 * qat_dbg_dev_handle_release_request() - Handle debug device release request
 * @arg: Request from userspace.
 *
 * Function handles debuggability device release request from userspace.
 *
 * Return: 0 on success, error code otherwise
 */
static int qat_dbg_dev_handle_release_request(unsigned long arg)
{
	int ret = 0;
	struct qatd_ioctl_req req = { 0 };

	ret = copy_from_user(&req, (struct qatd_ioctl_req *)arg, sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy from user\n");
		return -EFAULT;
	}

	req.request_result = qat_dbg_handle_release_request(&req);

	ret = copy_to_user((struct qatd_ioctl_req *)arg, &req, sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy to user\n");
		return -EFAULT;
	}

	return ret;
}

/**
 * qat_dbg_dev_handle_sync_request() - Handle debug device synchro. request
 * @arg: Request from userspace.
 *
 * Function handles debuggability device synchronization request from
 * userspace.
 *
 * Return: 0 on success, error code otherwise
 */
static int qat_dbg_dev_handle_sync_request(unsigned long arg)
{
	int ret = 0;
	struct qatd_ioctl_req req = { 0 };

	ret = copy_from_user(&req, (struct qatd_ioctl_req *)arg, sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy from user\n");
		return -EFAULT;
	}

	req.request_result = qat_dbg_handle_sync_request(&req);

	ret = copy_to_user((struct qatd_ioctl_req *)arg, &req, sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy to user\n");
		return -EFAULT;
	}

	return ret;
}

/**
 * qat_dbg_dev_handle_manual_dump() - Handle debug device crash dump request
 * @arg: Request from userspace.
 *
 * Function handles dubuggability device manual dump request from userspace.
 *
 * Return: 0 on success, error code otherwise
 */
static int qat_dbg_dev_handle_manual_dump(unsigned long arg)
{
	int ret = 0;
	struct qatd_ioctl_req req = { 0 };

	ret = copy_from_user(&req, (struct qatd_ioctl_req *)arg, sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy from user\n");
		return -EFAULT;
	}

	req.request_result = qat_dbg_handle_manual_dump_request(&req);

	ret = copy_to_user((struct qatd_ioctl_req *)arg, &req, sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy to user\n");
		return -EFAULT;
	}

	return ret;
}

/**
 * qat_dbg_dev_handle_err_resp() - Handle debug device error response request
 * @arg: Request from userspace.
 *
 * Function handles debuggability device error response request from userspace.
 *
 * Return: 0 on success, error code otherwise
 */
static int qat_dbg_dev_handle_err_resp(unsigned long arg)
{
	int ret = 0;
	struct qatd_ioctl_req req = { 0 };

	ret = copy_from_user(&req, (struct qatd_ioctl_req *)arg, sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy from user\n");
		return -EFAULT;
	}

	req.request_result = qat_dbg_handle_err_resp_request(&req);

	ret = copy_to_user((struct qatd_ioctl_req *)arg, &req, sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy to user\n");
		return -EFAULT;
	}

	return ret;
}

/**
 * qat_dbg_dev_handle_bsf_to_id() - Handle BSF to device id translation request
 * @arg: Request from userspace.
 *
 * Function handles Bus Slot Function to device identifier translation request.
 * The translation is necessary while working with VFs on host OS (e.g.
 * Data Plane Development Kit) to initialize debuggability feature for Virtual
 * Function device.
 *
 * Return: 0 on success, error code otherwise
 */
static int qat_dbg_dev_handle_bsf_to_id(unsigned long arg)
{
	int ret;
	u32 id;
	struct adf_accel_dev *accel_dev;
	struct pci_dev *pcidev;
	unsigned int devfn;
	int domain;
	u8 bus;
	struct qatd_ioctl_bsf2id_req req = { 0 };

	ret = copy_from_user(&req, (struct qatd_ioctl_bsf2id_req *)arg,
			     sizeof(req));
	if (unlikely(ret)) {
		pr_err("QAT: failed to copy from user\n");
		return -EFAULT;
	}

	req.request_result = -ENODEV;
	devfn = PCI_DEVFN(req.dev, req.func);
	for (id = 0; id < ADF_MAX_DEVICES; id++) {
		accel_dev = qatd_get_dev_by_id(id);
		if (!accel_dev)
			continue;

		pcidev = accel_to_pci_dev(accel_dev);
		domain = pci_domain_nr(pcidev->bus);
		bus = pcidev->bus->number;
		if (req.domain == domain && req.bus == bus &&
		    devfn == pcidev->devfn) {
			req.request_result = 0;
			req.device_id = accel_dev->accel_id;
			break;
		}
	}

	ret = copy_to_user((struct qatd_ioctl_bsf2id_req *)arg, &req,
			   sizeof(req));
	if (unlikely(ret)) {
		dev_err(&GET_DEV(accel_dev), "QAT: failed to copy to user\n");
		return -EFAULT;
	}

	return ret;
}

/**
 * qat_dbg_dev_ioctl() - Debuggability device input/output control
 * @fp: Pointer to a file.
 * @cmd: IOCTL command
 * @arg: Request from userspace.
 *
 * Function handles requests related to debiggability device input/output
 * control.
 *
 * Return: 0 on success, error code otherwise
 */
static long qat_dbg_dev_ioctl(struct file *fp, uint32_t cmd, unsigned long arg)
{
	long status;

	switch (cmd) {
	case IOCTL_QATD_STATUS:
		status = qat_dbg_dev_handle_status_request(arg);
		break;
	case IOCTL_QATD_BUFFER_REQ:
		status = qat_dbg_dev_handle_buffer_request(arg);
		break;
	case IOCTL_QATD_BUFFER_RELEASE:
		status = qat_dbg_dev_handle_release_request(arg);
		break;
	case IOCTL_QATD_SYNC_REQ:
		status = qat_dbg_dev_handle_sync_request(arg);
		break;
	case IOCTL_QATD_CRASH_DUMP:
		status = qat_dbg_dev_handle_manual_dump(arg);
		break;
	case IOCTL_QATD_ERR_RESP:
		status = qat_dbg_dev_handle_err_resp(arg);
		break;
	case IOCTL_QATD_BSF_TO_ID:
		status = qat_dbg_dev_handle_bsf_to_id(arg);
		break;
	default:
		pr_err("QAT: Invalid ioctl\n");
		status = -EFAULT;
		break;
	}

	return status;
}

/**
 * qat_dbg_chr_drv_create() - Create debuggability character device
 *
 * Function creates debuggability character device with a name qat_debug.
 *
 * Return: 0 on success, error code otherwise
 */
static int qat_dbg_chr_drv_create(void)
{
	dev_t dev_id;
	struct device *drv_device;

	if (alloc_chrdev_region(&dev_id, 0, 1, QATD_DEVICE_NAME)) {
		pr_err("QAT: unable to allocate chrdev region\n");
		return -EFAULT;
	}

#if KERNEL_VERSION(6, 4, 0) > LINUX_VERSION_CODE
	qatd_drv.drv_class = class_create(THIS_MODULE, QATD_DEVICE_NAME);
#else
	qatd_drv.drv_class = class_create(QATD_DEVICE_NAME);
#endif
	if (IS_ERR(qatd_drv.drv_class)) {
		pr_err("QAT: class_create failed for qat_dbg\n");
		goto err_chrdev_unreg;
	}
	qatd_drv.major = MAJOR(dev_id);
	cdev_init(&qatd_drv.drv_cdev, &qat_dbg_fops);
	if (cdev_add(&qatd_drv.drv_cdev, dev_id, 1)) {
		pr_err("QAT: cdev add failed\n");
		goto err_class_destr;
	}

	drv_device = device_create(qatd_drv.drv_class, NULL,
				   MKDEV(qatd_drv.major, 0),
				   NULL, QATD_DEVICE_NAME);
	if (IS_ERR(drv_device)) {
		pr_err("QAT: failed to create device\n");
		goto err_cdev_del;
	}
	return 0;
err_cdev_del:
	cdev_del(&qatd_drv.drv_cdev);
err_class_destr:
	class_destroy(qatd_drv.drv_class);
err_chrdev_unreg:
	unregister_chrdev_region(dev_id, 1);
	return -EFAULT;
}

/**
 * qat_dbg_chr_drv_destroy() - Destroy debuggability character device
 *
 * Function destroys debuggability character device.
 */
static void qat_dbg_chr_drv_destroy(void)
{
	device_destroy(qatd_drv.drv_class, MKDEV(qatd_drv.major, 0));
	cdev_del(&qatd_drv.drv_cdev);
	class_destroy(qatd_drv.drv_class);
	unregister_chrdev_region(MKDEV(qatd_drv.major, 0), 1);
}

/**
 * qat_dbg_dev_init_instance() - Initialize debuggability device instance
 * @accel_dev: Pointer to acceleration device.
 *
 * Function initializes debuggability device instance.
 *
 * Return: 0 on success, error code otherwise.
 */
int qat_dbg_dev_init_instance(struct adf_accel_dev *accel_dev)
{
	return qat_dbg_init_instance(accel_dev);
}

/**
 * qat_dbg_dev_shutdown_instance() - Shut down debuggability device instance
 * @accel_dev: Pointer to acceleration device.
 *
 * Function shuts down debuggability device instance.
 */
void qat_dbg_dev_shutdown_instance(struct adf_accel_dev *accel_dev)
{
	qat_dbg_shutdown_instance(accel_dev);
}

/**
 * qat_dbg_dev_restart_instance() - Restart debuggability device instance
 * @accel_dev: Pointer to acceleration device.
 *
 * Function restarts debuggability device instance.
 */
int qat_dbg_dev_restart_instance(struct adf_accel_dev *accel_dev)
{
	return qat_dbg_restart_instance(accel_dev);
}

/**
 * qat_dbg_dev_register() - Register debuggability character device
 *
 * Function registers debuggability character device with a name qat_debug.
 *
 * Return: 0 on success, error code otherwise
 */
int qat_dbg_dev_register(void)
{
	return qat_dbg_chr_drv_create();
}

/**
 * qat_dbg_dev_unregister() - Unregister debuggability character device
 *
 * Function unregisters debuggability character device.
 */
void qat_dbg_dev_unregister(void)
{
	qat_dbg_unregister_handler();
	qat_dbg_chr_drv_destroy();
}
