// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2014 - 2022 Intel Corporation */
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/bitops.h>
#include <linux/pci.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/crypto.h>
#include <linux/device.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <crypto/algapi.h>

#include "adf_accel_devices.h"
#include "adf_common_drv.h"
#include "adf_cfg.h"
#include "adf_cfg_common.h"
#include "adf_cfg_user.h"
#include "adf_cfg_device.h"
#include "adf_uio.h"
#include "qdm.h"
#include "adf_sla.h"
#include "adf_ctl_rl.h"
#include "adf_du_user.h"
#ifdef QAT_DBG
#include "qat_dbg.h"
#endif
#include "adf_heartbeat.h"

/* Max number of PCI buses in system */
#define MAX_PCI_BUS 256
/* Maximum number of instances multiplied by 5 */
#define COPY_KEY_LOOP_LIMIT 2560

#define DEVICE_NAME "qat_adf_ctl"

/*
 * Floyd's algorithm is used for loop detection.
 * @node:      Pointer to head of kernel space list
 */
#define ADF_DETECT_CYCLED(node)                                            \
({                                                                         \
	int ret = 0;                                                       \
	typeof(node) head = (node);                                        \
	struct adf_user_addr_info *fast =                                  \
		list_first_entry(head, struct adf_user_addr_info, list),   \
				  *slow = fast;                            \
	while (fast) {                                                     \
		fast = list_next_entry(fast, list);                        \
		if (!fast || &fast->list == head)                          \
			break;                                             \
		fast = list_next_entry(fast, list);                        \
		slow = list_next_entry(slow, list);                        \
		if (!fast || &fast->list == head)                          \
			break;                                             \
		if (fast->user_addr == slow->user_addr) {                  \
			dev_err(&GET_DEV(accel_dev),                       \
				"cycled loop detected\n");                 \
			ret = -EFAULT;                                     \
			break;                                             \
		}                                                          \
	}                                                                  \
	ret;                                                               \
})

/*
 * Macro creates a kernel space list containing user space addresses.
 * After each copy_from_user(), kernel space list is traversed to
 * verify whether the user space list is NULL terminated. A limit of
 * 2560(COPY_KEY_LOOP_LIMIT) is set when creating kernel space lists.
 * If a loop is detected, error is returned.
 * @node    pointer to first user space element.
 */
#define ADF_IS_USER_LIST_LOOPED(node)                                      \
({                                                                         \
	int ret = 0;                                                       \
	int cnt = 0;                                                       \
	typeof(node) list = (node);                                        \
	typeof(*list) user_data;                                           \
	struct adf_user_addr_info *curr, *tmp;                             \
	LIST_HEAD(usr_addr_list);                                          \
	while (list && cnt < COPY_KEY_LOOP_LIMIT) {                        \
		if (copy_from_user(&user_data, (void __user *)list,        \
				   sizeof(*list))) {                       \
			dev_err(&GET_DEV(accel_dev),                       \
				"failed to copy user info\n");             \
			ret = -EFAULT;                                     \
			break;                                             \
		}                                                          \
		curr = kzalloc(sizeof(*curr), GFP_KERNEL);                 \
		if (!curr) {                                               \
			ret = -ENOMEM;                                     \
			break;                                             \
		}                                                          \
		curr->user_addr = list;                                    \
		list_add_tail(&curr->list, &usr_addr_list);                \
		if (ADF_DETECT_CYCLED(&usr_addr_list)) {                   \
			ret = -EFAULT;                                     \
			break;                                             \
		}                                                          \
		list = user_data.next;                                     \
		cnt++;                                     \
	}                                                                  \
	list_for_each_entry_safe(curr, tmp, &usr_addr_list, list)  {       \
		list_del(&curr->list);                                     \
		kfree(curr);                                               \
	}                                                                  \
	ret;                                                               \
})

static DEFINE_MUTEX(adf_ctl_lock);
static long adf_ctl_ioctl(struct file *fp, unsigned int cmd, unsigned long arg);
static int adf_ctl_mmap_misc_counter(struct file *fp,
				     struct vm_area_struct *vma);


static const struct file_operations adf_ctl_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = adf_ctl_ioctl,
	.compat_ioctl = adf_ctl_ioctl,
	.mmap = adf_ctl_mmap_misc_counter,
};

void *misc_counter;
EXPORT_SYMBOL_GPL(misc_counter);

struct adf_ctl_drv_info {
	unsigned int major;
	struct cdev drv_cdev;
	struct class *drv_class;
};

/*
 * Structure to maintain user space address list and
 * is used to determine whether user space list has a loop
 */
struct adf_user_addr_info {
	struct list_head list;
	void *user_addr;
};

static struct adf_ctl_drv_info adf_ctl_drv;

static void adf_chr_drv_destroy(void)
{
	device_destroy(adf_ctl_drv.drv_class, MKDEV(adf_ctl_drv.major, 0));
	cdev_del(&adf_ctl_drv.drv_cdev);
	class_destroy(adf_ctl_drv.drv_class);
	unregister_chrdev_region(MKDEV(adf_ctl_drv.major, 0), 1);
}

static int adf_chr_drv_create(void)
{
	dev_t dev_id;
	struct device *drv_device;

	if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME)) {
		pr_err("QAT: unable to allocate chrdev region\n");
		return -EFAULT;
	}

#if KERNEL_VERSION(6, 4, 0) > LINUX_VERSION_CODE
	adf_ctl_drv.drv_class = class_create(THIS_MODULE, DEVICE_NAME);
#else
	adf_ctl_drv.drv_class = class_create(DEVICE_NAME);
#endif
	if (IS_ERR(adf_ctl_drv.drv_class)) {
		pr_err("QAT: class_create failed for adf_ctl\n");
		goto err_chrdev_unreg;
	}
	adf_ctl_drv.major = MAJOR(dev_id);
	cdev_init(&adf_ctl_drv.drv_cdev, &adf_ctl_ops);
	if (cdev_add(&adf_ctl_drv.drv_cdev, dev_id, 1)) {
		pr_err("QAT: cdev add failed\n");
		goto err_class_destr;
	}

	drv_device = device_create(adf_ctl_drv.drv_class, NULL,
				   MKDEV(adf_ctl_drv.major, 0),
				   NULL, DEVICE_NAME);
	if (IS_ERR(drv_device)) {
		pr_err("QAT: failed to create device\n");
		goto err_cdev_del;
	}
	return 0;
err_cdev_del:
	cdev_del(&adf_ctl_drv.drv_cdev);
err_class_destr:
	class_destroy(adf_ctl_drv.drv_class);
err_chrdev_unreg:
	unregister_chrdev_region(dev_id, 1);
	return -EFAULT;
}

static int adf_ctl_alloc_resources(struct adf_user_cfg_ctl_data **ctl_data,
				   unsigned long arg)
{
	struct adf_user_cfg_ctl_data *cfg_data;

	cfg_data = kzalloc(sizeof(*cfg_data), GFP_KERNEL);
	if (!cfg_data)
		return -ENOMEM;

	/* Initialize device id to NO DEVICE as 0 is a valid device id */
	cfg_data->device_id = ADF_CFG_NO_DEVICE;

	if (copy_from_user(cfg_data, (void __user *)arg, sizeof(*cfg_data))) {
		pr_err("QAT: failed to copy from user cfg_data.\n");
		kfree(cfg_data);
		return -EIO;
	}

	*ctl_data = cfg_data;
	return 0;
}

static int adf_add_key_value_data(struct adf_accel_dev *accel_dev,
				  const char *section,
				  const struct adf_user_cfg_key_val *key_val)
{
	if (key_val->type == ADF_HEX) {
		long *ptr = (long *)key_val->val;
		long val = *ptr;

		if (adf_cfg_add_key_value_param(accel_dev, section,
						key_val->key, (void *)val,
						key_val->type)) {
			dev_err(&GET_DEV(accel_dev),
				"failed to add hex keyvalue.\n");
			return -EFAULT;
		}
	} else {
		if (adf_cfg_add_key_value_param(accel_dev, section,
						key_val->key, key_val->val,
						key_val->type)) {
			dev_err(&GET_DEV(accel_dev),
				"failed to add keyvalue.\n");
			return -EFAULT;
		}
	}
	return 0;
}

static int adf_copy_key_value_data(struct adf_accel_dev *accel_dev,
				   struct adf_user_cfg_ctl_data *ctl_data)
{
	u32 inner_loop_ct = 0;
	u32 outer_loop_ct = 0;
	struct adf_user_cfg_key_val key_val;
	struct adf_user_cfg_key_val *params_head;
	struct adf_user_cfg_section section, *section_head;

	section_head = ctl_data->config_section;

	if (ADF_IS_USER_LIST_LOOPED(section_head))
		goto out_err;

	while (section_head && outer_loop_ct < COPY_KEY_LOOP_LIMIT) {
		if (copy_from_user(&section, (void __user *)section_head,
				   sizeof(*section_head))) {
			dev_err(&GET_DEV(accel_dev),
				"failed to copy section info\n");
			goto out_err;
		}

		if (adf_cfg_section_add(accel_dev, section.name)) {
			dev_err(&GET_DEV(accel_dev),
				"failed to add section.\n");
			goto out_err;
		}

		params_head = section.params;

		if (ADF_IS_USER_LIST_LOOPED(params_head))
			goto out_err;

		while (params_head && inner_loop_ct < COPY_KEY_LOOP_LIMIT) {
			if (copy_from_user(&key_val, (void __user *)params_head,
					   sizeof(key_val))) {
				dev_err(&GET_DEV(accel_dev),
					"Failed to copy keyvalue.\n");
				goto out_err;
			}
			if (adf_add_key_value_data(accel_dev, section.name,
						   &key_val)) {
				goto out_err;
			}
			params_head = key_val.next;
			inner_loop_ct++;
		}
		section_head = section.next;
		inner_loop_ct = 0;
		outer_loop_ct++;
	}
	return 0;
out_err:
	adf_cfg_del_all(accel_dev);
	return -EFAULT;
}

static int adf_copy_keyval_to_user(struct adf_accel_dev *accel_dev,
				   struct adf_user_cfg_ctl_data *ctl_data)
{
	struct adf_user_cfg_key_val key_val;
	struct adf_user_cfg_section section;
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES] = {0};
	char *user_ptr;

	if (copy_from_user(&section, (void __user *)ctl_data->config_section,
			   sizeof(struct adf_user_cfg_section))) {
		dev_err(&GET_DEV(accel_dev), "failed to copy section info\n");
		return -EFAULT;
	}

	if (copy_from_user(&key_val, (void __user *)section.params,
			   sizeof(struct adf_user_cfg_key_val))) {
		dev_err(&GET_DEV(accel_dev), "failed to copy key val\n");
		return -EFAULT;
	}

	user_ptr = ((char *)section.params) + ADF_CFG_MAX_KEY_LEN_IN_BYTES;

	if (adf_cfg_get_param_value(accel_dev, section.name,
				    key_val.key, val)) {
		dev_dbg(&GET_DEV(accel_dev),
			"failed to get %s value from config!\n", key_val.key);
		return -EFAULT;
	}

	if (copy_to_user((void __user *)user_ptr, val,
			 ADF_CFG_MAX_VAL_LEN_IN_BYTES)) {
		dev_err(&GET_DEV(accel_dev),
			"failed to copy keyvalue to user!\n");
		return -EFAULT;
	}

	return 0;
}

static int adf_ctl_ioctl_dev_config(unsigned long arg)
{
	int ret;
	struct adf_user_cfg_ctl_data *ctl_data;
	struct adf_accel_dev *accel_dev;
	struct adf_hw_device_data *hw_data;

	ret = adf_ctl_alloc_resources(&ctl_data, arg);
	if (ret)
		return ret;

	accel_dev = adf_devmgr_get_dev_by_id(ctl_data->device_id);
	if (!accel_dev) {
		ret = -EFAULT;
		goto out;
	}

	hw_data = accel_dev->hw_device;
	if (!hw_data) {
		dev_err(&GET_DEV(accel_dev),
			"Failed to init device - hw_data not set\n");
		ret = -EFAULT;
		goto out;
	}

	if (adf_dev_started(accel_dev)) {
		ret = -EFAULT;
		goto out;
	}

	if (adf_copy_key_value_data(accel_dev, ctl_data)) {
		ret = -EFAULT;
		goto out;
	}

	if (hw_data->config_device && hw_data->config_device(accel_dev)) {
		ret = -EFAULT;
		goto out;
	}

	set_bit(ADF_STATUS_CONFIGURED, &accel_dev->status);
out:
	kfree(ctl_data);
	return ret;
}

static int adf_ctl_ioctl_clear_dev_config(unsigned long arg)
{
	int ret;
	struct adf_user_cfg_ctl_data *ctl_data;
	struct adf_accel_dev *accel_dev;

	ret = adf_ctl_alloc_resources(&ctl_data, arg);
	if (ret)
		return ret;

	accel_dev = adf_devmgr_get_dev_by_id(ctl_data->device_id);
	if (!accel_dev) {
		ret = -EFAULT;
		goto out;
	}

	if (accel_dev->cfg && accel_dev->cfg->dev) {
		adf_cfg_device_clear(accel_dev->cfg->dev, accel_dev);
		kfree(accel_dev->cfg->dev);
		accel_dev->cfg->dev = NULL;
	}
	adf_cfg_del_all(accel_dev);

out:
	kfree(ctl_data);
	return ret;
}

static int adf_ctl_is_device_in_use(int id)
{
	struct adf_accel_dev *dev;

	list_for_each_entry(dev, adf_devmgr_get_head(), list) {
		if (id == dev->accel_id || id == ADF_CFG_ALL_DEVICES) {
			if (adf_devmgr_in_reset(dev) || adf_dev_in_use(dev)) {
				dev_info(&GET_DEV(dev),
					 "device qat_dev%d is busy\n",
					 dev->accel_id);
				return -EBUSY;
			}
		}
	}
	return 0;
}

static void adf_ctl_stop_devices(uint32_t id)
{
	struct adf_accel_dev *accel_dev;

	list_for_each_entry(accel_dev, adf_devmgr_get_head(), list) {
		if (id == accel_dev->accel_id || id == ADF_CFG_ALL_DEVICES) {
			if (!adf_dev_started(accel_dev))
				continue;

			/* First stop all VFs */
			if (!accel_dev->is_vf)
				continue;

#ifdef QAT_DBG
			qat_dbg_dev_shutdown_instance(accel_dev);
#endif
			adf_dev_stop(accel_dev);
			adf_dev_shutdown(accel_dev);
		}
	}

	list_for_each_entry(accel_dev, adf_devmgr_get_head(), list) {
		if (id == accel_dev->accel_id || id == ADF_CFG_ALL_DEVICES) {
			if (!adf_dev_started(accel_dev))
				continue;

#ifdef QAT_DBG
			qat_dbg_dev_shutdown_instance(accel_dev);
#endif
			adf_dev_stop(accel_dev);
			adf_dev_shutdown(accel_dev);
		}
	}
}

static int adf_notify_sys(struct notifier_block *this, unsigned long code,
			  void *unused)
{
	if (code == SYS_DOWN || code == SYS_HALT)
		adf_ctl_stop_devices(ADF_CFG_ALL_DEVICES);

	return NOTIFY_DONE;
}

static struct notifier_block adf_reboot_notifier = {
	.notifier_call  = adf_notify_sys,
};

static int adf_ctl_reset_devices(uint32_t id)
{
	struct adf_accel_dev *accel_dev;
	int ret = 0;

	list_for_each_entry(accel_dev, adf_devmgr_get_head(), list) {
		if (id == accel_dev->accel_id ||
		    (id == ADF_CFG_ALL_DEVICES && !accel_dev->is_vf)) {
			if (adf_dev_reset(accel_dev, ADF_DEV_RESET_ASYNC)) {
				dev_info(&GET_DEV(accel_dev),
					 "Failed to reset qat_dev%d\n",
					 accel_dev->accel_id);
				ret = -EFAULT;
			}
		}
	}
	return ret;
}

static int adf_ctl_ioctl_dev_stop(unsigned long arg)
{
	int ret;
	struct adf_user_cfg_ctl_data *ctl_data;

	ret = adf_ctl_alloc_resources(&ctl_data, arg);
	if (ret)
		return ret;

	if (adf_devmgr_verify_id(&ctl_data->device_id)) {
		pr_err("QAT: Device %d not found\n", ctl_data->device_id);
		ret = -ENODEV;
		goto out;
	}

	ret = adf_ctl_is_device_in_use(ctl_data->device_id);
	if (ret)
		goto out;

	if (ctl_data->device_id == ADF_CFG_ALL_DEVICES)
		pr_info("QAT: Stopping all acceleration devices.\n");
	else
		pr_info("QAT: Stopping acceleration device qat_dev%d.\n",
			ctl_data->device_id);

	adf_ctl_stop_devices(ctl_data->device_id);

out:
	kfree(ctl_data);
	return ret;
}

static int adf_ctl_ioctl_dev_start(unsigned long arg)
{
	int ret;
	struct adf_user_cfg_ctl_data *ctl_data;
	struct adf_accel_dev *accel_dev;
	struct adf_cfg_device *cfg_dev = NULL;

	ret = adf_ctl_alloc_resources(&ctl_data, arg);
	if (ret)
		return ret;

	accel_dev = adf_devmgr_get_dev_by_id(ctl_data->device_id);
	if (!accel_dev) {
		ret = -ENODEV;
		goto out;
	}

	if (!adf_dev_started(accel_dev)) {
		dev_info(&GET_DEV(accel_dev),
			 "Starting acceleration device qat_dev%d.\n",
			 ctl_data->device_id);
		ret = adf_dev_init(accel_dev);
		if (!ret)
			ret = adf_dev_start(accel_dev);
	} else {
		dev_info(&GET_DEV(accel_dev),
			 "Acceleration device qat_dev%d already started.\n",
			 ctl_data->device_id);
		goto out;
	}
	if (ret) {
		dev_err(&GET_DEV(accel_dev), "Failed to start qat_dev%d\n",
			ctl_data->device_id);
		adf_dev_stop(accel_dev);
		adf_dev_shutdown(accel_dev);
	} else {
		if (!accel_dev->is_vf) {
			ret = adf_cfg_setup_irq(accel_dev);
			if (ret) {
				dev_err(&GET_DEV(accel_dev),
					"Failed to setup irq for qat_dev%d\n",
					ctl_data->device_id);
				adf_dev_stop(accel_dev);
				adf_dev_shutdown(accel_dev);
				goto out;
			}
		}
#ifdef QAT_DBG
		if (qat_dbg_dev_init_instance(accel_dev)) {
			dev_err(&GET_DEV(accel_dev),
				"Failed to setup qat dbg instance\n");
			adf_dev_stop(accel_dev);
			adf_dev_shutdown(accel_dev);
			goto out;
		}
#endif /* QAT_DBG */
	}
	cfg_dev = accel_dev->cfg->dev;
	if (cfg_dev) {
		adf_cfg_device_clear(cfg_dev, accel_dev);
		kfree(cfg_dev);
		accel_dev->cfg->dev = NULL;
	}
	if (adf_devmgr_in_reset(accel_dev)) {
		clear_bit(ADF_STATUS_RESTARTING, &accel_dev->status);
		adf_dev_restarted_notify(accel_dev);
	}
out:
	kfree(ctl_data);
	return ret;
}

static int adf_ctl_ioctl_get_num_devices(unsigned long arg)
{
	uint32_t num_devices = 0;

	adf_devmgr_get_num_dev(&num_devices);
	if (copy_to_user((void __user *)arg, &num_devices, sizeof(num_devices)))
		return -EFAULT;

	return 0;
}

/*
 * adf_ctl_ioctl_dev_reset
 *
 * Function to reset acceleration device
 */
static int adf_ctl_ioctl_dev_reset(unsigned long arg)
{
	int ret;
	struct adf_user_cfg_ctl_data *ctl_data = NULL;

	ret = adf_ctl_alloc_resources(&ctl_data, arg);
	if (ret)
		return ret;

	/* Verify the device id */
	if (adf_devmgr_verify_id(&ctl_data->device_id)) {
		pr_err("QAT: Device %d not found\n", ctl_data->device_id);
		ret = -ENODEV;
		goto out;
	}

	if (ADF_CFG_ALL_DEVICES == ctl_data->device_id)
		pr_info("Scheduling reset of all acceleration devices.\n");
	else
		pr_info("Scheduling reset of device icp_dev%d.\n",
			(uint32_t)ctl_data->device_id);

	ret = adf_ctl_reset_devices(ctl_data->device_id);
	if (ret) {
		pr_err("failed to reset device %d.\n",
		       (uint32_t)ctl_data->device_id);
		ret = -ENODEV;
		goto out;
	}

out:
	kfree(ctl_data);
	return ret;
}

/*
 * adf_get_dev_node_id
 *
 * Function determines to what physical die the pci dev is connected to.
 */
static int adf_get_dev_node_id(struct pci_dev *pdev)
{
	int node_id = dev_to_node(&pdev->dev);

	if (node_id < 0) {
		unsigned int bus_per_cpu = 0;
		struct cpuinfo_x86 *c = &cpu_data(num_online_cpus() - 1);

		node_id = 0;

		/* if there is only one physical processor don't need
		 * to do any further calculations
		 */
		if (c->phys_proc_id == 0) {
			node_id = 0;
		} else {
			bus_per_cpu = MAX_PCI_BUS / (c->phys_proc_id + 1);
			if (bus_per_cpu != 0)
				node_id = pdev->bus->number / bus_per_cpu;
		}
	}

	return node_id;
}

static int adf_ctl_ioctl_get_status(unsigned long arg)
{
	struct adf_hw_device_data *hw_data;
	struct adf_dev_status_info dev_info;
	struct adf_accel_dev *accel_dev;

	if (copy_from_user(&dev_info, (void __user *)arg,
			   sizeof(struct adf_dev_status_info))) {
		pr_err("QAT: failed to copy from user.\n");
		return -EFAULT;
	}

	accel_dev = adf_devmgr_get_dev_by_id(dev_info.accel_id);
	if (!accel_dev)
		return -ENODEV;

	hw_data = accel_dev->hw_device;
	dev_info.state = adf_dev_started(accel_dev) ? DEV_UP : DEV_DOWN;
	dev_info.num_ae = hw_data->get_num_aes(hw_data);
	dev_info.num_accel = hw_data->get_num_accels(hw_data);
	dev_info.num_logical_accel = hw_data->num_logical_accel;
	dev_info.banks_per_accel = hw_data->num_banks
					/ hw_data->num_logical_accel;
	strlcpy(dev_info.name, hw_data->dev_class->name, sizeof(dev_info.name));
	dev_info.instance_id = hw_data->instance_id;
	dev_info.node_id     = adf_get_dev_node_id(accel_to_pci_dev(accel_dev));
	dev_info.type = hw_data->dev_class->type;
	dev_info.domain = pci_domain_nr(accel_to_pci_dev(accel_dev)->bus);
	dev_info.bus = accel_to_pci_dev(accel_dev)->bus->number;
	dev_info.dev = PCI_SLOT(accel_to_pci_dev(accel_dev)->devfn);
	dev_info.fun = PCI_FUNC(accel_to_pci_dev(accel_dev)->devfn);

	if (copy_to_user((void __user *)arg, &dev_info,
			 sizeof(struct adf_dev_status_info))) {
		dev_err(&GET_DEV(accel_dev), "failed to copy status.\n");
		return -EFAULT;
	}
	return 0;
}

static int adf_ctl_ioctl_dev_get_value(unsigned long arg)
{
	int ret = 0;
	struct adf_user_cfg_ctl_data *ctl_data;
	struct adf_accel_dev *accel_dev;

	ret = adf_ctl_alloc_resources(&ctl_data, arg);
	if (ret)
		return ret;

	accel_dev = adf_devmgr_get_dev_by_id(ctl_data->device_id);
	if (!accel_dev) {
		pr_err("QAT: Device %d not found\n", ctl_data->device_id);
		ret = -ENODEV;
		goto out;
	}

	ret = adf_copy_keyval_to_user(accel_dev, ctl_data);
	if (ret) {
		ret = -ENODEV;
		goto out;
	}
out:
	kfree(ctl_data);
	return ret;
}

static int adf_ctl_ioctl_check_cfg_section(unsigned long arg)
{
	struct adf_user_section_data cfg_data;
	struct adf_accel_dev *accel_dev;

	if (copy_from_user(&cfg_data, (void __user *)arg, sizeof(cfg_data))) {
		pr_err("QAT: failed to copy from user cfg_data.\n");
		return -EFAULT;
	}

	accel_dev = adf_devmgr_get_dev_by_id(cfg_data.device_id);
	if (!accel_dev) {
		pr_err("QAT: Device %d not found\n", cfg_data.device_id);
		return -ENODEV;
	}

	if (adf_cfg_sec_find(accel_dev, cfg_data.name))
		cfg_data.is_section_present = 1;
	else
		cfg_data.is_section_present = 0;

	if (copy_to_user((void __user *)arg, &cfg_data, sizeof(cfg_data))) {
		dev_err(&GET_DEV(accel_dev),
			"failed to copy cfg_data to user!\n");
		return -EFAULT;
	}

	return 0;
}

static int adf_ctl_ioctl_heartbeat(unsigned long arg)
{
	int ret = 0;
	struct adf_accel_dev *accel_dev;
	struct adf_dev_heartbeat_status_ctl hb_status;

	if (copy_from_user(&hb_status, (void __user *)arg, sizeof(hb_status))) {
		pr_err("QAT: failed to copy from user hb_status.\n");
		return -EFAULT;
	}

	accel_dev = adf_devmgr_get_dev_by_id(hb_status.device_id);
	if (!accel_dev)
		return -ENODEV;

	if (adf_heartbeat_status(accel_dev, &hb_status.status)) {
		dev_err(&GET_DEV(accel_dev),
			"failed to get heartbeat status\n");
		return -EAGAIN;
	}

	if (copy_to_user((void __user *)arg, &hb_status, sizeof(hb_status))) {
		dev_err(&GET_DEV(accel_dev),
			"failed to copy hb_status to user!\n");
		ret = -EFAULT;
	}

	return ret;
}

#ifdef QAT_HB_FAIL_SIM
static int adf_ctl_ioctl_heartbeat_sim_fail(unsigned long arg)
{
	struct adf_accel_dev *accel_dev =
			adf_devmgr_get_dev_by_id(arg);

	if (!accel_dev)
		return -ENODEV;

	if (adf_heartbeat_simulate_failure(accel_dev))
		return -EFAULT;

	return 0;
}
#endif

#ifdef QAT_DBG
static int adf_ctl_ioctl_debug_status_accel_dev(unsigned long arg)
{
	struct adf_dev_status_info dev_info;
	struct adf_accel_dev *accel_dev;
	struct adf_hw_device_data *hw_data;

	if (copy_from_user(&dev_info, (void __user *)arg,
			   sizeof(struct adf_dev_status_info))) {
		pr_err("QAT: failed to copy from user.\n");
		return -EFAULT;
	}

	accel_dev = qatd_get_dev_by_id(dev_info.accel_id);
	if (!accel_dev)
		return -ENODEV;

	hw_data = accel_dev->hw_device;
	if (accel_dev->cfg) /* Acceleration framework device */
		strlcpy(dev_info.name, hw_data->dev_class->name,
			sizeof(dev_info.name));
	else /* Detached VF fake accel device */
		snprintf(dev_info.name, sizeof(dev_info.name),
			 "%s%s",
			 hw_data->dev_class->name,
			 QATD_DETACHED_VF_NAME_SUFFIX);

	dev_info.domain = pci_domain_nr(accel_to_pci_dev(accel_dev)->bus);
	dev_info.bus = accel_to_pci_dev(accel_dev)->bus->number;
	dev_info.dev = PCI_SLOT(accel_to_pci_dev(accel_dev)->devfn);
	dev_info.fun = PCI_FUNC(accel_to_pci_dev(accel_dev)->devfn);
	dev_info.state = adf_dev_started(accel_dev) ? DEV_UP : DEV_DOWN;
	dev_info.node_id = adf_get_dev_node_id(accel_to_pci_dev(accel_dev));

	if (copy_to_user((void __user *)arg, &dev_info,
			 sizeof(struct adf_dev_status_info))) {
		dev_err(&GET_DEV(accel_dev), "failed to copy status.\n");
		return -EFAULT;
	}

	return 0;
}

#endif
static int adf_ctl_mmap_misc_counter(struct file *fp,
				     struct vm_area_struct *vma)
{
	unsigned long mem_size = vma->vm_end - vma->vm_start;

	if (mem_size != PAGE_SIZE) {
		pr_err("QAT: Incorrect mem_size for misc counter.\n");
		return -EINVAL;
	}

	if (misc_counter) {
		if (remap_pfn_range(vma, vma->vm_start,
				    virt_to_phys(misc_counter) >> PAGE_SHIFT,
				    mem_size,
				    vma->vm_page_prot)) {
			pr_err("QAT: Failed to mmap misc counter to user.\n");
			return -EFAULT;
		}
	}

	return 0;
}

static long adf_ctl_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	int ret;
	bool allowed = false;
	int i;
	static const unsigned int unrestricted_cmds[] = {
		IOCTL_GET_NUM_DEVICES,
		IOCTL_STATUS_ACCEL_DEV,
		IOCTL_HEARTBEAT_ACCEL_DEV,
		IOCTL_GET_CFG_VAL,
		IOCTL_RESERVE_RING,
		IOCTL_RELEASE_RING,
		IOCTL_ENABLE_RING,
		IOCTL_DISABLE_RING,
		IOCTL_CHECK_CFG_SECTION,
#ifdef QAT_DBG
		IOCTL_DEBUG_STATUS_ACCEL_DEV,
#endif
	};

	if (!capable(CAP_SYS_ADMIN)) {
		for (i = 0; i < ARRAY_SIZE(unrestricted_cmds); i++) {
			if (cmd == unrestricted_cmds[i]) {
				allowed = true;
				break;
			}
		}
		if (!allowed)
			return -EACCES;
	}

	if (mutex_lock_interruptible(&adf_ctl_lock))
		return -EFAULT;

	switch (cmd) {
	case IOCTL_CONFIG_SYS_RESOURCE_PARAMETERS:
		ret = adf_ctl_ioctl_dev_config(arg);
		break;

	case IOCTL_STOP_ACCEL_DEV:
		ret = adf_ctl_ioctl_dev_stop(arg);
		break;

	case IOCTL_START_ACCEL_DEV:
		ret = adf_ctl_ioctl_dev_start(arg);
		break;

	case IOCTL_GET_NUM_DEVICES:
		ret = adf_ctl_ioctl_get_num_devices(arg);
		break;

	case IOCTL_STATUS_ACCEL_DEV:
		ret = adf_ctl_ioctl_get_status(arg);
		break;
	case IOCTL_HEARTBEAT_ACCEL_DEV:
		ret = adf_ctl_ioctl_heartbeat(arg);
		break;
#ifdef QAT_HB_FAIL_SIM
	case IOCTL_HEARTBEAT_SIM_FAIL:
		ret = adf_ctl_ioctl_heartbeat_sim_fail(arg);
		break;
#endif
	case IOCTL_CLEAR_SYS_RESOURCE_PARAMETERS:
		ret = adf_ctl_ioctl_clear_dev_config(arg);
		break;
	case IOCTL_RESET_ACCEL_DEV:
		ret = adf_ctl_ioctl_dev_reset(arg);
		break;
	case IOCTL_GET_CFG_VAL:
		ret = adf_ctl_ioctl_dev_get_value(arg);
		break;
	case IOCTL_RESERVE_RING:
		ret = adf_ctl_ioctl_reserve_ring(arg);
		break;
	case IOCTL_RELEASE_RING:
		ret = adf_ctl_ioctl_release_ring(arg);
		break;
	case IOCTL_ENABLE_RING:
		ret = adf_ctl_ioctl_enable_ring(arg);
		break;
	case IOCTL_DISABLE_RING:
		ret = adf_ctl_ioctl_disable_ring(arg);
		break;
	case IOCTL_SLA_GET_CAPS:
		ret = adf_ctl_ioctl_sla_get_caps(arg);
		break;
	case IOCTL_SLA_CREATE:
		ret = adf_ctl_ioctl_sla_create(arg);
		break;
	case IOCTL_SLA_UPDATE:
		ret = adf_ctl_ioctl_sla_update(arg);
		break;
	case IOCTL_SLA_DELETE:
		ret = adf_ctl_ioctl_sla_delete(arg);
		break;
	case IOCTL_SLA_GET_LIST:
		ret = adf_ctl_ioctl_sla_get_list(arg);
		break;
	case IOCTL_DU_START:
		ret = adf_ctl_ioctl_du_start(arg);
		break;
	case IOCTL_DU_STOP:
		ret = adf_ctl_ioctl_du_stop(arg);
		break;
	case IOCTL_DU_QUERY:
		ret = adf_ctl_ioctl_du_query(arg);
		break;
	case IOCTL_DU_QUERY_VF:
		ret = adf_ctl_ioctl_du_query_vf(arg);
		break;
	case IOCTL_CHECK_CFG_SECTION:
		ret = adf_ctl_ioctl_check_cfg_section(arg);
		break;
#ifdef QAT_DBG
	case IOCTL_DEBUG_STATUS_ACCEL_DEV:
		ret = adf_ctl_ioctl_debug_status_accel_dev(arg);
		break;
#endif
	default:
		pr_err("QAT: Invalid ioctl\n");
		ret = -EFAULT;
		break;
	}
	mutex_unlock(&adf_ctl_lock);
	return ret;
}

static int __init adf_register_ctl_device_driver(void)
{
	mutex_init(&adf_ctl_lock);

	if (register_reboot_notifier(&adf_reboot_notifier)) {
		pr_err("QAT: cannot register reboot notifier\n");
		goto err_reboot_notifier;
	}

	if (adf_chr_drv_create())
		goto err_chr_dev;

	if (adf_init_aer())
		goto err_aer;

	if (adf_init_fatal_error_wq())
		goto err_event_wq;

	if (qat_crypto_register())
		goto err_crypto_register;

	if (adf_processes_dev_register())
		goto err_processes_dev_register;
	if (qdm_init())
		goto err_qdm_init;
	if (adf_uio_service_register())
		goto err_adf_service_register;
#ifdef QAT_DBG
	if (qat_dbg_dev_register())
		goto err_dbg_dev_register;
#endif

	return 0;

#ifdef QAT_DBG
err_dbg_dev_register:
#endif
err_adf_service_register:
err_qdm_init:
err_processes_dev_register:
	qat_crypto_unregister();
err_crypto_register:
	adf_exit_fatal_error_wq();
err_event_wq:
	adf_exit_aer();
err_aer:
	adf_chr_drv_destroy();
err_chr_dev:
	unregister_reboot_notifier(&adf_reboot_notifier);
err_reboot_notifier:
	mutex_destroy(&adf_ctl_lock);
	return -EFAULT;
}

static void __exit adf_unregister_ctl_device_driver(void)
{
#ifdef QAT_DBG
	qat_dbg_dev_unregister();
#endif
	adf_uio_service_unregister();
	qdm_exit();
	adf_processes_dev_unregister();
	adf_exit_vf_wq();
	adf_chr_drv_destroy();
	adf_exit_aer();
	adf_exit_fatal_error_wq();
	qat_crypto_unregister();
	adf_clean_vf_map(ADF_CFG_ALL_DEVICES);
	unregister_reboot_notifier(&adf_reboot_notifier);
	mutex_destroy(&adf_ctl_lock);
}

module_init(adf_register_ctl_device_driver);
module_exit(adf_unregister_ctl_device_driver);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Intel");
MODULE_DESCRIPTION("Intel(R) QuickAssist Technology");
MODULE_ALIAS_CRYPTO("intel_qat");
MODULE_VERSION(ADF_DRV_VERSION);
