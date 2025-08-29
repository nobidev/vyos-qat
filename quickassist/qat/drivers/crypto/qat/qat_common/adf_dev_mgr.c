// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2014 - 2022 Intel Corporation */
#include <linux/mutex.h>
#include <linux/list.h>
#include "adf_cfg.h"
#include "adf_common_drv.h"
#ifdef QAT_DBG
#include "qat_dbg.h"
#endif

#define ADF_NUM_FUNC_PER_DEV 8

static LIST_HEAD(accel_table);
static LIST_HEAD(vfs_table);
static DEFINE_MUTEX(table_lock);
static uint32_t num_devices;
static u8 id_map[ADF_MAX_DEVICES];

struct vf_id_map {
	u16 dev_id;
	u32 bdf;
	u32 id;
	u32 fake_id;
	bool attached;
	struct list_head list;
};

static int adf_get_vf_id(struct adf_accel_dev *vf,
			 struct adf_accel_dev *pf)
{
	u16 first_vf_offset;
	int sriov;
	int vf_id = 0;
	u8 vf_slot = PCI_SLOT(accel_to_pci_dev(vf)->devfn);
	u8 vf_func = PCI_FUNC(accel_to_pci_dev(vf)->devfn);
	u8 slot, func;

	/* Get the first vf offset */
	sriov = pci_find_ext_capability(accel_to_pci_dev(pf),
					PCI_EXT_CAP_ID_SRIOV);
	pci_read_config_word(accel_to_pci_dev(pf), sriov + PCI_SRIOV_VF_OFFSET,
			     &first_vf_offset);

	slot = PCI_SLOT(accel_to_pci_dev(pf)->devfn) +
			   (first_vf_offset / ADF_NUM_FUNC_PER_DEV);
	func = PCI_FUNC(accel_to_pci_dev(pf)->devfn) +
			(first_vf_offset % ADF_NUM_FUNC_PER_DEV);

	while (slot != vf_slot || func != vf_func) {
		vf_id++;
		if (!((func + 1) % ADF_NUM_FUNC_PER_DEV)) {
			func = 0x0;
			slot++;
			continue;
		}
		func++;
	}

	return vf_id;
}

static int adf_get_vf_num(struct adf_accel_dev *vf,
			  struct adf_accel_dev *pf)
{
	return (accel_to_pci_dev(vf)->bus->number << 8) | adf_get_vf_id(vf, pf);
}

static struct vf_id_map *adf_find_vf(u32 bdf)
{
	struct list_head *itr;

	list_for_each(itr, &vfs_table) {
		struct vf_id_map *ptr =
			list_entry(itr, struct vf_id_map, list);

		if (ptr->bdf == bdf)
			return ptr;
	}
	return NULL;
}

/**
 * adf_clean_vf_map() - Cleans VF id mapings
 *
 * Function cleans internal ids for virtual functions.
 * @dev_id : device id of VF to be cleaned
 */
void adf_clean_vf_map(u16 dev_id)
{
	struct vf_id_map *map;
	struct list_head *ptr, *tmp;

	mutex_lock(&table_lock);
	list_for_each_safe(ptr, tmp, &vfs_table) {
		map = list_entry(ptr, struct vf_id_map, list);

		if (dev_id != ADF_CFG_ALL_DEVICES &&
		    (map->dev_id != dev_id || map->bdf == -1))
			continue;

		if (map->bdf != -1) {
			id_map[map->id] = 0;
			num_devices--;
		}

		list_del(ptr);
		kfree(map);
	}
	mutex_unlock(&table_lock);
}
EXPORT_SYMBOL_GPL(adf_clean_vf_map);

/**
 * adf_devmgr_update_class_index() - Update internal index
 * @hw_data:  Pointer to internal device data.
 *
 * Function updates internal dev index for VFs
 */
void adf_devmgr_update_class_index(struct adf_hw_device_data *hw_data)
{
	struct adf_hw_device_class *class = hw_data->dev_class;
	struct list_head *itr;
	int i = 0;

	list_for_each(itr, &accel_table) {
		struct adf_accel_dev *ptr =
				list_entry(itr, struct adf_accel_dev, list);

		if (ptr->hw_device->dev_class == class)
			ptr->hw_device->instance_id = i++;

		if (i == class->instances)
			break;
	}
}
EXPORT_SYMBOL_GPL(adf_devmgr_update_class_index);

static unsigned int adf_find_free_id(void)
{
	unsigned int i;

	for (i = 0; i < ADF_MAX_DEVICES; i++) {
		if (!id_map[i]) {
			id_map[i] = 1;
			return i;
		}
	}
	return ADF_MAX_DEVICES + 1;
}

/**
 * adf_devmgr_add_dev() - Add accel_dev to the acceleration framework
 * @accel_dev:  Pointer to acceleration device.
 * @pf:		Corresponding PF if the accel_dev is a VF
 *
 * Function adds acceleration device to the acceleration framework.
 * To be used by QAT device specific drivers.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_devmgr_add_dev(struct adf_accel_dev *accel_dev,
		       struct adf_accel_dev *pf)
{
	struct list_head *itr;
	int ret = 0;

	if (num_devices == ADF_MAX_DEVICES) {
		dev_err(&GET_DEV(accel_dev), "Only support up to %d devices\n",
			ADF_MAX_DEVICES);
		return -EFAULT;
	}
#ifdef QAT_DBG
	/* Handle qat_xxxvf module insertion - remove fake device first if it
	   exists for given VF
	 */
	if (accel_dev->is_vf) {
		struct adf_pci_address pci_addr;
		struct adf_accel_vf_info *vf;

		adf_devmgr_get_dev_pci_addr(accel_dev, &pci_addr);
		vf = adf_devmgr_get_dev_vf_by_bdf(&pci_addr);
		qat_dbg_shutdown_instance_vf(vf, true);
	}
#endif

	mutex_lock(&table_lock);
	atomic_set(&accel_dev->ref_count, 0);

	/* PF on host or VF on guest */
	if (!accel_dev->is_vf || (accel_dev->is_vf && !pf)) {
		struct vf_id_map *map;

		list_for_each(itr, &accel_table) {
			struct adf_accel_dev *ptr =
				list_entry(itr, struct adf_accel_dev, list);

			if (ptr == accel_dev) {
				ret = -EEXIST;
				goto unlock;
			}
		}

		list_add_tail(&accel_dev->list, &accel_table);
		accel_dev->accel_id = adf_find_free_id();
		if (accel_dev->accel_id > ADF_MAX_DEVICES) {
			ret = -EFAULT;
			goto unlock;
		}
		num_devices++;
		map = kzalloc(sizeof(*map), GFP_KERNEL);
		if (!map) {
			ret = -ENOMEM;
			goto unlock;
		}
		map->dev_id = accel_dev->accel_pci_dev.pci_dev->device;
		map->bdf = ~0;
		map->id = accel_dev->accel_id;
		map->fake_id = map->id;
		map->attached = true;
		list_add_tail(&map->list, &vfs_table);
	} else if (accel_dev->is_vf && pf) {
		/* VF on host */
		struct vf_id_map *map;

		map = adf_find_vf(adf_get_vf_num(accel_dev, pf));
		if (map) {
			struct vf_id_map *next;

			accel_dev->accel_id = map->id;
			list_add_tail(&accel_dev->list, &accel_table);
			map->fake_id++;
			map->attached = true;
			next = list_next_entry(map, list);
			while (next && &next->list != &vfs_table) {
				next->fake_id++;
				next = list_next_entry(next, list);
			}

			ret = 0;
			goto unlock;
		}

		map = kzalloc(sizeof(*map), GFP_KERNEL);
		if (!map) {
			ret = -ENOMEM;
			goto unlock;
		}
		accel_dev->accel_id = adf_find_free_id();
		if (accel_dev->accel_id > ADF_MAX_DEVICES) {
			kfree(map);
			ret = -EFAULT;
			goto unlock;
		}
		num_devices++;
		list_add_tail(&accel_dev->list, &accel_table);
		map->dev_id = accel_dev->accel_pci_dev.pci_dev->device;
		map->bdf = adf_get_vf_num(accel_dev, pf);
		map->id = accel_dev->accel_id;
		map->fake_id = map->id;
		map->attached = true;
		list_add_tail(&map->list, &vfs_table);
	}
unlock:
	mutex_unlock(&table_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(adf_devmgr_add_dev);

#ifdef QAT_DBG
/**
 * adf_devmgr_add_fake_dev() - Create fake accel_dev
 *
 * Function creates accelerator device placeholder and returns pointer to it.
 * The device will not be visible in acceleration framework but will have
 * unique device id.
 * To be used by QAT Debuggability tool.
 *
 * Return: Pointer to created accelerator device on success, NULL otherwise.
 */
struct adf_accel_dev *adf_devmgr_add_fake_dev(void)
{
	struct adf_accel_dev *accel_dev = NULL;

	accel_dev = kzalloc(sizeof(*accel_dev), GFP_KERNEL);
	if (!accel_dev) {
		pr_err("QAT: Failed to create accel_dev\n");
		return NULL;
	}
	/* Do not increment num_devices so that fake dev will not be visible
	 * in acceleration framework */
	mutex_lock(&table_lock);
	accel_dev->accel_id = adf_find_free_id();
	if (accel_dev->accel_id >= ADF_MAX_DEVICES) {
		kfree(accel_dev);
		accel_dev = NULL;
	}

	mutex_unlock(&table_lock);

	return accel_dev;
}

#endif
struct list_head *adf_devmgr_get_head(void)
{
	return &accel_table;
}

/**
 * adf_devmgr_rm_dev() - Remove accel_dev from the acceleration framework.
 * @accel_dev:  Pointer to acceleration device.
 * @pf:		Corresponding PF if the accel_dev is a VF
 *
 * Function removes acceleration device from the acceleration framework.
 * To be used by QAT device specific drivers.
 *
 * Return: void
 */
void adf_devmgr_rm_dev(struct adf_accel_dev *accel_dev,
		       struct adf_accel_dev *pf)
{
#ifdef QAT_DBG
	struct adf_pci_address pci_addr;
	struct adf_accel_vf_info *vf_info = NULL;

	if (accel_dev->is_vf && pf) {
		adf_devmgr_get_dev_pci_addr(accel_dev, &pci_addr);
		vf_info = adf_devmgr_get_dev_vf_by_bdf(&pci_addr);
	}
#endif
	mutex_lock(&table_lock);
	if (!accel_dev->is_vf || (accel_dev->is_vf && !pf)) {
		id_map[accel_dev->accel_id] = 0;
		num_devices--;
	} else if (accel_dev->is_vf && pf) {
		struct vf_id_map *map, *next;

		map = adf_find_vf(adf_get_vf_num(accel_dev, pf));
		if (!map) {
			dev_err(&GET_DEV(accel_dev), "Failed to find VF map\n");
			goto unlock;
		}
		map->fake_id--;
		map->attached = false;
		next = list_next_entry(map, list);
		while (next && &next->list != &vfs_table) {
			next->fake_id--;
			next = list_next_entry(next, list);
		}
#ifdef QAT_DBG
		/* The VF is outside framework - Debuggability can be configured
		 * for it via sysfs */
		(void)qat_dbg_init_instance_vf(vf_info);
#endif
	}
unlock:
	list_del(&accel_dev->list);
	mutex_unlock(&table_lock);
}
EXPORT_SYMBOL_GPL(adf_devmgr_rm_dev);

#ifdef QAT_DBG
/**
 * adf_devmgr_rm_fake_dev() - Remove fake accel_dev
 * @accel_dev: Pointer to fake acceleration device.
 *
 * Function removes accelerator device placeholder.
 * To be used by QAT Debuggability tool.
 *
 * Return: none.
 */
void adf_devmgr_rm_fake_dev(struct adf_accel_dev *accel_dev)
{
	mutex_lock(&table_lock);
	id_map[accel_dev->accel_id] = 0;
	kfree(accel_dev);
	mutex_unlock(&table_lock);
}

#endif
struct adf_accel_dev *adf_devmgr_get_first(void)
{
	struct adf_accel_dev *dev = NULL;

	if (!list_empty(&accel_table))
		dev = list_first_entry(&accel_table, struct adf_accel_dev,
				       list);
	return dev;
}

/**
 * adf_devmgr_pci_to_accel_dev() - Get accel_dev associated with the pci_dev.
 * @pci_dev:  Pointer to pci device.
 *
 * Function returns acceleration device associated with the given pci device.
 * To be used by QAT device specific drivers.
 *
 * Return: pointer to accel_dev or NULL if not found.
 */
struct adf_accel_dev *adf_devmgr_pci_to_accel_dev(struct pci_dev *pci_dev)
{
	struct list_head *itr;

	mutex_lock(&table_lock);
	list_for_each(itr, &accel_table) {
		struct adf_accel_dev *ptr =
				list_entry(itr, struct adf_accel_dev, list);

		if (ptr->accel_pci_dev.pci_dev == pci_dev) {
			mutex_unlock(&table_lock);
			return ptr;
		}
	}
	mutex_unlock(&table_lock);
	return NULL;
}
EXPORT_SYMBOL_GPL(adf_devmgr_pci_to_accel_dev);

/**
 * adf_devmgr_get_dev_pci_addr() - Get PCI address of given accelerator device
 * @accel_dev:  Pointer to acceleration device.
 * @pci_addr:   Pointer to adf_pci_address structure which will be filled.
 *
 * To be used by QAT Debuggability tool.
 *
 * Return: none.
 */
void adf_devmgr_get_dev_pci_addr(struct adf_accel_dev *accel_dev,
				 struct adf_pci_address *pci_addr)
{
	struct pci_dev *pdev = accel_to_pci_dev(accel_dev);

	pci_addr->bus = pdev->bus->number;
	pci_addr->dev = PCI_SLOT(pdev->devfn);
	pci_addr->func = PCI_FUNC(pdev->devfn);
}

struct adf_accel_dev *adf_devmgr_get_dev_by_id(uint32_t id)
{
	struct list_head *itr;

	mutex_lock(&table_lock);
	list_for_each(itr, &accel_table) {
		struct adf_accel_dev *ptr =
				list_entry(itr, struct adf_accel_dev, list);
		if (ptr->accel_id == id) {
			mutex_unlock(&table_lock);
			return ptr;
		}
	}
	mutex_unlock(&table_lock);
	return NULL;
}

#ifdef QAT_DBG
struct adf_accel_vf_info *adf_devmgr_get_dev_vf_by_bdf(
	struct adf_pci_address *pci_addr)
{
	struct list_head *itr;
	struct adf_accel_dev *accel_dev;
	int totalvfs, i;
	struct adf_accel_vf_info *vf;
	struct adf_pci_address vf_pci_addr;

	mutex_lock(&table_lock);
	list_for_each(itr, &accel_table) {
		accel_dev = list_entry(itr, struct adf_accel_dev, list);
		if (accel_dev->is_vf || !accel_dev->pf.vf_info)
			continue;
		/* Search for BDF in PF VFs */
		totalvfs = pci_sriov_get_totalvfs(accel_to_pci_dev(
						     accel_dev));
		for (i = 0, vf = accel_dev->pf.vf_info; i < totalvfs;
		     i++, vf++) {
			if (!adf_get_vf_pci_addr(accel_dev, i, &vf_pci_addr))
				if (adf_is_bdf_equal(pci_addr, &vf_pci_addr))
					goto on_exit;
		}
	}

	vf = NULL;
on_exit:
	mutex_unlock(&table_lock);
	return vf;
}

/**
 * qatd_get_dev_by_id() - Get accelerator device structure for given device id
 * @id : Accelerator device id.
 *
 * Function search for given device id in devices added to acceleration
 * framework as well in Debuggability fake devices representing detached VFs.
 * To be used by QAT Debuggability tool.
 *
 * Return: Pointer to acceleration device on success, NULL otherwise.
 */
struct adf_accel_dev *qatd_get_dev_by_id(u32 id)
{
	struct list_head *itr;
	struct adf_accel_dev *accel_dev;
	int numvfs, i;
	struct adf_accel_vf_info *vf;

	mutex_lock(&table_lock);
	list_for_each(itr, &accel_table) {
		accel_dev = list_entry(itr, struct adf_accel_dev, list);
		if (accel_dev->accel_id == id)
			goto on_exit;
		if (accel_dev->is_vf || !accel_dev->pf.vf_info)
			continue;
		/* Search for given id in Debuggability fake devices */
		numvfs = pci_num_vf(accel_to_pci_dev(accel_dev));
		for (i = 0, vf = accel_dev->pf.vf_info; i < numvfs;
		     i++, vf++) {
			if (vf->qatd_fake_dev &&
			    vf->qatd_fake_dev->accel_id == id) {
				accel_dev = vf->qatd_fake_dev;
				goto on_exit;
			}
		}
	}

	accel_dev = NULL;
on_exit:
	mutex_unlock(&table_lock);
	return accel_dev;
}

#endif
int adf_devmgr_verify_id(uint32_t *id)
{
	struct adf_accel_dev *accel_dev;

	if (*id == ADF_CFG_ALL_DEVICES)
		return 0;

	accel_dev = adf_devmgr_get_dev_by_id(*id);
	if (!accel_dev)
		return -ENODEV;

	/* Correct the id if real and fake differ */
	*id = accel_dev->accel_id;
	return 0;
}

static int adf_get_num_dettached_vfs(void)
{
	struct list_head *itr;
	int vfs = 0;

	mutex_lock(&table_lock);
	list_for_each(itr, &vfs_table) {
		struct vf_id_map *ptr =
			list_entry(itr, struct vf_id_map, list);
		if (ptr->bdf != ~0 && !ptr->attached)
			vfs++;
	}
	mutex_unlock(&table_lock);
	return vfs;
}

void adf_devmgr_get_num_dev(uint32_t *num)
{
	*num = num_devices - adf_get_num_dettached_vfs();
}

/**
 * adf_dev_in_use() - Check whether accel_dev is currently in use
 * @accel_dev: Pointer to acceleration device.
 *
 * To be used by QAT device specific drivers.
 *
 * Return: 1 when device is in use, 0 otherwise.
 */
int adf_dev_in_use(struct adf_accel_dev *accel_dev)
{
	return atomic_read(&accel_dev->ref_count) != 0;
}
EXPORT_SYMBOL_GPL(adf_dev_in_use);

static int adf_dev_pf_get(struct adf_accel_dev *vf_accel_dev)
{
	int ret = 0;
	struct adf_accel_dev *pf_accel_dev = NULL;
	struct pci_dev *pf_pci_dev = NULL;

	pf_pci_dev = vf_accel_dev->accel_pci_dev.pci_dev->physfn;
	pf_accel_dev = adf_devmgr_pci_to_accel_dev(pf_pci_dev);
	if (pf_accel_dev) {
		if (atomic_add_return(1, &pf_accel_dev->ref_count) == 1) {
			if (!try_module_get(pf_accel_dev->owner))
				ret = -EFAULT;
		}
	}
	return ret;
}

static void adf_dev_pf_put(struct adf_accel_dev *vf_accel_dev)
{
	struct adf_accel_dev *pf_accel_dev = NULL;
	struct pci_dev *pf_pci_dev = NULL;

	pf_pci_dev = vf_accel_dev->accel_pci_dev.pci_dev->physfn;
	pf_accel_dev = adf_devmgr_pci_to_accel_dev(pf_pci_dev);
	if (pf_accel_dev) {
		if (atomic_sub_return(1, &pf_accel_dev->ref_count) == 0)
			module_put(pf_accel_dev->owner);
	}
}

/**
 * adf_dev_get() - Increment accel_dev reference count
 * @accel_dev: Pointer to acceleration device.
 *
 * Increment the accel_dev refcount and if this is the first time
 * incrementing it during this period the accel_dev is in use,
 * increment the module refcount too.
 * If the accel_dev parsed is vf accel_dev on host,
 * increment the corresponding pf accel_dev refcount and its module refcount.
 * To be used by QAT device specific drivers.
 *
 * Return: 0 when successful, EFAULT when fail to bump module refcount
 */
int adf_dev_get(struct adf_accel_dev *accel_dev)
{
	if (atomic_add_return(1, &accel_dev->ref_count) == 1) {
		if (!try_module_get(accel_dev->owner))
			return -EFAULT;
		if (accel_dev->is_vf)
			return adf_dev_pf_get(accel_dev);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(adf_dev_get);

/**
 * adf_dev_put() - Decrement accel_dev reference count
 * @accel_dev: Pointer to acceleration device.
 *
 * Decrement the accel_dev refcount and if this is the last time
 * decrementing it during this period the accel_dev is in use,
 * decrement the module refcount too.
 * If the accel_dev parsed is vf accel_dev on host,
 * decrement the corresponding pf accel_dev refcount and its module refcount.
 * To be used by QAT device specific drivers.
 *
 * Return: void
 */
void adf_dev_put(struct adf_accel_dev *accel_dev)
{
	if (atomic_sub_return(1, &accel_dev->ref_count) == 0) {
		module_put(accel_dev->owner);
		if (accel_dev->is_vf)
			adf_dev_pf_put(accel_dev);
	}
}
EXPORT_SYMBOL_GPL(adf_dev_put);

/**
 * adf_devmgr_in_reset() - Check whether device is in reset
 * @accel_dev: Pointer to acceleration device.
 *
 * To be used by QAT device specific drivers.
 *
 * Return: 1 when the device is being reset, 0 otherwise.
 */
int adf_devmgr_in_reset(struct adf_accel_dev *accel_dev)
{
	return test_bit(ADF_STATUS_RESTARTING, &accel_dev->status);
}
EXPORT_SYMBOL_GPL(adf_devmgr_in_reset);

/**
 * adf_dev_started() - Check whether device has started
 * @accel_dev: Pointer to acceleration device.
 *
 * To be used by QAT device specific drivers.
 *
 * Return: 1 when the device has started, 0 otherwise
 */
int adf_dev_started(struct adf_accel_dev *accel_dev)
{
	return test_bit(ADF_STATUS_STARTED, &accel_dev->status);
}
EXPORT_SYMBOL_GPL(adf_dev_started);

void adf_devmgr_update_drv_rm(u16 dev_id)
{
	struct list_head *itr;

	mutex_lock(&table_lock);
	list_for_each(itr, &accel_table) {
		struct adf_accel_dev *ptr =
			list_entry(itr, struct adf_accel_dev, list);
			struct pci_dev *pdev = accel_to_pci_dev(ptr);
			if (pdev->device == dev_id)
				ptr->is_drv_rm = true;
	}
	mutex_unlock(&table_lock);
}
EXPORT_SYMBOL_GPL(adf_devmgr_update_drv_rm);

/*
 * adf_devmgr_get_dev_by_bdf() - Look up accel_dev by BDF
 * @pci_addr: pointer to adf_pci_address structure
 *
 * To be used by DU and SLA ioctls.
 *
 * Return: accel_dev if found, NULL otherwise.
 *
 * Note: Caller has to call adf_dev_put once finished using the accel_dev!
 */
struct adf_accel_dev *adf_devmgr_get_dev_by_bdf(
			struct adf_pci_address *pci_addr)
{
	struct adf_accel_dev *accel_dev = NULL;
	struct pci_dev *pci_dev = NULL;
	unsigned int devfn = PCI_DEVFN(pci_addr->dev, pci_addr->func);
	bool dev_found = false;

	mutex_lock(&table_lock);
	list_for_each_entry(accel_dev, &accel_table, list) {
		pci_dev = accel_to_pci_dev(accel_dev);
		if (pci_dev->bus->number == pci_addr->bus &&
		    pci_dev->devfn == devfn &&
		    pci_domain_nr(pci_dev->bus) == pci_addr->domain_nr) {
			dev_found = true;
			break;
		}
	}
	mutex_unlock(&table_lock);
	if (dev_found) {
		adf_dev_get(accel_dev);
		return accel_dev;
	}

	return NULL;
}

/*
 * adf_devmgr_get_dev_by_domain_bus() - Look up accel_dev using pci domain and bus
 * @pci_addr: Address of pci device.
 *
 * To be used by DU and SLA ioctls.
 *
 * Return: accel_dev if found, NULL otherwise.
 *
 * Note: Caller has to call adf_dev_put once finished using the accel_dev!
 */
struct adf_accel_dev *
adf_devmgr_get_dev_by_pci_domain_bus(struct adf_pci_address *pci_addr)
{
	struct adf_accel_dev *accel_dev = NULL;
	struct pci_dev *pci_dev = NULL;
	bool dev_found = false;

	mutex_lock(&table_lock);
	list_for_each_entry(accel_dev, &accel_table, list) {
		pci_dev = accel_to_pci_dev(accel_dev);
		if (pci_dev->bus->number == pci_addr->bus &&
		    pci_domain_nr(pci_dev->bus) == pci_addr->domain_nr) {
			dev_found = true;
			break;
		}
	}

	mutex_unlock(&table_lock);
	if (dev_found) {
		adf_dev_get(accel_dev);
		return accel_dev;
	}

	return NULL;
}

/*
 * adf_get_vf_nr - Look up accel_dev and get vf number
 * @pci_addr: pointer to adf_pci_address structure
 * @vf_nr: Pointer to get the VF number
 *
 * To be used by DU and SLA ioctls.
 */
int adf_get_vf_nr(struct adf_pci_address *vf_pci_addr, int *vf_nr)
{
	struct adf_accel_dev *accel_dev = NULL;
	u16 first_vf_offset;
	int sriov;
	int vf_id = 0;
	u8 vf_slot = vf_pci_addr->dev;
	u8 vf_func = vf_pci_addr->func;
	u8 slot, func;

	if (vf_pci_addr->func > ADF_MAX_FUNC_PER_DEV)
		return -EINVAL;

	accel_dev = adf_devmgr_get_dev_by_pci_domain_bus(vf_pci_addr);
	if (!accel_dev)
		return -EINVAL;

	/* Get the first vf offset */
	sriov = pci_find_ext_capability(accel_to_pci_dev(accel_dev),
					PCI_EXT_CAP_ID_SRIOV);
	if (!sriov)
		return -EINVAL;

	pci_read_config_word(accel_to_pci_dev(accel_dev),
			     sriov + PCI_SRIOV_VF_OFFSET,
			     &first_vf_offset);
	slot = PCI_SLOT(accel_to_pci_dev(accel_dev)->devfn) +
			     (first_vf_offset / ADF_NUM_FUNC_PER_DEV);
	func = PCI_FUNC(accel_to_pci_dev(accel_dev)->devfn) +
			      (first_vf_offset % ADF_NUM_FUNC_PER_DEV);
	adf_dev_put(accel_dev);

	while (slot != vf_slot || func != vf_func) {
		vf_id++;
		if (!((func + 1) % ADF_NUM_FUNC_PER_DEV)) {
			func = 0x0;
			slot++;
			continue;
		}
		func++;
	}

	*vf_nr = vf_id;

	return 0;
}

/**
 * adf_get_vf_pci_addr() - Obtain PCI address of given accelerator device VF
 * @pf:       Pointer to acceleration device.
 * @vf_nr:    Virtual Function number.
 * @pci_addr: Pointer to adf_pci_address structure.
 *
 * To be used by QAT Debuggability tool.
 *
 * Return: 0 on success, error code otherwise.
 */
int adf_get_vf_pci_addr(struct adf_accel_dev *pf, u8 vf_nr,
			struct adf_pci_address *pci_addr)
{
	u16 vf_offset;
	int sriov;
	struct pci_dev *pdev = accel_to_pci_dev(pf);

	/* Get the first VF offset */
	sriov = pci_find_ext_capability(pdev,
					   PCI_EXT_CAP_ID_SRIOV);
	if (!sriov)
		return -EINVAL;

	pci_read_config_word(pdev, sriov + PCI_SRIOV_VF_OFFSET,
			     &vf_offset);
	vf_offset += vf_nr;
	adf_devmgr_get_dev_pci_addr(pf, pci_addr);
	pci_addr->dev += vf_offset / ADF_NUM_FUNC_PER_DEV;
	pci_addr->func += vf_offset % ADF_NUM_FUNC_PER_DEV;

	return 0;
}

/*
 * adf_is_vf_nr_valid - Look up accel_dev and check vf number is valid
 * @accel_dev: pointer to acceleration device
 * @vf_nr: vf number to be checked
 *
 * To be used by DU and SLA ioctls.
 */
int adf_is_vf_nr_valid(struct adf_accel_dev *accel_dev, int vf_nr)
{
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);
	u8 num_banks = GET_MAX_BANKS(accel_dev);

	if (hw_data->get_num_vfs)
		num_banks = hw_data->get_num_vfs(accel_dev);

	return (vf_nr >= 0 && vf_nr < num_banks ? 0 : -EINVAL);
}

/*
 * adf_is_bdf_equal - Compare and check both the BDF addresses are same or not
 * @bdf1: BDF address to be compared
 * @bdf2: BDF address to be compared
 *
 */
bool adf_is_bdf_equal(struct adf_pci_address *bdf1,
		      struct adf_pci_address *bdf2)
{
	return bdf1->bus == bdf2->bus &&
		bdf1->dev == bdf2->dev &&
		bdf1->func == bdf2->func;
}

/**
 * adf_get_pci_dev_by_bdf() - Get pci_dev structure for given PCI address
 * @pci_addr: Pointer to adf_pci_address structure.
 *
 * To be used by QAT Debuggability tool.
 *
 * Return: Pointer to kernel pci_dev structure on success, NULL otherwise.
 */
struct pci_dev *adf_get_pci_dev_by_bdf(struct adf_pci_address *pci_addr)
{
	struct pci_dev *pci_dev;
	unsigned int devfn;

	devfn = PCI_DEVFN(pci_addr->dev, pci_addr->func);
	/* Loop through all Co-processor devices */
	pci_dev = pci_get_class(PCI_CLASS_PROCESSOR_CO << 8, NULL);
	while (pci_dev) {
		if (pci_dev->bus->number == pci_addr->bus &&
		    pci_dev->devfn == devfn) {
			break;
		}

		pci_dev = pci_get_class(PCI_CLASS_PROCESSOR_CO << 8,
					   pci_dev);
	}

	return pci_dev;
}
