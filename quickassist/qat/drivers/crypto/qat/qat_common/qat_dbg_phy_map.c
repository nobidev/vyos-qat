// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2021 - 2022 Intel Corporation */

/***************************************************************************
 * @file qat_dbg_phy_map.c
 *
 * This file provides Linux kernel QAT debug physical memory map utilities
 *
 ***************************************************************************/

/* System headers */
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/signal.h>
#else
#include <linux/signal.h>
#endif
#include <linux/sched.h>
#include <linux/rtc.h>

/* Project headers */
#include "qat_dbg.h"
#include "qat_dbg_phy_map.h"
#include "adf_cfg_common.h"
#include "adf_common_drv.h"

#define QATD_MMAP_DEV_HEADER_FORMAT "%s %03d"

struct qatd_phy_proc_map {
	char *data;
	size_t size;
} __packed;

static DEFINE_MUTEX(qat_dbg_phy_map_lock);
struct qatd_phy_proc_map proc_mmap[ADF_MAX_DEVICES];

/**
 * qat_dbg_phy_map_read() - Read debuggability physical map
 * @buff: Pointer to userspace buffer.
 * @len: Length to be read.
 * @off: Pointer to a file offset.
 *
 * Function reads from process mmaped data and copies that data to userspace.
 *
 * Return: Length of a copied buffer on success, error code otherwise
 */
ssize_t qat_dbg_phy_map_read(char *buff, size_t len, loff_t *off)
{
	ssize_t size = 0;
	unsigned int dev = 0;
	char *start_ptr = NULL;
	char *end_ptr = NULL;
	char out_buf[QATD_MAX_FILE_LINE] = {0};
	size_t tmp = 0;
	size_t buffer_len = 0;

	mutex_lock(&qat_dbg_phy_map_lock);
	size = min_t(size_t, QATD_MAX_FILE_LINE, len);

	for (dev = 0; dev < ADF_MAX_DEVICES; dev++) {
		if (!proc_mmap[dev].data)
			continue;

		tmp += proc_mmap[dev].size;
		if ((*off + buffer_len) > tmp)
			continue;

		start_ptr =
			proc_mmap[dev].data + ((*off + buffer_len) -
			(tmp - proc_mmap[dev].size));
		end_ptr =
			start_ptr + min_t(size_t, proc_mmap[dev].size -
			(start_ptr - proc_mmap[dev].data),
			(size - buffer_len));

		if (start_ptr >= end_ptr)
			continue;

		memcpy(out_buf + buffer_len, start_ptr, (end_ptr - start_ptr));
		buffer_len += (end_ptr - start_ptr);
		if (buffer_len == size)
			break;
	}

	if (!start_ptr || !end_ptr) {
		mutex_unlock(&qat_dbg_phy_map_lock);
		return 0;
	}

	if (copy_to_user(buff, out_buf, buffer_len)) {
		mutex_unlock(&qat_dbg_phy_map_lock);
		return -EFAULT;
	}

	*off += buffer_len;
	mutex_unlock(&qat_dbg_phy_map_lock);

	return buffer_len;
}

/**
 * qat_dbg_phy_map_store() - Store physical process map
 * @accel_dev: Pointer to acceleration device.
 *
 * Function stores physical process map.
 *
 * Return: 0 on success, error code otherwise
 */
void qat_dbg_phy_map_store(struct adf_accel_dev *accel_dev)
{
	struct task_struct *task = NULL;
	struct vm_area_struct *vma = NULL;
	unsigned long pte_ul = 0;
	unsigned long lines = 0;
	int buffer_len = 0;
	size_t size = 0;
	struct rtc_time tm;

#if (KERNEL_VERSION(6, 1, 0) <= LINUX_VERSION_CODE)
	VMA_ITERATOR(vmi, current->mm, 0);
#endif
	if (!accel_dev)
		return;

	mutex_lock(&qat_dbg_phy_map_lock);

	vfree(proc_mmap[accel_dev->accel_id].data);
	proc_mmap[accel_dev->accel_id].data = NULL;
	proc_mmap[accel_dev->accel_id].size = 0;

	qat_dbg_time_getter(&tm);
	/* Estimating required space */
	rcu_read_lock();
	for_each_process(task)
	{
#if (KERNEL_VERSION(6, 1, 0) <= LINUX_VERSION_CODE)
		if (!task->mm)
			continue;
		for_each_vma(vmi, vma) {
#else
		if (!task->mm || !task->mm->mmap)
			continue;
		for (vma = task->mm->mmap; vma; vma = vma->vm_next)
		{
#endif
			if (!(vma->vm_flags & VM_PFNMAP) &&
			    !(vma->vm_flags & VM_HUGETLB))
				continue;

			lines++;
		}
	}
	size = (lines + 1) * QATD_MAX_FILE_LINE;

	proc_mmap[accel_dev->accel_id].data = vmalloc(size);
	if (!proc_mmap[accel_dev->accel_id].data) {
		pr_err("QAT: Failed to allocate memory for processes physical map\n");
		goto on_exit;
	}

	buffer_len = snprintf(proc_mmap[accel_dev->accel_id].data,
			     size,
			     QATD_MMAP_DEV_HEADER_FORMAT
			     " (%04d-%02d-%02d_%02d%02d%02d GMT)\n",
			     QATD_MMAP_DEV_HEADER,
			     accel_dev->accel_id,
			     (tm.tm_year + 1900),
			     tm.tm_mon + 1,
			     tm.tm_mday,
			     tm.tm_hour,
			     tm.tm_min,
			     tm.tm_sec);
 
	for_each_process(task)
	{
#if (KERNEL_VERSION(6, 1, 0) <= LINUX_VERSION_CODE)
		if (!task->mm)
			continue;

		for_each_vma(vmi, vma) {
#else
		if (!task->mm || !task->mm->mmap)
			continue;

		for (vma = task->mm->mmap; vma; vma = vma->vm_next) {
#endif
			unsigned long long seg_size, pfn;
			pte_t pte;

			if (buffer_len >= size) {
				pr_err("QAT: Failed to get processes "
					"physical map\n");
				proc_mmap[accel_dev->accel_id].size = size - 1;
				goto on_exit;
			}

			if (!(vma->vm_flags & VM_PFNMAP) &&
			    !(vma->vm_flags & VM_HUGETLB))
				continue;

			pte_ul = qat_dbg_get_pte(task->mm, vma->vm_start);
			seg_size = vma->vm_end - vma->vm_start;

			pte.pte = pte_ul;
			pfn = pte_pfn(pte) << PAGE_SHIFT;

			buffer_len += snprintf
				(proc_mmap[accel_dev->accel_id].data +
				buffer_len,
				size - buffer_len, "%d:0x%016llx:%llu\n",
				(int)task_tgid_vnr(task), pfn, seg_size);
		}
	}

	proc_mmap[accel_dev->accel_id].size = buffer_len;
on_exit:
	rcu_read_unlock();
	mutex_unlock(&qat_dbg_phy_map_lock);
}

void qat_dbg_phy_map_copy(struct adf_accel_dev *accel_dev_dst,
			  struct adf_accel_dev *accel_dev_src)
{
	struct qatd_phy_proc_map *src, *dst;
	int pos;

	if (!accel_dev_dst || !accel_dev_src)
		return;

	mutex_lock(&qat_dbg_phy_map_lock);

	src = proc_mmap + accel_dev_src->accel_id;
	dst = proc_mmap + accel_dev_dst->accel_id;
	dst->data = vmalloc(src->size);
	if (!dst->data) {
		pr_err("QAT: Failed to allocate memory for processes physical map\n");
		goto on_exit;
	}

	memcpy(dst->data, src->data, src->size);
	dst->size = src->size;
	/* Replace header with accelerator id */
	pos = snprintf(dst->data, dst->size, QATD_MMAP_DEV_HEADER_FORMAT,
		       QATD_MMAP_DEV_HEADER, accel_dev_dst->accel_id);
	if (pos > 0)
		dst->data[pos] = ' ';

on_exit:
	mutex_unlock(&qat_dbg_phy_map_lock);
}

/**
 * qat_dbg_phy_map_free() - Free debuggability physical process map
 */
void qat_dbg_phy_map_free(void)
{
	size_t i;

	mutex_lock(&qat_dbg_phy_map_lock);
	for (i = 0; i < ADF_MAX_DEVICES; i++) {
		vfree(proc_mmap[i].data);
		proc_mmap[i].data = NULL;
		proc_mmap[i].size = 0;
	}
	mutex_unlock(&qat_dbg_phy_map_lock);
}
