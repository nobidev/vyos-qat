/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2016, 2021 Intel Corporation */
#ifndef __QDM_H__
#define __QDM_H__
#include <linux/types.h>

struct device;

int qdm_init(void);
void qdm_exit(void);
int qdm_attach_device(struct device *dev);
int qdm_detach_device(struct device *dev);
int qdm_iommu_map(dma_addr_t *iova, void *vaddr, size_t size);
int qdm_iommu_unmap(dma_addr_t iova, size_t size);
int qdm_hugepage_iommu_map(dma_addr_t *iova, void *va_page, size_t size);

#endif /* __QDM_H__ */
