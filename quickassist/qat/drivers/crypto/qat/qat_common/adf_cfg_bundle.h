/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2017 - 2019, 2021 Intel Corporation */
#ifndef ADF_CFG_BUNDLE_H_
#define ADF_CFG_BUNDLE_H_

#include "adf_accel_devices.h"
#include "adf_cfg_common.h"
#include "adf_cfg_device.h"

#define MAX_SECTIONS_PER_BUNDLE 8
#define MAX_SECTION_NAME_LEN 64

#define TX	0x0
#define RX	0x1

#define ASSIGN_SERV_TO_RINGS(bund, index, base, stype, rng_per_srv) \
	do { \
		int j = 0; \
		typeof(bund) b = (bund); \
		typeof(index) i = (index); \
		typeof(base) s = (base); \
		typeof(stype) t = (stype); \
		typeof(rng_per_srv) rps = (rng_per_srv); \
		for (j = 0; j < rps; j++) { \
			b->rings[i + j]->serv_type = t; \
			b->rings[i + j + s]->serv_type = t; \
		} \
	} while (0)

struct adf_cfg_device;

enum adf_accel_serv_type {
	ADF_ACCEL_SERV_NA = 0x0,
	ADF_ACCEL_SERV_ASYM,
	ADF_ACCEL_SERV_SYM,
	ADF_ACCEL_SERV_RND,
	ADF_ACCEL_SERV_DC
};

struct adf_cfg_ring {
	u8 mode:1;
	enum adf_accel_serv_type serv_type;
	u8 number:4;
};

struct adf_cfg_bundle {
	/* Section(s) name this bundle is shared by */
	char **sections;
	int max_section;
	int section_index;
	int number;
	enum adf_cfg_bundle_type type;
	cpumask_t affinity_mask;
	int polling_mode;
	int instance_num;
	int num_of_rings;
	/* contains all the info about rings */
	struct adf_cfg_ring **rings;
	u16 in_use;
};

bool adf_cfg_is_free(struct adf_cfg_bundle *bundle);

int adf_cfg_get_ring_pairs_from_bundle(struct adf_cfg_bundle *bundle,
				       struct adf_cfg_instance *inst,
				       const char *process_name,
				       struct adf_cfg_instance *bundle_inst,
				       struct adf_cfg_device *device);

struct adf_cfg_instance *adf_cfg_get_free_instance(
					struct adf_accel_dev *accel_dev,
					struct adf_cfg_device *device,
					struct adf_cfg_bundle *bundle,
					struct adf_cfg_instance *inst,
					const char *process_name);

int adf_cfg_bundle_init(struct adf_cfg_bundle *bundle,
			struct adf_cfg_device *device,
			int bank_num,
			struct adf_accel_dev *accel_dev);

void adf_cfg_bundle_clear(struct adf_cfg_bundle *bundle,
			  struct adf_accel_dev *accel_dev);

int adf_cfg_init_ring2serv_mapping(struct adf_accel_dev *accel_dev,
				   struct adf_cfg_bundle *bundle);

int adf_cfg_rel_ring2serv_mapping(struct adf_cfg_bundle *bundle);

int adf_cfg_rel_ring2serv_mapping(struct adf_cfg_bundle *bundle);
#endif
