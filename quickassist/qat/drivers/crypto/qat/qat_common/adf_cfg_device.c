// SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
/* Copyright(c) 2017 - 2021 Intel Corporation */
#include <linux/pci.h>
#include "adf_cfg_device.h"
#include "adf_cfg_section.h"
#include "icp_qat_hw.h"
#include "adf_cfg_bundle.h"

#define ADF_CFG_SVCS_MAX (25)
#define ADF_CFG_DEPRE_PARAMS_NUM (4)

#define ADF_CFG_CAP_DC ADF_ACCEL_CAPABILITIES_COMPRESSION
#define ADF_CFG_CAP_ASYM ADF_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC
#define ADF_CFG_CAP_SYM ADF_ACCEL_CAPABILITIES_CRYPTO_SYMMETRIC
#define ADF_CFG_CAP_CY (ADF_CFG_CAP_ASYM | ADF_CFG_CAP_SYM)

#define ADF_CFG_FW_CAP_RL ICP_ACCEL_CAPABILITIES_RL
#define ADF_CFG_FW_CAP_HKDF ICP_ACCEL_CAPABILITIES_HKDF
#define ADF_CFG_FW_CAP_ECEDMONT ICP_ACCEL_CAPABILITIES_ECEDMONT
#define ADF_CFG_FW_CAP_EXT_ALGCHAIN ICP_ACCEL_CAPABILITIES_EXT_ALGCHAIN
#define ADF_CFG_FW_CAP_CIPHER ICP_ACCEL_CAPABILITIES_CIPHER
#define ADF_CFG_FW_CAP_AUTHENTICATION ICP_ACCEL_CAPABILITIES_AUTHENTICATION
#define SET_BIT(byte, bit) ((byte) |= (1UL << (bit)))
#define CLEAR_BIT(byte, bit) ((byte) &= ~(1UL << (bit)))

#define ADF_CFG_CY_RINGS \
	(CRYPTO | CRYPTO << ADF_CFG_SERV_RING_PAIR_1_SHIFT | \
	CRYPTO << ADF_CFG_SERV_RING_PAIR_2_SHIFT | \
	CRYPTO << ADF_CFG_SERV_RING_PAIR_3_SHIFT)

#define ADF_CFG_SYM_RINGS \
	(SYM | SYM << ADF_CFG_SERV_RING_PAIR_1_SHIFT | \
	SYM << ADF_CFG_SERV_RING_PAIR_2_SHIFT | \
	SYM << ADF_CFG_SERV_RING_PAIR_3_SHIFT)

#define ADF_CFG_ASYM_RINGS \
	(ASYM | ASYM << ADF_CFG_SERV_RING_PAIR_1_SHIFT | \
	ASYM << ADF_CFG_SERV_RING_PAIR_2_SHIFT | \
	ASYM << ADF_CFG_SERV_RING_PAIR_3_SHIFT)

#define ADF_CFG_CY_DC_RINGS \
	(CRYPTO | CRYPTO << ADF_CFG_SERV_RING_PAIR_1_SHIFT | \
	NA << ADF_CFG_SERV_RING_PAIR_2_SHIFT | \
	COMP << ADF_CFG_SERV_RING_PAIR_3_SHIFT)

#define ADF_CFG_ASYM_DC_RINGS \
	(ASYM | ASYM << ADF_CFG_SERV_RING_PAIR_1_SHIFT | \
	COMP << ADF_CFG_SERV_RING_PAIR_2_SHIFT | \
	COMP << ADF_CFG_SERV_RING_PAIR_3_SHIFT)

#define ADF_CFG_SYM_DC_RINGS \
	(SYM | SYM << ADF_CFG_SERV_RING_PAIR_1_SHIFT | \
	COMP << ADF_CFG_SERV_RING_PAIR_2_SHIFT | \
	COMP << ADF_CFG_SERV_RING_PAIR_3_SHIFT)

#define ADF_CFG_DC_RINGS \
	(COMP | COMP << ADF_CFG_SERV_RING_PAIR_1_SHIFT | \
	COMP << ADF_CFG_SERV_RING_PAIR_2_SHIFT | \
	COMP << ADF_CFG_SERV_RING_PAIR_3_SHIFT)

static char adf_cfg_deprecated_params[][ADF_CFG_MAX_KEY_LEN_IN_BYTES] = {
	ADF_DEV_KPT_ENABLE,
	ADF_STORAGE_FIRMWARE_ENABLED,
	ADF_RL_FIRMWARE_ENABLED,
	ADF_PKE_DISABLED
};
struct adf_cfg_enabled_services {
	const char svcs_enabled[ADF_CFG_MAX_VAL_LEN_IN_BYTES];
	u16 rng_to_svc_msk;
	u32 enabled_svc_cap;
	u32 enabled_fw_cap;
};

struct adf_cfg_profile {
	enum adf_cfg_fw_image_type fw_image_type;
	struct adf_cfg_enabled_services supported_svcs[ADF_CFG_SVCS_MAX];
};

static struct adf_cfg_profile adf_profiles[] = {
	{ADF_FW_IMAGE_DEFAULT,
		{
			{"cy", ADF_CFG_CY_RINGS, ADF_CFG_CAP_CY,
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_ECEDMONT |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"dc", ADF_CFG_DC_RINGS, ADF_CFG_CAP_DC, 0},
			{"sym", ADF_CFG_SYM_RINGS, ADF_CFG_CAP_SYM,
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"asym", ADF_CFG_ASYM_RINGS, ADF_CFG_CAP_ASYM,
				ADF_CFG_FW_CAP_ECEDMONT},
			{"cy;dc", ADF_CFG_CY_DC_RINGS,
				ADF_CFG_CAP_CY | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_ECEDMONT |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"dc;cy", ADF_CFG_CY_DC_RINGS,
				ADF_CFG_CAP_CY | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_ECEDMONT |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"asym;dc", ADF_CFG_ASYM_DC_RINGS,
				ADF_CFG_CAP_ASYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_ECEDMONT},
			{"dc;asym", ADF_CFG_ASYM_DC_RINGS,
				ADF_CFG_CAP_ASYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_ECEDMONT},
			{"sym;dc", ADF_CFG_SYM_DC_RINGS,
				ADF_CFG_CAP_SYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"dc;sym", ADF_CFG_SYM_DC_RINGS,
				ADF_CFG_CAP_SYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
		}
	},
	{ADF_FW_IMAGE_CRYPTO,
		{
			{"cy", ADF_CFG_CY_RINGS, ADF_CFG_CAP_CY,
				ADF_CFG_FW_CAP_RL | ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_ECEDMONT |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"sym", ADF_CFG_SYM_RINGS, ADF_CFG_CAP_SYM,
				ADF_CFG_FW_CAP_RL | ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"asym", ADF_CFG_ASYM_RINGS, ADF_CFG_CAP_ASYM,
				ADF_CFG_FW_CAP_RL | ADF_CFG_FW_CAP_ECEDMONT},
		}
	},
	{ADF_FW_IMAGE_COMPRESSION,
		{
			{"dc", ADF_CFG_DC_RINGS, ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_RL},
			{"sym", ADF_CFG_SYM_RINGS, ADF_CFG_CAP_SYM,
				ADF_CFG_FW_CAP_RL |
				ADF_CFG_FW_CAP_AUTHENTICATION},
			{"sym;dc", ADF_CFG_SYM_DC_RINGS,
				ADF_CFG_CAP_SYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_RL |
				ADF_CFG_FW_CAP_AUTHENTICATION},
			{"dc;sym", ADF_CFG_SYM_DC_RINGS,
				ADF_CFG_CAP_SYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_RL |
				ADF_CFG_FW_CAP_AUTHENTICATION},
		}
	},
	{ADF_FW_IMAGE_CUSTOM1,
		{
			{"cy", ADF_CFG_CY_RINGS, ADF_CFG_CAP_CY,
				ADF_CFG_FW_CAP_RL | ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_ECEDMONT |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"dc", ADF_CFG_DC_RINGS, ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_RL},
			{"sym", ADF_CFG_SYM_RINGS, ADF_CFG_CAP_SYM,
				ADF_CFG_FW_CAP_RL | ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"asym", ADF_CFG_ASYM_RINGS, ADF_CFG_CAP_ASYM,
				ADF_CFG_FW_CAP_RL | ADF_CFG_FW_CAP_ECEDMONT},
			{"cy;dc", ADF_CFG_CY_DC_RINGS,
				ADF_CFG_CAP_CY | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_RL | ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_ECEDMONT |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"dc;cy", ADF_CFG_CY_DC_RINGS,
				ADF_CFG_CAP_CY | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_RL | ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_ECEDMONT |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"asym;dc", ADF_CFG_ASYM_DC_RINGS,
				ADF_CFG_CAP_ASYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_RL | ADF_CFG_FW_CAP_ECEDMONT},
			{"dc;asym", ADF_CFG_ASYM_DC_RINGS,
				ADF_CFG_CAP_ASYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_RL | ADF_CFG_FW_CAP_ECEDMONT},
			{"sym;dc", ADF_CFG_SYM_DC_RINGS,
				ADF_CFG_CAP_SYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_RL | ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"dc;sym", ADF_CFG_SYM_DC_RINGS,
				ADF_CFG_CAP_SYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_RL | ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
		}
	},
	{ADF_FW_IMAGE_DEFAULT_C4XXX,
		{
			{"cy", ADF_CFG_CY_RINGS, ADF_CFG_CAP_CY,
			       ADF_CFG_FW_CAP_CIPHER |
			       ADF_CFG_FW_CAP_AUTHENTICATION |
			       ADF_CFG_FW_CAP_HKDF |
			       ADF_CFG_FW_CAP_ECEDMONT |
			       ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"dc", ADF_CFG_DC_RINGS, ADF_CFG_CAP_DC, 0},
			{"sym", ADF_CFG_SYM_RINGS, ADF_CFG_CAP_SYM,
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"asym", ADF_CFG_ASYM_RINGS, ADF_CFG_CAP_ASYM,
				ADF_CFG_FW_CAP_ECEDMONT},
			{"cy;dc", ADF_CFG_CY_DC_RINGS,
				ADF_CFG_CAP_CY | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_ECEDMONT |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"dc;cy", ADF_CFG_CY_DC_RINGS,
				ADF_CFG_CAP_CY | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_ECEDMONT |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"asym;dc", ADF_CFG_ASYM_DC_RINGS,
				ADF_CFG_CAP_ASYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_ECEDMONT},
			{"dc;asym", ADF_CFG_ASYM_DC_RINGS,
				ADF_CFG_CAP_ASYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_ECEDMONT},
			{"sym;dc", ADF_CFG_SYM_DC_RINGS,
				ADF_CFG_CAP_SYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
			{"dc;sym", ADF_CFG_SYM_DC_RINGS,
				ADF_CFG_CAP_SYM | ADF_CFG_CAP_DC,
				ADF_CFG_FW_CAP_CIPHER |
				ADF_CFG_FW_CAP_AUTHENTICATION |
				ADF_CFG_FW_CAP_HKDF |
				ADF_CFG_FW_CAP_EXT_ALGCHAIN},
		}
	},
};

int adf_cfg_get_ring_pairs(struct adf_cfg_device *device,
			   struct adf_cfg_instance *inst,
			   const char *process_name,
			   struct adf_accel_dev *accel_dev)
{
	int i = 0;
	int ret = -EFAULT;
	struct adf_cfg_instance *free_inst = NULL;
	struct adf_cfg_bundle *first_free_bundle = NULL;
	enum adf_cfg_bundle_type free_bundle_type;
	int first_user_bundle = 0;

	dev_dbg(&GET_DEV(accel_dev),
		"get ring pair for section %s, bundle_num is %d.\n",
				process_name, device->bundle_num);

	/* Section of user process with poll mode */
	if (strcmp(ADF_KERNEL_SEC, process_name) &&
	    strcmp(ADF_KERNEL_SAL_SEC, process_name) &&
	    (inst->polling_mode == ADF_CFG_RESP_POLL)) {
		first_user_bundle = device->max_kernel_bundle_nr + 1;
		for (i = first_user_bundle; i < device->bundle_num; i++) {
			free_inst =
				adf_cfg_get_free_instance(accel_dev,
							  device,
							  device->bundles[i],
							  inst,
							  process_name);

			if (!free_inst)
				continue;

			ret = adf_cfg_get_ring_pairs_from_bundle(
					device->bundles[i], inst,
					process_name, free_inst, device);
			return ret;
		}
	} else {
		/* Section of in-tree, or kernel API or user process
		 * with epoll mode
		 */
		if (!strcmp(ADF_KERNEL_SEC, process_name) ||
		    !strcmp(ADF_KERNEL_SAL_SEC, process_name))
			free_bundle_type = KERNEL;
		else
			free_bundle_type = USER;

		for (i = 0; i < device->bundle_num; i++) {
			/* Since both in-tree and kernel API's bundle type
			 * are kernel, use cpumask_subset to check if the
			 * ring's affinity mask is a subset of a bundle's
			 * one.
			 */
			if ((free_bundle_type == device->bundles[i]->type) &&
			    cpumask_subset(
					&inst->affinity_mask,
					&device->bundles[i]->affinity_mask)) {
				free_inst =
					adf_cfg_get_free_instance(
							accel_dev,
							device,
							device->bundles[i],
							inst,
							process_name);

				if (!free_inst)
					continue;

				ret = adf_cfg_get_ring_pairs_from_bundle(
							device->bundles[i],
							inst,
							process_name,
							free_inst, device);

				return ret;

			} else if (!first_free_bundle &&
				   adf_cfg_is_free(device->bundles[i])) {
				first_free_bundle = device->bundles[i];
			}
		}

		if (first_free_bundle) {
			free_inst = adf_cfg_get_free_instance(accel_dev,
							      device,
							      first_free_bundle,
							      inst,
							      process_name);

			if (!free_inst)
				return ret;

			ret = adf_cfg_get_ring_pairs_from_bundle(
					first_free_bundle, inst,
					process_name, free_inst, device);

			if (free_bundle_type == KERNEL) {
				device->max_kernel_bundle_nr =
					first_free_bundle->number;
			}
			return ret;
		}
	}
	pr_err("Don't have enough rings for instance %s in process %s\n",
	       inst->name, process_name);

	return ret;
}

int adf_cfg_get_services_enabled(struct adf_accel_dev *accel_dev,
				 u16 *ring_to_svc_map)
{
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES];
	u32 i = 0;
	struct adf_cfg_enabled_services *svcs = NULL;
	enum adf_cfg_fw_image_type fw_image_type = ADF_FW_IMAGE_DEFAULT;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;

	*ring_to_svc_map = 0;

	/* Get the services enabled by user */
	snprintf(key, sizeof(key), ADF_SERVICES_ENABLED);
	if (adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC, key, val))
		return -EFAULT;

	if (hw_data->get_fw_image_type) {
		if (hw_data->get_fw_image_type(accel_dev, &fw_image_type))
			return -EFAULT;
	}

	for (i = 0; i < ADF_CFG_SVCS_MAX; i++) {
		svcs = &adf_profiles[fw_image_type].supported_svcs[i];

		if (!strncmp(svcs->svcs_enabled, "",
			     ADF_CFG_MAX_VAL_LEN_IN_BYTES))
			break;

		if (!strncmp(val,
			     svcs->svcs_enabled,
			     ADF_CFG_MAX_VAL_LEN_IN_BYTES)) {
			*ring_to_svc_map = svcs->rng_to_svc_msk;
			return 0;
		}
	}

	dev_err(&GET_DEV(accel_dev),
		"Invalid ServicesEnabled %s for ServicesProfile: %d\n",
		val, fw_image_type);

	return -EFAULT;
}
EXPORT_SYMBOL_GPL(adf_cfg_get_services_enabled);

void adf_cfg_set_asym_rings_mask(struct adf_accel_dev *accel_dev)
{
	int service;
	u16 ena_srv_mask;
	u16 service_type;
	u16 asym_mask = 0;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;

	ena_srv_mask = hw_data->ring_to_svc_map;

	/* parse each service */
	for (service = 0;
	     service < ADF_CFG_MAX_SERVICES;
	     service++) {
		service_type =
			GET_SRV_TYPE(ena_srv_mask, service);
		switch (service_type) {
		case CRYPTO:
		case ASYM:
			SET_ASYM_MASK(asym_mask, service);
			if (service_type == CRYPTO)
				service++;
			break;
		}
	}

	hw_data->asym_rings_mask = asym_mask;
}
EXPORT_SYMBOL_GPL(adf_cfg_set_asym_rings_mask);

void adf_cfg_gen_dispatch_arbiter(struct adf_accel_dev *accel_dev,
				  const u32 *thrd_to_arb_map,
				  u32 *thrd_to_arb_map_gen,
				  u32 total_engines)
{
	int engine, thread, service, bits;
	u32 thread_ability, ability_map, service_mask, service_type;
	u16 ena_srv_mask = GET_HW_DATA(accel_dev)->ring_to_svc_map;

	for_each_set_bit(engine, &GET_HW_DATA(accel_dev)->ae_mask,
			 total_engines) {
		bits = 0;
		/* ability_map is used to indicate the threads ability */
		ability_map = thrd_to_arb_map[engine];
		thrd_to_arb_map_gen[engine] = 0;
		/* parse each thread on the engine */
		for (thread = 0;
		     thread < ADF_NUM_THREADS_PER_AE;
		     thread++) {
			/* get the ability of this thread */
			thread_ability = ability_map & ADF_THRD_ABILITY_MASK;
			ability_map >>= ADF_THRD_ABILITY_BIT_LEN;
			/* parse each service */
			for (service = 0;
			     service < ADF_CFG_MAX_SERVICES;
			     service++) {
				service_type =
					GET_SRV_TYPE(ena_srv_mask, service);
				switch (service_type) {
				case CRYPTO:
					service_mask = ADF_CFG_ASYM_SRV_MASK;
					if (thread_ability & service_mask)
						thrd_to_arb_map_gen[engine] |=
								(1 << bits);
					bits++;
					service++;
					service_mask = ADF_CFG_SYM_SRV_MASK;
					break;
				case COMP:
					service_mask = ADF_CFG_DC_SRV_MASK;
					break;
				case SYM:
					service_mask = ADF_CFG_SYM_SRV_MASK;
					break;
				case ASYM:
					service_mask = ADF_CFG_ASYM_SRV_MASK;
					break;
				default:
					service_mask = ADF_CFG_UNKNOWN_SRV_MASK;
				}
				if (thread_ability & service_mask)
					thrd_to_arb_map_gen[engine] |=
								(1 << bits);
				bits++;
			}
		}
	}
}
EXPORT_SYMBOL_GPL(adf_cfg_gen_dispatch_arbiter);

int adf_cfg_get_fw_image_type(struct adf_accel_dev *accel_dev,
			      enum adf_cfg_fw_image_type *fw_image_type)
{
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES];

	snprintf(key, sizeof(key), ADF_SERVICES_PROFILE);
	if (adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC,
				    key, val)) {
		memcpy(val, ADF_SERVICES_DEFAULT,
		       sizeof(ADF_SERVICES_DEFAULT));
		dev_info(&GET_DEV(accel_dev),
			 "Enabling default configuration\n");
	}
	adf_cfg_fw_string_to_id(val, accel_dev, &fw_image_type);

	return 0;
}
EXPORT_SYMBOL_GPL(adf_cfg_get_fw_image_type);

static int adf_cfg_get_caps_enabled(struct adf_accel_dev *accel_dev,
			u32 *enabled_svc_caps, u32 *enabled_fw_caps)
{
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES];
	u8 i = 0;
	struct adf_cfg_enabled_services *svcs = NULL;
	enum adf_cfg_fw_image_type fw_image_type = ADF_FW_IMAGE_DEFAULT;
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;

	*enabled_svc_caps = 0;
	*enabled_fw_caps = 0;

	/* Get the services enabled by user */
	snprintf(key, sizeof(key), ADF_SERVICES_ENABLED);
	if (adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC, key, val))
		return -EFAULT;

	/*
	 * Only the PF driver has the hook for get_fw_image_type as the VF's
	 * enabled service is from PFVF communication. The fw_image_type for
	 * the VF is set to DEFAULT since this type contains all kinds of
	 * enabled service.
	 */
	if (hw_data->get_fw_image_type) {
		if (hw_data->get_fw_image_type(accel_dev, &fw_image_type))
			return -EFAULT;
	}

	for (i = 0; i < ADF_CFG_SVCS_MAX; i++) {
		svcs = &adf_profiles[fw_image_type].supported_svcs[i];

		if (!strncmp(svcs->svcs_enabled, "",
			     ADF_CFG_MAX_VAL_LEN_IN_BYTES))
			break;

		if (!strncmp(val,
			     svcs->svcs_enabled,
			     ADF_CFG_MAX_VAL_LEN_IN_BYTES)) {
			*enabled_svc_caps = svcs->enabled_svc_cap;
			*enabled_fw_caps = svcs->enabled_fw_cap;
			return 0;
		}
	}

	dev_err(&GET_DEV(accel_dev),
		"Invalid ServicesEnabled %s for ServicesProfile: %d\n",
		val, fw_image_type);

	return -EFAULT;
}

static void adf_cfg_check_deprecated_params(struct adf_accel_dev *accel_dev)
{
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
	char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES];
	u8 i = 0;
	struct adf_accel_pci *accel_pci_dev = &accel_dev->accel_pci_dev;
	struct pci_dev *pdev = accel_pci_dev->pci_dev;

	for (i = 0; i < ADF_CFG_DEPRE_PARAMS_NUM; i++) {
		/* give a warning if the deprecated params are set by user */
		snprintf(key, sizeof(key), adf_cfg_deprecated_params[i]);

		/* skip valid param specific to device type */
		if (!strncmp(ADF_RL_FIRMWARE_ENABLED, key, sizeof(key)))
			if (pdev && IS_QAT_GEN3(pdev->device))
				continue;

		if (!adf_cfg_get_param_value(accel_dev, ADF_GENERAL_SEC,
					     key, val)) {
			dev_warn(&GET_DEV(accel_dev),
				 "Parameter '%s' has been deprecated\n", key);
		}
	}
}

static int adf_cfg_check_enabled_services(struct adf_accel_dev *accel_dev,
					  u32 enabled_svc_caps)
{
	u32 hw_caps = GET_HW_DATA(accel_dev)->accel_capabilities_mask;

	if ((enabled_svc_caps & hw_caps) == enabled_svc_caps)
		return 0;

	dev_err(&GET_DEV(accel_dev), "Unsupported device configuration\n");

	return -EFAULT;
}

void adf_cfg_get_accel_algo_cap(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 cipher_capabilities_mask = 0;
	u32 hash_capabilities_mask = 0;
	u32 accel_capabilities_mask = 0;
	u32 asym_capabilities_mask = 0;

	if (hw_data->get_accel_cap) {
		accel_capabilities_mask =
			hw_data->get_accel_cap(accel_dev);
	}

	if (accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_CIPHER) {
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_NULL);
#ifdef QAT_LEGACY_ALGORITHMS
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_ARC4);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_AES_ECB);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_DES_CBC);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_DES_ECB);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_3DES_ECB);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_3DES_CBC);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_3DES_CTR);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_AES_F8);
#endif
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_AES_CBC);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_AES_CTR);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_KASUMI_F8);
		SET_BIT(cipher_capabilities_mask,
			ADF_CY_SYM_CIPHER_SNOW3G_UEA2);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_AES_XTS);
	}

	if (accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_AUTHENTICATION) {
#ifdef QAT_LEGACY_ALGORITHMS
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_MD5);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_SHA1);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_SHA224);
#endif
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_SHA256);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_SHA384);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_SHA512);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_AES_XCBC);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_KASUMI_F9);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_SNOW3G_UIA2);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_AES_CMAC);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_AES_CBC_MAC);
	}

	if ((accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_CIPHER) &&
	    (accel_capabilities_mask &
		   ICP_ACCEL_CAPABILITIES_AUTHENTICATION)) {
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_AES_CCM);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_AES_GCM);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_AES_CCM);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_AES_GCM);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_AES_GMAC);
	}

	if (accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_ZUC) {
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_ZUC_EEA3);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_ZUC_EIA3);
	}

	if (accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_SHA3)
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_SHA3_256);

	if (accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_CHACHA_POLY) {
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_POLY);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_CHACHA);
	}

	if (accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_SM3)
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_SM3);

	if (accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_SHA3_EXT) {
#ifdef QAT_LEGACY_ALGORITHMS
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_SHA3_224);
#endif
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_SHA3_256);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_SHA3_384);
		SET_BIT(hash_capabilities_mask, ADF_CY_SYM_HASH_SHA3_512);
	}

	if (accel_capabilities_mask & ICP_ACCEL_CAPABILITIES_SM4) {
#ifdef QAT_LEGACY_ALGORITHMS
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_SM4_ECB);
#endif
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_SM4_CBC);
		SET_BIT(cipher_capabilities_mask, ADF_CY_SYM_CIPHER_SM4_CTR);
	}

	if (accel_capabilities_mask &
	    ICP_ACCEL_CAPABILITIES_CRYPTO_ASYMMETRIC) {
#ifdef QAT_LEGACY_ALGORITHMS
		SET_BIT(asym_capabilities_mask, ADF_CY_ASYM_DH);
		SET_BIT(asym_capabilities_mask, ADF_CY_ASYM_DSA);
#endif
		SET_BIT(asym_capabilities_mask, ADF_CY_ASYM_RSA);
		SET_BIT(asym_capabilities_mask, ADF_CY_ASYM_ECC);
		SET_BIT(asym_capabilities_mask, ADF_CY_ASYM_ECDH);
		SET_BIT(asym_capabilities_mask, ADF_CY_ASYM_ECDSA);
		SET_BIT(asym_capabilities_mask, ADF_CY_ASYM_KEY);
		SET_BIT(asym_capabilities_mask, ADF_CY_ASYM_LARGE_NUMBER);
		SET_BIT(asym_capabilities_mask, ADF_CY_ASYM_PRIME);
	}

	hw_data->cipher_capabilities_mask = cipher_capabilities_mask;
	hw_data->hash_capabilities_mask = hash_capabilities_mask;
	hw_data->asym_capabilities_mask = asym_capabilities_mask;
}
EXPORT_SYMBOL_GPL(adf_cfg_get_accel_algo_cap);

static int adf_cfg_update_pf_accel_cap_mask(struct adf_accel_dev *accel_dev)
{
	struct adf_hw_device_data *hw_data = accel_dev->hw_device;
	u32 enabled_svc_caps = 0;
	u32 enabled_fw_caps = 0;

	if (hw_data->get_accel_cap) {
		hw_data->accel_capabilities_mask =
			hw_data->get_accel_cap(accel_dev);
	}

	if (adf_cfg_get_caps_enabled(accel_dev, &enabled_svc_caps,
				     &enabled_fw_caps))
		return -EFAULT;

	if (adf_cfg_check_enabled_services(accel_dev, enabled_svc_caps))
		return -EFAULT;

	if (!(enabled_svc_caps & ADF_CFG_CAP_ASYM))
		hw_data->accel_capabilities_mask &= ~ADF_CFG_CAP_ASYM;
	if (!(enabled_svc_caps & ADF_CFG_CAP_SYM))
		hw_data->accel_capabilities_mask &= ~ADF_CFG_CAP_SYM;
	if (!(enabled_svc_caps & ADF_CFG_CAP_DC))
		hw_data->accel_capabilities_mask &= ~ADF_CFG_CAP_DC;

	/* Enable FW defined capabilities*/
	if (enabled_fw_caps)
		hw_data->accel_capabilities_mask |= enabled_fw_caps;

	/* Disable FW not defined capabilities*/
	if (!(enabled_fw_caps & ICP_ACCEL_CAPABILITIES_CIPHER))
		hw_data->accel_capabilities_mask &=
			~ICP_ACCEL_CAPABILITIES_CIPHER;
	if (!(enabled_fw_caps & ICP_ACCEL_CAPABILITIES_AUTHENTICATION))
		hw_data->accel_capabilities_mask &=
			~ICP_ACCEL_CAPABILITIES_AUTHENTICATION;

	return 0;
}

static int adf_cfg_update_vf_accel_cap_mask(struct adf_accel_dev *accel_dev)
{
	u32 enabled_svc_caps = 0;
	u32 enabled_fw_caps = 0;

	if (adf_cfg_get_caps_enabled(accel_dev, &enabled_svc_caps,
				     &enabled_fw_caps))
		return -EFAULT;

	if (adf_cfg_check_enabled_services(accel_dev, enabled_svc_caps))
		return -EFAULT;

	return 0;
}

int adf_cfg_device_init(struct adf_cfg_device *device,
			struct adf_accel_dev *accel_dev)
{
	int i = 0;
	/* max_inst indicates the max instance number one bank can hold */
	int max_inst = accel_dev->hw_device->tx_rx_gap;
	int ret = -ENOMEM;
	struct adf_hw_device_data *hw_data = GET_HW_DATA(accel_dev);

	adf_cfg_check_deprecated_params(accel_dev);

	device->bundle_num = 0;
	device->bundles = (struct adf_cfg_bundle **)
		kzalloc(sizeof(struct adf_cfg_bundle *)
			* accel_dev->hw_device->num_banks,
			GFP_KERNEL);
	if (!device->bundles)
		goto failed;

	device->bundle_num = accel_dev->hw_device->num_banks;
	device->bundles_free = accel_dev->hw_device->num_banks;

	device->instances = (struct adf_cfg_instance **)
		kzalloc(sizeof(struct adf_cfg_instance *)
			* device->bundle_num * max_inst,
			GFP_KERNEL);
	if (!device->instances)
		goto failed;

	device->instance_index = 0;

	device->max_kernel_bundle_nr = -1;

	dev_dbg(&GET_DEV(accel_dev), "init device with bundle information\n");

	ret = -EFAULT;

	/* Update the acceleration capability mask based on User capability */
	if (!accel_dev->is_vf) {
		if (adf_cfg_update_pf_accel_cap_mask(accel_dev))
			goto failed;
	} else {
		if (adf_cfg_update_vf_accel_cap_mask(accel_dev))
			goto failed;
	}

	/*
	 * Update the algorithms capability mask based on
	 * qat legacy algorithms
	 */
	adf_cfg_get_accel_algo_cap(accel_dev);

	/* Based on the svc configured, get ring_to_svc_map */
	if (hw_data->get_ring_to_svc_map) {
		if (hw_data->get_ring_to_svc_map(accel_dev,
						 &hw_data->ring_to_svc_map))
			goto failed;
	}

	ret = -ENOMEM;
	/*
	 * 1) get the config information to generate the ring to service
	 *    mapping table
	 * 2) init each bundle of this device
	 */
	for (i = 0; i < device->bundle_num; i++) {
		device->bundles[i] =
			kzalloc(sizeof(struct adf_cfg_bundle), GFP_KERNEL);
		if (!device->bundles[i])
			goto failed;

		device->bundles[i]->max_section = max_inst;
		adf_cfg_bundle_init(device->bundles[i], device, i, accel_dev);
	}

	return 0;

failed:
	for (i = 0; i < device->bundle_num; i++) {
		if (device->bundles[i])
			adf_cfg_bundle_clear(device->bundles[i], accel_dev);
	}

	for (i = 0; i < (device->bundle_num * max_inst); i++) {
		if (device->instances && device->instances[i])
			kfree(device->instances[i]);
	}

	kfree(device->instances);
	device->instances = NULL;

	dev_err(&GET_DEV(accel_dev), "Failed to do device init\n");
	return ret;
}

void adf_cfg_device_clear(struct adf_cfg_device *device,
			  struct adf_accel_dev *accel_dev)
{
	int i = 0;

	dev_dbg(&GET_DEV(accel_dev), "clear device with bundle information\n");
	for (i = 0; i < device->bundle_num; i++) {
		if (device->bundles && device->bundles[i]) {
			adf_cfg_bundle_clear(device->bundles[i], accel_dev);
			kfree(device->bundles[i]);
			device->bundles[i] = NULL;
		}
	}

	kfree(device->bundles);
	device->bundles = NULL;

	for (i = 0; i < device->instance_index; i++) {
		if (device->instances && device->instances[i]) {
			kfree(device->instances[i]);
			device->instances[i] = NULL;
		}
	}

	kfree(device->instances);
	device->instances = NULL;
}

static void adf_cfg_process_user_cy_section(struct adf_accel_dev *accel_dev,
					    struct adf_cfg_device_data *cfg)
{
	int num_user_sec = 0;
	unsigned long num_cy_inst = 0;
	struct list_head *list;
	char key[ADF_CFG_MAX_KEY_LEN_IN_BYTES];
	struct adf_cfg_section *sec;

	if (!accel_dev || !cfg)
		return;

	list_for_each(list, &cfg->sec_list) {
		sec = list_entry(list, struct adf_cfg_section, list);
		if (!sec->processed && !sec->is_derived) {
			strlcpy(key, ADF_NUM_CY, ADF_CFG_MAX_KEY_LEN_IN_BYTES);
			if (adf_cfg_set_value(accel_dev, sec->name, key,
					      &num_cy_inst))
				num_cy_inst = 0;
			if (num_cy_inst != 0)
				num_user_sec++;
		}
	}

	if (num_user_sec == 1)
		accel_dev->is_user_bundle_dist_needed = true;
}

int adf_config_device(struct adf_accel_dev *accel_dev)
{
	struct adf_cfg_device_data *cfg = NULL;
	struct adf_cfg_device *cfg_device = NULL;
	struct adf_cfg_section *sec;
	struct list_head *list;
	int ret = -ENOMEM;

	if (!accel_dev)
		return ret;

	cfg = accel_dev->cfg;
	cfg->dev = NULL;
	cfg_device = (struct adf_cfg_device *)
			kzalloc(sizeof(*cfg_device), GFP_KERNEL);
	if (!cfg_device)
		goto failed;

	ret = -EFAULT;

	if (adf_cfg_device_init(cfg_device, accel_dev))
		goto failed;

	cfg->dev = cfg_device;
	accel_dev->is_user_bundle_dist_needed = false;

	/* GENERAL and KERNEL section must be processed before others */
	list_for_each(list, &cfg->sec_list) {
		sec = list_entry(list, struct adf_cfg_section, list);
		if (!strcmp(sec->name, ADF_GENERAL_SEC)) {
			dev_dbg(&GET_DEV(accel_dev), "Process section %s\n",
				sec->name);
			ret = adf_cfg_process_section(accel_dev,
						      sec->name,
						      accel_dev->accel_id);
			if (ret)
				goto failed;
			sec->processed = true;
			break;
		}
	}

	list_for_each(list, &cfg->sec_list) {
		sec = list_entry(list, struct adf_cfg_section, list);
		if (!strcmp(sec->name, ADF_KERNEL_SEC)) {
			dev_dbg(&GET_DEV(accel_dev), "Process section %s\n",
				sec->name);
			ret = adf_cfg_process_section(accel_dev,
						      sec->name,
						      accel_dev->accel_id);
			if (ret)
				goto failed;
			sec->processed = true;
			break;
		}
	}

	list_for_each(list, &cfg->sec_list) {
		sec = list_entry(list, struct adf_cfg_section, list);
		if (!strcmp(sec->name, ADF_KERNEL_SAL_SEC)) {
			dev_dbg(&GET_DEV(accel_dev), "Process section %s\n",
				sec->name);
			ret = adf_cfg_process_section(accel_dev,
						      sec->name,
						      accel_dev->accel_id);
			if (ret)
				goto failed;
			sec->processed = true;
			break;
		}
	}

	adf_cfg_process_user_cy_section(accel_dev, cfg);

	list_for_each(list, &cfg->sec_list) {
		sec = list_entry(list, struct adf_cfg_section, list);
		/* avoid reprocessing one section */
		if (!sec->processed && !sec->is_derived) {
			dev_dbg(&GET_DEV(accel_dev), "Process section %s\n",
				sec->name);
			ret = adf_cfg_process_section(accel_dev,
						      sec->name,
						      accel_dev->accel_id);
			if (ret)
				goto failed;
			sec->processed = true;
		}
	}

#ifdef QAT_DBG
	list_for_each(list, &cfg->sec_list) {
		sec = list_entry(list, struct adf_cfg_section, list);
		if (!strncmp(sec->name, ADF_DEBUG_SEC,
			     ADF_CFG_MAX_SECTION_LEN_IN_BYTES)) {
			dev_dbg(&GET_DEV(accel_dev), "Process section %s\n",
				sec->name);
			ret = adf_cfg_process_section(accel_dev,
						      sec->name,
						      accel_dev->accel_id);
			if (ret)
				goto failed;
			sec->processed = true;
			break;
		}
	}
#endif

	/* newly added accel section */
	ret = adf_cfg_process_section(accel_dev,
				      ADF_ACCEL_SEC,
				      accel_dev->accel_id);
	if (ret)
		goto failed;

	/*
	 * put item-remove task after item-process
	 * because during process we may fetch values from those items
	 */
	list_for_each(list, &cfg->sec_list) {
		sec = list_entry(list, struct adf_cfg_section, list);
		if (!sec->is_derived) {
			dev_dbg(&GET_DEV(accel_dev), "Clean up section %s\n",
				sec->name);
			ret = adf_cfg_cleanup_section(accel_dev,
						      sec->name,
						      accel_dev->accel_id);
			if (ret)
				goto failed;
		}
	}

	ret = 0;
failed:
	if (ret) {
		if (cfg_device) {
			adf_cfg_device_clear(cfg_device, accel_dev);
			kfree(cfg_device);
			cfg->dev = NULL;
		}
		adf_cfg_del_all(accel_dev);
		dev_err(&GET_DEV(accel_dev), "Failed to config device\n");
	}

	return ret;
}
EXPORT_SYMBOL_GPL(adf_config_device);

