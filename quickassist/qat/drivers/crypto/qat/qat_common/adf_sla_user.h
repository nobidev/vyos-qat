/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2019, 2021 Intel Corporation */
#ifndef ADF_SLA_USER_H_
#define ADF_SLA_USER_H_

#include "adf_cfg_common.h"

#define ADF_MAX_SLA 64

/*
 *
 * @ingroup sla
 *
 * struct adf_user_service - For a given service, specifies the max
 * rate the device can sustain and the actual available rate, that is,
 * not yet allocated.
 *
 * @svc_type:                service type
 * @max_svc_rate_in_slau:    maximum rate defined in sla units
 * @avail_svc_rate_in_slau:  available rate defined in sla units
 */
struct adf_user_service {
	enum adf_svc_type svc_type;
	u32 max_svc_rate_in_slau;
	u32 avail_svc_rate_in_slau;
} __packed;

/*
 *
 * @ingroup sla
 *
 * struct adf_user_sla_caps - For a given device, specifies the maximum
 * number of SLAs, the number of SLAs still available and the number of SLAs
 * already allocated. Also, for each service, it provides details about
 * the rate still available.
 *
 * @pf_addr:	    BDF address of physical function for this device
 * @max_slas:       maximum number of SLAs supported on this device
 * @avail_slas:     number of SLAs still available
 * @used_slas:      number of SLAs already allocated
 *
 * @services:       for each service type, provides details about the rate still
 *                  available
 */
struct adf_user_sla_caps {
	struct adf_pci_address pf_addr;
	u16 max_slas;
	u16 avail_slas;
	u16 used_slas;
	struct adf_user_service services[ADF_MAX_SERVICES];
} __packed;

/*
 *
 * @ingroup sla
 *
 * struct adf_user_sla - parameters required to request an SLA
 *
 * @pci_addr:	    For IOCTL_SLA_CREATE this will be the BDF address of the
 *		    virtual function. For IOCTL_SLA_UPDATE/IOCTL_SLA_DELETE this
 *		    will be the BDF address of the physical function to which
 *		    the VF belongs to
 * @sla_id:	    For IOCTL_SLA_CREATE this is an output parameter. Kernel
 *		    will populate this with the sla_id which is device specific.
 *		    User has to keep track of both pf_addr and sla_id to later
 *		    update/delete the sla.
 *		    For IOCTL_SLA_CREATE/IOCTL_SLA_UPDATE this is an input
 *		    parameter that paired with pci_addr set to the PF BDF, will
 *		    uniquely identify the SLA system wide
 * @svc_type:       service type to request SLA for
 * @rate_in_slau:   rate requested in sla units. Must be lower or equal
 *		    to adf_user_sla_caps.services[svc_type].
 *		    avail_svc_rate_in_slau
 */
struct adf_user_sla {
	struct adf_pci_address pci_addr;
	u16 sla_id;
	enum adf_svc_type svc_type;
	u32 rate_in_slau;
} __packed;

/*
 *
 * @ingroup sla
 *
 * struct adf_user_slas - to be used with IOCTL_SLA_GET_LIST to retrieve the
 * list of allocated SLAs.
 *
 * @pf_addr:	BDF address of physical function for this device
 * @slas:       array of allocated SLAs.
 * @used_slas:  actual number of SLA allocated. Entries in slas from 0 to
 *              used_slas are valid.
 */
struct adf_user_slas {
	struct adf_pci_address pf_addr;
	struct adf_user_sla slas[ADF_MAX_SLA];
	u16 used_slas;
};

#endif
