/*
 * (c) Copyright 2016 G. Campana
 * (c) Copyright 2016 Quarkslab
 *
 * This file is part of Cappsule.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/user.h>
#include <sys/ioctl.h>

#include "api.h"
#include "params.h"
#include "cuapi/error.h"
#include "cuapi/trusted/channel.h"


struct capsule *create_capsule(int channel_fd, struct params *params,
			       char *errmsg, size_t size)
{
	struct cappsule_ioc_create create = {0};
	struct capsule *capsule;
	int ret, saved_errno;

	capsule = (struct capsule *)malloc(sizeof(*capsule));
	if (capsule == NULL) {
		strncpy(errmsg, "allocation failed", size);
		return NULL;
	}

	create.params = &params->shared;
	create.policy_uuid = params->policy_uuid;
	create.no_gui = params->shared.no_gui;
	create.tty_size = params->tty_size;
	create.memory_limit = params->memory_limit;
	create.uid = params->shared.uid;

	ret = ioctl(channel_fd, CAPPSULE_IOC_CREATE_CAPSULE, &create);
	if (ret < 0) {
		saved_errno = errno;
		if (saved_errno <= CAPPSULE_ERRNO_BASE) {
			snprintf(errmsg, size, "failed to create capsule: %s",
				 strerror(saved_errno));
		} else {
			snprintf(errmsg, size, "failed to create capsule: %s",
				 hv_error_message(saved_errno));
		}

		free(capsule);
		return NULL;
	}

	/* fill capsule informations */
	init_capsule(capsule, create.result_capsule_id, params);

	return capsule;
}
