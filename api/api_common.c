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

#include "api.h"
#include "params.h"

bool capsule_devices_ready(struct context *ctx, struct capsule *capsule)
{
	return ctx->notif->nr_devices == capsule->devices_ready;
}

bool capsule_devices_error(struct capsule *capsule)
{
	return capsule->devices_errors > 0;
}

bool capsule_has_exited(struct capsule *capsule)
{
	return capsule->exited;
}

void init_capsule(struct capsule *capsule, unsigned int capsule_id,
		  struct params *params)
{
	capsule->capsule_id = capsule_id;
	capsule->ucred.pid = params->pid;
	capsule->ucred.uid = params->shared.uid;
	capsule->ucred.gid = params->shared.gid;
	capsule->params = *params;
	capsule->devices_ready = 0;
	capsule->devices_errors = 0;
	capsule->exited = false;
}

struct capsule *find_capsule_by_id(struct context *ctx, unsigned int capsule_id)
{
	struct capsule *capsule;

	for (capsule = ctx->capsules; capsule != NULL; capsule = capsule->next) {
		if (capsule->capsule_id == capsule_id)
			return capsule;
	}

	return NULL;
}

int capsule_set_exited(struct context *ctx, unsigned int capsule_id, kill_t reason)
{
	struct capsule *capsule;

	capsule = find_capsule_by_id(ctx, capsule_id);
	if (capsule == NULL) {
		fprintf(stderr, "BUG: failed to find capsule %d on exit\n",
			capsule_id);
		return -1;
	}

	capsule->exited = true;
	capsule->exit_reason = reason;
	return 0;
}

void free_capsule(struct capsule *capsule)
{
	free_misc_filesystems(&capsule->params.fs);

	memset(capsule, -1, sizeof(*capsule));
	free(capsule);
}
