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

#ifndef PARAMS_H
#define PARAMS_H

#include <stdbool.h>
#include <sys/user.h>
#include <linux/limits.h>

/* This structure is maped in capsule memory and used by exec_in_capsule to
 * initialize the capsule from userland.
 * This structure is opaque to the hypervisor (just a bunch of pages). */
struct shared_params {
	char argv[PAGE_SIZE];
	char env[PAGE_SIZE];
	uid_t uid;
	gid_t gid;
	bool no_gui;

	char cwd[PATH_MAX];
	char groups[256];
};

void exec_in_capsule(struct shared_params *params, unsigned int capsule_id);

#endif
