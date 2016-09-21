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

#ifndef MOUNT_HANDLER_H
#define MOUNT_HANDLER_H

#include <limits.h>

#include "fs_mount_type.h"
#include "policy.h"

typedef int (*capsule_fs_mount_routine)(const char *, const char *, const char *);

struct mount_handler {
	enum fs_mount_type type;
	const char *name;
	capsule_fs_mount_routine mount;
	bool diff_dir_required;
	bool work_dir_required;
};

struct mount_point {
	uid_t uid;
	gid_t gid;
	const char *base_dir;
	struct policy *policy;

	struct capsule_fs *fs;
	struct mount_handler *mhandler;
	char uuid[UUID_STR_LENGTH + 1];
	char target[PATH_MAX];
};

int install_network_config(const char *rootfs);
int build_fs_dir(struct mount_point *mp, char *result, size_t size);
int init_capsule_filesystems(struct mount_point *mp);
int mount_capsule_fs(struct mount_point *mp, char *target);

struct mount_handler *mount_handler_by_type(enum fs_mount_type type);

#endif
