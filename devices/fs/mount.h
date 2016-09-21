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

#ifndef MOUNT_H
#define MOUNT_H

#include <stdio.h>

#include "fs_mount_type.h"
#include "mount_handler.h"
#include "uuid.h"

#define RUN_USER_DIR_FMT	"/run/user/%u/"
#define FS_DIR_FMT		RUN_USER_DIR_FMT "cappsule/fs/%s/%s/%s/"

static inline void fmt_run_user_dir(char *fs_base_dir, size_t size, uid_t uid)
{
	snprintf(fs_base_dir, size, RUN_USER_DIR_FMT, uid);
}

/* /run/user/1000/cappsule/fs/unrestricted/overlay/6666cd76-f969-3646-9e7b-e39d750cc7d9/ */
static inline void fmt_fs_dir(char *fs_dir, size_t size, struct mount_point *mp)
{
	snprintf(fs_dir, size, FS_DIR_FMT, mp->uid, mp->policy->name,
		 mp->mhandler->name, mp->uuid);
}

#undef FS_DIR_FMT
#undef UPPER_DIR_FMT

#endif
