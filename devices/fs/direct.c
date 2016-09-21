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
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>

#include "userland.h"
#include "mount_handler.h"
#include "direct.h"


int direct_mount_fs(const char *fs_real_root, const char *fs_dir,
		    const char *UNUSED(diff_dir))
{
	int flags;

	flags = MS_BIND | MS_NODEV | MS_NOSUID | MS_NOEXEC;
	if (mount(fs_real_root, fs_dir, "none", flags, "") == -1) {
		warn("cannot mount direct fs on %s", fs_dir);
		return -1;
	}

	return 0;
}
