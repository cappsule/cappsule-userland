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

#include "mount_handler.h"
#include "aufs.h"

int aufs_mount_fs(const char *fs_real_root, const char *fs_dir,
		  const char *diff_dir)
{
	char *fmt, *mount_opts;

	fmt = "br=%s=ro:%s=rw,udba=none";
	if (asprintf(&mount_opts, fmt, fs_real_root, diff_dir) == -1) {
		warn("asprintf");
		return -1;
	}

	/* mount -t aufs -o "br=$real_root=ro:$diff_dir=rw,udba=none" none $fs_dir */
	if (mount("none", fs_dir, "aufs", 0, mount_opts) == -1) {
		warn("cannot mount capsule fs on %s", fs_dir);
		free(mount_opts);
		return -1;
	}

	free(mount_opts);
	return 0;
}
