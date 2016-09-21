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
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "mount_handler.h"
#include "overlay.h"
#include "userland.h"

#define DEFAULT_FS_TYPE	"overlay"

static char *fs_types[] = { DEFAULT_FS_TYPE, "overlayfs" };
static char *fs_type = DEFAULT_FS_TYPE;


static int do_mount(const char *fs_real_root,
		    const char *fs_dir,
		    const char *diff_dir,
		    char *workdir)
{
	char *fmt, *opts;
	int ret;

	if (workdir != NULL)
		fmt = "lowerdir=%s,upperdir=%s,workdir=%s";
	else
		fmt = "lowerdir=%s,upperdir=%s";

	if (asprintf(&opts, fmt, fs_real_root, diff_dir, workdir) == -1) {
		warn("asprintf");
		return -2;
	}

	/* mount -t overlayfs -o "lowerdir=$real_root,upperdir=$diff_dir" overlayfs $fs_dir */
	ret = mount(fs_type, fs_dir, fs_type, 0, opts);

	free(opts);

	return ret;
}

int overlay_mount_fs(const char *fs_real_root, const char *fs_dir,
		     const char *diff_dir)
{
	char workdir[PATH_MAX];
	int ret;

	ret = get_workdir(diff_dir, workdir, sizeof(workdir));
	if (ret != 0)
		return ret;

	/* Compatibility was broken between 2 overlayfs versions. There's no
	 * easy way to figure out which version of overlayfs is running. Try to
	 * mount overlayfs with workdir option, and if it fails, without workdir
	 * option. */
	ret = do_mount(fs_real_root, fs_dir, diff_dir, workdir);
	if (ret != 0)
		ret = do_mount(fs_real_root, fs_dir, diff_dir, NULL);

	if (ret != 0) {
		if (ret == -1)
			warn("cannot mount capsule fs on %s", fs_dir);
		else
			warnx("cannot mount capsule fs on %s", fs_dir);
	}

	return ret;
}

/*
 * Determine which overlay filesystem is configured in the kernel.
 *
 * Ubuntu 14.04: mount -t overlayfs
 * Debian 8: mount -t overlay
 */
int overlay_init(void)
{
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(fs_types); i++) {
		/* even if filesystem type is valid, mount will fail because
		 * options aren't set */
		ret = mount(fs_types[i], "/tmp", fs_types[i], MS_SILENT, NULL);
		if (ret == -1 && errno != ENODEV) {
			fs_type = fs_types[i];
			return 0;
		}
	}

	return -1;
}
