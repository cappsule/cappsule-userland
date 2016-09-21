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

#ifndef OVERLAY_H
#define OVERLAY_H

/* trailing slash is required, otherwise make_dirs() doesn't create the
 * directory */
#define WORKDIR_EXT	".workdir/"

static inline int get_workdir(const char *diff_dir, char *workdir, size_t size)
{
	size_t len;

	len = strlen(diff_dir);
	while (len > 0 && diff_dir[len-1] == '/')
		len--;

	if (len + sizeof(WORKDIR_EXT) >= size) {
		warnx("upperdir \"%s\" name is too long", diff_dir);
		return -1;
	}

	strncpy(workdir, diff_dir, size);
	strncpy(workdir + len, WORKDIR_EXT, size - len);

	return 0;
}

#undef WORKDIR_EXT

int overlay_mount_fs(const char *fs_real_root, const char *fs_dir,
		     const char *fs_diff_dir);
int overlay_init(void);

#endif
