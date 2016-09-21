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
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "userland.h"
#include "ramfs.h"

#define FILE_LIST	CONFIG_PATH "ramfs.conf"

static char *src_cappsule[] = {
	RAMFS_SRC "fsclient",
	RAMFS_SRC "mount_override.so",
	RAMFS_SRC "netclient",
	RAMFS_SRC "snapshot",
#ifndef NOGUI
	RAMFS_SRC "guiclient",
	RAMFS_SRC "accept_override.so",
	RAMFS_SRC "qubes_drv.so",
#endif
	NULL,
};

static char *dst_cappsule[] = {
	RAMFS "usr/bin/fsclient",
	RAMFS "usr/lib/mount_override.so",
	RAMFS "usr/bin/netclient",
	RAMFS "usr/bin/snapshot",
#ifndef NOGUI
	RAMFS "usr/bin/guiclient",
	RAMFS "usr/lib/accept_override.so",
	RAMFS "usr/lib/xorg/modules/drivers/qubes_drv.so",
#endif
	NULL,
};

static void free_file_list(char **files, size_t n)
{
	size_t i;

	if (files != NULL) {
		for (i = 0; i < n; i++)
			free(files[i]);

		free(files);
	}
}

static err_t read_file_list(char ***p_files)
{
	char **files, **ptr;
	char line[1024];
	size_t i, n;
	FILE *fp;

	files = NULL;
	i = 0;

	fp = fopen(FILE_LIST, "r");
	if (fp == NULL)
		return save_errno_msg(ERROR_LIBC_FOPEN, FILE_LIST);

	while (fgets(line, sizeof(line), fp) != NULL) {
		n = strlen(line);

		/* rstrip */
		while (n > 0 && isspace(line[n-1]))
			n--;

		/* skip empty line */
		if (n == 0)
			continue;

		/* skip comment */
		if (line[0] == '#')
			continue;

		line[n] = '\x00';

		ptr = files;
		files = (char **) realloc(ptr, (i + 1) * sizeof(*files));
		if (files == NULL) {
			free_file_list(ptr, i);
			fclose(fp);
			return save_errno(ERROR_LIBC_REALLOC);
		}

		files[i] = strdup(line);
		if (files[i] == NULL) {
			free_file_list(ptr, i);
			fclose(fp);
			return save_errno(ERROR_LIBC_STRDUP);
		}

		i++;
	}

	fclose(fp);

	ptr = files;
	files = (char **) realloc(ptr, (i + 1) * sizeof(*files));
	if (files == NULL) {
		free_file_list(ptr, i);
		return save_errno(ERROR_LIBC_REALLOC);
	}

	files[i] = NULL;

	*p_files = files;
	return SUCCESS;
}

static err_t copy_files(char **files)
{
	char **d, **s, **src;
	err_t error;
	char *dst;

	for (src = files; *src != NULL; src++) {
		if (asprintf(&dst, RAMFS "%s", *src) == -1)
			return save_errno(ERROR_LIBC_ASPRINTF);

		error = make_dirs(dst);
		if (!error)
			error = copy_file(*src, dst);

		free(dst);
		if (error)
			return error;
	}

	for (s = src_cappsule, d = dst_cappsule; *s != NULL; s++, d++) {
		error = make_dirs(*d);
		if (error)
			return error;

		error = copy_file(*s, *d);
		if (error)
			return error;
	}

	return SUCCESS;
}

err_t mount_ramfs(void)
{
	char **file, **files;
	unsigned long flags;
	mode_t mode;
	err_t error;

	mode = umask(S_IWGRP | S_IWOTH);

	error = make_dirs(RAMFS "/");
	if (error)
		goto restore_umask;

	/* Unmount in case the fs is already mounted. */
	umount(RAMFS);

	/* sudo mount -o nosuid,nodev -t ramfs ramfs $RAMFS */
	flags = MS_NOSUID | MS_NODEV;
	if (mount("ramfs", RAMFS, "ramfs", flags, NULL) != 0) {
		error = save_errno_msg(ERROR_LIBC_MOUNT, RAMFS);
		goto rm_ramfs_dir;
	}

	error = read_file_list(&files);
	if (error)
		goto umount_ramfs;

	error = copy_files(files);

	for (file = files; *file != NULL; file++)
		free(*file);
	free(files);

	if (error) {
		print_error(error, "failed to copy RAMFS files");
		reset_saved_errno();
		error = ERROR_RAMFS_COPY_FILES;
		goto umount_ramfs;
	}

	/* sudo mount -r -o remount,nosuid,nodev $RAMFS */
	if (mount(NULL, RAMFS, NULL, flags | MS_REMOUNT, NULL) != 0) {
		error = save_errno_msg(ERROR_LIBC_MOUNT,
				       "remount " RAMFS " read-only");
		goto umount_ramfs;
	}

	umask(mode);

	return SUCCESS;

umount_ramfs:
	if (umount(RAMFS) != 0)
		warn("umount(\"" RAMFS "\")");
rm_ramfs_dir:
	if (rmdir(RAMFS) != 0)
		warn("rmdir(\"" RAMFS "\")");
restore_umask:
	umask(mode);
	return error;
}

void umount_ramfs(void)
{
	if (umount(RAMFS) != 0)
		warn("umount(\"" RAMFS "\")");

	if (rmdir(RAMFS) != 0)
		warn("rmdir(\"" RAMFS "\")");
}

// vim: noet:ts=8:sw=8:
