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

#define _DEFAULT_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sendfile.h>

#include "userland.h"

static err_t try_mkdir(char *pathname)
{
	struct stat st;

	if (mkdir(pathname, 0755) == 0)
		return SUCCESS;

	/* ensure directory hasn't already been created by another process */
	if (errno == EEXIST && stat(pathname, &st) == 0 && S_ISDIR(st.st_mode))
		return SUCCESS;

	return save_errno_msg(ERROR_LIBC_STAT, pathname);
}

/* makes all intermediate-level directories needed to contain the leaf
 * component */
err_t make_dirs(const char *dst)
{
	struct stat st;
	char *p, *tdst;
	err_t error;

	error = SUCCESS;

	/* ensure dst is writeable */
	tdst = strdup(dst);
	if (tdst == NULL) {
		error = save_errno(ERROR_LIBC_STRDUP);
		goto out;
	}

	p = tdst;
	while (1) {
		p = strchr(p + 1, '/');
		if (p == NULL)
			break;

		*p = '\x00';

		if (stat(tdst, &st) != 0) {
			if (errno != ENOENT) {
				error = save_errno_msg(ERROR_LIBC_STAT, tdst);
				break;
			}

			error = try_mkdir(tdst);
			if (error != SUCCESS)
				break;
		} else if (!S_ISDIR(st.st_mode & S_IFMT)) {
			error = save_errmsg(ERROR_FS_NOT_A_DIR, tdst);
			break;
		}

		*p = '/';
	}

out:
	free(tdst);
	return error;
}

err_t copy_file(const char *src, const char *dst)
{
	struct stat st;
	ssize_t count;
	int in, out;
	err_t error;

	error = SUCCESS;

	in = open(src, O_RDONLY);
	if (in == -1) {
		error = save_errno_msg(ERROR_LIBC_OPEN, src);
		goto ret;
	}

	if (fstat(in, &st) == -1) {
		error = save_errno_msg(ERROR_LIBC_FSTAT, src);
		goto close_in;
	}

	out = open(dst, O_RDWR | O_CREAT | O_TRUNC, st.st_mode);
	if (out == -1) {
		error = save_errno_msg(ERROR_LIBC_OPEN, dst);
		goto close_in;
	}

	count = sendfile(out, in, NULL, st.st_size);
	if (count != st.st_size) {
		error = save_errno(ERROR_LIBC_SENDFILE);
		goto close_out;
	}

close_out:
	close(out);
close_in:
	close(in);
ret:
	return error;
}

// vim: noet:ts=8:sw=8:
