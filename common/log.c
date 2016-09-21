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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "userland.h"


static err_t create_logdir(char *filename)
{
	int doesntexist;
	struct stat st;
	mode_t mode;
	err_t error;
	char *p;

	error = SUCCESS;
	p = strrchr(filename, '/');
	if (p == NULL)
		return error;

	*p = '\x00';
	doesntexist = (stat(p, &st) != 0 && errno == ENOENT);
	*p = '/';
	if (doesntexist) {
		mode = umask(0);
		error = make_dirs(filename);
		umask(mode);
	}

	return error;
}

err_t open_log_file(unsigned int capsule_id, char *filename, int *p_fd)
{
	char path[PATH_MAX];
	mode_t mode;
	err_t error;
	int fd;

	snprintf(path, sizeof(path), LOG_CAPSULE_DIR_FMT "%s",
		 capsule_id, filename);

	error = create_logdir(path);
	if (error) {
		*p_fd = -1;
		return error;
	}

	mode = umask(0);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	umask(mode);
	if (fd == -1)
		error = save_errno_msg(ERROR_LIBC_OPEN, path);

	*p_fd = fd;
	return error;
}

static err_t dup2logfd(int oldfd, int newfd)
{
	char str[32];

	if (dup2(newfd, oldfd) == -1) {
		switch (oldfd) {
		case STDOUT_FILENO:
			strncpy(str, "stdout", sizeof(str));
			break;
		case STDERR_FILENO:
			strncpy(str, "stderr", sizeof(str));
			break;
		default:
			snprintf(str, sizeof(str), "%d", oldfd);
			break;
		}
		return save_errno_msg(ERROR_LIBC_DUP2, str);
	}

	return SUCCESS;
}

err_t set_logfile(unsigned int capsule_id, char *filename)
{
	err_t error;
	int fd;

	error = open_log_file(capsule_id, filename, &fd);
	if (error)
		return error;

	error = dup2logfd(STDOUT_FILENO, fd);
	if (!error)
		error = dup2logfd(STDERR_FILENO, fd);

	close(fd);
	return error;
}
