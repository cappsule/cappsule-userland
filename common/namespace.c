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
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include "namespace.h"


static int get_net_namespace_path(pid_t pid, char *path, size_t size)
{
	char buf[PATH_MAX];
	int ret;

	snprintf(buf, sizeof(buf), "/proc/%d/ns/net", pid);

	ret = readlink(buf, path, size);
	if (ret == -1 || ret >= (ssize_t)size) {
		warn("readlink(\"%s\") failed", buf);
		return -1;
	}

	path[ret] = '\x00';

	return 0;
}

int join_netns(pid_t pid)
{
	char path1[64], path2[64];
	char buf[PATH_MAX];
	int fd;

	if (get_net_namespace_path(getpid(), path1, sizeof(path1)) != 0)
		return -1;

	if (get_net_namespace_path(pid, path2, sizeof(path2)) != 0)
		return -1;

	if (strcmp(path1, path2) == 0) {
		fprintf(stderr, "net namespaces of %d and %d are identical\n",
			getpid(), pid);
		return -1;
	}

	snprintf(buf, sizeof(buf), "/proc/%d/ns/net", pid);
	fd = open(buf, O_RDONLY);
	if (fd == -1) {
		warn("open(\"%s\") failed", buf);
		return -1;
	}

	if (setns(fd, CLONE_NEWNET) != 0) {
		warn("failed to reassociate with %d netns", pid);
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}

bool is_net_namespace_different(pid_t pid)
{
	char path1[64], path2[64];

	if (get_net_namespace_path(getpid(), path1, sizeof(path1)) != 0)
		return false;

	if (get_net_namespace_path(pid, path2, sizeof(path2)) != 0)
		return false;

	return strcmp(path1, path2) != 0;
}
