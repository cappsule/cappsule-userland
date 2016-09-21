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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "userland.h"

int create_abstract_socket(int type,
			    const char *name,
			    struct sockaddr_un *addr,
			    socklen_t *len)
{
	int fd;

	fd = socket(AF_UNIX, type, 0);
	if (fd == -1) {
		warn("socket");
		return -1;
	}

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	addr->sun_path[0] = '\x00';
	strncpy(addr->sun_path + 1, name, sizeof(addr->sun_path) - 1);

	*len = sizeof(addr->sun_family) + 1 + strlen(name);

	return fd;
}

/* If backlog isn't positive, listen() isn't called. It allows this function to
 * be used with sockets which aren't connection-mode. */
int bind_abstract_socket(int type, const char *name, int backlog)
{
	struct sockaddr_un addr;
	socklen_t len;
	int fd;

	fd = create_abstract_socket(type, name, &addr, &len);
	if (fd == -1)
		return -1;

	if (bind(fd, (struct sockaddr *)&addr, len) == -1) {
		warn("bind");
		close(fd);
		return -1;
	}

	if (backlog > 0) {
		if (listen(fd, backlog) == -1) {
			warn("listen");
			close(fd);
			return -1;
		}
	}

	return fd;
}

int connect_to_abstract_socket(int type, const char *name)
{
	struct sockaddr_un addr;
	socklen_t len;
	int fd;

	fd = create_abstract_socket(type, name, &addr, &len);
	if (fd == -1)
		return -1;

	if (connect(fd, (struct sockaddr *)&addr, len) == -1) {
		warn("connect");
		close(fd);
		return -1;
	}

	return fd;
}

/* http://www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html */
int timeval_subtract(struct timeval *result,
		     struct timeval *x,
		     struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	   tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

void display_version(const char *filename, const char *version, int do_exit)
{
	const char *p;

	p = strrchr(filename, '/');
	if (p != NULL)
		p++;
	else
		p = filename;

	fprintf(stderr, "%s %s\n", p, version);

	if (do_exit)
		exit(1);
}
