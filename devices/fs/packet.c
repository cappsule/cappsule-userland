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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fuse.h>

#include "fsclient.h"
#include "packet.h"
#include "protocol.h"
#include "userland.h"
#include "cuapi/guest/xchan.h"
#include "xchan.h"


int in_capsule(int nohv)
{
	struct stat st;

	if (nohv)
		return 1;

	return stat(GUEST_CONSOLE_DEVICE, &st) != -1;
}

static void reopen_stdout(void)
{
	int fd;

	/* XXX: dirty. guest kernel should send a SIGCONT to fsclient on first
	 * schedule */
	while (!in_capsule(false))
		usleep(100000);

	fd = open(GUEST_CONSOLE_DEVICE, O_WRONLY, 0);
	if (fd == -1)
		err(1, "open(console)");

	if (dup2(fd, STDOUT_FILENO) < 0)
		err(1, "dup2");

	if (dup2(fd, STDERR_FILENO) < 0)
		err(1, "dup2");

	if (close(fd) < 0)
		err(1, "close");
}

static void reconnect(struct fsclient *fsclient)
{
	err_t error;

	if (!fsclient->nohv)
		reopen_stdout();

	error = xchan_capsule_init(XCHAN_FS, &fsclient->xchan);
	if (error) {
		print_error(error, "failed to init xchan");
		exit(EXIT_FAILURE);
	}

	if (chroot_to_empty() != 0)
		exit(EXIT_FAILURE);

	if (fsclient->userspec != NULL)
		drop_uid_from_str(fsclient->userspec);
}

void do_request(struct fsclient *fsclient, enum cpsl_request type,
		struct cli_packet *p, size_t size)
{
	struct fuse_context *ctx;
	size_t offset;
	err_t error;

	if (fsclient->xchan == NULL)
		reconnect(fsclient);

	p->type = type;
	p->size = size;

	/* pass the uid and gid of the process invoking the operation to
	 * fsserver */
	ctx = fuse_get_context();
	p->uid = ctx->uid;
	p->gid = ctx->gid;

	offset = offsetof(struct cli_packet, d);
	error = xchan_sendall(fsclient->xchan, p, offset + size);
	if (error) {
		print_error(error, "failed to send request");
		exit(EXIT_FAILURE);
	}
}

void do_response(struct fsclient *fsclient, void *buf, size_t size)
{
	err_t error;

	if (fsclient->xchan == NULL)
		reconnect(fsclient);

	error = xchan_recvall(fsclient->xchan, buf, size);
	if (error) {
		print_error(error, "failed to recv response");
		exit(EXIT_FAILURE);
	}
}

// vim: noet:ts=8:
