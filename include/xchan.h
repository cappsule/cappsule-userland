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

#ifndef XCHAN_H
#define XCHAN_H

#include <stdbool.h>
#include <sys/ioctl.h>

#include "cuapi/common/xchan.h"	/* from hypervisor */
#include "error.h"

#define XCHAN_START	'!'

struct ring;
struct xchan {
	/* use pointer to avoid "ring.h" include */
	struct ring *ring_r;
	struct ring *ring_w;

	bool trusted;
	int xchan_fd;
	int event_fd;
};

err_t xchan_poll(struct xchan *xchan);
err_t xchan_recv(struct xchan *xchan, void *buf, size_t len, size_t *ret);
err_t xchan_recv_nopoll(struct xchan *xchan, void *buf, size_t len, size_t *ret);
err_t xchan_send(struct xchan *xchan, const void *buf, size_t len, size_t *ret);
err_t xchan_sendall(struct xchan *xchan, const void *buf, size_t len);
err_t xchan_recvall(struct xchan *xchan, void *buf, size_t len);
err_t xchan_accept(struct xchan *xchan);

err_t xchan_trusted_init(int capsule_id, enum xchan_type type,
			 struct xchan **xchan);
err_t xchan_capsule_init(enum xchan_type type, struct xchan **xchan);

err_t xchan_console_resize(struct xchan *xchan, struct winsize winsize);

#endif
