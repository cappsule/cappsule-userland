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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <linux/types.h>
#include <sys/eventfd.h>
#include <asm-generic/types.h>

#include "ring.h"
#include "cuapi/guest/xchan.h"
#include "cuapi/trusted/xchan.h"
#include "xchan.h"

err_t xchan_console_resize(struct xchan *xchan, struct winsize winsize)
{
	err_t error;

	if (ioctl(xchan->xchan_fd, CAPPSULE_IOC_XCHAN_CONSOLE_RESIZE, &winsize) != 0)
		error = save_errno_msg(ERROR_LIBC_IOCTL, "console_resize");
	else
		error = SUCCESS;

	return error;
}

err_t xchan_poll(struct xchan *xchan)
{
	err_t error;
	int ret;
	__u64 n;

retry:
	ret = read(xchan->event_fd, &n, sizeof(n));
	if (ret == sizeof(n)) {
		error = SUCCESS;
	} else {
		if (ret == 0) {
			error = ERROR_XCHAN_EVENTFD_CLOSED;
		} else if (ret == -1) {
			if (errno == EAGAIN)
				goto retry;
			error = save_errno(ERROR_XCHAN_EVENTFD_INVALID_READ);
		} else {
			error = ERROR_XCHAN_EVENTFD_INVALID_READ;
		}
	}

	return error;
}

static err_t xchan_notify(struct xchan *xchan)
{
	int request;
	err_t error = SUCCESS;

	if (xchan->trusted)
		request = CAPPSULE_IOC_XCHAN_NOTIFY;
	else
		request = XCHAN_IOC_GUEST_NOTIFY;

	if (ioctl(xchan->xchan_fd, request, 0) != 0)
		error = save_errno_msg(ERROR_LIBC_IOCTL, "notify");

	return error;
}

/* pop data from ring buffer */
err_t xchan_recv(struct xchan *xchan, void *buf, size_t len, size_t *ret)
{
	err_t error;

retry:
	error = ring_read(xchan->ring_r, buf, len, ret);
	if (error)
		return error;

	if (*ret == 0) {
		error = xchan_poll(xchan);
		if (error)
			return error;
		goto retry;
	}

	if (ring_notification_requested(xchan->ring_r))
		error = xchan_notify(xchan);

	return error;
}

err_t xchan_recv_nopoll(struct xchan *xchan, void *buf, size_t len, size_t *ret)
{
	err_t error;

	error = ring_read(xchan->ring_r, buf, len, ret);
	if (error)
		return error;

	if (*ret > 0 && ring_notification_requested(xchan->ring_r))
		error = xchan_notify(xchan);

	return error;
}

/* add buffer to ring buffer, and notify other end */
err_t xchan_send(struct xchan *xchan, const void *buf, size_t len, size_t *ret)
{
	err_t error;

retry:
	error = ring_write(xchan->ring_w, buf, len, ret);
	if (error)
		return error;

	if (*ret == 0) {
		warnx("%s: can't write anything", __func__);
		usleep(100);
		goto retry;
	}

	if (ring_notification_requested(xchan->ring_w))
		error = xchan_notify(xchan);

	return error;
}

err_t xchan_sendall(struct xchan *xchan, const void *buf, size_t len)
{
	const unsigned char *p;
	err_t error;
	size_t n;

	error = SUCCESS;
	p = buf;
	while (len > 0) {
		error = xchan_send(xchan, p, len, &n);
		if (error)
			break;
		len -= n;
		p += n;
	}

	return error;
}

err_t xchan_recvall(struct xchan *xchan, void *buf, size_t len)
{
	unsigned char *p;
	err_t error;
	size_t n;

	error = SUCCESS;
	p = buf;
	while (len > 0) {
		error = xchan_recv(xchan, p, len, &n);
		if (error)
			break;
		len -= n;
		p += n;
	}

	return error;
}

err_t xchan_accept(struct xchan *xchan)
{
	err_t error;
	char c;

	error = xchan_recvall(xchan, &c, sizeof(c));
	if (error)
		return error;

	if (c != XCHAN_START)
		return ERROR_XCHAN_ACCEPT;

	return SUCCESS;
}

/* tell other end we're up */
static err_t xchan_connect(struct xchan *xchan)
{
	size_t ret;
	err_t error;
	char c;
	int i;

	/* xchan_sendall can't be used because ioctl may fail if trusted guest
	 * didn't create xchan yet */

	c = XCHAN_START;
	error = ring_write(xchan->ring_w, &c, sizeof(c), &ret);
	if (error)
		return error;

	error = ERROR_XCHAN_CONNECT;
	if (ret == 0)
		return error;

	for (i = 0; error && i < 10; i++) {
		if (ioctl(xchan->xchan_fd, XCHAN_IOC_GUEST_NOTIFY, 0) == 0) {
			error = SUCCESS;
			break;
		} else {
			/* sleep for 0.1 sec */
			usleep(100000);
		}
	}

	return error;
}

static err_t xchan_init(bool trusted, int capsule_id,
			enum xchan_type type, struct xchan **rxchan)
{
	union {
		struct xchan_guest_ioctl guest;
		struct xchan_ioctl trusted;
	} infos;
	int xchan_fd, prot, event_fd, request;
	struct xchan *xchan;
	size_t length, size;
	char *device, *q;
	err_t error;
	void *p;

	size = sizeof(*xchan) + sizeof(*xchan->ring_r) + sizeof(*xchan->ring_w);
	q = (char *)malloc(size);
	if (q == NULL) {
		error = save_errno(ERROR_LIBC_MALLOC);
		goto malloc_failed;
	}

	xchan = (struct xchan *)q;
	xchan->ring_r = (struct ring *)(q + sizeof(*xchan));
	xchan->ring_w = (struct ring *)(q + sizeof(*xchan) + sizeof(*xchan->ring_r));

	event_fd = eventfd(0, 0);
	if (event_fd == -1) {
		error = save_errno(ERROR_LIBC_EVENTFD);
		goto eventfd_failed;
	}

	if (trusted)
		device = "/dev/" TRUSTED_XCHAN_DEVICE_NAME;
	else
		device = "/dev/" GUEST_XCHAN_DEVICE_NAME;

	xchan_fd = open(device, O_RDWR);
	if (xchan_fd == -1) {
		error = save_errno_msg(ERROR_LIBC_OPEN, device);
		goto open_device_failed;
	}

	if (trusted) {
		infos.trusted.capsule_id = capsule_id;
		infos.trusted.type = type;
		infos.trusted.eventfd = event_fd;
		request = CAPPSULE_IOC_XCHAN_INFOS;
	} else {
		infos.guest.type = type;
		infos.guest.eventfd = event_fd;
		request = XCHAN_IOC_GUEST_SET_INFOS;
	}

	if (ioctl(xchan_fd, request, &infos.trusted) != 0) {
		error = save_errno_msg(ERROR_LIBC_IOCTL, "infos");
		goto ioctl_failed;
	}

	length = xchan_npages(type) * PAGE_SIZE;
	if (length == 0) {
		error = ERROR_XCHAN_INVALID_TYPE;
		goto invalid_size;
	}

	prot = PROT_READ | PROT_WRITE;
	p = mmap(NULL, length, prot, MAP_SHARED, xchan_fd, 0);
	if (p == MAP_FAILED) {
		error = save_errno(ERROR_LIBC_MMAP);
		goto mmap_failed;
	}

	if (trusted) {
		/* hypervisor initialized pages to zero */
		ring_init(xchan->ring_r, p, length / 2);
		p = (unsigned char *)p + length / 2;
		ring_init(xchan->ring_w, p, length / 2);
	} else {
		/* inverse of trusted xchan */
		ring_init(xchan->ring_w, p, length / 2);
		p = (unsigned char *)p + length / 2;
		ring_init(xchan->ring_r, p, length / 2);
	}

	xchan->trusted = trusted;
	xchan->xchan_fd = xchan_fd;
	xchan->event_fd = event_fd;

	if (!trusted)
		xchan_connect(xchan);

	*rxchan = xchan;
	return SUCCESS;

mmap_failed:
invalid_size:
ioctl_failed:
	close(xchan_fd);
open_device_failed:
	close(event_fd);
eventfd_failed:
	free(xchan);
malloc_failed:
	*rxchan = NULL;
	return error;
}

err_t xchan_trusted_init(int capsule_id, enum xchan_type type,
			 struct xchan **xchan)
{
	return xchan_init(true, capsule_id, type, xchan);
}

err_t xchan_capsule_init(enum xchan_type type, struct xchan **xchan)
{
	return xchan_init(false, -1, type, xchan);
}
