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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "readall.h"


/**
 * Write @p count bytes of data.
 *
 * @return SUCCESS if no error occured
 */
err_t writeall(int fd, const void *buf, size_t count)
{
	const char *p;
	ssize_t i;

	p = buf;
	do {
		i = write(fd, p, count);
		if (i == 0) {
			return ERROR_COMMON_CONNECTION_CLOSED;
		} else if (i == -1) {
			if (errno == EINTR)
				continue;
			return save_errno(ERROR_LIBC_WRITE);
		}
		count -= i;
		p += i;
	} while (count > 0);

	return SUCCESS;
}

/**
 * Read @p count bytes of data.
 *
 * @return SUCCESS if no error occured
 */
err_t readall(int fd, void *buf, size_t count)
{
	unsigned char *p;
	ssize_t n;
	size_t i;

	p = buf;
	i = count;
	while (i > 0) {
		n = read(fd, p, i);
		if (n == 0) {
			return ERROR_COMMON_CONNECTION_CLOSED;
		} else if (n == -1) {
			if (errno == EINTR)
				continue;
			return save_errno(ERROR_LIBC_READ);
		}
		i -= n;
		p += n;
	}

	return SUCCESS;
}

/**
 * Send @p len bytes of data.
 *
 * @return SUCCESS if no error occured
 */
err_t sendall(int sockfd, const void *buf, size_t len, int flags)
{
	const char *p;
	ssize_t i;

	p = buf;
	do {
		i = send(sockfd, p, len, flags);
		if (i == 0) {
			return ERROR_COMMON_CONNECTION_CLOSED;
		} else if (i == -1) {
			if (errno == EINTR)
				continue;
			return save_errno(ERROR_LIBC_SEND);
		}
		len -= i;
		p += i;
	} while (len > 0);

	return SUCCESS;
}

/**
 * Receive @p len bytes of data.
 *
 * @return SUCCESS if no error occured
 */
err_t recvall(int sockfd, void *buf, size_t len, int flags)
{
	unsigned char *p;
	ssize_t n;
	size_t i;

	p = buf;
	i = len;
	while (i > 0) {
		n = recv(sockfd, p, i, flags);
		if (n == 0) {
			return ERROR_COMMON_CONNECTION_CLOSED;
		} else if (n == -1) {
			if (errno == EINTR)
				continue;
			return save_errno(ERROR_LIBC_RECV);
		}
		i -= n;
		p += n;
	}

	return SUCCESS;
}
