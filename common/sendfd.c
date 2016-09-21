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

/* http://www.lst.de/~okir/blackhats/node121.html
 * http://keithp.com/blogs/fd-passing/ */

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "userland.h"

#define MAX_FD		3
#define STR(a)		#a
#define XSTR(a)		STR(a)

union cmsgu_send {
	struct cmsghdr cmsghdr;
	char control[CMSG_SPACE(sizeof(int) * MAX_FD)];
};

union cmsgu_recv {
	struct cmsghdr cmsghdr;
	char control[CMSG_SPACE(sizeof(int) * MAX_FD)];
};

/*
 * Gets the peer credentials of a locally connected UNIX socket.
 */
int get_peercred(int sock, struct pcred *pcred)
{
	struct ucred ucred;
	socklen_t len;
	int ret;

	len = sizeof(ucred);
	ret = getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &ucred, &len);
	if (ret != 0 || len != sizeof(ucred))
		return -1;

	pcred->pid = ucred.pid;
	pcred->uid = ucred.uid;
	pcred->gid = ucred.gid;

	return 0;
}

/*
 * Receives a set of file descriptors from a UNIX socket.
 */
int recv_fds(int sock, int *fds, unsigned int n_fds, int flags)
{
	union cmsgu_recv cmsgu;
	bool got_fds;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	unsigned int i, n;
	struct iovec iov;
	char nothing;
	ssize_t ret;
	int *p;

	if (n_fds > MAX_FD) {
		warnx("can't recv more than " XSTR(MAX_FD) " fds");
		return -1;
	}

	iov.iov_base = &nothing;
	iov.iov_len = sizeof(nothing);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = cmsgu.control;
	msg.msg_controllen = sizeof(cmsgu.control);

	ret = recvmsg(sock, &msg, flags);
	if (ret != 1) {
		warn("recvmsg");
		return -1;
	}

	if (msg.msg_flags != 0) {
		warnx("recvmsg failed: flags set");
		return -1;
	}

	got_fds = false;
	cmsg = CMSG_FIRSTHDR(&msg);
	while (cmsg != NULL) {
		if (cmsg->cmsg_level != SOL_SOCKET) {
			warnx("recvmsg failed: cmsg level != SOL_SOCKET");
			return -1;
		}

		if (cmsg->cmsg_type == SCM_RIGHTS) {
			if (got_fds) {
				warnx("recvmsg failed: can't receive fds twice");
				return -1;
			}

			n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			if (n != n_fds) {
				warnx("recvmsg failed: invalid number of fds");
				return -1;
			}

			/* Copy received file descriptors. */
			p = (int *)CMSG_DATA(cmsg);
			for (i = 0; i < n_fds; i++)
				fds[i] = p[i];

			got_fds = true;
		} else {
			warnx("recvmsg failed: invalid cmsg type");
			return -1;
		}
		cmsg = CMSG_NXTHDR(&msg, cmsg);
	}

	if (!got_fds) {
		warnx("recvmsg failed: no fds");
		return -1;
	}

	return 0;
}

/*
 * Sends a set of file descriptors across a UNIX socket.
 */
int send_fds(int sock, const int *fds, unsigned int n_fds)
{
	union cmsgu_send cmsgu;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	unsigned int i;
	char nothing;
	ssize_t ret;
	int *p;

	if (n_fds > MAX_FD) {
		warnx("can't send more than " XSTR(MAX_FD) " fds");
		return -1;
	}

	nothing = 'x';
	iov.iov_base = &nothing;
	iov.iov_len = sizeof(nothing);

	memset(&cmsgu, 0, sizeof(cmsgu));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = cmsgu.control;
	msg.msg_controllen = sizeof(cmsgu.control);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int) * n_fds);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	p = (int *)CMSG_DATA(cmsg);
	for (i = 0; i < n_fds; i++)
		p[i] = fds[i];

	ret = sendmsg(sock, &msg, 0);
	if (ret != 1) {
		warn("sendmsg");
		return -1;
	}

	return 0;
}
