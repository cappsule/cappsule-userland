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

#define _XOPEN_SOURCE
#include <err.h>
#include <signal.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/signalfd.h>

#include "userland.h"


int read_signal(int sfd)
{
	struct signalfd_siginfo fdsi;

	if (read(sfd, &fdsi, sizeof(fdsi)) != sizeof(fdsi)) {
		warn("failed to read signal info");
		return -1;
	}

	return fdsi.ssi_signo;
}

err_t create_signalfd(int *r_signal_fd, ...)
{
	va_list argptr;
	int sfd, signo;
	sigset_t mask;

	/* get the previous value of the signal mask */
	if (sigprocmask(SIG_SETMASK, NULL, &mask) == -1)
		return save_errno(ERROR_LIBC_SIGPROCMASK);

	va_start(argptr, r_signal_fd);
	while (1) {
		signo = va_arg(argptr, int);
		if (signo == -1)
			break;

		sigaddset(&mask, signo);
	}

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
		return save_errno(ERROR_LIBC_SIGPROCMASK);

	sfd = signalfd(-1, &mask, SFD_CLOEXEC);
	if (sfd == -1)
		return save_errno(ERROR_LIBC_SIGNALFD);

	*r_signal_fd = sfd;

	return SUCCESS;
}
