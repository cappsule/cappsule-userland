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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "error.h"

/* XXX: not thread safe */
static char msg[1024];
char error_saved_msg[ERROR_MSG_LEN] = { 0 };
int error_saved_errno = 0;

#define ARRAY_SIZE(arr)		(sizeof(arr) / sizeof(arr[0]))
#define BUILD_BUG_ON(condition)	((void)sizeof(char[1 - 2*!!(condition)]))
#define X(k, v)			[k] = v,

#define ENUM_MAP(X) 										\
	X(SUCCESS,				"success")					\
												\
	X(ERROR_LIBC_ACCEPT,			"accept failed")				\
	X(ERROR_LIBC_ASPRINTF,			"asprintf failed")				\
	X(ERROR_LIBC_BIND,			"bind failed")					\
	X(ERROR_LIBC_CALLOC,			"calloc failed")				\
	X(ERROR_LIBC_DUP2,			"dup2 failed")					\
	X(ERROR_LIBC_EVENTFD,			"eventfd failed")				\
	X(ERROR_LIBC_FOPEN,			"fopen failed")					\
	X(ERROR_LIBC_FORK,			"fork failed")					\
	X(ERROR_LIBC_FPRINTF,			"fprintf failed")				\
	X(ERROR_LIBC_FSTAT,			"fstat failed")					\
	X(ERROR_LIBC_FTRUNCATE,			"ftruncate failed")				\
	X(ERROR_LIBC_GETPWNAM,			"getpwnam failed")				\
	X(ERROR_LIBC_IOCTL,			"ioctl failed")					\
	X(ERROR_LIBC_LISTEN,			"listen failed")				\
	X(ERROR_LIBC_MALLOC,			"malloc failed")				\
	X(ERROR_LIBC_MKDIR,			"mkdir failed")					\
	X(ERROR_LIBC_MMAP,			"mmap failed")					\
	X(ERROR_LIBC_MOUNT,			"mount failed")					\
	X(ERROR_LIBC_OPEN,			"open failed")					\
	X(ERROR_LIBC_OPENDIR,			"opendir failed")				\
	X(ERROR_LIBC_PIPE,			"pipe failed")					\
	X(ERROR_LIBC_PRCTL_PDEATHSIG,		"failed to get/set parent process death signal")\
	X(ERROR_LIBC_READ,			"read failed")					\
	X(ERROR_LIBC_REALLOC,			"realloc failed")				\
	X(ERROR_LIBC_RECV,			"recv failed")					\
	X(ERROR_LIBC_SENDFILE,			"sendfile failed")				\
	X(ERROR_LIBC_SEND,			"send failed")					\
	X(ERROR_LIBC_SIGNALFD,			"signalfd failed")				\
	X(ERROR_LIBC_SIGPROCMASK,		"sigprocmask failed")				\
	X(ERROR_LIBC_SHM_OPEN,			"shm_open failed")				\
	X(ERROR_LIBC_SHM_UNLINK,		"shm_unlink failed")				\
	X(ERROR_LIBC_SOCKET,			"socket failed")				\
	X(ERROR_LIBC_STAT,			"stat failed")					\
	X(ERROR_LIBC_STRDUP,			"strdup failed")				\
	X(ERROR_LIBC_SWAPOFF,			"swapoff failed")				\
	X(ERROR_LIBC_SWAPON,			"swapon failed")				\
	X(ERROR_LIBC_WAITPID,			"waitpid failed")				\
	X(ERROR_LIBC_WRITE,			"write failed")					\
												\
	X(ERROR_COMMON_DROP_PRIVS,		"failed to drop privileges")			\
	X(ERROR_COMMON_CHROOT_TO_EMPTY,		"failed to chroot to empty directory")		\
	X(ERROR_COMMON_BIND_SOCKET,		"failed to create or bind socket")		\
	X(ERROR_COMMON_CONNECTION_CLOSED,	"connection closed")				\
	X(ERROR_COMMON_INVALID_JSON_SIZE,	"invalid json size")				\
												\
	X(ERROR_FS_NOT_A_DIR,			"failed to make dirs: a directory component in pathname isn't a directory")\
												\
	X(ERROR_RAMFS_COPY_FILES,		"failed to copy files")				\
												\
	X(ERROR_SWAP_RESTORE,			"one or several devices can't be restarted")	\
												\
	X(ERROR_XCHAN_INVALID_TYPE,		"xchan: invalid type")				\
	X(ERROR_XCHAN_RING_READ,		"xchan: failed to read from ring")		\
	X(ERROR_XCHAN_RING_WRITE,		"xchan: failed to write to ring")		\
	X(ERROR_XCHAN_EVENTFD_INVALID_READ,	"xchan: invalid eventfd read")			\
	X(ERROR_XCHAN_EVENTFD_CLOSED,		"xchan: eventfd closed")			\
	X(ERROR_XCHAN_ACCEPT,			"xchan: accept failed")				\
	X(ERROR_XCHAN_CONNECT,			"xchan: connect failed")			\
												\
	X(ERROR_POLICY_INVALID_CONFIG_DIR,	"policies directory needs to be absolute")	\
	X(ERROR_POLICY_PRESENT_TWICE,		"policy is present twice")			\
	X(ERROR_POLICY_NO_CONFIG_FILE,		"no policy configuration file found")		\
	X(ERROR_POLICY_INVALID_JSON,		"failed to parse policy: invalid json")		\
	X(ERROR_POLICY_INVALID,			"failed to parse policy")			\
												\
	X(ERROR_CAPSULE_NOT_FOUND,		"capsule not found")				\


static const char *error_msg[] = {
	ENUM_MAP(X)
};
#undef X

#define X(n, v)		+ 1
#define NB_MSG		(0 ENUM_MAP(X))

const char *error_message(int caps_errno)
{
	char buf[128];
	char *p, *q;
	size_t len;

	/* ensure at compile time that each err_t has an index in
	 * error_msg array */
	BUILD_BUG_ON(NB_MSG != ERROR_MAX);

	if (caps_errno < 0 || (unsigned int)caps_errno >= ARRAY_SIZE(error_msg)) {
		sprintf(msg, "unknown error %d", caps_errno);
		return msg;
	}

	/* create the error message, and include additional info if set */
	if (error_saved_msg[0] == '\x00') {
		strncpy(msg, error_msg[caps_errno], sizeof(msg)-1);
		msg[sizeof(msg)-1] = '\x00';
	} else {
		snprintf(msg, sizeof(msg), "%s (%s)",
			 error_msg[caps_errno], error_saved_msg);
	}

	len = strlen(msg);
	p = msg + len;
	len = sizeof(msg)-1 - len;

	/* if an errno is saved, append a string describing error number */
	if (error_saved_errno != 0 && len > 2) {
		strncpy(p, ": ", 2);
		q = strerror_r(error_saved_errno, buf, sizeof(buf));
		strncpy(p + 2, q, len - 2);
	}

	msg[sizeof(msg)-1] = '\x00';

	return msg;

}

void print_error_message(int caps_errno)
{
	fprintf(stderr, "%s\n", error_message(caps_errno));
}
// vim: noet:ts=8:
