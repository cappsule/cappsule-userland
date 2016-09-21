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

#ifndef ERROR_H
#define ERROR_H

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define ERROR_MSG_LEN	128

typedef enum {
	SUCCESS = 0,

	/* libc errors */
	ERROR_LIBC_ACCEPT,
	ERROR_LIBC_ASPRINTF,
	ERROR_LIBC_BIND,
	ERROR_LIBC_CALLOC,
	ERROR_LIBC_DUP2,
	ERROR_LIBC_EVENTFD,
	ERROR_LIBC_FOPEN,
	ERROR_LIBC_FORK,
	ERROR_LIBC_FPRINTF,
	ERROR_LIBC_FSTAT,
	ERROR_LIBC_FTRUNCATE,
	ERROR_LIBC_GETPWNAM,
	ERROR_LIBC_IOCTL,
	ERROR_LIBC_LISTEN,
	ERROR_LIBC_MALLOC,
	ERROR_LIBC_MKDIR,
	ERROR_LIBC_MMAP,
	ERROR_LIBC_MOUNT,
	ERROR_LIBC_OPEN,
	ERROR_LIBC_OPENDIR,
	ERROR_LIBC_PIPE,
	ERROR_LIBC_PRCTL_PDEATHSIG,
	ERROR_LIBC_READ,
	ERROR_LIBC_REALLOC,
	ERROR_LIBC_RECV,
	ERROR_LIBC_SENDFILE,
	ERROR_LIBC_SEND,
	ERROR_LIBC_SHM_OPEN,
	ERROR_LIBC_SHM_UNLINK,
	ERROR_LIBC_SIGNALFD,
	ERROR_LIBC_SIGPROCMASK,
	ERROR_LIBC_SOCKET,
	ERROR_LIBC_STAT,
	ERROR_LIBC_STRDUP,
	ERROR_LIBC_SWAPOFF,
	ERROR_LIBC_SWAPON,
	ERROR_LIBC_WAITPID,
	ERROR_LIBC_WRITE,

	/* common */
	ERROR_COMMON_DROP_PRIVS,
	ERROR_COMMON_CHROOT_TO_EMPTY,
	ERROR_COMMON_BIND_SOCKET,
	ERROR_COMMON_CONNECTION_CLOSED,
	ERROR_COMMON_INVALID_JSON_SIZE,

	/* filesystem */
	ERROR_FS_NOT_A_DIR,

	/* ramfs */
	ERROR_RAMFS_COPY_FILES,

	/* swap */
	ERROR_SWAP_RESTORE,

	/* xchan */
	ERROR_XCHAN_INVALID_TYPE,
	ERROR_XCHAN_RING_READ,
	ERROR_XCHAN_RING_WRITE,
	ERROR_XCHAN_EVENTFD_INVALID_READ,
	ERROR_XCHAN_EVENTFD_CLOSED,
	ERROR_XCHAN_ACCEPT,
	ERROR_XCHAN_CONNECT,

	/* policy */
	ERROR_POLICY_INVALID_CONFIG_DIR,
	ERROR_POLICY_PRESENT_TWICE,
	ERROR_POLICY_NO_CONFIG_FILE,
	ERROR_POLICY_INVALID_JSON,
	ERROR_POLICY_INVALID,

	/* capsule */
	ERROR_CAPSULE_NOT_FOUND,

	ERROR_MAX,
} err_t;

extern char error_saved_msg[ERROR_MSG_LEN];
extern int error_saved_errno;

const char *error_message(int caps_errno);

/* save current errno */
static inline err_t save_errno(err_t error)
{
	if (error_saved_errno == 0)
		error_saved_errno = errno;
	else
		fprintf(stderr, "an error is already saved\n");
	return error;
}

/* save an additional error message */
static inline err_t save_errmsg(err_t error, const char *msg)
{
	if (error_saved_msg[0] == '\x00') {
		strncpy(error_saved_msg, msg, sizeof(error_saved_msg)-1);
		error_saved_msg[sizeof(error_saved_msg)-1] = '\x00';
	} else {
		fprintf(stderr, "an error message is already saved\n");
	}

	return error;
}

/* save current errno and an additional error message */
static inline err_t save_errno_msg(err_t error, const char *msg)
{
	save_errmsg(error, msg);
	return save_errno(error);
}

/* reset errno and additional error message */
static inline void reset_saved_errno(void)
{
	error_saved_errno = 0;
	error_saved_msg[0] = '\x00';
}

#define print_error(caps_errno, fmt, ...)	do {			\
		fprintf(stderr, fmt "\n", ##__VA_ARGS__);		\
		fprintf(stderr, "%s\n", error_message(caps_errno));	\
	} while (0)

#endif /* ERROR_H */
