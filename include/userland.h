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

#ifndef USERLAND_H
#define USERLAND_H

#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/limits.h>

typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

#include "cuapi/guest/console.h"
#include "cuapi/trusted/channel.h"
#include "fs_mount_type.h"
#include "error.h"
#include "uuid.h"

#define INSTALL_PREFIX		"/usr/local/cappsule/"

#define BIN_PATH		INSTALL_PREFIX "usr/bin/"
#define LIB_PATH		INSTALL_PREFIX "usr/lib/"
#define CONFIG_PATH		INSTALL_PREFIX "etc/cappsule/"
#define POLICIES_PATH		CONFIG_PATH "policies/"

#define CAPPSULE_RUN_DIR	"/run/cappsule/"
#define CAPSULE_FS		CAPPSULE_RUN_DIR "fs/"
#define DISPLAY_ENV_FILE	CAPPSULE_RUN_DIR "display"
#define RAMFS			CAPPSULE_RUN_DIR "ramfs/"
#define RAMFS_SRC		INSTALL_PREFIX "usr/share/cappsule/ramfs/"


#define LOG_DIR			"/var/log/cappsule/"
#define LOG_CAPSULE_DIR_FMT	LOG_DIR "%d/"

#define CAPPSULE_PID_FILE	"/var/run/cappsule.pid"

#define CHANNEL_DEVICE		"/dev/" CHANNEL_DEVICE_NAME
#define GUEST_CONSOLE_DEVICE	"/dev/" GUEST_CONSOLE_DEVICE_NAME
#define NOTIF_ADDR		"cappsule_notif"
#define CONSOLE_SOCKET		"cappsule_console"
#define API_SOCKET		"cappsule_api"

#define ENV_CAPSULE_ID		"CAPSULE_ID"

#ifndef UNUSED
# ifdef __GNUC__
#   define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
# else
#   define UNUSED(x) UNUSED_ ## x
# endif
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof(arr[0]))
#endif

enum daemon_status {
	DAEMON_STATUS_INIT,
	DAEMON_STATUS_READY,
	DAEMON_STATUS_EXIT,
};

struct capsule_creds {
	struct uuid policy_uuid;
	uid_t uid;
	gid_t gid;
	pid_t pid;
};

struct capsule_fs {
	enum fs_mount_type type;
	char path[PATH_MAX];
};

struct capsule_filesystems {
	struct capsule_fs rootfs;
	char base_dir[PATH_MAX];

	unsigned int nmiscfs;
	struct capsule_fs **miscfs;
};

struct policy;
struct policies;
struct devices_sockets;
struct sockaddr;
struct sockaddr_un;
struct timeval;

struct pcred {
	pid_t pid;
	uid_t uid;
	gid_t gid;
};

static inline struct capsule_fs **alloc_misc_filesystems(unsigned int n)
{
	struct capsule_fs **miscfs, *fs;
	size_t size1, size2;
	unsigned int i;

	if (n > 128) {
		warnx("invalid miscfs array size (%d)", n);
		return NULL;
	}

	size1 = n * sizeof(*miscfs);
	size2 = n * sizeof(**miscfs);

	miscfs = malloc(size1 + size2);
	if (miscfs == NULL) {
		warn("malloc");
		return NULL;
	}

	fs = (struct capsule_fs *)((char *)miscfs + size1);
	for (i = 0; i < n; i++)
		miscfs[i] = &fs[i];

	return miscfs;
}
static inline void free_misc_filesystems(struct capsule_filesystems *fs)
{
	free(fs->miscfs);
	fs->miscfs = NULL;
}


void monitor(int channel_fd, int api_fd, struct devices_sockets *notif);

err_t make_dirs(const char *dst);
err_t copy_file(const char *src, const char *dst);

const char *hv_error_message(int caps_errno);

int create_abstract_socket(int type, const char *name, struct sockaddr_un *addr, socklen_t *len);
int bind_abstract_socket(int type, const char *name, int backlog);
int connect_to_abstract_socket(int type, const char *name);
int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y);

void display_version(const char *filename, const char *version, int do_exit);
int daemonize(void);
err_t status_update(enum daemon_status status);
int status_unlink(void);
void print_exited_child(void);
int read_signal(int sfd);
err_t create_signalfd(int *r_signal_fd, ...);

int get_peercred(int sock, struct pcred *pcred);
int recv_fds(int sock, int *fds, unsigned int n_fds, int flags);
int send_fds(int sock, const int *fds, unsigned int n_fds);

int setup_fake_name(int argc, char *argv[], char *fake_name);
void addtoproctitle(const char *title);

int chroot_to_empty(void);
int drop_uid(uid_t uid, gid_t gid);
int drop_uid_from_str(char *userspec);
int drop_dangerous_capabilities(void);

err_t open_log_file(unsigned int capsule_id, char *filename, int *p_fd);
err_t set_logfile(unsigned int capsule_id, char *filename);

int rmrf(const char *basedir);

int run_api_server(int channel_fd, struct policies *policies,
		   struct devices_sockets *notif);

#endif /* USERLAND_H */

// vim: noet:ts=8:sw=8:
