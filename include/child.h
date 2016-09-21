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

#ifndef CHILD_H
#define CHILD_H

#include "devices.h"
#include "fs_mount_type.h"
#include "userland.h"
#include "uuid.h"

#ifndef UNUSED
# ifdef __GNUC__
#   define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
# else
#   define UNUSED(x) UNUSED_ ## x
# endif
#endif

#define CHILD_DEATH_SIGNAL	SIGTERM

struct policies;
struct serve_arg;

struct child_arg {
	/* filled by parent */
	void *arg;

	/* filled with monitor message */
	struct uuid policy_uuid;
	unsigned int capsule_id;
	pid_t pid;
	uid_t uid;
	gid_t gid;
	struct capsule_filesystems fs;
	char display[32];
};

struct device {
	enum device_type type;
	int notif_fd;
	const char *policies_path;
	struct policies **policies;
	struct serve_arg *(*init)(struct child_arg *);
	void (*serve)(struct serve_arg *);
	int (*prepare_child)(struct child_arg *);
	void (*child_created)(struct child_arg *);
	void (*cleanup_child)(struct child_arg *);
};

int connect_to_monitor(int *notification_fd);

void sigchld_handler(int UNUSED(dummy));
void handle_notif_msg(struct device *device);
void debug_device(struct device *device);
void init_children(void);

#endif /* CHILD_H */

// vim: noet:ts=8:
