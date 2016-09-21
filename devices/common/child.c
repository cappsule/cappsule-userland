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
#define _XOPEN_SOURCE_EXTENDED
#include <err.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/prctl.h>

#include "devices.h"
#include "child.h"
#include "devices.h"
#include "policy.h"
#include "userland.h"

struct child {
	void (*cleanup)(struct child_arg *);
	struct child_arg arg;
	pid_t pid;
};

static struct child *children;
static unsigned int nchild;


int connect_to_monitor(int *notification_fd)
{
	int notif;

	notif = connect_to_abstract_socket(SOCK_STREAM, NOTIF_ADDR);
	if (notif == -1)
		return -1;

	*notification_fd = notif;

	return 0;
}

void sigchld_handler(int UNUSED(dummy))
{
	pid_t pid;

	pid = waitpid(-1, NULL, WNOHANG);
	if (pid == -1) {
		/* happen when monitor already notified fsserver or guiserver
		 * that capsule exited */
		//warn("wait");
	} else if (pid > 0) {
		printf("[*] child (pid %d) exited\n", pid);
	}
}

static void sigchld_block(int block)
{
	sigset_t mask;

	/* get the previous value of the signal mask */
	if (sigprocmask(SIG_SETMASK, NULL, &mask) == -1)
		err(1, "sigprocmask");

	if (block)
		sigaddset(&mask, SIGCHLD);
	else
		sigdelset(&mask, SIGCHLD);

	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1)
		err(1, "sigprocmask");
}

/* must be called with SIGCHLD blocked */
static void reap_child(unsigned int index)
{
	struct child *child;
	pid_t pid;

	child = &children[index];
	pid = child->pid;

	if (kill(pid, CHILD_DEATH_SIGNAL) == -1)
		warn("%s: kill", __func__);

	waitpid(pid, NULL, 0);

	if (child->cleanup != NULL)
		child->cleanup(&child->arg);

	/* swap reaped child and last element of array */
	memcpy(&children[index], &children[--nchild], sizeof(*children));

	if (nchild == 0) {
		free(children);
		children = NULL;
	}
}

static void capsule_exited(unsigned int id)
{
	unsigned int i;
	int reaped;

	printf("[*] capsule %d exited\n", id);

	reaped = 0;
	sigchld_block(1);
	printf("[*] nchild: %d\n", nchild);
	for (i = 0; i < nchild && !reaped; i++) {
		if (children[i].arg.capsule_id == id) {
			reap_child(i);
			reaped = 1;
		}
	}
	sigchld_block(0);

	/* happen when child doesn't use X (or doesn't use fsserver, which is
	 * very unlikely unless capsule crashed in early steps) */
	if (!reaped) {
		//warnx("%s: child not found", __func__);
	}
}

/* Send a device event to the daemon. */
static int send_device_event(struct device *device,
			     enum device_event_type event_type,
			     unsigned int capsule_id)
{
	struct device_event event;
	ssize_t ret;

	event.capsule_id = capsule_id;
	event.type = device->type;
	event.event = event_type;

	ret = write(device->notif_fd, &event, sizeof(event));
	return (ret == sizeof(event) ? 0 : -1);
}

static int event_child_ready(struct device *device, unsigned int capsule_id)
{
	return send_device_event(device, DEVICE_EVENT_DEVICE_READY, capsule_id);
}

static int event_child_ignored(struct device *device, unsigned int capsule_id)
{
	return send_device_event(device, DEVICE_EVENT_CREATE_IGNORED,
				 capsule_id);
}

static int event_child_failed(struct device *device, unsigned int capsule_id)
{
	return send_device_event(device, DEVICE_EVENT_CREATE_FAILURE,
				 capsule_id);
}

static int create_child(unsigned int capsule_id, struct device *device)
{
	struct child *child, *tmp_children;
	struct capsule_filesystems fs;
	struct capsule_creds creds;
	struct serve_arg *arg;
	char display[32];
	pid_t pid;
	int ret;

	fs.nmiscfs = 0;
	fs.miscfs = NULL;

	ret = 0;
	sigchld_block(1);

	tmp_children = (struct child *) realloc(children, sizeof(*children) * (nchild + 1));
	if (tmp_children == NULL) {
		warnx("can't allocate new child: realloc");
		ret = -1;
		goto out;
	}

	children = tmp_children;

	if (get_capsule_creds(capsule_id, &creds) != 0) {
		ret = -1;
		goto out;
	}

	if (get_capsule_rootfs(capsule_id, &fs) != 0) {
		ret = -1;
		goto out;
	}

	if (get_capsule_miscfs(capsule_id, &fs) != 0) {
		ret = -1;
		goto out;
	}

	if (get_capsule_display(capsule_id, display, sizeof(display)) != 0) {
		ret = -1;
		goto out;
	}

	child = &tmp_children[nchild];
	child->arg.capsule_id = capsule_id;

	child->arg.policy_uuid = creds.policy_uuid;
	child->arg.capsule_id = capsule_id;
	child->arg.pid = creds.pid;
	child->arg.uid = creds.uid;
	child->arg.gid = creds.gid;
	child->arg.fs = fs;
	strncpy(child->arg.display, display, sizeof(child->arg.display));

	if (device->prepare_child != NULL) {
		if (device->prepare_child(&child->arg) != 0) {
			ret = -1;
			goto out;
		}
	}

	pid = fork();
	if (pid == -1) {
		warn("fork");
		ret = -1;
		goto out;
	} else if (pid == 0) {
		/* initialize child and tell API server wether it succeed or
		 * not */
		arg = device->init(&child->arg);
		if (arg != NULL)
			event_child_ready(device, capsule_id);
		else
			event_child_failed(device, capsule_id);

		close(device->notif_fd);

		/* if initialization was successful, serve */
		if (arg != NULL)
			device->serve(arg);

		free_misc_filesystems(&fs);
		exit(EXIT_FAILURE);
	}

	printf("[*] new capsule: %d\n", capsule_id);

	child->cleanup = device->cleanup_child;
	child->pid = pid;

	nchild++;

	if (device->child_created != NULL)
		device->child_created(&child->arg);

out:
	free_misc_filesystems(&fs);
	sigchld_block(0);
	return ret;
}

void debug_device(struct device *device)
{
	struct serve_arg *serve_arg;
	unsigned int capsule_id;
	struct child_arg arg;
	pid_t pid;
	char *s;

	capsule_id = 1;
	s = getenv("POLICY_UUID");
	if (s == NULL || uuid_from_str(s, &arg.policy_uuid) != 0) {
		fprintf(stderr, "failed to get policy uuid from environment\n");
		exit(EXIT_FAILURE);
	}

	arg.capsule_id = capsule_id;
	arg.pid = -1;
	arg.uid = 1000;
	arg.gid = 1000;
	arg.fs.rootfs.type = FS_MOUNT_TYPE_OVERLAY;
	strncpy(arg.fs.rootfs.path, "/", sizeof(arg.fs.rootfs.path));

	if (device->prepare_child != NULL) {
		if (device->prepare_child(&arg) != 0)
			exit(1);
	}

	pid = fork();
	if (pid == -1) {
		err(1, "fork");
	} else if (pid == 0) {
		serve_arg = device->init(&arg);
		if (serve_arg != NULL)
			device->serve(serve_arg);
		exit(EXIT_FAILURE);
	} else {
		printf("[*] new capsule: %d\n", capsule_id);

		if (device->child_created != NULL)
			device->child_created(&arg);

		if (waitpid(pid, NULL, 0) == -1)
			err(1, "waitpid");

		if (device->cleanup_child != NULL)
			device->cleanup_child(&arg);
	}
}

void handle_notif_msg(struct device *device)
{
	struct notif_msg msg;
	err_t error;
	size_t n;

	n = read(device->notif_fd, &msg, sizeof(msg));
	if (n != sizeof(msg)) {
		if (n == 0) {
			printf("[*] monitor died, exiting\n");
			exit(EXIT_SUCCESS);
		} else {
			err(1, "%s: read (%ld)", __func__, n);
		}
	}

	switch (msg.type) {
	case NOTIFICATION_CAPSULE_CREATED:
		if (msg.no_gui && device->type == DEVICE_GUI) {
			event_child_ignored(device, msg.capsule_id);
			break;
		}

		if (create_child(msg.capsule_id, device) != 0)
			event_child_failed(device, msg.capsule_id);
		break;
	case NOTIFICATION_CAPSULE_EXIT:
		capsule_exited(msg.capsule_id);
		break;
	case NOTIFICATION_RELOAD_POLICIES:
		printf("[*] reloading policies\n");
		error = reload_policies(device->policies_path,
					device->policies);
		if (error)
			print_error(error, "failed to reload policies");
		break;
	default:
		warnx("%s: unknown msg type %d", __func__, msg.type);
		break;
	}
}

void init_children(void)
{
	/* static variables, anyway */
	nchild = 0;
	children = NULL;
}

// vim: noet:ts=8:
