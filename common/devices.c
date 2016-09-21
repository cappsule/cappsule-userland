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
#include <err.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/prctl.h>

#include "userland.h"
#include "devices.h"
#include "readall.h"

#define FSSERVER	BIN_PATH "fsserver"
#define GUISERVER	BIN_PATH "guiserver"
#define NETSERVER	BIN_PATH "netserver"
#define CONSOLESERVER	BIN_PATH "consoleserver"

struct device_server {
	int notif_socket;
	bool no_gui;
	bool no_console;
};

struct dev {
	char *filename;
	char *logfile;
	bool enabled;
};


static int notify_devices(struct devices_sockets *notif, struct notif_msg *msg)
{
	int fd, ret;
	unsigned i;

	ret = 0;
	for (i = 0; i < notif->nr_devices; i++) {
		fd = notif->fds[i];

		if (writeall(fd, msg, sizeof(*msg)) != SUCCESS) {
			warnx("can't send notification to device %d (crash?)",
			      i);
			ret = -1;
		}
	}

	return ret;
}

int notify_devices_of_capsule_exit(unsigned int capsule_id,
				   struct devices_sockets *notif)
{
	struct notif_msg msg;

	msg.type = NOTIFICATION_CAPSULE_EXIT;
	msg.capsule_id = capsule_id;

	return notify_devices(notif, &msg);
}

int notify_devices_of_capsule_creation(unsigned int capsule_id,
				       struct devices_sockets *notif,
				       bool no_gui)
{
	struct notif_msg msg;

	msg.type = NOTIFICATION_CAPSULE_CREATED;
	msg.capsule_id = capsule_id;
	msg.no_gui = no_gui;

	return notify_devices(notif, &msg);
}

int notify_devices_of_policies_reload(struct devices_sockets *notif)
{
	struct notif_msg msg;

	msg.type = NOTIFICATION_RELOAD_POLICIES;
	msg.capsule_id = -1;

	return notify_devices(notif, &msg);
}

/* wait for a connection on multiple sockets with a timeout */
static int wait_for_devices_helper(int socket, int *fds, unsigned int nr)
{
	struct timeval tv1, tv2, timeout;
	struct sockaddr_un addr;
	unsigned int i;
	socklen_t len;
	int ret;

	ret = 0;
	for (i = 0; i < nr; i++) {
		len = sizeof(addr);
		gettimeofday(&tv1, NULL);
		fds[i] = accept(socket, (struct sockaddr *)&addr, &len);
		gettimeofday(&tv2, NULL);
		if (fds[i] == -1) {
			if (errno == EAGAIN) {
				timeval_subtract(&timeout, &tv2, &tv1);
				if (timeout.tv_sec < SOCKET_TIMEOUT) {
					i--;
					continue;
				} else {
					warnx("%s: timeout", __func__);
					ret = -1;
					break;
				}
			} else {
				warn("%s: accept", __func__);
				ret = -1;
				break;
			}
		}
	}

	return ret;
}

static void close_fds(int *fds, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		if (fds[i] != -1) {
			close(fds[i]);
			fds[i] = -1;
		}
	}
}

/* Each device makes a connection to the notification socket. Wait for them. */
static struct devices_sockets *wait_for_devices(struct device_server *server)
{
	struct devices_sockets *sockets;
	unsigned int n;
	int sock;

	sockets = (struct devices_sockets *)malloc(sizeof(*sockets));
	if (sockets == NULL) {
		warn("malloc");
		return NULL;
	}

	memset(sockets, -1, sizeof(*sockets));

	n = NR_DEVICES;
	if (server->no_gui)
		n--;
	if (server->no_console)
		n--;

	sock = server->notif_socket;
	if (wait_for_devices_helper(sock, sockets->fds, n) != 0) {
		close_fds(sockets->fds, n);
		free(sockets);
		return NULL;
	}

	sockets->nr_devices = n;
	return sockets;
}

static int create_timeout_socket(const char *name)
{
	struct sockaddr_un addr;
	struct timeval tv;
	socklen_t len;
	int fd, ret;

	fd = create_abstract_socket(SOCK_STREAM, name, &addr, &len);
	if (fd == -1) {
		warnx("cannot create unix socket %s", name);
		return -1;
	}

	/* Setup a timeout after which accept() fails. It prevents
	 * wait_for_devices() to wait indefinitely for children if there's
	 * an error. */
	tv.tv_sec = SOCKET_TIMEOUT;
	tv.tv_usec = 0;
	ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (ret == -1) {
		warn("setsockopt(SO_RCVTIMEO)");
		goto error;
	}

	if (bind(fd, (struct sockaddr *)&addr, len) == -1) {
		warn("%s: bind", __func__);
		goto error;
	}

	if (listen(fd, NR_DEVICES) == -1) {
		warn("%s: listen", __func__);
		goto error;
	}

	return fd;

error:
	close(fd);
	return -1;
}

static int run_device(struct dev *device, struct device_server *server)
{
	char *argv[] = { device->filename, NULL };
	pid_t pid;
	int fd;

	pid = fork();
	switch (pid) {
	case -1:
		warn("fork");
		return -1;
	case 0:
		/* don't inherit parent's signal handler */
		if (signal(SIGTERM, SIG_DFL) == SIG_ERR ||
		    signal(SIGINT, SIG_DFL) == SIG_ERR)
			err(1, "signal");

		/* receive SIGTERM when parent (daemon) dies */
		if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1)
			err(1, "prctl");

		/* don't leak device server sockets to child */
		close(server->notif_socket);

		fd = creat(device->logfile, 0644);
		if (fd == -1)
			err(1, "creat(\"%s\")", device->logfile);

		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);

		if (execvp(argv[0], argv) < 0)
			err(1, "execvp(\"%s\")", argv[0]);
	default:
		break;
	}

	printf("[*] %s running (pid: %d)\n", argv[0], pid);

	return 0;
}

struct devices_sockets *run_devices(bool no_gui, bool no_console)
{
	struct devices_sockets *sockets;
	struct device_server server;
	unsigned int i;
	int ret;

	struct dev devices[] = {
		{ FSSERVER, LOG_DIR "fsserver.log", true },
		{ NETSERVER, LOG_DIR "netserver.log", true },
		{ CONSOLESERVER, LOG_DIR "consoleserver.log", !no_console },
		{ GUISERVER, LOG_DIR "guiserver.log" , !no_gui },
	};

	/* Create AF_UNIX socket on which devices will connect. Used to notify
	 * them on capsule creation/exit. */
	server.notif_socket = create_timeout_socket(NOTIF_ADDR);
	if (server.notif_socket == -1)
		goto error_notif_socket;

	server.no_gui = no_gui;
	server.no_console = no_console;

	/* run each device */
	ret = 0;
	for (i = 0; i < ARRAY_SIZE(devices); i++) {
		if (!devices[i].enabled)
			continue;

		ret = run_device(&devices[i], &server);
		if (ret != 0) {
			fprintf(stderr, "failed to start device \"%s\"",
				devices[i].filename);
			break;
		}
	}

	if (ret != 0)
		goto error_run_device;

	sockets = wait_for_devices(&server);
	if (sockets == NULL)
		goto error_wait_for_devices;

	/* each device is connected, close listening notif socket */
	close(server.notif_socket);

	return sockets;

	free(sockets);
error_wait_for_devices:
error_run_device:
	close(server.notif_socket);
error_notif_socket:
	return NULL;
}

// vim: noet:ts=8:sw=8:
