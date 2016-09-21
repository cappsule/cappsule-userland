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
#include <grp.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <linux/limits.h>

#include "userland.h"
#include "devices.h"
#include "params.h"
#include "readall.h"

#define CORE_PATTERN	"/proc/sys/kernel/core_pattern"
#define SUID_DUMPABLE	"/proc/sys/fs/suid_dumpable"


static void setup_userland_console(void)
{
	int fd;

	fd = open(GUEST_CONSOLE_DEVICE, O_RDWR);
	if (fd == -1)
		err(1, "open(\"" GUEST_CONSOLE_DEVICE "\")");

	/* Sets this process as the group and session leader. */
	if (setsid() == -1)
		err(1, "setsid");

	/* Sets the console as the controlling TTY for this session. */
	if (ioctl(fd, TIOCSCTTY, 1) != 0)
		err(1, "cannot set " GUEST_CONSOLE_DEVICE " as the controlling tty");

	if (dup2(fd, STDIN_FILENO) == -1 ||
	    dup2(fd, STDOUT_FILENO) == -1 ||
	    dup2(fd, STDERR_FILENO) == -1)
		err(1, "dup2");

	if (close(fd) == -1)
		err(1, "close");
}

static void setup_hostname(unsigned int capsule_id)
{
	char hostname[64];
	int n;

	n = snprintf(hostname, sizeof(hostname), "capsule-%u", capsule_id);
	if (sethostname(hostname, n) != 0)
		warnx("can't set hostname to \"%s\"", hostname);
}

static void setup_userland_filesystem(void)
{
	int error;

	if (chroot(CAPSULE_FS) == -1)
		err(1, "chroot");

	error = mount("proc", "/proc", "proc", MS_MGC_VAL, NULL);
	if (error)
		warn("mount /proc");

	/* https://www.kernel.org/doc/Documentation/filesystems/devpts.txt */
	error = mount("cappsule-devpts", "/dev/pts", "devpts", MS_MGC_VAL, "newinstance");
	if (error)
		warn("mount /dev/pts");

	error = mount("/dev/pts/ptmx", "/dev/ptmx", "ptmx", MS_BIND, NULL);
	if (error)
		warn("mount /dev/pts/ptmx");

	if (chown("/dev/ptmx", 0, 5) == -1)
		warn("chown(/dev/ptmx, 0, 0)");

	if (chmod("/dev/ptmx", 0666) == -1)
		warn("chmod(/dev/ptmx, 0666)");
}

static void setup_creds(uid_t uid, gid_t gid, char *groups)
{
	char *str, *token;
	size_t size;
	gid_t *list;

	size = 0;
	list = NULL;
	for (str = groups; ; str = NULL) {
		token = strtok(str, ",");
		if (token == NULL)
			break;
		list = (gid_t *) realloc(list, (size + 1) * sizeof(*list));
		if (list == NULL)
			err(1, "realloc");

		list[size++] = atoi(token);
	}

	if (setgroups(size, list) == -1)
		err(1, "setgroups");

	free(list);

	if (setregid(gid, gid) == -1)
		err(1, "setreuid");

	if (setreuid(uid, uid) == -1)
		err(1, "setreuid");
}

static void setup_cwd(char *cwd)
{
	if (*cwd == '\x00')
		cwd = "/";

	/* cwd may not be allowed by filesystem policy, chdir to / if
	 * necessary */
	if (chdir(cwd) == -1 && chdir("/") == -1)
		warn("chdir");
}

static char **build_array(char *str)
{
	unsigned int i, n;
	char **array, *p;
	size_t len;

	p = str;
	n = 1;
	while (1) {
		len = strlen(p);
		if (len == 0)
			break;

		p += len + 1;
		n++;
	}

	array = (char **)malloc(sizeof(char *) * n);
	if (array == NULL)
		err(1, "malloc");

	p = str;
	for (i = 0; i < n - 1; i++) {
		array[i] = p;
		p += strlen(p) + 1;
	}

	array[n-1] = NULL;

	return array;
}

/* Reset core_pattern to "core"
 *
 * It fixes 2 issues (if the first char of this file is a pipe symbol):
 *  - process never terminate if specified coredump program can't be accessed,
 *  - this feature could be use to escape exec policies.  */
static void reset_core_pattern(void)
{
	int fd;

	fd = open(SUID_DUMPABLE, O_WRONLY);
	if (fd != -1) {
		if (write(fd, "0", 1) != 1)
			warn("write to " SUID_DUMPABLE);
		close(fd);
	} else {
		warn("failed to open \"" SUID_DUMPABLE "\"");
	}

	fd = open(CORE_PATTERN, O_WRONLY);
	if (fd != -1) {
		if (write(fd, "core\n", 5) != 5)
			warn("write to " CORE_PATTERN);
		close(fd);
	} else {
		warn("failed to open \"" CORE_PATTERN "\"");
	}
}

static int disable_pulseaudio(char **env)
{
	char *home, **p, path[PATH_MAX];
	int fd;

	/* don't try to use host socket which is now invalid */
	snprintf(path, sizeof(path), "/var/run/user/%d/pulse/native", getuid());
	unlink(path);

	snprintf(path, sizeof(path), "/var/run/user/%d/pulse/pid", getuid());
	unlink(path);

	/* find HOME environment variable */
	home = NULL;
	for (p = env; *p != NULL; p++) {
		if (strncmp(*p, "HOME=", 5) == 0) {
			home = *p + 5;
			break;
		}
	}

	if (home == NULL) {
		fprintf(stderr, "HOME environment variable is unset\n");
		return -1;
	}

	/* echo 'autospawn=no' > ~/.pulse/client.conf */
	snprintf(path, sizeof(path), "%s/.pulse", home);
	if (mkdir(path, 0755) == -1 && errno != EEXIST) {
		perror("failed to create ~/.pulse/ directory");
		return -1;
	}

	snprintf(path, sizeof(path), "%s/.pulse/client.conf", home);
	fd = open(path, O_TRUNC | O_WRONLY | O_CREAT, 0644);
	if (fd == -1) {
		perror("failed to open ~/.pulse/client.conf");
		return -1;
	}

	if (write(fd, "autospawn=no\n", 13) != 13) {
		fprintf(stderr, "failed to edit \"%s\"\n", path);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static int setup_pipe_device_ready(int *pipe_device_ready_r)
{
	int fd;

	/* the file descriptor is given through STDIN_FILENO */
	fd = dup(STDIN_FILENO);
	if (fd == -1) {
		warn("dup");
		return -1;
	}

	*pipe_device_ready_r = fd;

	return 0;
}

static int wait_for_devices(int pipe_device_ready_r, bool no_gui)
{
	unsigned int count, n;
	err_t error;
	char c;

	n = NR_DEVICES;

	/* there's no console client */
	n--;

	/* fsclient is always ready and doesn't write to pipe_device_ready_w */
	n--;

	if (no_gui)
		n--;

	for (count = 0; count < n; count++) {
		error = readall(pipe_device_ready_r, &c, sizeof(c));
		if (error) {
			print_error(error, "pipe device ready");
			close(pipe_device_ready_r);
			return -1;
		}
	}

	close(pipe_device_ready_r);
	return 0;
}

void exec_in_capsule(struct shared_params *params, unsigned int capsule_id)
{
	int pipe_device_ready_r;
	char **argv;
	char **env;

	if (setup_pipe_device_ready(&pipe_device_ready_r) != 0) {
		fprintf(stderr, "failed to get pipe device ready fd");
		exit(EXIT_FAILURE);
	}

	/* setup console as soon as possible to get error messages */
	setup_userland_console();

	argv = build_array(params->argv);
	env = build_array(params->env);

	setup_hostname(capsule_id);

	setup_userland_filesystem();

	reset_core_pattern();

	unlink("/var/run/dbus/system_bus_socket");
	unlink("/var/run/dbus/pid");

	setup_creds(params->uid, params->gid, params->groups);

	setup_cwd(params->cwd);

	if (!params->no_gui)
		disable_pulseaudio(env);

	if (wait_for_devices(pipe_device_ready_r, params->no_gui) != 0) {
		fprintf(stderr, "failed to wait for devices");
		exit(EXIT_FAILURE);
	}

	/* execvpe segfault if file is NULL (virt exec -p unrestricted '') */
	if (argv[0] == NULL)
		errx(EXIT_FAILURE, "no program given");

	execvpe(argv[0], argv, env);

	err(EXIT_FAILURE, "failed to exec %s", argv[0]);
}

// vim: noet:ts=8:
