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
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>

#include "params.h"
#include "userland.h"
#include "cuapi/error.h"

#define STACK_SIZE	(1024 * 1024)

extern char **environ;
static char child_stack[STACK_SIZE];

struct clone_arg {
	int channel_fd;
	bool no_gui;
};


static int get_exit_status(int status)
{
	return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
}

static void snapshot(int channel_fd, bool no_gui)
{
	struct cappsule_ioc_snapshot snapshot;
	int saved_errno, ret, status;
	struct shared_params *params;
	int flags;
	void *p;

	flags = MAP_ANONYMOUS|MAP_PRIVATE;
	p = mmap(NULL, sizeof(*params), PROT_READ|PROT_WRITE, flags, -1, 0);
	if (p == MAP_FAILED)
		err(EXIT_FAILURE, "mmap");

	params = p;
	memset(params, 0, sizeof(*params));
	params->no_gui = no_gui;

	snapshot.params = params;
	snapshot.params_size = sizeof(*params);

	/* Ensures all pages are resident in memory before taking the
	 * snapshot. */
	if (mlockall(MCL_CURRENT) != 0)
		err(EXIT_FAILURE, "cannot lock address space");

	ret = ioctl(channel_fd, CAPPSULE_IOC_SNAPSHOT, &snapshot);
	if (ret == 0) {
		/* snapshot succeed */
		status = EXIT_SUCCESS;
	} else if (ret == -1) {
		saved_errno = errno;
		if (saved_errno <= CAPPSULE_ERRNO_BASE) {
			fprintf(stderr, "snapshot ioctl failed: %s\n",
				strerror(saved_errno));
		} else {
			fprintf(stderr, "snapshot failed: %s\n",
				hv_error_message(saved_errno));
		}

		status = EXIT_FAILURE;
	} else {
		/* snapshot succeed, this code is executed from capsule and
		 * never returns */
		exec_in_capsule(params, snapshot.result_capsule_id);
		status = EXIT_FAILURE;
	}

	exit(status);
}

static int launch_init(void *arg_)
{
	struct clone_arg *arg;
	int status;
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		err(1, "fork");
	} else if (pid == 0) {
		arg = (struct clone_arg *)arg_;
		snapshot(arg->channel_fd, arg->no_gui);
	}

	if (prctl(PR_SET_NAME, "/sbin/init", 0, 0, 0) == -1)
		warn("prctl(PR_SET_NAME) failed");

	while (1) {
		pid = wait(&status);
		if (pid == -1) {
			if (errno == ECHILD)
				break;
			else
				warn("waitpid init");
		}
	}

	return get_exit_status(status);
}

static int exec_in_new_pid_namespace(int channel_fd, bool no_gui)
{
	struct clone_arg arg;
	int flags, status;
	pid_t pid;

	arg.channel_fd = channel_fd;
	arg.no_gui = no_gui;

	flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_PTRACE | SIGCHLD;
	pid = clone(launch_init, child_stack + STACK_SIZE, flags, &arg);
	if (pid == -1)
		err(1, "clone failed");

	if (waitpid(pid, &status, 0) == -1)
		err(1, "waitpid parent");

	return get_exit_status(status);
}

/* It's overcomplicated to pass the file descriptor to capsule_init through
 * capsule params, which are reset at each capsule creation. Use STDIN_FILENO
 * instead. */
static int setup_pipe_device_ready(int pipe_device_ready_r)
{
	if (dup2(pipe_device_ready_r, STDIN_FILENO) == -1) {
		warn("dup2");
		return -1;
	}

	close(pipe_device_ready_r);

	return 0;
}

static void usage(char *filename)
{
	printf("Usage: %s [options ...]\n", filename);
	printf("  -f, --fd [fd]\t\tchannel file descriptor\n");
	printf("  -n, --no-gui\n");
	printf("  -p, --pipe [fd]\t\tdevice ready file descriptor\n");
}

static struct option long_options[] = {
        { "fd", required_argument, NULL, 'f' },
        { "no-gui", no_argument, NULL, 'n' },
        { "pipe", required_argument, NULL, 'p' },
        { NULL, 0, NULL, 0 }
};

int main(int argc, char *argv[])
{
	int c, channel_fd, flags, pipe_device_ready_r;
	bool no_gui;

	channel_fd = -1;
	no_gui = false;
	pipe_device_ready_r = -1;

	while (1) {
		c = getopt_long(argc, argv, "f:np:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'f':
			channel_fd = atoi(optarg);
			break;
		case 'n':
			no_gui = true;
			break;
		case 'p':
			pipe_device_ready_r = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (channel_fd == -1) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (setup_pipe_device_ready(pipe_device_ready_r) != 0)
		exit(EXIT_FAILURE);

	flags = fcntl(channel_fd, F_GETFD, 0);
	if (flags < 0)
		err(1, "failed to get fd flag");

	if (fcntl(channel_fd, F_SETFD, flags | FD_CLOEXEC) != 0)
		err(1, "failed to set close-on-exec flag");

	setup_fake_name(argc, argv, "/sbin/init");
	return exec_in_new_pid_namespace(channel_fd, no_gui);
}

// vim: noet:ts=8:
