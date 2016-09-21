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

#define _DEFAULT_SOURCE
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/wait.h>

#include "userland.h"

#define STATUS_FILE	CAPPSULE_RUN_DIR "daemon.status"


int create_pid_file(char *filename, pid_t pid)
{
	FILE *fp;
	int ret;

	fp = fopen(filename, "w");
	if (fp == NULL) {
		warn("failed to create \"%s\"", filename);
		return -1;
	}

	ret = 0;
	if (fprintf(fp, "%u\n", pid) <= 0) {
		warn("failed to write pid to \"%s\"", filename);
		ret = -1;
	}

	fclose(fp);

	return ret;
}

/* redirect stdout and stderr to daemon.log, stdin to /dev/null, and run in
 * background */
int daemonize(void)
{
	int fd;

	fd = creat(LOG_DIR "daemon.log", 0644);
	if (fd == -1) {
		warn("creat(\"" LOG_DIR "cappsule.log\"");
		return -1;
	}

	if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
		warn("dup2");
		close(fd);
		return -1;
	}

	close(fd);

	fd = open("/dev/null", O_RDONLY);
	if (fd == -1) {
		warn("can't open /dev/null");
		return -1;
	}

	if (dup2(fd, STDIN_FILENO) < 0) {
		warn("dup2");
		close(fd);
		return -1;
	}

	close(fd);

	if (daemon(0, 1) == -1) {
		warn("daemon");
		return -1;
	}

	if (create_pid_file(CAPPSULE_PID_FILE, getpid()) != 0) {
		warn("failed to create pid file");
		return -1;
	}

	return 0;
}

err_t status_update(enum daemon_status status)
{
	err_t error;
	FILE *fp;

	if (status == DAEMON_STATUS_READY)
		printf("[*] daemon ready\n");

	fp = fopen(STATUS_FILE, "w");
	if (fp == NULL)
		return save_errno_msg(ERROR_LIBC_FOPEN, STATUS_FILE);

	error = SUCCESS;
	if (fprintf(fp, "%d\n", status) <= 0)
		error = save_errno_msg(ERROR_LIBC_FPRINTF, STATUS_FILE);

	fclose(fp);

	return error;
}

int status_unlink(void)
{
	if (unlink(STATUS_FILE) == -1 && errno != ENOENT) {
		warn("failed to unlink status file (\"" STATUS_FILE "\")");
		return -1;
	}

	return 0;
}

/* print information about child exit */
void print_exited_child(void)
{
	char buf[128], comm[128], *p;
	siginfo_t info;
	int fd, ret;

	strncpy(comm, "?", sizeof(comm));

	ret = waitid(P_ALL, -1, &info, WEXITED | WNOHANG | WNOWAIT);
	if (ret == -1) {
		warn("waitid failed");
		goto out;
	}

	/* use /proc/pid/comm instead of /proc/pid/exe which doesn't exist
	 * anymore */
	snprintf(buf, sizeof(buf), "/proc/%d/comm", info.si_pid);
	fd = open(buf, O_RDONLY);
	if (fd == -1) {
		warn("open(\"%s\") failed", buf);
		goto out;
	}

	memset(comm, 0, sizeof(comm));
	ret = read(fd, comm, sizeof(comm)-1);
	close(fd);

	if (ret == -1)
		goto out;

	p = strchr(comm, '\n');
	if (p != NULL)
		*p = '\x00';

out:
	warnx("one of the children (%s) died, exiting.", comm);
}

