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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>

#include "exec.h"
#include "namespace.h"


/* system() could be used, but avoid /bin/sh -c */
int exec_cmd_redirect_output(const char *cmd, char *const argv[], int fd_out,
			     int netns_pid)
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid != 0) {
		/* Not needed for parent. */
		if (fd_out != -1)
			close(fd_out);

		if (pid == -1) {
			warn("fork");
			return -1;
		}
	}
	else {
		if (fd_out != -1) {
			if (dup2(fd_out, 1) == -1 || dup2(fd_out, 2) == -1) {
				warn("dup2");
				return -1;
			}

			close(fd_out);
		}

		if (netns_pid != -1 && join_netns(netns_pid) != 0) {
			fprintf(stderr, "failed to join network namespace %d\n",
				netns_pid);
			return -1;
		}

		if (execvp(cmd, argv) < 0) {
			warn("execvp(\"%s\")", cmd);
			return 126;
		}
	}

	if (waitpid(pid, &status, 0) < 0) {
		warn("waitpid");
		return -1;
	}

	if (!WIFEXITED(status)) {
		warnx("%s failed", cmd);
		return -1;
	}

	return WEXITSTATUS(status);
}

int exec_cmd_output_file(const char *cmd, char *const argv[],
			 char *output_path, mode_t mode, pid_t netns_pid)
{
	int fd;

	fd = creat(output_path, mode);
	if (fd == -1) {
		warn("cannot open file %s", output_path);
		return -1;
	}

	return exec_cmd_redirect_output(cmd, argv, fd, netns_pid);
}

int exec_cmd_piped(const char *cmd, char *const argv[], int *outfd,
		   pid_t netns_pid)
{
	int pipefd[2];

	if (pipe(pipefd) == -1) {
		warn("pipe");
		*outfd = -1;
		return -1;
	}

	*outfd = pipefd[0];
	return exec_cmd_redirect_output(cmd, argv, pipefd[1], netns_pid);
}

int exec_cmd(const char *cmd, char *const argv[], bool quiet, pid_t netns_pid)
{
	if (quiet) {
		return exec_cmd_output_file(cmd, argv, "/dev/null", 0644,
					    netns_pid);
	} else {
		return exec_cmd_redirect_output(cmd, argv, -1, netns_pid);
	}
}

// vim: noet:ts=8:sw=8:
