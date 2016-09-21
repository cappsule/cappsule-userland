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

#ifndef EXEC_H
#define EXEC_H

#include <stdbool.h>
#include <sys/types.h>

#define EXEC_CMD(cmd, args...)					\
	({							\
		char *const argv[] = { cmd, ##args, NULL };	\
		exec_cmd(cmd, argv, false, -1);			\
	})							\

#define EXEC_CMD_NETNS(netns_pid, cmd, args...)			\
	({							\
		char *const argv[] = { cmd, ##args, NULL };	\
		exec_cmd(cmd, argv, false, netns_pid);		\
	})							\

#define EXEC_CMD_QUIET(cmd, args...)				\
	({							\
		char *const argv[] = { cmd, ##args, NULL };	\
		exec_cmd(cmd, argv, true, -1);			\
	})							\

#define EXEC_CMD_OUTPUT_FILE(path, mode, cmd, args...)		\
	({							\
		char *const argv[] = { cmd, ##args, NULL };	\
		exec_cmd_output_file(cmd, argv, path, mode, -1);\
	})							\

#define EXEC_CMD_PIPE(pipe, cmd, args...)			\
	({							\
		char *const argv[] = { cmd, ##args, NULL };	\
	 	exec_cmd_piped(cmd, argv, pipe, -1);		\
	})							\


int exec_cmd(const char *cmd, char *const argv[], bool quiet, pid_t netns_pid);
int exec_cmd_piped(const char *cmd, char *const argv[], int *outfd,
		   pid_t netns_pid);
int exec_cmd_output_file(const char *cmd, char *const argv[],
			 char *output_path, mode_t mode, pid_t netns_pid);

#endif

// vim: noet:ts=8:sw=8:
