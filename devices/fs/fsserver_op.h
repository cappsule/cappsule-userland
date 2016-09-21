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

#ifndef FSSERVER_OP_H
#define FSSERVER_OP_H

#define MAX_FILE	65536

#define DEBUG
#ifdef DEBUG
#define debug(fmt, ...)	printf(fmt "\n", ##__VA_ARGS__)
#else
#define debug(fmt, ...)	do { } while (0)
#endif

struct client {
	struct xchan *xchan;
	int fd[MAX_FILE];
	unsigned int n;		/* number of opened files */
	struct policy *policy;
	uid_t uid;
	gid_t gid;
	int procfd;
};

ssize_t handle_request(struct client *client, struct cli_packet *cli,
		       union srv_packet *srvd);

#endif
