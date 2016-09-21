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

#ifndef API_H
#define API_H

#include <poll.h>
#include <sys/socket.h>
#include <linux/limits.h>

#include "devices.h"
#include "error.h"
#include "params.h"
#include "policy.h"
#include "userland.h"
#include "uuid.h"
#include "fs_mount_type.h"
#include "cuapi/common/kill.h"

#define INITIALIZATION_TIMEOUT	5000	/* ms */

struct params {
	struct shared_params shared;

	struct capsule_filesystems fs;
	pid_t pid;
	struct uuid policy_uuid;
	struct winsize tty_size;
	unsigned int memory_limit;
	char display[32];
};

struct capsule {
	unsigned int capsule_id;
	struct ucred ucred;
	struct params params;
	unsigned int devices_ready;
	unsigned int devices_errors;
	bool exited;
	kill_t exit_reason;

	struct capsule *prev;
	struct capsule *next;
};

struct client {
	int c;
	struct ucred ucred;
	struct client *prev;
	struct client *next;
};

#define EVENT_LISTEN_EXIT	(1 << 0)
#define EVENT_LISTEN_ALL	(EVENT_LISTEN_EXIT)

struct event_listener {
	struct client *client;
	unsigned int capsule_id;
	unsigned event_bitmask;
	struct event_listener *prev;
	struct event_listener *next;
};

/* once all the devices of a capsule are initialized, the capsule is considered
 * "pending" */
struct pending_capsule {
	struct capsule *capsule;
	struct client *client;
	struct timeval creation;
	struct pending_capsule *prev;
	struct pending_capsule *next;
};

struct context {
	struct policies *policies;
	struct devices_sockets *notif;
	struct pollfd *pollfds;
	struct client *clients;
	struct event_listener *listeners;
	struct capsule *capsules;
	struct pending_capsule *pending;
	nfds_t nfds;
	int socket_fd;
	int signal_fd;
	int channel_fd;
	bool child_exited;
};

struct api_kill_infos {
	unsigned int capsule_id;
	kill_t reason;
};

struct params;

void init_capsule(struct capsule *capsule, unsigned int capsule_id, struct params *params);
struct capsule *create_capsule(int channel_fd, struct params *params,
			       char *errmsg, size_t size);
int capsule_set_exited(struct context *ctx, unsigned int capsule_id, kill_t reason);
struct capsule *find_capsule_by_id(struct context *ctx, unsigned int capsule_id);
struct event_listener *find_listener_by_client(struct context *ctx, struct client *client);
struct event_listener *find_listener_by_capsule(struct context *ctx, unsigned int capsule_id);
bool capsule_devices_ready(struct context *ctx, struct capsule *capsule);
bool capsule_devices_error(struct capsule *capsule);
bool capsule_has_exited(struct capsule *capsule);
int kill_capsule(int channel_fd, unsigned int capsule_id);
struct json_object *api_action(struct context *ctx, struct client *client,
			       const char *buf, int channel_fd);
int send_json_response(struct client *client, struct json_object *jobj);
int reload_update_policies(struct context *ctx);
void handle_client_error(struct context *ctx, struct client *client);

struct json_object *build_json_error(const char *msg);
struct json_object *build_json_result(size_t size, ...);

struct pending_capsule *find_pending_by_client(struct context *ctx,
					       struct client *client);
struct pending_capsule *find_pending_by_capsule(struct context *ctx,
						struct capsule *capsule);
void delete_pending(struct context *ctx, struct pending_capsule *pending);
int get_pending_timeout(struct context *ctx);
void delete_expired_pendings(struct context *ctx);
struct pending_capsule *create_pending(struct context *ctx,
				       struct capsule *capsule,
				       struct client *client);
err_t send_creation_response(struct context *ctx, struct capsule *capsule,
			     bool success, const char *errmsg);

void free_capsule(struct capsule *capsule);

#endif
