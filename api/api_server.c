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
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/signalfd.h>

#include <json-c/json.h>

#include "cuapi/common/kill_msg.h"
#include "cuapi/trusted/channel.h"

#include "devices.h"
#include "api.h"
#include "json.h"
#include "readall.h"
#include "userland.h"


static int build_kill_msg(char *buf, size_t bufsize, unsigned int capsule_id, kill_t reason)
{
	struct json_object *jobj, *val;
	const char *p;
	char msg[128];
	int ret;

	switch (reason) {
	case KILL_VMCALL_EXIT:
	case KILL_VMCALL_FATAL_SIGNAL:
		/* build an empty reason for normal exits */
		msg[0] = '\x00';
		break;
	default:
		snprintf(msg, sizeof(msg), KILL_MSG_FMT, kill_msg(reason));
		break;
	}

	ret = -1;

	jobj = json_object_new_object();
	if (jobj == NULL)
		goto out;

	val = json_object_new_string("exit");
	if (val == NULL)
		goto out;
	json_object_object_add(jobj, "event", val);

	val = json_object_new_int(capsule_id);
	if (val == NULL)
		goto out;
	json_object_object_add(jobj, "capsule_id", val);

	val = json_object_new_string(msg);
	if (val == NULL)
		goto out;
	json_object_object_add(jobj, "reason", val);

	p = json_object_to_json_string(jobj);
	if (p == NULL)
		goto out;

	strncpy(buf, p, bufsize-1);
	buf[bufsize-1] = '\x00';
	ret = 0;

out:
	if (jobj != NULL)
		json_object_put(jobj);

	return ret;
}

static struct client *find_client_by_socket(struct context *ctx, int c)
{
	struct client *client;

	for (client = ctx->clients; client != NULL; client = client->next) {
		if (client->c == c)
			return client;
	}

	return NULL;
}

static void delete_client(struct context *ctx, struct client *client)
{
	close(client->c);

	if (client->prev != NULL)
		client->prev->next = client->next;
	if (client->next != NULL)
		client->next->prev = client->prev;
	if (client == ctx->clients)
		ctx->clients = client->next;

	/* prefer NULL pointer dereference over use-after-free */
	client->prev = NULL;
	client->next = NULL;

	free(client);
}

static void unpoll_client_fd(struct context *ctx, int c)
{
	unsigned int i;

	for (i = 0; i < ctx->nfds; i++) {
		if (ctx->pollfds[i].fd == c) {
			ctx->pollfds[i].fd = ctx->pollfds[ctx->nfds-1].fd;
			ctx->nfds--;
			return;
		}
	}

	fprintf(stderr, "BUG: failed to remove fd %c from polling array\n", c);
}

static void delete_listener(struct context *ctx, struct event_listener *listener)
{
	if (listener->prev != NULL)
		listener->prev->next = listener->next;
	if (listener->next != NULL)
		listener->next->prev = listener->prev;
	if (listener == ctx->listeners)
		ctx->listeners = listener->next;

	listener->prev = listener->next = NULL;
	free(listener);
}

/**
 * Delete each capsule's listener and send the kill reason to each associated
 * client.
 */
static int delete_listeners_for_capsule(struct context *ctx,
					struct capsule *capsule)
{
	unsigned int capsule_id;
	kill_t reason;
	char buf[128];

	capsule_id = capsule->capsule_id;
	reason = capsule->exit_reason;

	if (build_kill_msg(buf, sizeof(buf), capsule_id, reason) != 0) {
		snprintf(buf, sizeof(buf),
			 "{\"event\": \"exit\", \"capsule_id\": %d, \"reason\": \"unknown\"}", capsule_id);
	}

	while (1) {
		struct event_listener *listener;
		err_t error;

		listener = find_listener_by_capsule(ctx, capsule_id);
		if (listener == NULL)
			break;

		error = send_json(listener->client->c, buf);
		if (error)
			print_error(error, "failed to send kill informations to client");

		delete_listener(ctx, listener);
	}

	return 0;
}

static int delete_capsule(struct context *ctx, struct capsule *capsule)
{
	if (capsule->prev != NULL)
		capsule->prev->next = capsule->next;

	if (capsule->next != NULL)
		capsule->next->prev = capsule->prev;

	if (capsule == ctx->capsules)
		ctx->capsules = capsule->next;

	capsule->prev = NULL;
	capsule->next = NULL;

	free_capsule(capsule);

	return 0;
}

static void delete_exited_capsule(struct context *ctx, struct capsule *capsule)
{
	struct pending_capsule *pending;
	char errmsg[128];

	/* A capsule may exit before the initialization of all the devices.
	 * Notify client and don't leave a dangling capsule pointer in a
	 * pending structure.
	 *
	 * Note there can't be any listeners if capsule isn't fully
	 * initialized. */
	pending = find_pending_by_capsule(ctx, capsule);
	if (pending != NULL) {
		snprintf(errmsg, sizeof(errmsg),
			 "capsule %d exited before device initialization",
			 capsule->capsule_id);
		send_creation_response(ctx, capsule, false, errmsg);
	} else {
		delete_listeners_for_capsule(ctx, capsule);
	}

	delete_capsule(ctx, capsule);
}

static void delete_exited_capsules(struct context *ctx)
{
	struct capsule *capsule, *next;

	for (capsule = ctx->capsules; capsule != NULL; capsule = next) {
		next = capsule->next;
		if (capsule_has_exited(capsule))
			delete_exited_capsule(ctx, capsule);
	}
}

int kill_capsule(int channel_fd, unsigned int capsule_id)
{
	int ret;

	ret = ioctl(channel_fd, CAPPSULE_IOC_KILL_CAPSULE, capsule_id);
	if (ret != 0)
		warn("ioctl(CAPPSULE_IOC_KILL_CAPSULE; %d) failed", capsule_id);

	return ret ? -1 : 0;
}

/**
 * Remove client's socket from the set of file descriptors, delete client from
 * clients list, and kill associated capsule.
 */
void handle_client_error(struct context *ctx, struct client *client)
{
	struct event_listener *listener;
	struct pending_capsule *pending;

	// Unregister any listener associated with this client.
	listener = find_listener_by_client(ctx, client);
	if (listener != NULL)
		delete_listener(ctx, listener);

	/* don't leave a dangling client pointer in a pending structure */
	pending = find_pending_by_client(ctx, client);
	if (pending != NULL)
		delete_pending(ctx, pending);

	unpoll_client_fd(ctx, client->c);
	delete_client(ctx, client);
}

static int handle_socket_event(struct context *ctx, int c)
{
	struct json_object *jobj;
	struct client *client;
	char buf[16384];
	err_t error;

	client = find_client_by_socket(ctx, c);
	if (client == NULL) {
		fprintf(stderr, "BUG: failed to find client (socket: %d)\n", c);
		unpoll_client_fd(ctx, c);
		return -1;
	}

	error = recv_json(c, buf, sizeof(buf));
	if (error) {
		if (error != ERROR_COMMON_CONNECTION_CLOSED)
			print_error(error, "failed to receive json request");
		handle_client_error(ctx, client);
		return -1;
	}

	jobj = api_action(ctx, client, buf, ctx->channel_fd);
	if (send_json_response(client, jobj) != 0) {
		handle_client_error(ctx, client);
		return -1;
	}

	return 0;
}

/**
 * Notify devices of the capsule exit and send a JSON message to each client
 * related to this capsule telling why the capsule has exited. Clients are then
 * removed, and the capsule is removed from context.
 */
static int handle_capsule_exit(struct context *ctx, unsigned int capsule_id,
			       kill_t reason)
{
	if (notify_devices_of_capsule_exit(capsule_id, ctx->notif) == -1)
		warnx("cannot notify devices of capsule exit");

	return capsule_set_exited(ctx, capsule_id, reason);
}

static struct client *create_client(struct context *ctx, int c)
{
	struct client *client;

	client = (struct client *)malloc(sizeof(*client));
	if (client == NULL) {
		warn("malloc");
		return NULL;
	}

	client->c = c;
	client->prev = NULL;

	if (ctx->clients == NULL) {
		client->next = NULL;
	} else {
		ctx->clients->prev = client;
		client->next = ctx->clients;
	}
	ctx->clients = client;

	return client;
}

/* TODO: don't allow flood of clients */
static int handle_new_client(struct context *ctx)
{
	struct sockaddr_un addr;
	struct pollfd *pollfds;
	struct client *client;
	socklen_t len;
	size_t size;
	int c, ret;

retry:
	len = sizeof(addr);
	c = accept(ctx->socket_fd, (struct sockaddr *)&addr, &len);
	if (c == -1) {
		if (errno != EINTR) {
			warn("%s: accept", __func__);
			return -1;
		} else {
			goto retry;
		}
	}

	client = create_client(ctx, c);
	if (client == NULL) {
		/* XXX: notify client of failure */
		close(c);
		return -1;
	}

	len = sizeof(struct ucred);
	ret = getsockopt(c, SOL_SOCKET, SO_PEERCRED, &client->ucred, &len);
	if (ret == -1) {
		/* XXX: notify client of failure */
		warn("getsockopt(SO_PEERCRED)");
		delete_client(ctx, client);
		return -1;
	}

	size = (ctx->nfds + 1) * sizeof(*pollfds);
	pollfds = (struct pollfd *)realloc(ctx->pollfds, size);
	if (pollfds == NULL) {
		/* XXX: notify client of failure */
		warn("realloc");
		delete_client(ctx, client);
		return -1;
	}

	ctx->pollfds = pollfds;
	ctx->pollfds[ctx->nfds].fd = c;
	ctx->pollfds[ctx->nfds].events = POLLIN;
	ctx->nfds++;

	return 0;
}

int reload_update_policies(struct context *ctx)
{
	struct cappsule_ioc_policies exec_policies;
	err_t error;
	int ret;

	printf("[*] reloading policies of API server\n");

	error = reload_policies(POLICIES_PATH, &ctx->policies);
	if (error) {
		print_error(error, "failed to reload policies");
		return -1;
	}

	if (notify_devices_of_policies_reload(ctx->notif) == -1) {
		fprintf(stderr, "cannot notify devices to reload policies\n");
		return -1;
	}

	error = build_exec_policies(ctx->policies, &exec_policies);
	if (error) {
		print_error(error, "failed to re-build exec policies");
		return -1;
	}

	ret = ioctl(ctx->channel_fd, CAPPSULE_IOC_SET_EXEC_POLICIES, &exec_policies);
	if (ret < 0) {
		fprintf(stderr, "failed to reload exec policies (%s)\n",
			strerror(errno));
		free(exec_policies.buf);
		return -1;
	}

	free(exec_policies.buf);

	return 0;
}

/**
 * SIGHUP tells the API server to reload the policies.
 */
static int handle_sighup(struct context *ctx)
{
	return reload_update_policies(ctx);
}

/**
 * The hypervisor writes on channel fd the reason and the id of each exited
 * capsule.
 */
static int handle_exits(struct context *ctx)
{
	struct capsule_event_kill event;
	unsigned int capsule_id;
	kill_t reason;
	int ret;

	while (1) {
		ret = read(ctx->channel_fd, &event, sizeof(event));
		if (ret == -1) {
			warn("failed to read exited capsule from channel fd");
			break;
		}

		if (ret == 0)
			break;

		capsule_id = event.capsule_id;
		reason = event.reason;
		ret = handle_capsule_exit(ctx, capsule_id, reason);
		if (ret != 0)
			break;
	}

	return ret;
}

static int handle_signal(struct context *ctx)
{
	struct signalfd_siginfo fdsi;
	int ret;

	if (readall(ctx->signal_fd, &fdsi, sizeof(fdsi)) != SUCCESS) {
		warn("failed to read signal info");
		return -1;
	}

	switch (fdsi.ssi_signo) {
	case SIGCHLD:
		print_exited_child();
		ctx->child_exited = true;
		ret = 0;
		break;

	case SIGHUP:
		ret = handle_sighup(ctx);
		break;

	default:
		fprintf(stderr, "BUG: unexpected signal %s\n",
			strsignal(fdsi.ssi_signo));
		ret = -1;
		break;
	}

	return ret;
}

/**
 * Receive message from each devices. If each device is ready, the capsule's id
 * is sent to the client.
 */
static err_t handle_device_event(struct context *ctx, int s)
{
	struct device_event event;
	struct capsule *capsule;
	const char *device_name;
	char buf[128];
	err_t error;
	static const char *device_names[] = {
		[DEVICE_CONSOLE] 	= "console",
		[DEVICE_FS] 		= "fs",
		[DEVICE_NET] 		= "net",
		[DEVICE_GUI]		= "gui",
	};

	error = recvall(s, &event, sizeof(event), 0);
	if (error)
		return error;

	capsule = find_capsule_by_id(ctx, event.capsule_id);
	if (capsule == NULL)
		return ERROR_CAPSULE_NOT_FOUND;

	if (event.type < 0 || event.type >= NR_DEVICES) {
		fprintf(stderr, "BUG: received event with invalid device type\n");
		return ERROR_MAX; /* XXX */
	}

	error = SUCCESS;
	device_name = device_names[event.type];

	switch (event.event) {
	case DEVICE_EVENT_DEVICE_READY:
	case DEVICE_EVENT_CREATE_IGNORED:
		capsule->devices_ready++;
		break;
	case DEVICE_EVENT_CREATE_FAILURE:
		fprintf(stderr, "[-] creation of \"%s\" device failed for capsule %d\n",
			device_name, event.capsule_id);
		capsule->devices_errors++;
		break;
	default:
		fprintf(stderr, "[-] unknown device notification (%d) received for capsule %d\n",
			event.event, event.capsule_id);
		break;
	}

	/* notify the client if devices initialization succeed or if an error
	 * occured */
	if (capsule_devices_error(capsule)) {
		snprintf(buf, sizeof(buf),
			 "creation of \"%s\" device failed for capsule %d",
			 device_name, capsule->capsule_id);
		error = send_creation_response(ctx, capsule, false, buf);
	} else if (capsule_devices_ready(ctx, capsule)) {
		error = send_creation_response(ctx, capsule, true, NULL);
	}

	return error;
}

static err_t api_server(int s, int channel_fd, int sfd,
		        struct policies *policies,
			struct devices_sockets *notif)
{
	int c, j, n, timeout_ms;
	struct pollfd *pollfds;
	struct context ctx;
	unsigned int i;
	err_t error = SUCCESS;

	ctx.signal_fd = sfd;
	ctx.channel_fd = channel_fd;
	ctx.socket_fd = s;

	/*
	 * The server needs to poll on:
	 *     - its listening server socket
	 *     - the signal fd
	 *     - channel fd
	 *     - each connected device server
	 * Clients sockets are appended once a connection is established.
	 */
	ctx.nfds = 3 + notif->nr_devices;
	pollfds = (struct pollfd *)malloc(ctx.nfds * sizeof(*pollfds));
	if (pollfds == NULL) {
		error = save_errno(ERROR_LIBC_MALLOC);
		return error;
	}

	pollfds[0].fd = ctx.socket_fd;
	pollfds[0].events = POLLIN;

	pollfds[1].fd = ctx.signal_fd;
	pollfds[1].events = POLLIN;

	pollfds[2].fd = ctx.channel_fd;
	pollfds[2].events = POLLIN;

	for (i = 0; i < notif->nr_devices; i++) {
		pollfds[3 + i].fd = notif->fds[i];
		pollfds[3 + i].events = POLLIN;
	}

	ctx.child_exited = false;
	ctx.notif = notif;
	ctx.policies = policies;
	ctx.listeners = NULL;
	ctx.clients = NULL;
	ctx.capsules = NULL;
	ctx.pollfds = pollfds;
	ctx.pending = NULL;

	while (true) {
		timeout_ms = get_pending_timeout(&ctx);
		n = TEMP_FAILURE_RETRY(poll(ctx.pollfds, ctx.nfds, timeout_ms));
		if (n == -1) {
			warn("%s: poll", __func__);
			continue;
		} else if (n == 0) {
			delete_expired_pendings(&ctx);
			continue;
		}

		for (i = 0, j = 0; j < n && i < ctx.nfds; i++) {
			if (ctx.pollfds[i].revents == 0)
				continue;

			if (i == 0) {
				handle_new_client(&ctx);
			} else if (i == 1) {
				handle_signal(&ctx);
			} else if (i == 2) {
				handle_exits(&ctx);
			} else if (i < notif->nr_devices + 3) {
				c = ctx.pollfds[i].fd;
				handle_device_event(&ctx, c);
			} else {
				c = ctx.pollfds[i].fd;
				handle_socket_event(&ctx, c);
			}

			j++;
		}

		// Remove any exited capsules.
		delete_exited_capsules(&ctx);

		// Return if anything went wrong with a device server.
		if (ctx.child_exited)
			break;
	}

	free(ctx.pollfds);
	return error;
}

/**
 * Run the API server. Never returns except if an error occurs during the
 * initialisation, or when a device exits.
 */
int run_api_server(int channel_fd, struct policies *policies,
		   struct devices_sockets *notif)
{
	int s, sfd, status;
	err_t error;

	s = -1;
	sfd = -1;
	error = SUCCESS;
	status = EXIT_SUCCESS;

	s = bind_abstract_socket(SOCK_STREAM, API_SOCKET, MAX_CAPSULE);
	if (s == -1) {
		error = save_errno_msg(ERROR_COMMON_BIND_SOCKET, API_SOCKET);
		goto error;
	}

	error = create_signalfd(&sfd, SIGCHLD, SIGHUP, -1);
	if (error)
		goto error;

	error = status_update(DAEMON_STATUS_READY);
	if (error)
		goto error;

	error = api_server(s, channel_fd, sfd, policies, notif);

error:
	if (error) {
		print_error(error, "failed to run api server");
		status = EXIT_FAILURE;
	}

	close(sfd);
	close(s);

	return status;
}
