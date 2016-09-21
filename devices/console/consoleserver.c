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
#include <pty.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <termios.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <linux/limits.h>

#include "child.h"
#include "console.h"
#include "policy.h"
#include "userland.h"
#include "xchan.h"
#include "readall.h"

#define BUFFER_SIZE		(240 * 80)
#define MAX_CONSOLE_CLIENTS	16

struct scrollback_buffer {
	char *buffer;
	size_t size;
};

struct console_client {
	int pts;
};

struct server_context {
	unsigned int capsule_id;
	uid_t uid;
	gid_t gid;
	pid_t pgid;
	int server_fd;
	struct pollfd *pollfds;
	nfds_t nfds;
	unsigned nr_clients;
	struct console_client *clients;
	struct winsize ws;
	int ctty;
	struct scrollback_buffer scrollback;
	int sigfd;
};

struct serve_arg {
	struct server_context *ctx;
	struct xchan *xchan;
};

enum {
	POLL_SERVERFD,
	POLL_EVENTFD,
	POLL_SIGNALFD,
	POLL_CLIENT,	/* must be the last one, in order to remove it from
			 * pollfds if stdin is closed */
};

static struct policies *policies;
static int console_fd;

char version[] = GIT_VERSION;

static int tty_get_size(int fd, struct winsize *winsize)
{
	return ioctl(fd, TIOCGWINSZ, winsize);
}

static int tty_set_as_ctty(int fd)
{
	return ioctl(fd, TIOCSCTTY, 0);
}

static int tty_unset_ctty(int fd)
{
	return ioctl(fd, TIOCNOTTY);
}

static int scrollback_buffer_create(struct scrollback_buffer *sb, size_t size)
{
	sb->buffer = (char *)calloc(1, size);
	if (sb->buffer == NULL) {
		warn("calloc");
		return -1;
	}

	sb->size = 0;

	return 0;
}

static int scrollback_buffer_push(struct scrollback_buffer *sb,
				  const void *data,
				  size_t n)
{
	size_t keep_size, overlap_size;
	char *p;

	p = (char *)data;
	if (n > BUFFER_SIZE) {
		p += (n - BUFFER_SIZE);
		n = BUFFER_SIZE;
	}

	if (n == BUFFER_SIZE) {
		memcpy(sb->buffer, p, BUFFER_SIZE);
		sb->size = BUFFER_SIZE;
	} else if (sb->size + n <= BUFFER_SIZE) {
		memcpy(sb->buffer + sb->size, p, n);
		sb->size += n;
	} else {
		overlap_size = n - (BUFFER_SIZE - sb->size);
		keep_size = sb->size - overlap_size;
		memmove(sb->buffer, sb->buffer + overlap_size, keep_size);
		memcpy(sb->buffer + keep_size, p, n);
		sb->size = BUFFER_SIZE;
	}

	return 0;
}

static int scrollback_buffer_send(struct scrollback_buffer *sb, int fd)
{
	err_t error;

	error = writeall(fd, sb->buffer, sb->size);
	if (error) {
		print_error(error, "writeall");
		return -1;
	}

	return 0;
}

static int handle_console_resize(struct xchan *xchan, struct server_context *ctx)
{
	struct winsize winsize;
	int pts, ret = -1;
	unsigned int i;

	for (i = 0; i < ctx->nr_clients; i++) {
		pts = ctx->clients[i].pts;

		if (ctx->ctty != pts)
			continue;

		if (tty_get_size(pts, &winsize) != 0)
			continue;

		if (winsize.ws_row != ctx->ws.ws_row ||
		    winsize.ws_col != ctx->ws.ws_col) {
			fprintf(stderr, "-- Resizing console to %dx%d\n", winsize.ws_row, winsize.ws_col);
			ret = xchan_console_resize(xchan, winsize);
		}

		ctx->ws = winsize;
		break;
	}

	return ret;
}

/* Handling SIGTERM from the signalfd handler allows remaining data to be
 * printed before exiting. */
static int handle_capsule_exit(struct server_context *UNUSED(ctx))
{
	printf("got SIGTERM\n");
	exit(EXIT_SUCCESS);
	return 0;
}

static int handle_signal(int sigfd, struct xchan *xchan, struct server_context *ctx)
{
	int signo, ret;

	signo = read_signal(sigfd);
	if (signo == -1)
		return -1;

	switch (signo) {
	case SIGWINCH:
		ret = handle_console_resize(xchan, ctx);
		break;

	case CHILD_DEATH_SIGNAL:
		ret = handle_capsule_exit(ctx);
		break;

	default:
		ret = -1;
	}

	return ret;
}

static int bind_console_socket(unsigned int capsule_id)
{
	char socket_path[128];
	snprintf(socket_path, sizeof(socket_path), CONSOLE_SOCKET ":%d", capsule_id);

	return bind_abstract_socket(SOCK_STREAM, socket_path, 10);
}

static int pty_create_raw(struct server_context *ctx, int *ptm, int *pts)
{
	struct termios tios = {0};
	int master, slave;
	int ret;
	int ctty;

	cfmakeraw(&tios);
	ret = openpty(&master, &slave, NULL, &tios, NULL);
	if (ret == -1) {
		warn("openpty");
		return -1;
	}

	ctty = ctx->ctty;

	/* Set this new pty as ctty. */
	if (ctty != -1 && tty_unset_ctty(ctty) != 0) {
		warn("cannot unset current ctty");
		return -1;
	}

	if (tty_set_as_ctty(slave) != 0) {
		warn("cannot set pty as controlling terminal");
		tty_set_as_ctty(ctty); // Restore previous ctty.
		close(master);
		close(slave);
		return -1;
	}

	ctx->ctty = slave;
	*ptm = master;
	*pts = slave;
	return 0;
}

static int dispatch_console_data(struct server_context *ctx, void *buf, size_t n)
{
	unsigned int i;

	/* Push data to the log buffer. */
	if (scrollback_buffer_push(&ctx->scrollback, buf, n) != 0)
		return -1;

	/* Send data to connected clients. */
	for (i = 0; i < ctx->nr_clients; i++) {
		if (write(ctx->pollfds[POLL_CLIENT + i].fd, buf, n) != (ssize_t)n)
			warn("write");
	}

	return 0;
}

static int release_ctty(struct server_context *ctx)
{
	int prev_pts;

	if (ctx->ctty == -1)
		return 0;

	if (tty_unset_ctty(ctx->ctty) != 0)
		warn("cannot unset ctty");

	ctx->ctty = -1;
	if (ctx->nr_clients == 0)
		return 0;

	prev_pts = ctx->clients[ctx->nr_clients-1].pts;
	if (tty_set_as_ctty(prev_pts) != 0)
		return -1;

	fprintf(stderr, "ctty released to %d\n", prev_pts);
	ctx->ctty = prev_pts;
	kill(getpid(), SIGWINCH);

	return 0;
}

static int close_client_console(struct server_context *ctx, int pts)
{
	unsigned int i;

	for (i = 0; i < ctx->nr_clients; i++) {

		if (ctx->clients[i].pts == pts) {
			ctx->clients[i] = ctx->clients[ctx->nr_clients - 1];
			ctx->nr_clients--;

			if (ctx->ctty == pts && release_ctty(ctx) != 0)
				warnx("cannot release ctty");
		}

		if (ctx->pollfds[POLL_CLIENT + i].fd == pts) {
			ctx->pollfds[POLL_CLIENT + i].fd = ctx->pollfds[POLL_CLIENT + ctx->nr_clients - 1].fd;
			ctx->nfds--;
			close(pts);
			return 0;
		}
	}

	return -1;
}

static int handle_console_client_connection(struct server_context *ctx)
{
	struct sockaddr_un addr;
	socklen_t len;
	int client;
	struct pcred cred;

	len = sizeof(addr);
retry:
	client = accept(ctx->server_fd, (struct sockaddr *)&addr, &len);
	if (client == -1) {
		if (errno == EINTR)
			goto retry;
		else {
			warn("%s: accept", __func__);
			return -1;
		}
	}

	if (get_peercred(client, &cred) != 0) {
		warnx("cannot get client credentials");
		close(client);
		return -1;
	}

	if (cred.uid != 0 && cred.uid != ctx->uid) {
		warnx("unauthorized connection from pid %d (uid: %d)\n",
		      cred.pid, cred.uid);
		close(client);
		return -1;
	}

	if (ctx->nr_clients >= MAX_CONSOLE_CLIENTS) {
		warnx("connection refused for pid %d: too many clients connected",
		      cred.pid);
		close(client);
		return -1;
	}

	int ptm, pts;
	if (pty_create_raw(ctx, &ptm, &pts) != 0) {
		warnx("cannot create a new pty");
		close(client);
		return -1;
	}

	if (send_fds(client, &ptm, 1) != 0) {
		warnx("cannot send pts to console client");
		close(pts);
		close(ptm);
		close(client);
		return -1;
	}
	close(client);
	close(ptm);

	if (scrollback_buffer_send(&ctx->scrollback, pts) != 0)
		warnx("cannot send scrollback buffer to client");

	struct console_client *clients;
	struct pollfd *pollfds;
	size_t size;

	size = (ctx->nfds+1) * sizeof(struct pollfd);
	pollfds = (struct pollfd *)realloc(ctx->pollfds, size);
	if (pollfds == NULL) {
		warn("realloc");
		close(pts);
		return -1;
	}

	size = (ctx->nr_clients + 1) * sizeof(struct console_client);
	clients = (struct console_client *)realloc(ctx->clients, size);
	if (clients == NULL) {
		warn("realloc");
		ctx->pollfds = pollfds;
		close(pts);
		return -1;
	}

	ctx->clients = clients;
	ctx->clients[ctx->nr_clients].pts = pts;
	ctx->nr_clients++;

	ctx->pollfds = pollfds;
	ctx->pollfds[ctx->nfds].fd = pts;
	ctx->pollfds[ctx->nfds].events = POLLIN;
	ctx->nfds++;

	return pts;
}

static struct serve_arg *init(struct child_arg *arg)
{
	struct serve_arg *serve_arg;
	struct server_context *ctx;
	struct policy *policy;
	struct xchan *xchan;
	err_t error;

	if (prctl(PR_SET_PDEATHSIG, CHILD_DEATH_SIGNAL) == -1) {
		warn("prctl");
		return NULL;
	}

	policy = get_policy_by_uuid(policies, &arg->policy_uuid);
	if (policy == NULL) {
		warnx("bad policy uuid");
		return NULL;
	}

	error = set_logfile(arg->capsule_id, "consoleserver.log");
	if (error) {
		print_error(error, "failed to set logfile");
		reset_saved_errno();
	}

	printf("[*] policy: %s\n", policy->name);
	printf("[*] uid=%d gid=%d\n", arg->uid, arg->gid);

	/* not required by child */
	close(console_fd);

	error = xchan_trusted_init(arg->capsule_id, XCHAN_CONSOLE, &xchan);
	if (error) {
		print_error(error, "failed to init xchan");
		return NULL;
	}

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL) {
		warn("malloc");
		return NULL;
	}

	/* Creates a new session id */
	ctx->pgid = setsid();
	if (ctx->pgid == -1) {
		warn("setsid");
		return NULL;
	}

	ctx->server_fd = bind_console_socket(arg->capsule_id);
	if (ctx->server_fd == -1) {
		warn("cannot bind socket for console server");
		return NULL;
	}

	error = create_signalfd(&ctx->sigfd, SIGWINCH, CHILD_DEATH_SIGNAL, -1);
	if (error) {
		print_error(error, "failed to create signalfd");
		return NULL;
	}

	if (setgid(arg->gid) != 0) {
		warn("setgid");
		return NULL;
	}

	if (setuid(arg->uid) != 0) {
		warn("setuid");
		return NULL;
	}

	ctx->uid = arg->uid;
	ctx->gid = arg->gid;

	/* parent process death signal is reset after setuid */
	if (prctl(PR_SET_PDEATHSIG, CHILD_DEATH_SIGNAL) == -1) {
		warn("prctl");
		return NULL;
	}

	if (scrollback_buffer_create(&ctx->scrollback, BUFFER_SIZE) != 0) {
		warn("cannot create scrollback buffer");
		return NULL;
	}

	ctx->ws.ws_row = 0;
	ctx->ws.ws_col = 0;
	ctx->ctty = -1;
	ctx->nr_clients = 0;
	ctx->clients = NULL;
	ctx->nfds = 3;
	ctx->pollfds = (struct pollfd *)malloc(ctx->nfds * sizeof(struct pollfd));
	if (ctx->pollfds == NULL) {
		warn("malloc");
		return NULL;
	}

	serve_arg = (struct serve_arg *)malloc(sizeof(*serve_arg));
	if (serve_arg == NULL) {
		warn("malloc");
		return NULL;
	}

	serve_arg->ctx = ctx;
	serve_arg->xchan = xchan;

	return serve_arg;
}

static void serve(struct serve_arg *arg)
{
	struct server_context *ctx;
	struct xchan *xchan;
	unsigned int i;
	char buf[4096];
	ssize_t size;
	err_t error;
	size_t n;

	xchan = arg->xchan;
	ctx = arg->ctx;

	ctx->pollfds[POLL_SERVERFD].fd = ctx->server_fd;
	ctx->pollfds[POLL_SERVERFD].events = POLLIN;

	ctx->pollfds[POLL_EVENTFD].fd = xchan->event_fd;
	ctx->pollfds[POLL_EVENTFD].events = POLLIN;

	ctx->pollfds[POLL_SIGNALFD].fd = ctx->sigfd;
	ctx->pollfds[POLL_SIGNALFD].events = POLLIN;

	while (1) {
		if (TEMP_FAILURE_RETRY(poll(ctx->pollfds, ctx->nfds, -1)) == -1)
			err(1, "poll");

		/* Incoming data from capsule. Must be processed before signals,
		 * otherwise SIGTERM is handled and console server exits before
		 * printing remaing data. */
		if (ctx->pollfds[POLL_EVENTFD].revents & POLLIN) {
			error = xchan_poll(xchan);
			if (error) {
				print_error(error, "xchan poll failed");
				break;
			}

			error = xchan_recv_nopoll(xchan, buf, sizeof(buf), &n);

			/* If capsule has exited, xchan_recv_nopoll() fails
			 * because of ioctl(CAPPSULE_IOC_XCHAN_NOTIFY); but some
			 * data may still remain in ring_r and must be printed.
			 * Call dispatch_console_data() before error
			 * handling. */
			if (n > 0)
				dispatch_console_data(ctx, buf, n);

			if (error) {
				print_error(error, "xchan_recv_nopoll failed");
				break;
			}
		}

		/* Incoming signals. */
		if (ctx->pollfds[POLL_SIGNALFD].revents & POLLIN)
			handle_signal(ctx->sigfd, xchan, ctx);

		/* Incoming data from clients. */
		for (i = 0; i < ctx->nr_clients; i++) {
			int pts = ctx->pollfds[POLL_CLIENT + i].fd;

			if (ctx->pollfds[POLL_CLIENT + i].revents & POLLHUP) {
				if (close_client_console(ctx, pts) != 0)
					errx(1, "cannot close client console");
			}
			else if (ctx->pollfds[POLL_CLIENT + i].revents & POLLIN) {
				size = read(pts, buf, sizeof(buf));
				if (size > 0) {
					error = xchan_sendall(xchan, buf, size);
					if (error) {
						print_error(error,
							    "failed to send packet");
						break;
					}
				} else if (size == 0) {
					/* don't poll stdin anymore if fd is closed */
					if (close_client_console(ctx, pts) != 0)
						errx(1, "cannot close client console");
				} else {
					if (errno != EINTR)
						err(1, "read(STDIN_FILENO)");
				}
			}
		}

		/* Incoming connections to console server. */
		if (ctx->pollfds[POLL_SERVERFD].revents & POLLIN)
			handle_console_client_connection(ctx);
	}

	free(arg);

	exit(EXIT_SUCCESS);
}

static void usage(char *filename)
{
	fprintf(stderr, "%s [option...]\n\n", filename);
	fprintf(stderr, "  -d, --debug <policies dir>\trun in foreground\n");
	fprintf(stderr, "  -v, --version\tdisplay the version number\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct device device;
	char *policies_path;
	int c, debug;
	err_t error;

	struct option long_options[] = {
		{ "debug", required_argument, NULL, 'd' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	init_children();
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	debug = 0;
	policies_path = POLICIES_PATH;

	while (1) {
		c = getopt_long(argc, argv, "d:v", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			debug = 1;
			policies_path = optarg;
			break;
		case 'v':
			display_version(argv[0], version, 1);
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	display_version(argv[0], version, 0);

	error = parse_configuration_files(policies_path, &policies);
	if (error) {
		print_error(error, "failed to parse configuration files in %s",
			    policies_path);
		exit(EXIT_FAILURE);
	}

	if (signal(SIGCHLD, sigchld_handler) == SIG_ERR)
		err(1, "signal");

	device.type = DEVICE_CONSOLE;
	device.policies_path = POLICIES_PATH;
	device.policies = &policies;
	device.init = init;
	device.serve = serve;
	device.prepare_child = NULL;
	device.child_created = NULL;
	device.cleanup_child = NULL;

	if (debug) {
		device.notif_fd = -1;
		debug_device(&device);
		exit(0);
	}

	console_fd = bind_abstract_socket(SOCK_STREAM, CONSOLE_SOCKET, 10);
	if (console_fd == -1)
		errx(1, "cannot bind socket \"" CONSOLE_SOCKET "\"");

	connect_to_monitor(&device.notif_fd);

	while (1) {
		handle_notif_msg(&device);
	}

	free_policies(policies);
	close(console_fd);
	close(device.notif_fd);

	return 0;
}
