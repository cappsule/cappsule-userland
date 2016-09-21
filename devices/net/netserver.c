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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <getopt.h>
#include <net/if.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <linux/if_tun.h>
#include <linux/limits.h>

#include "policy.h"
#include "userland.h"
#include "child.h"
#include "xchan.h"
#include "net_common.h"
#include "net_policy.h"
#include "uuid.h"

struct net_cb_arg {
	int tunfd;
	char *ifrn_name;
};

struct serve_arg {
	struct xchan *xchan;
	int tunfd;
};

static struct policies *policies;

char version[] = GIT_VERSION;


static struct serve_arg *init(struct child_arg *arg)
{
	struct net_cb_arg *net_cb_arg;
	struct serve_arg *serve_arg;
	struct policy *policy;
	struct xchan *xchan;
	err_t error;

	if (prctl(PR_SET_PDEATHSIG, CHILD_DEATH_SIGNAL) == -1) {
		warn("prctl");
		return NULL;
	}

	policy = get_policy_by_uuid(policies, &arg->policy_uuid);
	if (policy == NULL) {
		fprintf(stderr, "bad policy uuid\n");
		return NULL;
	}

	error = set_logfile(arg->capsule_id, "netserver.log");
	if (error) {
		print_error(error, "failed to set logfile");
		reset_saved_errno();
	}

	printf("[*] policy: %s\n", policy->name);
	printf("[*] uid=%d gid=%d\n", arg->uid, arg->gid);

	error = xchan_trusted_init(arg->capsule_id, XCHAN_NET, &xchan);
	if (error) {
		print_error(error, "failed to init xchan");
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

	/* parent process death signal is reset after setuid */
	if (prctl(PR_SET_PDEATHSIG, CHILD_DEATH_SIGNAL) == -1) {
		warn("prctl");
		return NULL;
	}

	error = xchan_accept(xchan);
	if (error) {
		print_error(error, "failed to accept net client");
		return NULL;
	}

	error = xchan_sendall(xchan, &arg->capsule_id, sizeof(arg->capsule_id));
	if (error) {
		print_error(error, "failed to send capsule id");
		return NULL;
	}

	serve_arg = (struct serve_arg *)malloc(sizeof(*serve_arg));
	if (serve_arg == NULL) {
		warn("malloc");
		return NULL;
	}

	net_cb_arg = (struct net_cb_arg *)arg->arg;
	serve_arg->xchan = xchan;
	serve_arg->tunfd = net_cb_arg->tunfd;

	return serve_arg;
}

static void serve(struct serve_arg *arg)
{
	network(arg->xchan, arg->tunfd);
	free(arg);
	exit(EXIT_SUCCESS);
}

/* create tun fd */
static int prepare_net(struct child_arg *arg)
{
	struct net_cb_arg *net_cb_arg;
	struct policy *policy;
	struct ifreq ifr;
	int tunfd;
	char *p;

	policy = get_policy_by_uuid(policies, &arg->policy_uuid);
	if (policy == NULL) {
		fprintf(stderr, "bad policy uuid\n");
		return -1;
	}

	tunfd = create_tun(&ifr);
	if (tunfd == -1)
		return -1;

	if (set_tun_network_policy(tunfd, policy) != 0)
		goto fail;

	if (setup_tun_ifconfig(&ifr, arg->capsule_id) != 0)
		goto fail;

	if (ioctl(tunfd, TUNGETIFF, &ifr) == -1) {
		warn("ioctl(TUNGETIFF)");
		goto fail;
	}

	net_cb_arg = (struct net_cb_arg *)malloc(sizeof(*net_cb_arg));
	if (net_cb_arg == NULL) {
		warn("malloc");
		goto fail;
	}

	p = strdup(ifr.ifr_name);
	if (p == NULL) {
		free(net_cb_arg);
		warn("strdup");
		goto fail;
	}

	arg->arg = net_cb_arg;
	net_cb_arg->tunfd = tunfd;
	net_cb_arg->ifrn_name = p;

	return 0;

fail:
	close(tunfd);
	return -1;
}

/* close tun fd, which was passed to child */
static void child_created(struct child_arg *arg)
{
	struct net_cb_arg *net_cb_arg;

	net_cb_arg = (struct net_cb_arg *)arg->arg;
	close(net_cb_arg->tunfd);
}

/* remove firewall rules */
static void cleanup_net(struct child_arg *arg)
{
	struct net_cb_arg *net_cb_arg;

	net_cb_arg = (struct net_cb_arg *)arg->arg;
	cleanup_interface_policy(net_cb_arg->ifrn_name);
	free(net_cb_arg->ifrn_name);
	free(net_cb_arg);
}

static void usage(char *filename)
{
	fprintf(stderr, "%s [option...]\n\n", filename);
	fprintf(stderr, "  -n, --no-monitor <policies dir>\trun without monitor\n");
	fprintf(stderr, "  -v, --version\t\t\tdisplay the version number\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	struct device device;
	char *policies_path;
	int c, nomonitor;
	err_t error;

	struct option long_options[] = {
		{ "no-monitor", required_argument, NULL, 'n' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	init_children();
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	nomonitor = 0;
	policies_path = POLICIES_PATH;

	while (1) {
		c = getopt_long(argc, argv, "n:v", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'n':
			nomonitor = 1;
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
		err(EXIT_FAILURE, "signal");

	device.type = DEVICE_NET;
	device.policies_path = policies_path;
	device.policies = &policies;
	device.init = init;
	device.serve = serve;
	device.prepare_child = prepare_net;
	device.child_created = child_created;
	device.cleanup_child = cleanup_net;

	if (nomonitor) {
		device.notif_fd = -1;
		debug_device(&device);
		exit(EXIT_SUCCESS);
	}

	connect_to_monitor(&device.notif_fd);

	while (1) {
		handle_notif_msg(&device);
	}

	free_policies(policies);
	close(device.notif_fd);

	return EXIT_SUCCESS;
}
