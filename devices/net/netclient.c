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
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/route.h>
#include <linux/if_tun.h>

#include "device_client.h"
#include "net_common.h"
#include "userland.h"
#include "xchan.h"

#define XCHAN_DEVICE	"/dev/" GUEST_XCHAN_DEVICE_NAME


static inline void fill_sockaddr(struct sockaddr *sockaddr, unsigned long s_addr)
{
	struct sockaddr_in *in;

	in = (struct sockaddr_in *)sockaddr;
	in->sin_family = AF_INET;
	in->sin_addr.s_addr = s_addr;
}

/* route add default gw 10.0.0.1 dev eth1 */
static int setup_routes(int sockfd, struct ifreq *ifr, __be32 gateway)
{
	struct rtentry route;

	if (ioctl(sockfd, SIOCGIFFLAGS, ifr) != 0) {
		warn("ioctl(SIOCGIFFLAGS)");
		return -1;
	}

	ifr->ifr_flags = IFF_UP | IFF_RUNNING | IFF_POINTOPOINT/* | IFF_MULTICAST*/;
	if (ioctl(sockfd, SIOCSIFFLAGS, ifr) != 0) {
		warn("ioctl(SIOCSIFFLAGS)");
		return -1;
	}

	memset(&route, 0, sizeof(route));

	fill_sockaddr(&route.rt_dst, INADDR_ANY);
	fill_sockaddr(&route.rt_genmask, INADDR_ANY);
	fill_sockaddr(&route.rt_gateway, gateway);

	route.rt_flags = RTF_UP | RTF_GATEWAY;
	route.rt_metric = 0;
	route.rt_dev = ifr->ifr_name;

	if (ioctl(sockfd, SIOCADDRT, &route) != 0) {
		warn("ioctl(SIOCADDRT)");
		return -1;
	}

	return 0;
}

static int ifconfig(int sockfd, struct ifreq *ifr, __be32 ip, __be32 netmask)
{
	struct sockaddr_in *addr;

	addr = (struct sockaddr_in *)&ifr->ifr_addr;

	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = ip;
	if (ioctl(sockfd, SIOCSIFADDR, ifr) == -1) {
		warn("ioctl(SIOCSIFADDR)");
		return -1;
	}

	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = netmask;
	if (ioctl(sockfd, SIOCSIFNETMASK, ifr) == -1) {
		warn("ioctl(SIOCSIFNETMASK)");
		return -1;
	}

	return 0;
}

static int create_tun_interface(unsigned int capsule_id)
{
	__be32 ip, gateway;
	int sockfd, tunfd;
	struct ifreq ifr;

	tunfd = create_tun(&ifr);
	if (tunfd == -1)
		return -1;

	/* ifconfig eth1 10.0.0.xx netmask 255.255.255.0 */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		warn("socket");
		return -1;
	}

	/* ip = inet_addr("10.0.0.xx") */
	/* nm = inet_addr("255.255.255.0") */
	ip = capsule_ip_address(capsule_id);
	if (ifconfig(sockfd, &ifr, ntohl(ip), 0x00ffffff) != 0) {
		close(sockfd);
		return -1;
	}

	ifr.ifr_mtu = 3000;
	if (ioctl(sockfd, SIOCSIFMTU, &ifr) == -1) {
		warn("ioctl(SIOCSIFMTU)");
		close(sockfd);
		return -1;
	}

	gateway = capsule_gw_address(capsule_id);
	if (setup_routes(sockfd, &ifr, ntohl(gateway)) != 0) {
		close(sockfd);
		return -1;
	}

	close(sockfd);
	return tunfd;
}

static int ifup_loopback(void)
{
	struct ifreq ifr;
	int sockfd;
	__be32 ip;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		warn("socket");
		return -1;
	}

	strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
	ifr.ifr_flags = IFF_UP | IFF_RUNNING;

	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) != 0) {
		warn("ioctl(SIOCSIFFLAGS)");
		return -1;
	}

	ip = htonl(INADDR_LOOPBACK);
	if (ifconfig(sockfd, &ifr, ip, 0x000000ff) != 0) {
		close(sockfd);
		return -1;
	}

	close(sockfd);

	return 0;
}

/* XXX: debug: remove me */
static void debug_reopen_pty(void)
{
	struct stat st;
	int fd, ret;

	while (1) {
		ret = stat(GUEST_CONSOLE_DEVICE, &st);
		if (ret != -1)
			break;
		usleep(100000);
	}

	fd = open(GUEST_CONSOLE_DEVICE, O_WRONLY, 0);
	if (fd == -1)
		err(1, "open(console)");

	if (dup2(fd, STDOUT_FILENO) < 0)
		err(1, "dup2");

	if (dup2(fd, STDERR_FILENO) < 0)
		err(1, "dup2");

	if (close(fd) < 0)
		err(1, "close");
}

static unsigned int get_capsule_id(struct xchan *xchan)
{
	unsigned int capsule_id;
	err_t error;
	size_t size;

	error = xchan_recv(xchan, &capsule_id, sizeof(capsule_id), &size);
	if (error) {
		print_error(error, "failed to receive capsule id");
		exit(EXIT_FAILURE);
	}

	if (size != sizeof(capsule_id))
		errx(1, "failed to receive capsule id");

	return capsule_id;
}

static void usage(char *filename)
{
	fprintf(stderr, "%s [option...]\n\n", filename);
	fprintf(stderr, "  -n, --no-hv\t\t\trun without hypervisor\n");
	fprintf(stderr, "  -p, --pipe\t\t\tdevice ready file descriptor\n");
	fprintf(stderr, "  -u, --userspec uid:gid\tspecify user and group to use\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int c, nohv, pipe_device_ready_w, tunfd;
	unsigned int capsule_id;
	struct xchan *xchan;
	char *userspec;
	err_t error;

	struct option long_options[] = {
		{ "no-hv", no_argument, NULL, 'n' },
		{ "pipe", required_argument, NULL, 'p' },
		{ "userspec", required_argument, NULL, 'u' },
		{ NULL, 0, NULL, 0 }
	};

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	userspec = NULL;
	nohv = 0;
	pipe_device_ready_w = -1;

	while (1) {
		c = getopt_long(argc, argv, "np:u:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'n':
			nohv = 1;
			break;
		case 'p':
			pipe_device_ready_w = atoi(optarg);
			break;
		case 'u':
			userspec = optarg;
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	if (unshare(CLONE_NEWNET) != 0) {
		warn("failed to unshare network namespace");
		exit(EXIT_FAILURE);
	}

	if (!nohv)
		debug_reopen_pty();

	error = xchan_capsule_init(XCHAN_NET, &xchan);
	if (error) {
		print_error(error, "failed to init xchan");
		exit(EXIT_FAILURE);
	}

	capsule_id = get_capsule_id(xchan);

	if (ifup_loopback() != 0) {
		warnx("failed to ifup lo");
		exit(EXIT_FAILURE);
	}

	tunfd = create_tun_interface(capsule_id);
	if (tunfd == -1) {
		warnx("failed to create tun interface");
		exit(EXIT_FAILURE);
	}

	/* /proc may not be mounted */
	//if (chroot_to_empty() != 0)
	//	exit(EXIT_FAILURE);

	if (userspec != NULL)
		drop_uid_from_str(userspec);

	if (client_ready(pipe_device_ready_w) != 0)
		exit(EXIT_FAILURE);

	network(xchan, tunfd);

	return 0;
}
