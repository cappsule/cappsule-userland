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
#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <linux/if_tun.h>

#include "userland.h"
#include "xchan.h"
#include "net_common.h"

#define TUN_DEVICE	"/dev/net/tun"
#define TUN_INTERFACE	"tun-caps-"
#define STACK_SIZE	(MAX_SIZE + 1024 * 1024)

#define STR(s)	#s
#define XSTR(s)	STR(s)
#define SOCKFD_IOCTL(request, saddr)					\
	do {								\
		addr->sin_addr.s_addr = saddr;				\
		if (ioctl(sockfd, request, ifr) != 0) {			\
			warn("ioctl(" XSTR(request) ")");		\
			goto out;					\
		}							\
	} while (0)

struct child_params {
	struct xchan *xchan;
	int tunfd;
};

static unsigned char child_stack[STACK_SIZE];

static void writeall(int fd, const void *buf, size_t count)
{
	const unsigned char *p;
	ssize_t n;
	size_t i;

	p = buf;
	i = count;
	while (i > 0) {
		n = write(fd, p, i);
		if (n <= 0) {
			if (n == -1 && errno == EINTR)
				continue;
			err(1, "writeall");
		}
		i -= n;
		p += n;
	}
}

static int local_to_remote(void *params)
{
	struct xchan *xchan;
	char buf[MAX_SIZE];
	int size, tunfd;
	err_t error;

	xchan = ((struct child_params *)params)->xchan;
	tunfd = ((struct child_params *)params)->tunfd;

	while (1) {
		size = read(tunfd, buf, sizeof(buf));
		if (size == 0) {
			err(1, "tun closed");
		} else if (size == -1) {
			if (errno == EINTR)
				continue;
			err(1, "failed to recv data from tun");
		}

		error = xchan_sendall(xchan, &size, sizeof(size));
		if (error) {
			print_error(error, "failed to send packet size");
			exit(EXIT_FAILURE);
		}

		error = xchan_sendall(xchan, buf, size);
		if (error) {
			print_error(error, "failed to send packet");
			exit(EXIT_FAILURE);
		}
	}

	return 1;
}

static void remote_to_local(struct xchan *xchan, int tunfd)
{
	char buf[MAX_SIZE];
	unsigned int size;
	err_t error;

	while (1) {
		error = xchan_recvall(xchan, &size, sizeof(size));
		if (error) {
			print_error(error, "failed to receive packet size");
			exit(EXIT_FAILURE);
		}

		if (size > MAX_SIZE)
			errx(1, "invalid size (%d)", size);

		error = xchan_recvall(xchan, buf, size);
		if (error) {
			print_error(error, "failed to receive packet");
			exit(EXIT_FAILURE);
		}

		writeall(tunfd, buf, size);
	}
}

void network(struct xchan *xchan, int tunfd)
{
	struct child_params params;
	pid_t pid;
	int flags;

	flags = SIGCHLD;
	flags |= CLONE_FILES | CLONE_FS | CLONE_IO;
	flags |= CLONE_PARENT | CLONE_PTRACE | CLONE_THREAD;
	flags |= CLONE_SIGHAND | CLONE_SYSVSEM | CLONE_VM;

	params.xchan = xchan;
	params.tunfd = tunfd;
	pid = clone(local_to_remote, child_stack + STACK_SIZE, flags, &params);
	if (pid == -1)
		err(1, "clone");

	remote_to_local(xchan, tunfd);

	exit(0);
}

int setup_tun_ifconfig(struct ifreq *ifr, unsigned int id)
{
	struct sockaddr_in *addr;
	in_addr_t ip, gateway;
	int error, sockfd;

	error = -1;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		warn("socket");
		goto out;
	}

	addr = (struct sockaddr_in *)&ifr->ifr_addr;
	addr->sin_family = AF_INET;

	ip = capsule_ip_address(id);
	gateway = capsule_gw_address(id);

	SOCKFD_IOCTL(SIOCSIFADDR, ntohl(gateway));
	SOCKFD_IOCTL(SIOCSIFDSTADDR, ntohl(ip));
	SOCKFD_IOCTL(SIOCSIFNETMASK, inet_addr("255.255.255.255"));

	ifr->ifr_mtu = 3000;
	if (ioctl(sockfd, SIOCSIFMTU, ifr) != 0) {
		warn("ioctl(SIOCSIFMTU)");
		goto out;
	}

	ifr->ifr_flags = IFF_UP | IFF_RUNNING | IFF_POINTOPOINT;
	if (ioctl(sockfd, SIOCSIFFLAGS, ifr) != 0) {
		warn("ioctl(SIOCSIFFLAGS)");
		goto out;
	}

	error = 0;

out:
	close(sockfd);
	return error;
}

int create_tun(struct ifreq *ifr)
{
	int tunfd;

	tunfd = open(TUN_DEVICE, O_RDWR);
	if (tunfd == -1) {
		warn("open(\"" TUN_DEVICE "\")");
		return -1;
	}

	memset(ifr, 0, sizeof(*ifr));
	strncpy(ifr->ifr_name, TUN_INTERFACE "%d", IFNAMSIZ);
	ifr->ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;

	if (ioctl(tunfd, TUNSETIFF, (void *)ifr) < 0) {
		warn("ioctl(TUNSETIFF)");
		close(tunfd);
		return -1;
	}

	return tunfd;
}
