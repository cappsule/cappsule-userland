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
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <linux/limits.h>

#include "cuapi/log.h"
#include "cuapi/trusted/channel.h"
#include "userland.h"

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC	1000000000L
#endif

#define FD_HV	0
#define FD_TG	1
#define FD_CPSL	2

#define get_fd_hv()			FDS[FD_HV]
#define get_fd_tg()			FDS[FD_TG]
#define get_fd_cpsl(id) 		FDS[2 + (id)]
#define get_fd_cpsl_dmesg(id)		FDS[2 + (id) * 2]
#define set_fd_hv(fd)			do { FDS[FD_HV] = fd; } while (0)
#define set_fd_tg(fd)			do { FDS[FD_TG] = fd; } while (0)
#define set_fd_cpsl(id, fd)		do { FDS[2 + (id)] = fd; } while (0)
#define set_fd_cpsl_dmesg(id, fd)	do { FDS[2 + (id) * 2] = fd; } while (0)

static int FDS[2 + MAX_CAPSULE * 2];


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

static void close_cpsl_fds(unsigned short id)
{
	close(get_fd_cpsl(id));
	set_fd_cpsl(id, -1);
	close(get_fd_cpsl_dmesg(id));
	set_fd_cpsl_dmesg(id, -1);
}

static void open_cpsl_fds(unsigned int id)
{
	err_t error;
	int fd;

	if (get_fd_cpsl(id) != -1) {
		warnx("fd log of capsule %d isn't closed", id);
		close_cpsl_fds(id);
	}

	error = open_log_file(id, "capsule.log", &fd);
	if (error) {
		print_error(error, "failed to create logfile");
		exit(EXIT_FAILURE);
	}

	set_fd_cpsl(id, fd);

	error = open_log_file(id, "dmesg.log", &fd);
	if (error) {
		print_error(error, "failed to create logfile");
		exit(EXIT_FAILURE);
	}

	set_fd_cpsl_dmesg(id, fd);
}

static void read_log_entry(int devfd, int debug)
{
	char buf[LOG_LINE_MAX + 128], *p;
	struct log_entry entry;
	int cpsl_closed, fd, n;
	unsigned short id;

	n = read(devfd, &entry, sizeof(entry));
	if (n == -1) {
		if (errno == EAGAIN) {
			warnx("read: EAGAIN\n");
			return;
		} else {
			err(1, "read");
		}
	}

	if ((size_t)n < sizeof(entry.header))
		errx(1, "read: invalid size %d", n);

	if (debug) {
		/* remove trailing line returns from capsule dmesg entry */
		if (entry.header.level == CPSL_DMESG) {
			n = strlen(entry.buffer);
			while (n > 0 && entry.buffer[n-1] == '\n')
				entry.buffer[--n] = '\x00';
		}

		printf("[%c] %d %s\n",
		       (entry.header.facility == LOG_HV) ? 'h' :
		       (entry.header.facility == LOG_CPSL) ? 'c' :
		       't',
		       entry.header.id,
		       entry.buffer);
		return;
	}

	fd = -1;
	cpsl_closed = 0;
	p = buf;
	n = snprintf(buf, sizeof(buf)-1, "[%f] %s\n",
		(float)entry.header.timestamp / NSEC_PER_SEC,
		     entry.buffer);
	if (n < 0 || n > (int)sizeof(buf)-1)
		n = sizeof(buf)-1;

	switch (entry.header.facility) {
	case LOG_HV:
		fd = get_fd_hv();
		break;

	case LOG_TG:
		fd = get_fd_tg();
		break;

	case LOG_CPSL:
		id = entry.header.id;

		/* XXX: this is isn't reliable */
		if (strcmp(entry.buffer, "process encapsulated") == 0)
			open_cpsl_fds(id);
		else if (strcmp(entry.buffer, "kill cappsule") == 0)
			cpsl_closed = 1;

		if (entry.header.level == CPSL_DMESG) {
			fd = get_fd_cpsl_dmesg(id);
			p = entry.buffer;
			n = entry.header.size;
			/* remove trailing null byte */
			if (n > 0)
				n--;
		} else {
			fd = get_fd_cpsl(id);
		}
		break;
	}

	if (fd == -1)
		errx(1, "logfile not open");

	writeall(fd, p, n);

	if (cpsl_closed)
		close_cpsl_fds(id);
}

static void usage(char *filename)
{
	printf("%s [option...]\n\n", filename);
	printf("  -d, --debug\tdisplay log entries to stdout\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct pollfd fds;
	int c, debug, fd;
	struct option long_options[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ NULL, 0, NULL, 0 }
	};

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	debug = 0;
	while (1) {
		c = getopt_long(argc, argv, "d", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			debug = 1;
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1)
		err(1, "prctl");

	if (!debug) {
		/* XXX: logrotate */

		memset(FDS, -1, sizeof(FDS));

		fd = creat(LOG_DIR "hv.log", S_IRUSR | S_IWUSR);
		if (fd == -1)
			err(1, "can't create " LOG_DIR "hv.log");

		set_fd_hv(fd);

		fd = creat(LOG_DIR "tg.log", S_IRUSR | S_IWUSR);
		if (fd == -1)
			err(1, "can't create " LOG_DIR "tg.log");

		set_fd_tg(fd);
	}

	fd = open("/dev/" LOG_DEVICE, O_RDONLY);
	if (fd == -1)
		err(1, "can't open " LOG_DEVICE);

	fds.fd = fd;
	fds.events = POLLIN;

	while (1) {
		if (TEMP_FAILURE_RETRY(poll(&fds, 1, -1)) == -1)
			err(1, "poll");

		if (fds.revents != POLLIN)
			errx(1, "error on poll result events");

		read_log_entry(fd, debug);
	}

	close(fd);

	close(get_fd_hv());
	close(get_fd_tg());

	return 0;
}

// vim: noet:ts=8:
