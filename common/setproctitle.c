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
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

#include "userland.h"


/* Fix __progname, otherwise message displayed by err() family of functions may
 * be invalid.
 *
 * http://www.gnu.org/software/libc/manual/html_node/Error-Messages.html#Error-Messages */
static int fix_progname(char *argv0)
{
	char *p;

	p = strrchr(argv0, '/');
	if (p == NULL)
		p = strdup(argv0);
	else
		p = strdup(p + 1);

	if (p == NULL) {
		warn("strdup");
		return -1;
	}

	program_invocation_short_name =	p;

	return 0;
}

int setup_fake_name(int argc, char *argv[], char *fake_name)
{
	unsigned long arg_end, arg_start;
	int ret;

	arg_start = (unsigned long)fake_name;
	arg_end = arg_start + strlen(fake_name) + 1;

	if (prctl(PR_SET_MM, PR_SET_MM_ARG_START, arg_start, 0, 0) != 0) {
		warn("prctl(PR_SET_MM_ARG_START)");
		return -1;
	}

	if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, arg_end, 0, 0) != 0) {
		warn("prctl(PR_SET_MM_ARG_END)");
		return -1;
	}

	ret = 0;
	if (argc > 1 && argv[0] != NULL)
		ret = fix_progname(argv[0]);

	return ret;
}

/*
 * From lxc/utils.c.
 *
 * Sets the process title to the specified title. Note:
 *   1. this function requires root to succeed
 *   2. it clears /proc/self/environ
 *   3. it may not succed (e.g. if title is longer than /proc/self/environ +
 *      the original title)
 */
static int setproctitle(const char *title)
{
	unsigned long arg_start, arg_end, env_start, env_end;
	char buf[2048], *tmp;
	unsigned int len;
	int i, ret;
	FILE *fp;

	fp = fopen("/proc/self/stat", "r");
	if (fp == NULL) {
		warn("%s: failed to open \"/proc/self/stat\"", __func__);
		return -1;
	}

	tmp = fgets(buf, sizeof(buf), fp);
	fclose(fp);

	if (tmp == NULL) {
		warnx("%s: failed to read \"/proc/self/stat\"", __func__);
		return -1;
	}

	/* Skip the first 47 fields, column 48-51 are ARG_START and
	 * ARG_END. */
	tmp = strchr(buf, ' ');
	for (i = 0; i < 46; i++) {
		if (tmp == NULL)
			return -1;
		tmp = strchr(tmp + 1, ' ');
	}

	if (tmp == NULL) {
		warnx("%s: failed to parse \"/proc/self/stat\"", __func__);
		return -1;
	}

	i = sscanf(tmp, "%lu %lu %lu %lu", &arg_start, &arg_end, &env_start, &env_end);
	if (i != 4) {
		warnx("%s: failed to parse \"/proc/self/stat\"", __func__);
		return -1;
	}

	/* Include the null byte here, because in the calculations below we
	 * want to have room for it. */
	len = strlen(title) + 1;

	/* We're truncating the environment, so we should use at most the
	 * length of the argument + environment for the title. */
	if (len > env_end - arg_start) {
		arg_end = env_end;
		len = env_end - arg_start;
	} else {
		/* Only truncate the environment if we're actually going to
		 * overwrite part of it. */
		if (len >= arg_end - arg_start) {
			env_start = env_end;
		}

		arg_end = arg_start + len;

		/* check overflow */
		if (arg_end < len || arg_end < arg_start) {
			return -1;
		}

	}

	strcpy((char *)arg_start, title);

	ret = 0;
	ret |= prctl(PR_SET_MM, PR_SET_MM_ARG_START, arg_start, 0, 0);
	ret |= prctl(PR_SET_MM, PR_SET_MM_ARG_END, arg_end, 0, 0);
	ret |= prctl(PR_SET_MM, PR_SET_MM_ENV_START, env_start, 0, 0);
	ret |= prctl(PR_SET_MM, PR_SET_MM_ENV_END, env_end, 0, 0);
	if (ret == -1)
		warn("%s: prctl failed", __func__);

	return ret;
}

void addtoproctitle(const char *title)
{
	char buf[2048];
	size_t i, size;
	int fd;

	fd = open("/proc/self/cmdline", O_RDONLY);
	if (fd == -1) {
		warn("%s: failed to open \"/proc/self/cmdline\"", __func__);
		return;
	}

	size = read(fd, buf, sizeof(buf));
	close(fd);

	if (size <= 0) {
		warn("%s: failed read \"/proc/self/cmdline\"", __func__);
		return;
	}

	for (i = 0; i < size; i++) {
		if (buf[i] == '\x00')
			buf[i] = ' ';
	}

	strncpy(buf + size, title, sizeof(buf) - size);
	buf[sizeof(buf) - 1] = '\x00';

	setproctitle(buf);
}
