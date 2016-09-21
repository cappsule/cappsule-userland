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
#include <stdio.h>
#include <unistd.h>

#include "userland.h"

#define EMPTY_CHROOT	"/proc/self/fdinfo"


int chroot_to_empty(void)
{
	if (chroot(EMPTY_CHROOT) != 0) {
		warn("can't chroot to \"" EMPTY_CHROOT "\"");
		return -1;
	}

	if (chdir("/") != 0) {
		warn("failed to chdir to / after chroot");
		return -1;
	}

	return 0;
}

int drop_uid(uid_t uid, gid_t gid)
{
	int ret = 0;

	if (setresgid(gid, gid, gid) != 0) {
		warn("setresgid(%d, %d, %d)", gid, gid, gid);
		ret = -1;
	}

	if (setresuid(uid, uid, uid) != 0) {
		warn("setresuid(%d, %d, %d)", uid, uid, uid);
		ret = -1;
	}

	return ret;
}

int drop_uid_from_str(char *userspec)
{
	uid_t uid;
	gid_t gid;

	if (userspec == NULL || sscanf(userspec, "%d:%d", &uid, &gid) != 2) {
		warnx("failed to scan \"%s\" for uid and gid", userspec);
		return -1;
	}

	return drop_uid(uid, gid);
}
