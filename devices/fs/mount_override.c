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

#define _GNU_SOURCE 1
#include <err.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

#include "userland.h"

static typeof(mount) *real_mount;
static int hijacked;

/* unnecessary complicated because there's a trailing slash in CAPSULE_FS */
static int check_target(const char *target)
{
	size_t len;

	if (strncmp(target, CAPSULE_FS, sizeof(CAPSULE_FS)-2) != 0)
		return 0;

	/* Any directory under CAPSULE_FS is a valid target. It's a bit loose
	 * but required by nohv. */
	len = sizeof(CAPSULE_FS)-2;
	if (strlen(target) != len && target[len] != '/')
		return 0;

	return 1;
}

/* remove nosuid option of first mount call
 *
 * Since fusermount always adds "nosuid" to the mount options, setuid bit is
 * ignored otherwise. Target program is fsclient. */
int mount(const char *source,
	  const char *target,
	  const char *filesystemtype,
	  unsigned long mountflags,
	  const void *data)
{
	if (real_mount == NULL) {
		if (unsetenv("LD_PRELOAD") == -1)
			warn("unsetenv(\"LD_PRELOAD\")");

		real_mount = dlsym(RTLD_NEXT, "mount");
		if (real_mount == NULL)
			err(1, "dlsym");
	}

	/* fsclient calls fuse_main() which fork before executing fusermount or
	 * mount.
	 *
	 * If fsclient is compromised (eg: with ptrace), an attacker may call
	 * fusermount on a malicious fuse FS, in order to call a setuid binary
	 * if nosuid is unset.
	 * It cannot happen because fsclient runs with root privileges
	 * (otherwise LD_PRELOAD is ignored because fusermount and mount are
	 * setuid). */
	if (!hijacked && check_target(target)) {
		mountflags &= ~MS_NOSUID;
		hijacked = 1;
	}

	return real_mount(source, target, filesystemtype, mountflags, data);
}

// vim: noet:ts=8:
