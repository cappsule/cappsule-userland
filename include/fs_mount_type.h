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

#ifndef FS_MOUNT_TYPE_H
#define FS_MOUNT_TYPE_H

#include <string.h>

enum fs_mount_type {
	FS_MOUNT_TYPE_INVALID = -1,
	FS_MOUNT_TYPE_OVERLAY = 0,
	FS_MOUNT_TYPE_AUFS,
	FS_MOUNT_TYPE_DIRECT_ACCESS,
	FS_MOUNT_TYPE_MAX,
};

static inline const char *mount_type_to_name(enum fs_mount_type type)
{
	switch (type) {
	case FS_MOUNT_TYPE_OVERLAY:		return "overlay";
	case FS_MOUNT_TYPE_AUFS:		return "aufs";
	case FS_MOUNT_TYPE_DIRECT_ACCESS:	return "direct";
	default: 				return "invalid";
	}
}

static inline enum fs_mount_type mount_type_from_name(const char *name)
{
	static const char *mount_type_names[FS_MOUNT_TYPE_MAX] = {
		[FS_MOUNT_TYPE_OVERLAY]		= "overlay",
		[FS_MOUNT_TYPE_AUFS]		= "aufs",
		[FS_MOUNT_TYPE_DIRECT_ACCESS] 	= "direct",
	};

	unsigned int i;
	for (i = 0; i < FS_MOUNT_TYPE_MAX; i++) {
		if (strcmp(name, mount_type_names[i]) == 0)
			return i;
	}

	return FS_MOUNT_TYPE_INVALID;
}

#endif /* FS_MOUNT_TYPE_H */
