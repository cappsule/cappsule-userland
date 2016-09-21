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

#ifndef _PROTOCOL_H
#define _PROTOCOL_H 1

#include <dirent.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/user.h>

#include "cuapi/common/xchan.h"

#define MAX_SIZE	(XCHAN_NPAGES_FS / 2 * PAGE_SIZE - 128)

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

enum cpsl_request {
	CPSL_GETATTR=0,
	CPSL_READLINK,
	CPSL_MKDIR,
	CPSL_UNLINK,
	CPSL_RMDIR,
	CPSL_SYMLINK,
	CPSL_RENAME,
	CPSL_LINK,
	CPSL_CHMOD,
	CPSL_CHOWN,
	CPSL_TRUNCATE,
	CPSL_UTIMENS,
	CPSL_OPEN,
	CPSL_READ,
	CPSL_WRITE,
	CPSL_RELEASE,
	CPSL_OPENDIR,
	CPSL_READDIR,
	CPSL_RELEASEDIR,
	CPSL_CREATE,
	CPSL_STATFS,
	CPSL_MAX,
};

struct string {
	size_t size;
	char buf[];
} __attribute__((packed));

struct cli_path {
	struct string path;
} __attribute__((packed));

struct srv_error {
	int error;
} __attribute__((packed));

struct srv_getattr {
	int error;
	struct stat stat;
} __attribute__((packed));

struct srv_statfs {
	int error;
	struct statvfs statvfs;
} __attribute__((packed));

struct cli_readlink {
	size_t len;
	struct string path;
} __attribute__((packed));

struct srv_readlink {
	int error;
	struct string path;
} __attribute__((packed));

struct cli_symlink {
	int null_offset;
	struct string paths;
} __attribute__((packed));

struct cli_rename {
	int null_offset;
	struct string paths;
} __attribute__((packed));

struct cli_link {
	int null_offset;
	struct string paths;
} __attribute__((packed));

struct cli_chmod {
	mode_t mode;
	struct string path;
} __attribute__((packed));

struct cli_chown {
	uid_t uid;
	gid_t gid;
	struct string path;
} __attribute__((packed));

struct cli_truncate {
	off_t size;
	struct string path;
} __attribute__((packed));

struct cli_utimens {
	struct timespec ts[2];
	struct string path;
} __attribute__((packed));

struct cli_open {
	int flags;
	struct string path;
} __attribute__((packed));

struct srv_open {
	uint64_t fh;
	int error;
} __attribute__((packed));

struct cli_read {
	uint64_t fh;
	size_t size;
	off_t off;
} __attribute__((packed));

struct srv_read {
	int error;
	struct string buf;
} __attribute__((packed));

struct cli_write {
	uint64_t fh;
	off_t off;
	struct string buf;
} __attribute__((packed));

struct cli_release {
	uint64_t fh;
} __attribute__((packed));

struct srv_opendir {
	uint64_t fh;
	int error;
} __attribute__((packed));

struct cli_readdir {
	uint64_t fh;
} __attribute__((packed));

struct srv_readdir {
	int error;
	unsigned char buf[];
} __attribute__((packed));

struct cli_mkdir {
	mode_t mode;
	struct string path;
} __attribute__((packed));

struct cli_create {
	int flags;
	mode_t mode;
	struct string path;
} __attribute__((packed));

struct srv_create {
	uint64_t fh;
	int error;
} __attribute__((packed));

union cli_packet_data {
	struct cli_path path;
	struct cli_readlink readlink;
	struct cli_symlink symlink;
	struct cli_rename rename;
	struct cli_link link;
	struct cli_chmod chmod;
	struct cli_chown chown;
	struct cli_truncate truncate;
	struct cli_utimens utimens;
	struct cli_open open;
	struct cli_read read;
	struct cli_write write;
	struct cli_release release;
	struct cli_readdir readdir;
	struct cli_mkdir mkdir;
	struct cli_create create;
};

struct cli_packet {
	enum cpsl_request type;
	size_t size;
	uid_t uid;
	gid_t gid;
	union cli_packet_data d;
} __attribute__((packed));

union srv_packet {
	struct srv_error error;
	struct srv_getattr getattr;
	struct srv_readlink readlink;
	struct srv_open open;
	struct srv_read read;
	struct srv_opendir opendir;
	struct srv_readdir readdir;
	struct srv_create create;
	struct srv_statfs statfs;
};

#endif /* _PROTOCOL_H */

// vim: noet: ts=8:
