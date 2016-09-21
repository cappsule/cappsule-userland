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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include "fsclient.h"
#include "packet.h"
#include "protocol.h"

static struct fsclient fsclient;
static struct cli_packet *clip;

struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[];
	/*
	  char pad;
	  char d_type;
	*/
};


/* Special directories (/proc, /sys, etc.) are mounted into capsulefs before
 * snapshot. mount() needs to stat target directory through fuse fsclient.
 *
 * Currently, there is no easy way to guess if fsclient is running in guest or
 * host. This is why dirty network heuristics are used. */
static int handle_mount_setup(const char *path, struct stat *st, int *error)
{
	/* running in guest if already connected */
	if (fsclient.xchan != NULL)
		return 0;

	if (in_capsule(fsclient.nohv))
		return 0;

	*error = 0;
	if (stat(path, st) != 0)
		*error = -errno;

	return 1;
}

static size_t fill_cli_path(struct string *string, const char *path)
{
	size_t path_len;

	/* XXX: check path_len against MAX_SIZE */

	path_len = strlen(path) + 1;
	string->size = path_len;
	memcpy(string->buf, path, path_len);

	return path_len;
}

static struct cli_path *build_path_packet(const char *path, size_t *packet_size)
{
	struct cli_path *cli;
	size_t path_len;

	cli = &clip->d.path;
	path_len = fill_cli_path(&cli->path, path);
	*packet_size = sizeof(*cli) + path_len;

	return cli;
}

static void send_and_recv(enum cpsl_request type, size_t cli_size,
			void *srv, size_t srv_size)
{
	do_request(&fsclient, type, clip, cli_size);
	do_response(&fsclient, srv, srv_size);
}

static int cpsl_getattr(const char *path, struct stat *stat)
{
	struct srv_getattr srv;
	size_t packet_size;
	int error;

	if (handle_mount_setup(path, stat, &error))
		return error;

	build_path_packet(path, &packet_size);
	send_and_recv(CPSL_GETATTR, packet_size, &srv, sizeof(srv));
	error = srv.error;
	if (!error)
		*stat = srv.stat;

	return error;
}

static int cpsl_statfs(const char *path, struct statvfs *statvfs)
{
	struct srv_statfs srv;
	size_t packet_size;
	int error;

	build_path_packet(path, &packet_size);
	send_and_recv(CPSL_STATFS, packet_size, &srv, sizeof(srv));
	error = srv.error;
	if (!error)
		*statvfs = srv.statvfs;

	return error;
}

static int cpsl_readlink(const char *path, char *buf, size_t len)
{
	size_t packet_size, path_len;
	struct cli_readlink *cli;
	struct srv_readlink srv;
	int error;

	cli = &clip->d.readlink;
	cli->len = len;
	path_len = fill_cli_path(&cli->path, path);
	packet_size = sizeof(*cli) + path_len;

	/* sizeof(srv) can be used because sizeof(srv.path.buf) == 0 */
	send_and_recv(CPSL_READLINK, packet_size, &srv, sizeof(srv));

	error = srv.error;
	if (!error) {
		if (srv.path.size > len) {
			warnx("cpsl_read: invalid size");
			return -EFAULT;
		} else if (srv.path.size > 0) {
			/* trust srv.path.size */
			do_response(&fsclient, buf, srv.path.size);
			buf[srv.path.size] = '\x00';
		}
	}

	return error;
}

static int cpsl_mkdir(const char *path, mode_t mode)
{
	size_t packet_size, path_len;
	struct cli_mkdir *cli;
	struct srv_error srv;

	cli = &clip->d.mkdir;
	cli->mode = mode;
	path_len = fill_cli_path(&cli->path, path);
	packet_size = sizeof(*cli) + path_len;

	send_and_recv(CPSL_MKDIR, packet_size, &srv, sizeof(srv));

	return srv.error;
}

static int cpsl_unlink(const char *path)
{
	struct srv_error srv;
	size_t packet_size;

	build_path_packet(path, &packet_size);
	send_and_recv(CPSL_UNLINK, packet_size, &srv, sizeof(srv));

	return srv.error;
}

static int cpsl_rmdir(const char *path)
{
	struct srv_error srv;
	size_t packet_size;

	build_path_packet(path, &packet_size);
	send_and_recv(CPSL_RMDIR, packet_size, &srv, sizeof(srv));

	return srv.error;
}

static int cpsl_symlink(const char *oldpath, const char *newpath)
{
	size_t packet_size, oldpath_len, newpath_len, path_len;
	struct cli_symlink *cli;
	struct srv_error srv;
	char *p;

	oldpath_len = strlen(oldpath);
	newpath_len = strlen(newpath);
	p = malloc(oldpath_len + 1 + newpath_len + 1);
	if (p == NULL)
		return -ENOMEM;
	memcpy(p, oldpath, oldpath_len);
	memcpy(p + oldpath_len + 1, newpath, newpath_len + 1);
	p[oldpath_len] = 'x'; /* not null because fil_cli_path uses strlen */

	cli = &clip->d.symlink;
	cli->null_offset = oldpath_len;
	path_len = fill_cli_path(&cli->paths, p);
	packet_size = sizeof(*cli) + path_len;
	free(p);

	send_and_recv(CPSL_SYMLINK, packet_size, &srv, sizeof(srv));

	return srv.error;
}

static int cpsl_rename(const char *oldpath, const char *newpath)
{
	size_t packet_size, oldpath_len, newpath_len, path_len;
	struct cli_rename *cli;
	struct srv_error srv;
	char *p;

	oldpath_len = strlen(oldpath);
	newpath_len = strlen(newpath);
	p = malloc(oldpath_len + 1 + newpath_len + 1);
	if (p == NULL)
		return -ENOMEM;
	memcpy(p, oldpath, oldpath_len);
	memcpy(p + oldpath_len + 1, newpath, newpath_len + 1);
	p[oldpath_len] = 'x';  /* not null because fil_cli_path uses strlen */

	cli = &clip->d.rename;
	cli->null_offset = oldpath_len;
	path_len = fill_cli_path(&cli->paths, p);
	packet_size = sizeof(*cli) + path_len;
	free(p);

	send_and_recv(CPSL_RENAME, packet_size, &srv, sizeof(srv));

	return srv.error;
}

static int cpsl_link(const char *oldpath, const char *newpath)
{
	size_t packet_size, oldpath_len, newpath_len, path_len;
	struct cli_link *cli;
	struct srv_error srv;
	char *p;

	oldpath_len = strlen(oldpath);
	newpath_len = strlen(newpath);
	p = malloc(oldpath_len + 1 + newpath_len + 1);
	if (p == NULL)
		return -ENOMEM;
	memcpy(p, oldpath, oldpath_len);
	memcpy(p + oldpath_len + 1, newpath, newpath_len + 1);
	p[oldpath_len] = 'x'; /* not null because fil_cli_path uses strlen */

	cli = &clip->d.link;
	cli->null_offset = oldpath_len;
	path_len = fill_cli_path(&cli->paths, p);
	packet_size = sizeof(*cli) + path_len;
	free(p);

	send_and_recv(CPSL_LINK, packet_size, &srv, sizeof(srv));

	return srv.error;
}

static int cpsl_chmod(const char *path, mode_t mode)
{
	size_t packet_size, path_len;
	struct cli_chmod *cli;
	struct srv_error srv;

	cli = &clip->d.chmod;
	cli->mode = mode;
	path_len = fill_cli_path(&cli->path, path);
	packet_size = sizeof(*cli) + path_len;

	send_and_recv(CPSL_CHMOD, packet_size, &srv, sizeof(srv));

	return srv.error;
}

static int cpsl_chown(const char *path, uid_t uid, gid_t gid)
{
	size_t packet_size, path_len;
	struct cli_chown *cli;
	struct srv_error srv;

	cli = &clip->d.chown;
	cli->uid = uid;
	cli->gid = gid;
	path_len = fill_cli_path(&cli->path, path);
	packet_size = sizeof(*cli) + path_len;

	send_and_recv(CPSL_CHOWN, packet_size, &srv, sizeof(srv));

	return srv.error;
}

static int cpsl_truncate(const char *path, off_t size)
{
	size_t packet_size, path_len;
	struct cli_truncate *cli;
	struct srv_error srv;

	cli = &clip->d.truncate;
	cli->size = size;
	path_len = fill_cli_path(&cli->path, path);
	packet_size = sizeof(*cli) + path_len;

	send_and_recv(CPSL_TRUNCATE, packet_size, &srv, sizeof(srv));

	return srv.error;
}

static int cpsl_utimens(const char *path, const struct timespec ts[2])
{
	size_t packet_size, path_len;
	struct cli_utimens *cli;
	struct srv_error srv;

	cli = &clip->d.utimens;
	memcpy(&cli->ts, ts, sizeof(cli->ts));
	path_len = fill_cli_path(&cli->path, path);
	packet_size = sizeof(*cli) + path_len;

	send_and_recv(CPSL_UTIMENS, packet_size, &srv, sizeof(srv));

	return srv.error;
}

static int cpsl_read_helper(char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
	struct cli_read *cli;
	struct srv_read srv;

	cli = &clip->d.read;
	cli->fh = fi->fh;
	cli->size = size;
	cli->off = off;

	/* sizeof(srv) can be used because sizeof(srv.buf.buf) == 0 */
	send_and_recv(CPSL_READ, sizeof(*cli), &srv, sizeof(srv));
	if (srv.error < 0)
		return srv.error;

	if (srv.buf.size > size) {
		warnx("cpsl_read: invalid size");
		return -EFAULT;
	}

	do_response(&fsclient, buf, srv.buf.size);

	return srv.buf.size;
}

static int cpsl_read(const char *UNUSED(path), char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
	int total_size, res;
	ssize_t max_size;

	max_size = MAX_SIZE;
	total_size = 0;

	/* read as much data as possible */
	do {
		res = cpsl_read_helper(buf, size, off, fi);
		if (res > 0) {
			total_size += res;
			buf += res;
			off += res;
			size -= res;
		} else if (res < 0) {
			total_size = res;
			break;
		} else {
			break;
		}
	} while (res == max_size && size > 0);

	return total_size;
}

static int cpsl_write_helper(const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
	size_t max_size, packet_size;
	struct cli_write *cli;
	struct srv_error srv;

	max_size = MAX_SIZE - sizeof(*cli);
	if (size > max_size)
		size = max_size;

	cli = &clip->d.write;
	cli->fh = fi->fh;
	cli->off = off;
	cli->buf.size = size;
	memcpy(cli->buf.buf, buf, size);

	packet_size = sizeof(*cli) + size;
	send_and_recv(CPSL_WRITE, packet_size, &srv, sizeof(srv));

	return srv.error;
}

static int cpsl_write(const char *UNUSED(path), const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
	int total_size, res;

	total_size = 0;

	do {
		res = cpsl_write_helper(buf, size, off, fi);
		if (res > 0) {
			total_size += res;
			buf += res;
			off += res;
			size -= res;
		} else if (res < 0) {
			if (total_size == 0)
				total_size = res;
			break;
		} else {
			break;
		}
	} while (size > 0);

	return total_size;
}

static int cpsl_release_helper(enum cpsl_request type, const char *UNUSED(path), struct fuse_file_info *fi)
{
	struct cli_release *cli;
	struct srv_error srv;

	cli = &clip->d.release;
	cli->fh = fi->fh;

	send_and_recv(type, sizeof(*cli), &srv, sizeof(srv));

	return srv.error;
}

static int cpsl_release(const char *path, struct fuse_file_info *fi)
{
	return cpsl_release_helper(CPSL_RELEASE, path, fi);
}

static int cpsl_opendir(const char *path, struct fuse_file_info *fi)
{
	struct srv_opendir srv;
	size_t packet_size;

	build_path_packet(path, &packet_size);
	send_and_recv(CPSL_OPENDIR, packet_size, &srv, sizeof(srv));
	if (!srv.error)
		fi->fh = srv.fh;

	return srv.error;
}

static int cpsl_open(const char *path, struct fuse_file_info *fi)
{
	size_t packet_size, path_len;
	struct cli_open *cli;
	struct srv_open srv;
	struct stat st;

	if (stat(path, &st) != 0 && S_ISDIR(st.st_mode))
		return cpsl_opendir(path, fi);

	cli = &clip->d.open;
	cli->flags = fi->flags;
	path_len = fill_cli_path(&cli->path, path);
	packet_size = sizeof(*cli) + path_len;

	send_and_recv(CPSL_OPEN, packet_size, &srv, sizeof(srv));
	if (!srv.error)
		fi->fh = srv.fh;

	return srv.error;
}

static int cpsl_readdir(const char *UNUSED(path), void *buf, fuse_fill_dir_t filler,
			off_t offset, struct fuse_file_info *fi)
{
	unsigned int bpos, count;
	struct cli_readdir *cli;
	struct srv_readdir srv;
	struct linux_dirent *d;
	unsigned char *dirp;
	int stop, error;
	struct stat st;
	size_t size;

	cli = &clip->d.readdir;
	cli->fh = fi->fh;
	offset = offset;
	stop = 0;

	do {
		size = offsetof(struct srv_readdir, buf);
		send_and_recv(CPSL_READDIR, sizeof(*cli), &srv, size);
		if (srv.error <= 0) {
			error = srv.error;
			break;
		}

		count = srv.error;
		dirp = malloc(count);
		if (dirp == NULL) {
			error = -errno;
			break;
		}

		do_response(&fsclient, dirp, count);

		for (bpos = 0; bpos < count && bpos + 4096; ) {
			d = (struct linux_dirent *)(dirp + bpos);
			memset(&st, 0, sizeof(st));
			st.st_ino = d->d_ino;
			st.st_mode = *(char *)(buf + bpos + d->d_reclen - 1) << 12;
			if (filler(buf, d->d_name, &st, 0)) {
				stop = 1;
				error = 0;
				break;
			}
			bpos += d->d_reclen;
		}

		free(dirp);
	} while (!stop);

	return error;
}

static int cpsl_releasedir(const char *path, struct fuse_file_info *fi)
{
	return cpsl_release_helper(CPSL_RELEASEDIR, path, fi);
}

static int cpsl_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	size_t packet_size, path_len;
	struct cli_create *cli;
	struct srv_create srv;

	cli = &clip->d.create;
	cli->flags = fi->flags;
	cli->mode = mode;
	path_len = fill_cli_path(&cli->path, path);
	packet_size = sizeof(*cli) + path_len;

	send_and_recv(CPSL_CREATE, packet_size, &srv, sizeof(srv));
	if (!srv.error)
		fi->fh = srv.fh;

	return srv.error;
}

static struct fuse_operations cpsl_oper = {
	.getattr = cpsl_getattr,
	.readlink = cpsl_readlink,
	.mkdir = cpsl_mkdir,
	.unlink = cpsl_unlink,
	.rmdir = cpsl_rmdir,
	.symlink = cpsl_symlink,
	.rename = cpsl_rename,
	.link = cpsl_link,
	.chmod = cpsl_chmod,
	.chown = cpsl_chown,
	.truncate = cpsl_truncate,
	.utimens = cpsl_utimens,
	.open = cpsl_open,
	.read = cpsl_read,
	.write = cpsl_write,
	.release = cpsl_release,
	.opendir = cpsl_opendir,
	.readdir = cpsl_readdir,
	.releasedir = cpsl_releasedir,
	.create = cpsl_create,
	.statfs = cpsl_statfs,
};

static void usage(char *filename)
{
	fprintf(stderr, "usage: %s [options] -- mountpoint [options]\n", filename);
	fprintf(stderr, "  -n, --no-hv\t\t\trun without hypervisor\n");
	fprintf(stderr, "  -u, --userspec=uid:gid\tspecify user and group to use\n");
	exit(0);
}

/* return -1 on error, 0 if arg is to be discarded, 1 if arg should be kept */
static int opt_proc(void *data,
		    const char *arg,
		    int UNUSED(key),
		    struct fuse_args *UNUSED(outargs))
{
	struct fsclient *fsclient = (struct fsclient *)data;

	if (strcmp(arg, "-n") == 0 || strcmp(arg, "--no-hv") == 0) {
		fsclient->nohv = 1;
		return 0;
	}

	if (strncmp(arg, "-u=", 3) == 0) {
		fsclient->userspec = (char *)arg + 3;
		return 0;
	}

	if (strncmp(arg, "--userspec=", 11) == 0) {
		fsclient->userspec = (char *)arg + 11;
		return 0;
	}

	return 1;
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	if (argc < 2)
		usage(argv[0]);

	clip = malloc(sizeof(*clip) + MAX_SIZE);
	if (clip == NULL)
		err(1, "malloc");

	fsclient.xchan = NULL;
	fsclient.nohv = 0;
	fsclient.userspec = NULL;

	fuse_opt_parse(&args, &fsclient, NULL, opt_proc);

	return fuse_main(args.argc, args.argv, &cpsl_oper, NULL);
}

// vim: noet:ts=8:
