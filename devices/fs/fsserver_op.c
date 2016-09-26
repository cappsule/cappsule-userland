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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>

#include "protocol.h"
#include "policy.h"
#include "fsserver_op.h"

typedef ssize_t (*server_op_t)(struct client *client, union cli_packet_data *clid, size_t size,
			       union srv_packet *srvd);

static int safe_opendir(struct client *client, const char *path);

struct relpath {
	/* private buffer for directory and filename pointers */
	char buf[PATH_MAX];

	/* directory opened to get a fd (must be canonical) */
	char *directory;
	/* file descriptor of directory given to *at() functions */
	int dirfd;

	/* pathname given to *at() functions */
	char *filename;

	/* resolved path (must be canonical) */
	char full_path[PATH_MAX];
};

static int split_path(const char *path, struct relpath *relpath)
{
	size_t size;
	char *p;

	size = strlen(path);
	if (size == 0 || size >= sizeof(relpath->buf))
		return -1;

	/* ensure path is absolute */
	if (path[0] != '/')
		return -1;

	strncpy(relpath->buf, path, sizeof(relpath->buf));

	/* remove trailing slashes */
	p = relpath->buf + size - 1;
	while (p > relpath->buf && *p == '/')
		*p-- = '\x00';

	/* don't allow . and .. filename */
	p = strrchr(relpath->buf, '/');
	if (strcmp(p + 1, ".") == 0 || strcmp(p + 1, "..") == 0)
		return -1;

	/* exception for "/": directory = "/" and filename = "." */
	if (strcmp(relpath->buf, "/") == 0) {
		relpath->buf[1] = '.';
		relpath->buf[2] = '\x00';
	}

	/* split directory from filename */
	relpath->filename = strrchr(relpath->buf, '/');
	if (relpath->filename != relpath->buf)
		relpath->directory = relpath->buf;
	else
		relpath->directory = (char *)"/";
	*relpath->filename++ = '\x00';

	return 0;
}

static int get_full_path(int procfd, struct relpath *relpath)
{
	char buf[32];
	size_t size;
	char *p;
	int ret;

	snprintf(buf, sizeof(buf), "%d", relpath->dirfd);

	size = sizeof(relpath->full_path);
	ret = readlinkat(procfd, buf, relpath->full_path, size);
	if (ret < 0 || ret >= (ssize_t)size)
		return -1;

	if (ret + strlen(relpath->filename) >= size)
		return -1;

	/* avoid //. if fullpath is /. */
	if (strcmp(relpath->directory, "/") != 0 &&
	    strcmp(relpath->filename, ".") != 0) {
		p = relpath->full_path + ret;
		snprintf(p, size - ret, "/%s", relpath->filename);
	}

	return 0;
}

static int open_directory(int procfd, const char *path, struct relpath *relpath)
{
	if (split_path(path, relpath) != 0)
		return -ENAMETOOLONG;

	relpath->dirfd = open(relpath->directory, O_DIRECTORY);
	if (relpath->dirfd == -1)
		return -errno;

	if (get_full_path(procfd, relpath) != 0) {
		close(relpath->dirfd);
		return -ENAMETOOLONG;
	}

	return 0;
}

/* return 1 if fd available, 0 otherwise */
static int fd_available(struct client *client)
{
	return client->n < MAX_FILE;
}

static unsigned int add_opened_file(struct client *client, int fd)
{
	unsigned int fh;

	/* should never happen */
	if (!fd_available(client))
		errx(1, "add_opened_file: too much files open");

	for (fh = 0; fh < MAX_FILE; fh++) {
		if (client->fd[fh] == -1) {
			client->fd[fh] = fd;
			client->n++;
			return fh;
		}
	}

	/* should never happen */
	errx(1, "add_opened_file: no file handle available");

	return -1;
}

static int get_fd(struct client *client, unsigned int fh)
{
	if (fh >= MAX_FILE)
		return -1;

	return client->fd[fh];
}

static int remove_opened_file(struct client *client, unsigned int fh)
{
	if (fh >= MAX_FILE)
		return -1;

	if (client->fd[fh] == -1)
		return -1;

	while (1) {
		if (close(client->fd[fh]) == -1) {
			if (errno != EINTR)
				err(1, "remove_opened_file: close");
		} else {
			break;
		}
	}

	client->fd[fh] = -1;
	client->n--;

	return 0;
}

/* return 1 if user string is valid, 0 otherwise */
static int valid_buf(char *buf, size_t size, union cli_packet_data *data, size_t usize)
{
	char *ubuf = (char *)data;

	return ((buf >= ubuf) && (buf + size >= ubuf) &&
		(buf < ubuf + usize) && (buf + size <= ubuf + usize) &&
		(size <= usize));
}

static char *get_relative_path(union cli_packet_data *clid, size_t size, struct string *string)
{
	if (string->size == 0)
		return NULL;

	if (!valid_buf(string->buf, string->size, clid, size))
		return NULL;

	if (string->buf[string->size-1] != '\x00')
		return NULL;

	return string->buf;
}

static char *get_path(union cli_packet_data *clid, size_t size, struct string *string)
{
	char *path;

	path = get_relative_path(clid, size, string);
	if (path == NULL)
		return NULL;

	if (path[0] != '/')
		return NULL;

	return path;
}

static bool preg_match_array(struct array *array, const char *element)
{
	unsigned int i;

	if (array == NULL)
		return false;

	for (i = 0; i < array->n; i++) {
		if (regexec(array->files[i].preg, element, 0, NULL, 0) == 0)
			return true;
	}

	return false;
}

/* path is either:
 * - relpath.directory
 * - relpath.full_path */
static bool check_fs_policy(struct policy *policy, const char *path,
			    enum fs_access_type access_type)
{
	bool ret;

	if (strcmp(path, "/") == 0 || strcmp(path, "/.") == 0) {
		if (access_type != ACCESS_DIR_READ &&
		    access_type != ACCESS_DIR_EXEC) {
			warnx("%s: bad access type to /", __func__);
			return false;
		}
	}

	switch (access_type) {
	case ACCESS_FILE_READ:
		ret = preg_match_array(policy->fs.files_r, path);
		break;
	case ACCESS_FILE_WRITE:
		ret = preg_match_array(policy->fs.files_w, path);
		break;
	case ACCESS_DIR_READ:
		ret = preg_match_array(policy->fs.dir_r, path);
		break;
	case ACCESS_DIR_EXEC:
		ret = preg_match_array(policy->fs.dir_x, path);
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

/* getattr, readlink
 *
 * Examples:
 *  - ^/usr/bin$
 *  - ^/@HOME@/Documents/.*$
 */
static bool is_dir_exec(struct policy *policy, struct relpath *relpath)
{
	return check_fs_policy(policy, relpath->directory, ACCESS_DIR_EXEC);
}

/* opendir
 *
 * Examples:
 *  - ^/etc/dbus-1/session\.d/.*$
 *  - ^/usr/share$
 */
static bool is_dir_readable(struct policy *policy, struct relpath *relpath)
{
	return check_fs_policy(policy, relpath->full_path, ACCESS_DIR_READ);
}

/* mkdir, unlink, rmdir, symlink, link, rename, chmod, chown, truncate, utimens,
 * create, open
 *
 * Examples:
 *  - ^/var/log/apache2/.*$
 *  - ^/@HOME@/\.local/share/recently-used\.xbel[^/]*$
 */
static bool is_file_writeable(struct policy *policy, struct relpath *relpath)
{
	return check_fs_policy(policy, relpath->full_path, ACCESS_FILE_WRITE);
}

/* open
 *
 * Examples:
 *  - ^/usr/sbin/.*$
 *  - ^/etc/ld\.so\.cache$
 */
static bool is_file_readable(struct policy *policy, struct relpath *relpath)
{
	return check_fs_policy(policy, relpath->full_path, ACCESS_FILE_READ);
}

static int safe_statfs(struct client *client, const char *path,
		       struct statvfs *st)
{
	struct relpath relpath;
	int fd, ret;

	debug("[o] statfs(\"%s\")", path);

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (!is_dir_exec(client->policy, &relpath)) {
		debug("[-] statfs(\"%s\") forbidden", path);
		ret = -EACCES;
		goto out;
	}

	fd = openat(relpath.dirfd, relpath.filename, O_RDONLY | O_NOFOLLOW);
	if (fd == -1) {
		ret = -errno;
		goto out;
	}

	ret = fstatvfs(fd, st);
	if (ret != 0) {
		ret = -errno;
		close(fd);
		debug("[-] open failed: stat failed: %s", strerror(errno));
		goto out;
	}

	close(fd);

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_statfs(struct client *client, union cli_packet_data *clid,
			 size_t size, union srv_packet *srvd)
{
	struct srv_statfs *srv;
	struct cli_path *cli;
	char *path;

	cli = &clid->path;
	srv = &srvd->statfs;
	memset(&srv->statvfs, 0, sizeof(srv->statvfs));

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	srv->error = safe_statfs(client, path, &srv->statvfs);
	return sizeof(*srv);
}

static int safe_getattr(struct client *client, const char *path, struct stat *st)
{
	struct relpath relpath;
	int ret;

	debug("[o] getattr(\"%s\")", path);

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (!is_dir_exec(client->policy, &relpath)) {
		debug("[-] stat \"%s\" forbidden", path);
		ret = -EACCES;
		goto out;
	}

	ret = fstatat(relpath.dirfd, relpath.filename, st, AT_SYMLINK_NOFOLLOW);
	if (ret != 0) {
		ret = -errno;
		debug("[-] stat failed: %s", strerror(errno));
	}

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_getattr(struct client *client, union cli_packet_data *clid,
			size_t size, union srv_packet *srvd)
{
	struct srv_getattr *srv;
	struct cli_path *cli;
	char *path;

	cli = &clid->path;
	srv = &srvd->getattr;
	memset(&srv->stat, 0, sizeof(srv->stat));

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	srv->error = safe_getattr(client, path, &srv->stat);
	return sizeof(*srv);
}

static int safe_readlink(struct client *client, const char *path, char *buf,
			 size_t len)
{
	struct relpath relpath;
	int ret;

	debug("[o] readlink(\"%s\")", path);

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (!is_dir_exec(client->policy, &relpath)) {
		debug("[-] readlink \"%s\" forbidden", relpath.directory);
		ret = -EACCES;
		goto out;
	}

	ret = readlinkat(relpath.dirfd, relpath.filename, buf, len);
	if (ret == -1 || ret >= (ssize_t)len) {
		ret = (ret == -1) ? -errno : -EFAULT;
		debug("[-] readlink \"%s\" failed: %s", path, strerror(-ret));
		goto out;
	}

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_readlink(struct client *client, union cli_packet_data *clid,
			   size_t size, union srv_packet *srvd)
{
	struct srv_readlink *srv;
	struct cli_readlink *cli;
	char *path;

	cli = &clid->readlink;
	srv = &srvd->readlink;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	if (cli->len > MAX_SIZE)
		cli->len = MAX_SIZE;

	srv->error = safe_readlink(client, path, srv->path.buf, cli->len);
	if (srv->error >= 0) {
		srv->path.size = srv->error;
		srv->error = 0;
	} else {
		srv->path.size = 0;
	}

	return sizeof(*srv) + srv->path.size;
}

static int safe_mkdir(struct client *client, const char *path, mode_t mode)
{
	struct relpath relpath;
	int ret;

	debug("[o] mkdir(\"%s\", %04o)", path, mode);

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (!is_file_writeable(client->policy, &relpath)) {
		debug("%s: check_fs_policy (\"%s\") forbidden", __func__, path);
		ret = -EACCES;
		goto out;
	}

	ret = mkdirat(relpath.dirfd, relpath.filename, mode);
	if (ret == -1)
		ret = -errno;

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_mkdir(struct client *client, union cli_packet_data *clid, size_t size,
			union srv_packet *srvd)
{
	struct cli_mkdir *cli;
	struct srv_error *srv;
	mode_t mode;
	char *path;

	cli = &clid->mkdir;
	srv = &srvd->error;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	mode = cli->mode;
	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	srv->error = safe_mkdir(client, path, mode);
	return sizeof(*srv);
}

static int safe_unlink(struct client *client, const char *path)
{
	struct relpath relpath;
	int ret;

	debug("[o] unlink(\"%s\")", path);

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (!is_file_writeable(client->policy, &relpath)) {
		debug("%s: check_fs_policy (\"%s\") forbidden", __func__, path);
		ret = -EACCES;
		goto out;
	}

	ret = unlinkat(relpath.dirfd, relpath.filename, 0);
	if (ret == -1)
		ret = -errno;

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_unlink(struct client *client, union cli_packet_data *clid,
			 size_t size, union srv_packet *srvd)
{
	struct srv_error *srv;
	struct cli_path *cli;
	char *path;

	cli = &clid->path;
	srv = &srvd->error;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	srv->error = safe_unlink(client, path);
	return sizeof(*srv);
}

static int safe_rmdir(struct client *client, const char *path)
{
	struct relpath relpath;
	int ret;

	debug("[o] rmdir(\"%s\")", path);

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (!is_file_writeable(client->policy, &relpath)) {
		debug("%s: check_fs_policy (\"%s\") forbidden", __func__, path);
		ret = -EACCES;
		goto out;
	}

	ret = unlinkat(relpath.dirfd, relpath.filename, AT_REMOVEDIR);
	if (ret == -1)
		ret = -errno;

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_rmdir(struct client *client, union cli_packet_data *clid, size_t size,
			union srv_packet *srvd)
{
	struct srv_error *srv;
	struct cli_path *cli;
	char *path;

	cli = &clid->path;
	srv = &srvd->error;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	srv->error = safe_rmdir(client, path);
	return sizeof(*srv);
}

static int safe_symlink(struct client *client, const char *oldpath,
			const char *newpath)
{
	struct relpath relpath;
	int ret;

	debug("[o] symlink(\"%s\", \"%s\")", oldpath, newpath);

	ret = open_directory(client->procfd, newpath, &relpath);
	if (ret != 0)
		return ret;

	if (!is_file_writeable(client->policy, &relpath)) {
		debug("%s: check_fs_policy (\"%s\") forbidden", __func__, newpath);
		ret = -EACCES;
		goto out;
	}

	ret = symlinkat(oldpath, relpath.dirfd, relpath.filename);
	if (ret == -1)
		ret = -errno;

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_symlink(struct client *client,
			  union cli_packet_data *clid,
			  size_t size,
			  union srv_packet *srvd)
{
	char *oldpath, *newpath, *paths;
	struct cli_symlink *cli;
	struct srv_error *srv;

	cli = &clid->symlink;
	srv = &srvd->error;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	/* oldpath may be relative */
	paths = get_relative_path(clid, size, &cli->paths);
	if (paths == NULL) {
		warnx("%s: invalid paths", __func__);
		return -1;
	}

	if ((size_t)cli->null_offset >= cli->paths.size) {
		warnx("%s: invalid null offset", __func__);
		return -1;
	}

	paths[cli->null_offset] = '\x00';
	oldpath = paths;

	newpath = oldpath + cli->null_offset + 1;
	if (newpath[0] != '/') {
		warnx("%s: invalid newpath", __func__);
		return -1;
	}

	srv->error = safe_symlink(client, oldpath, newpath);
	return sizeof(*srv);
}

static int safe_rename(struct client *client, const char *oldpath,
		       const char *newpath)
{
	struct relpath oldrelpath, newrelpath;
	int ret;

	debug("[o] rename(\"%s\", \"%s\")", oldpath, newpath);

	ret = open_directory(client->procfd, oldpath, &oldrelpath);
	if (ret != 0)
		return ret;

	ret = open_directory(client->procfd, newpath, &newrelpath);
	if (ret != 0)
		goto out0;

	if (!is_file_writeable(client->policy, &oldrelpath) ||
	    !is_file_writeable(client->policy, &newrelpath)) {
		debug("%s: check_fs_policy (\"%s\") forbidden", __func__, oldpath);
		debug("%s: check_fs_policy (\"%s\") forbidden", __func__, newpath);
		ret = -EACCES;
		goto out;
	}

	ret = renameat(oldrelpath.dirfd, oldrelpath.filename, newrelpath.dirfd,
		       newrelpath.filename);
	if (ret == -1)
		ret = -errno;

out:
	close(newrelpath.dirfd);
out0:
	close(oldrelpath.dirfd);
	return ret;
}

static ssize_t do_rename(struct client *client, union cli_packet_data *clid,
			 size_t size, union srv_packet *srvd)
{
	char *oldpath, *newpath, *paths;
	struct cli_rename *cli;
	struct srv_error *srv;

	cli = &clid->rename;
	srv = &srvd->error;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	paths = get_path(clid, size, &cli->paths);
	if (paths == NULL) {
		warnx("%s: invalid paths", __func__);
		return -1;
	}

	if ((size_t)cli->null_offset >= cli->paths.size) {
		warnx("%s: invalid null offset", __func__);
		return -1;
	}

	paths[cli->null_offset] = '\x00';
	oldpath = paths;

	newpath = oldpath + cli->null_offset + 1;
	if (newpath[0] != '/') {
		warnx("%s: invalid newpath", __func__);
		return -1;
	}

	srv->error = safe_rename(client, oldpath, newpath);
	return sizeof(*srv);
}

static int safe_link(struct client *client, const char *oldpath,
		     const char *newpath)
{
	struct relpath oldrelpath, newrelpath;
	int ret;

	debug("[o] link(\"%s\", \"%s\")", oldpath, newpath);

	ret = open_directory(client->procfd, oldpath, &oldrelpath);
	if (ret != 0)
		return ret;

	ret = open_directory(client->procfd, newpath, &newrelpath);
	if (ret != 0)
		goto out0;

	if (!is_file_writeable(client->policy, &oldrelpath) ||
	    !is_file_writeable(client->policy, &newrelpath)) {
		debug("%s: check_fs_policy (\"%s\") forbidden", __func__, oldpath);
		debug("%s: check_fs_policy (\"%s\") forbidden", __func__, newpath);
		ret = -EACCES;
		goto out;
	}

	ret = linkat(oldrelpath.dirfd, oldrelpath.filename, newrelpath.dirfd,
		     newrelpath.filename, 0);
	if (ret == -1)
		ret = -errno;

out:
	close(newrelpath.dirfd);
out0:
	close(oldrelpath.dirfd);
	return ret;
}

static ssize_t do_link(struct client *client,
		       union cli_packet_data *clid,
		       size_t size,
		       union srv_packet *srvd)
{
	char *oldpath, *newpath, *paths;
	struct srv_error *srv;
	struct cli_link *cli;

	cli = &clid->link;
	srv = &srvd->error;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	/* oldpath may be relative */
	paths = get_relative_path(clid, size, &cli->paths);
	if (paths == NULL) {
		warnx("%s: invalid paths", __func__);
		return -1;
	}

	if ((size_t)cli->null_offset >= cli->paths.size) {
		warnx("%s: invalid null offset", __func__);
		return -1;
	}

	paths[cli->null_offset] = '\x00';
	oldpath = paths;

	newpath = oldpath + cli->null_offset + 1;
	if (newpath[0] != '/') {
		warnx("%s: invalid newpath", __func__);
		return -1;
	}

	srv->error = safe_link(client, oldpath, newpath);
	return sizeof(*srv);
}

static int safe_chmod(struct client *client, const char *path, mode_t mode)
{
	struct relpath relpath;
	int fd, ret;

	debug("[o] chmod(\"%s\", %04o)", path, mode);

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (!is_file_writeable(client->policy, &relpath)) {
		debug("%s: check_fs_policy (\"%s\") forbidden", __func__, path);
		ret = -EACCES;
		goto out;
	}

	/* man fchmodat:
	 * AT_SYMLINK_NOFOLLOW If pathname is a symbolic link, do not
	 * dereference it: instead operate on the link itself. This flag is not
	 * currently implemented.*/
	fd = openat(relpath.dirfd, relpath.filename, O_RDONLY | O_NOFOLLOW);
	if (fd == -1) {
		ret = -errno;
		goto out;
	}

	ret = fchmod(fd, mode);
	if (ret == -1)
		ret = -errno;

	close(fd);

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_chmod(struct client *client, union cli_packet_data *clid, size_t size,
			union srv_packet *srvd)
{
	struct cli_chmod *cli;
	struct srv_error *srv;
	mode_t mode;
	char *path;

	cli = &clid->chmod;
	srv = &srvd->error;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	mode = cli->mode;
	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	srv->error = safe_chmod(client, path, mode);
	return sizeof(*srv);
}

static int safe_chown(struct client *client, const char *path, uid_t uid,
		      gid_t gid)
{
	struct relpath relpath;
	int flag, ret;

	debug("[o] chown(\"%s\", %d, %d)", path, uid, gid);

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (!is_file_writeable(client->policy, &relpath)) {
		debug("%s: check_fs_policy (\"%s\") forbidden", __func__, path);
		ret = -EACCES;
		goto out;
	}

	flag = AT_SYMLINK_NOFOLLOW;
	ret = fchownat(relpath.dirfd, relpath.filename, uid, gid, flag);
	if (ret == -1)
		ret = -errno;

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_chown(struct client *client, union cli_packet_data *clid,
			size_t size, union srv_packet *srvd)
{
	struct cli_chown *cli;
	struct srv_error *srv;
	char *path;
	uid_t uid;
	gid_t gid;

	cli = &clid->chown;
	srv = &srvd->error;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	uid = cli->uid;
	gid = cli->gid;
	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	srv->error = safe_chown(client, path, uid, gid);
	return sizeof(*srv);
}

static int safe_truncate(struct client *client, const char *path, size_t size)
{
	struct relpath relpath;
	int fd, ret;

	debug("[o] truncate(\"%s\", %ld)", path, size);

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (!is_file_writeable(client->policy, &relpath)) {
		debug("%s: check_fs_policy (\"%s\") forbidden", __func__, path);
		ret = -EACCES;
		goto out;
	}

	fd = openat(relpath.dirfd, relpath.filename, O_WRONLY | O_NOFOLLOW);
	if (fd == -1) {
		ret = -errno;
		goto out;
	}

	ret = ftruncate(fd, size);
	if (ret == -1)
		ret = -errno;

	close(fd);

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_truncate(struct client *client, union cli_packet_data *clid,
			   size_t size, union srv_packet *srvd)
{
	struct cli_truncate *cli;
	struct srv_error *srv;
	off_t trunc_size;
	char *path;

	cli = &clid->truncate;
	srv = &srvd->error;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	trunc_size = cli->size;
	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	/* XXX: check trunc_size */
	srv->error = safe_truncate(client, path, trunc_size);
	return sizeof(*srv);
}

static int safe_utimens(struct client *client, const char *path,
			const struct timespec times[2])
{
	struct relpath relpath;
	int flag, ret;

	debug("[o] utimens(\"%s\")", path);

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (!is_file_writeable(client->policy, &relpath)) {
		debug("%s: check_fs_policy (\"%s\") forbidden", __func__, path);
		ret = -EACCES;
		goto out;
	}

	flag = AT_SYMLINK_NOFOLLOW;
	ret = utimensat(relpath.dirfd, relpath.filename, times, flag);
	if (ret == -1)
		ret = -errno;

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_utimens(struct client *client, union cli_packet_data *clid,
			  size_t size, union srv_packet *srvd)
{
	struct cli_utimens *cli;
	struct srv_error *srv;
	char *path;

	cli = &clid->utimens;
	srv = &srvd->error;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	srv->error = safe_utimens(client, path, cli->ts);
	return sizeof(*srv);
}

static int safe_open(struct client *client, const char *path, int flags)
{
	struct relpath relpath;
	int error, fd, ret;
	struct stat st;
	bool ok;

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (flags & (O_WRONLY | O_RDWR))
		ok = is_file_writeable(client->policy, &relpath);
	else
		ok = is_file_readable(client->policy, &relpath);

	if (!ok) {
		debug("[-] open(\"%s\", %d) forbidden", path, flags);
		ret = -EACCES;
		goto out;
	}

	/* if filename is a symlink, fsclient should have resolved it, so
	 * O_NOFOLLOW is correct */
	fd = openat(relpath.dirfd, relpath.filename, flags | O_NOFOLLOW);
	if (fd == -1) {
		ret = -errno;
		goto out;
	}

	error = fstat(fd, &st);
	if (error != 0) {
		ret = -errno;
		close(fd);
		debug("[-] open failed: stat failed: %s", strerror(errno));
		goto out;
	}

	/* permissions for directories are different */
	if (S_ISDIR(st.st_mode)) {
		close(fd);
		ret = safe_opendir(client, path);
		goto out;
	}

	if (!S_ISREG(st.st_mode)) {
		ret = -EPERM;
		close(fd);
		debug("[-] open failed: not a regular file or a directory");
		goto out;
	}

	/* Instructs kernel to prefetch regular files opened as read-only.
	 * Those files are very likely to be read by subsequent calls from the
	 * client. */
	if (!(flags & (O_WRONLY | O_RDWR))) {
		if (readahead(fd, 0, st.st_size) != 0)
			warn("readahead");
	}

	ret = fd;

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_open(struct client *client, union cli_packet_data *clid,
		       size_t size, union srv_packet *srvd)
{
	struct cli_open *cli;
	struct srv_open *srv;
	int fd, flags;
	char *path;

	cli = &clid->open;
	srv = &srvd->open;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	if (!fd_available(client)) {
		warnx("open: no fd available");
		srv->error = -ENFILE;
		srv->fh = 0;
		return sizeof(*srv);
	}

	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	debug("[o] open(\"%s\", %08o)", path, cli->flags);

	flags = cli->flags;
	if (flags & O_DIRECTORY) {
		srv->error = -EINVAL;
		srv->fh = 0;
		debug("[-] open(\"%s\", %d) failed: invalid flags", path,
		      flags);
		goto out;
	}

	/* From fuse.h:
	 *
	 * No creation (O_CREAT, O_EXCL) and by default also no
	 * truncation (O_TRUNC) flags will be passed to open(). If an
	 * application specifies O_TRUNC, fuse first calls truncate()
	 * and then open(). Only if 'atomic_o_trunc' has been
	 * specified and kernel version is 2.6.24 or later, O_TRUNC is
	 * passed on to open. */
	if (flags & (O_CREAT | O_EXCL | O_TRUNC))
		warnx("%s: wtf! %d", __func__, flags);
	flags &= ~(O_CREAT | O_EXCL | O_TRUNC);

	fd = safe_open(client, path, flags);
	if (fd >= 0) {
		srv->error = 0;
		srv->fh = (uint64_t)add_opened_file(client, fd);
	} else {
		srv->error = fd;
	}

out:
	//debug("[*] open(\"%s\", %d) = %ld %d", path, flags, srv->fh, srv->error);
	return sizeof(*srv);
}

static ssize_t do_read(struct client *client, union cli_packet_data *clid, size_t size,
		union srv_packet *srvd)
{
	struct cli_read *cli;
	struct srv_read *srv;
	size_t read_size;
	unsigned int fh;
	off_t read_off;
	int fd;

	cli = &clid->read;
	srv = &srvd->read;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	fh = (unsigned int)cli->fh;
	read_size = cli->size;
	read_off = cli->off;

	//debug("[*] read(%d, buf, %ld) at %ld", fh, read_size, read_off);

	fd = get_fd(client, fh);
	if (fd == -1) {
		debug("[-] do_read: invalid file handle %d", fh);
		srv->error = -EBADF;
		return sizeof(*srv);
	}

	/* error is ignored */
	/*if (lseek(fd, cli->off, SEEK_SET) == -1)
	  warnx("do_read: lseek(%ld)", cli->off);*/

	if (read_size > MAX_SIZE)
		read_size = MAX_SIZE;

	srv->buf.size = pread(fd, srv->buf.buf, read_size, read_off);
	//debug("[*] do_read: %ld", srv->buf.size);
	if (srv->buf.size == (size_t)-1) {
		srv->error = -errno;
		return sizeof(*srv);
	} else {
		srv->error = (int)srv->buf.size;
		return sizeof(*srv) + srv->buf.size;
	}
}

static ssize_t do_write(struct client *client, union cli_packet_data *clid, size_t size,
			union srv_packet *srvd)
{
	size_t write_size, count;
	struct cli_write *cli;
	struct srv_error *srv;
	unsigned int fh;
	off_t write_off;
	char *write_buf;
	int fd;

	cli = &clid->write;
	srv = &srvd->error;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	write_buf = cli->buf.buf;
	write_size = cli->buf.size;
	if (!valid_buf(write_buf, write_size, clid, size)) {
		warnx("%s: invalid write size", __func__);
		return -1;
	}

	fh = (unsigned int)cli->fh;
	write_off = cli->off;

	//debug("[*] %s(%d, buf, %ld) at %ld", __func__, fh, write_size, write_off);

	fd = get_fd(client, fh);
	if (fd == -1) {
		debug("[-] %s: invalid file handle %d", __func__, fh);
		srv->error = -EBADF;
		return sizeof(*srv);
	}

	count = pwrite(fd, write_buf, write_size, write_off);
	//debug("[*] %s: %ld", __func__, count);
	if (count == (size_t)-1)
		srv->error = -errno;
	else
		srv->error = (int)count;

	return sizeof(*srv);
}

static ssize_t do_release(struct client *client, union cli_packet_data *clid, size_t size,
			union srv_packet *srvd)
{
	struct cli_release *cli;
	struct srv_error *srv;
	unsigned int fh;

	cli = &clid->release;
	srv = &srvd->error;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	fh = (unsigned int)cli->fh;
	//debug("[*] release(%d)", fh);

	srv->error = remove_opened_file(client, fh);
	if (srv->error != 0) {
		srv->error = -EBADF;
		debug("[-] release failed");
	}

	return sizeof(*srv);
}

static int safe_opendir(struct client *client, const char *path)
{
	struct relpath relpath;
	int fd, ret;

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (!is_dir_readable(client->policy, &relpath)) {
		debug("[-] opendir(\"%s\") forbidden", path);
		ret = -EACCES;
		goto out;
	}

	fd = openat(relpath.dirfd, relpath.filename, O_DIRECTORY | O_NOFOLLOW);
	if (fd == -1) {
		ret = -errno;
		debug("[-] opendir(\"%s\") failed", path);
		goto out;
	}

	ret = fd;

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_opendir(struct client *client, union cli_packet_data *clid,
			  size_t size, union srv_packet *srvd)
{
	struct srv_opendir *srv;
	struct cli_path *cli;
	char *path;
	int ret;

	cli = &clid->path;
	srv = &srvd->opendir;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	if (!fd_available(client)) {
		warnx("opendir: no fd available");
		srv->error = -ENFILE;
		srv->fh = 0;
		return sizeof(*srv);
	}

	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	ret = safe_opendir(client, path);
	if (ret >= 0) {
		srv->error = 0;
		srv->fh = (uint64_t)add_opened_file(client, ret);
	} else {
		srv->error = ret;
		srv->fh = 0;
	}

	return sizeof(*srv);
}

static ssize_t do_readdir(struct client *client, union cli_packet_data *clid, size_t size,
			union srv_packet *srvd)
{
	struct cli_readdir *cli;
	struct srv_readdir *srv;
	struct linux_dirent *dirp;
	unsigned int fh, count;
	int fd, bytes;

	cli = &clid->readdir;
	srv = &srvd->readdir;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	fh = (unsigned int)cli->fh;

	fd = get_fd(client, fh);
	if (fd == -1) {
		debug("[-] do_readdir: invalid file handle %d", fh);
		srv->error = -EBADF;
		return sizeof(*srv);
	}

	dirp = (struct linux_dirent *)srv->buf;
	count = MAX_SIZE;
	bytes = syscall(SYS_getdents, fd, dirp, count);

	if (bytes == -1) {
		srv->error = -errno;
		return sizeof(*srv);
	} else {
		srv->error = bytes;
		return sizeof(*srv) + bytes;
	}
}

static int safe_create(struct client *client, const char *path, int flags,
		       mode_t mode)
{
	struct relpath relpath;
	int fd, ret;

	debug("[o] create(\"%s, %d, %04o\")", path, flags, mode);

	ret = open_directory(client->procfd, path, &relpath);
	if (ret != 0)
		return ret;

	if (!is_file_writeable(client->policy, &relpath)) {
		debug("[-] open(\"%s\", %d) forbidden", path, flags);
		ret = -EACCES;
		goto out;
	}

	fd = openat(relpath.dirfd, relpath.filename, flags | O_NOFOLLOW, mode);
	if (fd == -1) {
		ret = -errno;
		goto out;
	}

	ret = fd;

out:
	close(relpath.dirfd);
	return ret;
}

static ssize_t do_create(struct client *client, union cli_packet_data *clid,
			 size_t size, union srv_packet *srvd)
{
	struct cli_create *cli;
	struct srv_create *srv;
	int fd, flags;
	mode_t mode;
	char *path;

	cli = &clid->create;
	srv = &srvd->create;

	if (size < sizeof(*cli)) {
		warnx("%s: invalid size", __func__);
		return -1;
	}

	flags = cli->flags;
	mode = cli->mode;
	path = get_path(clid, size, &cli->path);
	if (path == NULL) {
		warnx("%s: invalid path", __func__);
		return -1;
	}

	/* XXX */
	flags &= (O_CREAT | O_TRUNC | O_RDWR | O_WRONLY | O_RDONLY | O_APPEND);
	if (!(flags & O_CREAT)) {
		warnx("%s: no O_CREAT flag", __func__);
		srv->error = -EINVAL;
		goto out;
	}

	fd = safe_create(client, path, flags, mode);
	if (fd >= 0) {
		srv->error = 0;
		srv->fh = (uint64_t)add_opened_file(client, fd);
	} else {
		srv->error = fd;
	}

out:
	return sizeof(*srv);
}

static server_op_t server_op[] = {
	do_getattr,
	do_readlink,
	do_mkdir,
	do_unlink,
	do_rmdir,
	do_symlink,
	do_rename,
	do_link,
	do_chmod,
	do_chown,
	do_truncate,
	do_utimens,
	do_open,
	do_read,
	do_write,
	do_release,
	do_opendir,
	do_readdir,
	do_release,
	do_create,
	do_statfs,
};

ssize_t handle_request(struct client *client, struct cli_packet *cli,
		       union srv_packet *srvd)
{
	return server_op[cli->type](client, &cli->d, cli->size, srvd);
}
