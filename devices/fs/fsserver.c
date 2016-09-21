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
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>

#include "mount.h"
#include "mount_handler.h"
#include "uuid.h"
#include "protocol.h"
#include "policy.h"
#include "userland.h"
#include "child.h"
#include "overlay.h"
#include "xchan.h"
#include "fsserver_op.h"

struct policies *policies;
char version[] = GIT_VERSION;

struct serve_arg {
	struct cli_packet *cli;
	struct policy *policy;
	union srv_packet *srv;
	struct xchan *xchan;
	int procfd;
	uid_t uid;
	gid_t gid;
};

static int fix_dynamic_policy_array(struct array *array, char *home)
{
	unsigned int i;
	regex_t *preg;
	char *regexp;
	int ret;

	if (array == NULL)
		return -1;

	for (i = 0; i < array->n; i++) {
		if (array->files[i].preg != NULL)
			continue;

		preg = malloc(sizeof(*preg));
		if (preg == NULL) {
			warn("malloc");
			return -1;
		}

		regexp = array->files[i].regexp;
		regexp = replace_home(regexp, home);
		if (regexp == NULL) {
			fprintf(stderr, "replace_home failed (out of memory)");
			return -1;
		}

		ret = regcomp(preg, regexp, REG_NOSUB | REG_EXTENDED);
		if (ret != 0) {
			fprintf(stderr, "regcomp failed on \"%s\" (%d)", regexp,
				ret);
			return -1;
		}

		free(array->files[i].regexp);

		array->files[i].regexp = regexp;
		array->files[i].preg = preg;
	}

	return 0;
}

/* compile missing regexps relying on a dynamic pattern (eg: home) */
static int fix_dynamic_policy(struct policy *policy, uid_t uid)
{
	struct passwd *pwd;
	char *home;

	pwd = getpwuid(uid);
	if (pwd == NULL) {
		warn("getpwuid");
		return -1;
	}

	home = pwd->pw_dir;

	if (fix_dynamic_policy_array(policy->fs.files_r, home) != 0)
		return -1;

	if (fix_dynamic_policy_array(policy->fs.files_w, home) != 0)
		return -1;

	if (fix_dynamic_policy_array(policy->fs.files_x, home) != 0)
		return -1;

	if (fix_dynamic_policy_array(policy->fs.dir_r, home) != 0)
		return -1;

	if (fix_dynamic_policy_array(policy->fs.dir_x, home) != 0)
		return -1;

	return 0;
}

/* general informations */
static void init_mount_point(struct mount_point *mp, const char *base_dir,
			     uid_t uid, gid_t gid, struct policy *policy)
{
	memset(mp, -1, sizeof(*mp));
	mp->uid = uid;
	mp->gid = gid;
	mp->base_dir = base_dir;
	mp->policy = policy;
}

/* informations specific to a filesystem */
static int fill_mount_point(struct mount_point *mp, struct capsule_fs *fs)
{
	struct uuid uuid;

	mp->fs = fs;

	mp->mhandler = mount_handler_by_type(fs->type);
	if (mp->mhandler == NULL) {
		warnx("invalid root fstype");
		return -1;
	}

	if (uuid_name_generate(fs->path, &uuid) != 0) {
		warnx("cannot generate uuid");
		return -1;
	}

	uuid_print(uuid, mp->uuid, sizeof(mp->uuid));

	return 0;
}

static int mount_miscfs(struct capsule_filesystems *filesystems,
			struct mount_point *mp,
			char *root_dir)
{
	struct capsule_fs *fs;
	char target[PATH_MAX];
	unsigned int i;

	for (i = 0; i < filesystems->nmiscfs; i++) {
		fs = filesystems->miscfs[i];

		/* /run/user/1000/cappsule/fs/unrestricted/overlay/$(uuid "/")/home */
		snprintf(target, sizeof(target), "%s/%s", root_dir, fs->path);

		if (fill_mount_point(mp, fs) != 0)
			return -1;

		if (mount_capsule_fs(mp, target) != 0) {
			fprintf(stderr, "failed to mount miscfs \"%s\"",
				fs->path);
			return -1;
		}
	}

	return 0;
}

/**
 * Mount shared folders.
 *
 * Build a new capsule_filesystems structure to mount shared folders using
 * "direct" filesystem type.
 */
static int mount_shared_folders(struct mount_point *mp, char *root_dir)
{
	struct capsule_filesystems filesystems;
	struct array *folders;
	struct passwd *pwd;
	unsigned int i;
	int ret;

	folders = mp->policy->shared.folders;
	if (folders == NULL)
		return 0;

	pwd = getpwuid(mp->uid);
	if (pwd == NULL) {
		warnx("cannot find user for uid %u", mp->uid);
		return -1;
	}

	filesystems.nmiscfs = folders->n;
	filesystems.miscfs = alloc_misc_filesystems(folders->n);
	if (filesystems.miscfs == NULL) {
		warn("malloc");
		return -1;
	}

	ret = 0;
	for (i = 0; i < folders->n; i++ ) {
		char *folder, *shared_dir;
		struct capsule_fs *fs;

		folder = folders->folders[i].folder;
		shared_dir = replace_home(folder, pwd->pw_dir);
		if (shared_dir == NULL) {
			ret = -1;
			break;
		}

		fs = filesystems.miscfs[i];
		fs->type = FS_MOUNT_TYPE_DIRECT_ACCESS;
		strncpy(fs->path, shared_dir, sizeof(fs->path));
		free(shared_dir);

	}

	if (ret == 0)
		ret = mount_miscfs(&filesystems, mp, root_dir);

	free_misc_filesystems(&filesystems);

	return ret;
}

static struct serve_arg *init(struct child_arg *arg)
{
	struct serve_arg *serve_arg;
	char root_dir[PATH_MAX];
	struct cli_packet *cli;
	union srv_packet *srv;
	struct policy *policy;
	struct mount_point mp;
	struct xchan *xchan;
	err_t error;
	int procfd;

	if (prctl(PR_SET_PDEATHSIG, CHILD_DEATH_SIGNAL) == -1) {
		warn("prctl");
		return NULL;
	}

	policy = get_policy_by_uuid(policies, &arg->policy_uuid);
	if (policy == NULL) {
		warnx("bad policy uuid");
		return NULL;
	}

	error = set_logfile(arg->capsule_id, "fsserver.log");
	if (error) {
		print_error(error, "failed to set logfile");
		reset_saved_errno();
	}

	printf("[*] policy: %s\n", policy->name);
	printf("[*] uid=%d gid=%d\n", arg->uid, arg->gid);

	/* Unshare the mount namespace. mount/umount calls don't affect parent
	 * mount namespace anymore. It allows several capsules to use the same
	 * filesystem. As a side effect, unmounting filesystem at fsserver exit
	 * isn't required anymore. */
	if (unshare(CLONE_NEWNS) != 0) {
		warn("failed to unshare mount namespace");
		return NULL;
	}

	/* ensure that new mount points aren't shared with parent namespace */
	if (mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL) != 0) {
		warn("failed to make / private");
		return NULL;
	}

	init_mount_point(&mp, arg->fs.base_dir, arg->uid, arg->gid, policy);
	if (init_capsule_filesystems(&mp) != 0)
		return NULL;

	/* mount capsule root filesystem */
	if (fill_mount_point(&mp, &arg->fs.rootfs) != 0)
		return NULL;

	/* /run/user/1000/cappsule/fs/unrestricted/overlay/$(uuid "/")/ */
	fmt_fs_dir(root_dir, sizeof(root_dir), &mp);

	if (mount_capsule_fs(&mp, root_dir) != 0) {
		fprintf(stderr, "failed to mount capsule filesystem");
		return NULL;
	}

	/* mount misc filesystems */
	if (mount_miscfs(&arg->fs, &mp, root_dir) != 0)
		return NULL;

	/*  mount shared folders */
	if (mount_shared_folders(&mp, root_dir) != 0)
		return NULL;

	install_network_config(root_dir);

	error = xchan_trusted_init(arg->capsule_id, XCHAN_FS, &xchan);
	if (error) {
		print_error(error, "failed to init xchan");
		return NULL;
	}

	procfd = open("/proc/self/fd", O_DIRECTORY);
	if (procfd == -1) {
		warn("open(\"/proc/self/fd\")");
		return NULL;
	}

	if (chroot(root_dir) == -1) {
		warn("chroot(%s)", root_dir);
		close(procfd);
		return NULL;
	}

	if (chdir("/") == -1) {
		warn("chdir /");
		close(procfd);
		return NULL;
	}

	if (setgid(arg->gid) != 0) {
		warn("setgid");
		close(procfd);
		return NULL;
	}

	if (setuid(arg->uid) != 0) {
		warn("setuid");
		close(procfd);
		return NULL;
	}

	/* parent process death signal is reset after setuid */
	if (prctl(PR_SET_PDEATHSIG, CHILD_DEATH_SIGNAL) == -1) {
		warn("prctl");
		close(procfd);
		return NULL;
	}

	if (fix_dynamic_policy(policy, arg->uid) != 0)
		return NULL;

	cli = calloc(1, sizeof(*cli) + MAX_SIZE);
	srv = calloc(1, sizeof(*srv) + MAX_SIZE);
	if (cli == NULL || srv == NULL) {
		warn("malloc");
		free(cli);
		free(srv);
		close(procfd);
		return NULL;
	}

	/* ensure umask is set to 0, otherwise some system calls may not apply
	 * specified permissions */
	umask(0);

	error = xchan_accept(xchan);
	if (error) {
		print_error(error, "failed to accept fs client");
		free(cli);
		free(srv);
		close(procfd);
		return NULL;
	}

	serve_arg = (struct serve_arg *)malloc(sizeof(*serve_arg));
	if (serve_arg == NULL) {
		warn("malloc");
		free(cli);
		free(srv);
		close(procfd);
		return NULL;
	}

	serve_arg->cli = cli;
	serve_arg->srv = srv;
	serve_arg->policy = policy;
	serve_arg->xchan = xchan;
	serve_arg->uid = arg->uid;
	serve_arg->gid = arg->gid;
	serve_arg->procfd = procfd;

	return serve_arg;
}

static void serve(struct serve_arg *arg)
{
	struct cli_packet *cli;
	union srv_packet *srv;
	struct client client;
	size_t offset;
	ssize_t size;
	err_t error;

	cli = arg->cli;
	srv = arg->srv;

	client.n = 0;
	client.policy = arg->policy;
	client.procfd = arg->procfd;
	client.uid = getuid();
	client.gid = getgid();
	client.xchan = arg->xchan;
	memset(client.fd, -1, sizeof(client.fd));

	while (1) {
		offset = offsetof(struct cli_packet, d);
		error = xchan_recvall(client.xchan, cli, offset);
		if (error) {
			print_error(error, "failed to receive packet header");
			break;
		}

		if (cli->size > MAX_SIZE) {
			warnx("packet too big (%d: %ld)", cli->type, cli->size);
			break;
		}

		error = xchan_recvall(client.xchan, (char *)&cli->d, cli->size);
		if (error) {
			print_error(error, "failed to receive packet");
			break;
		}

		if (cli->type >= CPSL_MAX) {
			warnx("unknown packet type %d", cli->type);
			break;
		}

		/* If fsserver runs as root and the uid or gid of the capsule's
		 * process invoking the operation changed, update fsuid and
		 * fsgid. Otherwise, all accesses to the filesystem are made as
		 * root. */
		if (arg->uid == 0) {
			if (client.uid != cli->uid || client.gid != cli->gid) {
				setfsuid(cli->uid);
				if (setfsuid(-1) != (int)cli->uid) {
					warn("setfsuid(%d)", cli->uid);
					break;
				}

				setfsgid(cli->gid);
				if (setfsgid(-1) != (int)cli->gid) {
					warn("setfsgid(%d)", cli->gid);
					break;
				}

				client.uid = cli->uid;
				client.gid = cli->gid;
			}
		}

		size = handle_request(&client, cli, srv);
		if (size < 0)
			break;

		error = xchan_sendall(client.xchan, srv, size);
		if (error) {
			print_error(error, "failed to set packet");
			break;
		}
	}

	close(client.procfd);

	free(cli);
	free(srv);
	exit(EXIT_SUCCESS);
}

static void usage(char *filename)
{
	fprintf(stderr, "%s [option...]\n\n", filename);
	fprintf(stderr, "  -n, --no-monitor <policies dir>\trun without monitor\n");
	fprintf(stderr, "  -v, --version\tdisplay the version number\n");
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	struct device device;
	char *policies_path;
	int c, nomonitor;
	err_t error;

	struct option long_options[] = {
		{ "no-monitor", required_argument, NULL, 'n' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	init_children();
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	nomonitor = 0;
	policies_path = POLICIES_PATH;

	while (1) {
		c = getopt_long(argc, argv, "n:v", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'n':
			nomonitor = 1;
			policies_path = optarg;
			break;
		case 'v':
			display_version(argv[0], version, 1);
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	display_version(argv[0], version, 0);

	if (overlay_init() != 0) {
		fprintf(stderr, "failed to determine if overlay filesystem is configured in the kernel\n");
		exit(EXIT_FAILURE);
	}

	error = parse_configuration_files(policies_path, &policies);
	if (error) {
		print_error(error, "failed to parse configuration files in %s",
			    policies_path);
		exit(EXIT_FAILURE);
	}

	if (signal(SIGCHLD, sigchld_handler) == SIG_ERR)
		err(EXIT_FAILURE, "signal");

	device.type = DEVICE_FS;
	device.policies_path = policies_path;
	device.policies = &policies;
	device.init = init;
	device.serve = serve;
	device.prepare_child = NULL;
	device.child_created = NULL;
	device.cleanup_child = NULL;

	if (nomonitor) {
		device.notif_fd = -1;
		debug_device(&device);
		exit(EXIT_SUCCESS);
	}

	connect_to_monitor(&device.notif_fd);

	while (1) {
		handle_notif_msg(&device);
	}

	free_policies(policies);
	close(device.notif_fd);

	return 0;
}

// vim: noet:ts=8:
