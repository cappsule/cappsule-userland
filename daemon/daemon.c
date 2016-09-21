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
#include <ctype.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <asm/unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "userland.h"
#include "namespace.h"
#include "policy.h"
#include "exec.h"
#include "swap.h"
#include "devices.h"
#include "cuapi/error.h"
#include "cuapi/common/process.h"
#include "ramfs.h"

#define TMPDIR		"/run/shm/"
#define X11_UNIX	"/tmp/.X11-unix/X%d"
#define SYSCTL_RCU	"/sys/module/rcupdate/parameters/rcu_cpu_stall_suppress"
#define CPU_KERNEL_MAX	"/sys/devices/system/cpu/kernel_max"
#define CPU_ONLINE	"/sys/devices/system/cpu/cpu%d/online"
#define SYSCTL_IPV4_FORWARD	"/proc/sys/net/ipv4/ip_forward"
#define SYSCTL_VM_DROP_CACHES 	"/proc/sys/vm/drop_caches"

#define LOGGER			BIN_PATH "logger"
#define MODULE_HV		INSTALL_PREFIX "usr/share/cappsule/cappsule.ko"
#define MODULE_HV_NAME		"cappsule"
#define MODULE_GUEST		INSTALL_PREFIX "usr/share/cappsule/cappsule-guest.ko"
#define MODULE_GUEST_NAME	"cappsule_guest"

#define FSCLIENT_	"fsclient"
#define FSCLIENT	RAMFS "usr/bin/" FSCLIENT_
#define GUICLIENT	RAMFS "usr/bin/guiclient"
#define NETCLIENT	RAMFS "usr/bin/netclient"
#define SNAPSHOT	RAMFS "usr/bin/snapshot"
#define XORG		RAMFS "usr/lib/xorg/Xorg"
#define XORG_MODULES	RAMFS "usr/lib/xorg/modules/"
#define ACCEPT_SO	RAMFS "usr/lib/accept_override.so"
#define MOUNT_SO	RAMFS "usr/lib/mount_override.so"

/* find /run/shm/libs/ -type d | awk '{ print "\"" $1 ":\" \\"}' */
#define LD_LIBRARY_PATH "LD_LIBRARY_PATH="			\
	RAMFS "lib:"						\
	RAMFS "lib/x86_64-linux-gnu:"				\
	RAMFS "lib64:"						\
	RAMFS "usr/lib:"					\
	RAMFS "usr/lib/xorg/modules:"				\
	RAMFS "usr/lib/xorg/modules/input:"			\
	RAMFS "usr/lib/xorg/modules/drivers:"			\
	RAMFS "usr/lib/xorg/modules/extensions:"		\
	RAMFS "usr/lib/x86_64-linux-gnu:"			\
	RAMFS "usr/lib/x86_64-linux-gnu/dri:"

static int module_inserted, vmounted, ramfs_mounted;
static pid_t daemon_pid, xorg_pid, logger_pid;
static pid_t fsclient_pid, guiclient_pid, netclient_pid;
static int channel_fd;
static char rcu_cpu_stall_suppress;
static int *offlined_cpus;
static char **mounts;

char version[] = GIT_VERSION;


static void rmdir_(const char *pathname)
{
	if (rmdir(pathname) == -1) {
		if (errno != ENOENT)
			warn("rmdir(\"%s\")", pathname);
	}
}

static void insmod(const char *module_path)
{
	int fd;

	fd = open(module_path, O_RDONLY);
	if (fd == -1)
		err(1, "open(\"%s\")", module_path);

	if (syscall(__NR_finit_module, fd, "", 0) == -1) {
		if (errno <= CAPPSULE_ERRNO_BASE) {
			err(1, "finit_module");
		} else {
			errx(1, "can't launch hypervisor: %s",
			     hv_error_message(errno));
		}
	}

	close(fd);
}

static void rmmod(const char *name)
{
	int i;

	for (i = 0; i < 5; i++) {
		if (syscall(__NR_delete_module, name, O_NONBLOCK) == 0)
			break;

		if (errno == EWOULDBLOCK && i < 4)
			usleep(500000);
		else
			err(1, "delete_module");
	}
}

static void run_program(char **argv, pid_t *pid, char **env, char *logfile,
			pid_t netns_pid)
{
	int fd;

	*pid = fork();
	switch (*pid) {
	case -1:
		err(1, "fork");
	case 0:
		for (; *env != NULL; env++) {
			if (putenv(*env) == -1)
				err(1, "putenv");
		}

		if (logfile != NULL) {
			fd = creat(logfile, 0644);
			if (fd != -1) {
				dup2(fd, STDOUT_FILENO);
				dup2(fd, STDERR_FILENO);
				close(fd);
			}
		}

		if (netns_pid != -1 && join_netns(netns_pid) != 0)
			exit(EXIT_FAILURE);

		if (execvp(argv[0], argv) < 0)
			err(1, "execvp(\"%s\")", argv[0]);
	default:
		break;
	}

	printf("[*] %s running (pid: %d)\n", argv[0], *pid);
}

/* test connection through abstract unix socket address */
static int test_xorg_connection(int display_number)
{
	struct sockaddr_un un;
	char name[256];
	socklen_t len;
	int ret, sock;

	snprintf(name, sizeof(name), X11_UNIX, display_number);

	sock = create_abstract_socket(SOCK_STREAM, name, &un, &len);
	if (sock == -1)
		errx(1, "cannot create unix socket %s", name);

	ret = connect(sock, (struct sockaddr *)&un, len);
	close(sock);

	return (ret == 0);
}

/* don't know a better way of finding inactive X display other than that */
static int find_inactive_display(void)
{
	int display;

	for (display = 0; display < 10; display++) {
		if (!test_xorg_connection(display))
			return display;
	}

	return -1;
}

/* allow virtexec to know the display number of the encapsulated Xorg */
static void create_display_env_file(int display)
{
	mode_t mode;
	FILE *fp;

	mode = umask(S_IXUSR | S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH);

	fp = fopen(DISPLAY_ENV_FILE, "w");
	if (fp == NULL)
		err(1, "can't create " DISPLAY_ENV_FILE);
	if (fprintf(fp, "%d\n", display) < 0)
		err(1, "fprintf" DISPLAY_ENV_FILE);
	fclose(fp);

	umask(mode);
}

static int run_xorg(pid_t netns_pid)
{
	char display_env[32];
	char *argv[] = {
		XORG,
		"-modulepath", XORG_MODULES,
		"-config", CONFIG_PATH "xorg.conf",
		"-logfile", "/var/run/cappsule-xorg.log",
		"-nolisten", "tcp",
		display_env,
		NULL
	};
	char *env[] = {
		LD_LIBRARY_PATH,
		"LD_PRELOAD=" ACCEPT_SO,
		NULL
	};
	int display, i, status;
	pid_t pid;

	display = find_inactive_display();
	if (display == -1)
		errx(1, "can't find an inactive display");

	snprintf(display_env, sizeof(display_env), ":%d", display);
	run_program(argv, &xorg_pid, env, "/dev/null", netns_pid);

	/* Xorg runs in a different network namespace, hence the fork. */
	pid = fork();
	if (pid == -1) {
		err(EXIT_FAILURE, "fork");
	} else if (pid == 0) {
		if (netns_pid != -1 && join_netns(netns_pid) != 0)
			exit(EXIT_FAILURE);

		for (i = 0; i < 2000; i++) {
			if (test_xorg_connection(display))
				exit(EXIT_SUCCESS);
			usleep(1000);
		}

		exit(EXIT_FAILURE);
	}

	if (waitpid(pid, &status, 0) == -1)
		err(EXIT_FAILURE, "waitpid");

	if (!WIFEXITED(status))
		errx(EXIT_FAILURE, "failed to get exit status");

	if (WEXITSTATUS(status) != EXIT_SUCCESS)
		errx(EXIT_FAILURE, "xorg not running after 2 seconds");

	return display;
}

static void run_guiclient(int display, char *pipe_device_ready_w,
			  pid_t netns_pid)
{
	char display_env[32];
	char *env[] = { LD_LIBRARY_PATH, display_env, NULL };
	char *argv[] = { GUICLIENT, "-p", pipe_device_ready_w, NULL, NULL };
	struct pollfd pollfds;
	char c, strfd[32];
	int pipefd[2];
	int ret;

	if (pipe(pipefd) == -1)
		err(1, "pipe");

	snprintf(strfd, sizeof(strfd), "%d", pipefd[1]);
	argv[3] = strfd;

	snprintf(display_env, sizeof(display_env), "DISPLAY=:%d", display);
	run_program(argv, &guiclient_pid, env, NULL, netns_pid);

	close(pipefd[1]);

	/* once connection from guiclient to Xorg is established, guiclient
	 * writes something on pipe */
	printf("[*] waiting for xorg connection...\n");

	pollfds.fd = pipefd[0];
	pollfds.events = POLLIN | POLLERR;

	ret = poll(&pollfds, 1, SOCKET_TIMEOUT * 1000);
	if (ret <= 0)
		err(1, "guiclient error");

	if (read(pipefd[0], &c, sizeof(c)) != sizeof(c))
		err(1, "guiclient communication with Xorg failed");

	close(pipefd[0]);

	printf("[+] guiclient ready (%c)\n", c);
}

/* run fsclient and wait for fuse filesystem to be mounted */
static void run_fsclient(void)
{
	/* -f is required to run fsclient in foreground, otherwise pid fsclient
	 * pid can't be predicted. If multi-thread is not disabled (-s), each
	 * thread pid should be allowed to run in capsule. */
	char *argv[] = {
		FSCLIENT,
		"-s",
		"-f",
		"-o", "allow_other",
		"-o", "default_permissions",
		CAPSULE_FS,
		NULL
	};
	char *env[] = {
		LD_LIBRARY_PATH,
		"LD_PRELOAD=" MOUNT_SO,
		NULL
	};
	int mounted, i, ret;
	char line[4096];
	FILE *fp;

	mkdir(CAPSULE_FS, 0755);

	run_program(argv, &fsclient_pid, env, NULL, -1);

	/* wait for fuse fs to be mounted */
	mounted = 0;
	for (i = 0; i < 2000 && !mounted; i++) {
		usleep(1000);

		fp = fopen("/etc/mtab", "r");
		if (fp == NULL)
			err(1, "can't open /etc/mtab");
		while (fgets(line, sizeof(line), fp) != NULL) {
			ret = strncmp(line, FSCLIENT_, sizeof(FSCLIENT_) - 1);
			if (ret == 0) {
				mounted = 1;
				break;
			}
		}
		fclose(fp);
	}

	if (!mounted)
		errx(1, "fuse filesystem is not mounted after 2 seconds");

	i = strlen(line);
	line[i-1] = '\x00';
	printf("[*] fuse filesystem mounted (%s)\n", line);
}

static void run_netclient(char *pipe_device_ready_w)
{
	char *argv[] = { NETCLIENT, "--pipe", pipe_device_ready_w, NULL };
	char *env[] = { NULL };
	bool new_netns;
	int i;

	run_program(argv, &netclient_pid, env, NULL, -1);

	/* wait for the new network namespace */
	new_netns = false;
	for (i = 0; i < 2000; i++) {
		usleep(1000);
		if (is_net_namespace_different(netclient_pid)) {
			new_netns = true;
			break;
		}
	}

	if (!new_netns)
		errx(1, "netclient didn't create a new network namespace after 2 seconds\n");
}

static void run_logger(int debug)
{
	char *argv[] = { LOGGER, NULL, NULL };
	char *env[] = { NULL };

	if (debug)
		argv[1] = "--debug";

	run_program(argv, &logger_pid, env, NULL, -1);
}

/* don't keep filesystem which aren't in RAM */
static int skip_fstype(const char *fstype)
{
	const char **p, *fstypes[] = {
		"sysfs", "proc", "devtmpfs", "tmpfs", "cgroup", NULL
	};

	for (p = fstypes; *p != NULL; p++) {
		if (strcmp(*p, fstype) == 0)
			return 0;
	}

	return 1;
}

static void free_mounts(char **mounts)
{
	char **p;

	if (mounts == NULL)
		return;

	for (p = mounts; *p != NULL; p++)
		free(*p);

	free(mounts);
}

static char **add_fstab_entry(char **mounts, char *mount_point, int *n)
{
	char *p, **tmp;

	p = strdup(mount_point);
	if (p == NULL)
		err(1, "strdup");

	tmp = (char **) realloc(mounts, sizeof(*mounts) * (*n + 1));
	if (tmp == NULL)
		err(1, "realloc");

	tmp[*n] = p;
	*n = *n + 1;

	return tmp;
}

static char **parse_fstab(void)
{
	char *special_dirs[] = { "tmp_root", "tmp_chroot", NULL };
	char line[4096], mount_point[4096], fstype[128];
	char **mounts, **tmp, **p;
	int ret, n;
	FILE *fp;

	mounts = NULL;
	n = 0;

	fp = fopen("/proc/mounts", "r");
	while (fgets(line, sizeof(line), fp) != NULL) {
		ret = sscanf(line, "%*s %4095s %127s %*d %*d\n",
			mount_point, fstype);
		if (ret != 2) {
			warnx("failed to parse \"/proc/mounts\": %s", line);
			continue;
		}

		if (skip_fstype(fstype))
			continue;

		mounts = add_fstab_entry(mounts, mount_point, &n);
	}
	fclose(fp);

	for (p = special_dirs; *p != NULL; p++)
		mounts = add_fstab_entry(mounts, *p, &n);

	tmp = (char **) realloc(mounts, sizeof(*mounts) * (n + 1));
	if (tmp == NULL) {
		free_mounts(mounts);
		err(1, "realloc");
	}

	mounts = tmp;
	mounts[n] = NULL;

	return mounts;
}

/* Mount special directories into capsulefs.
 *
 * It doesn't require to write into capsulefs, only getattr. There's a special
 * case in fsclient to avoid any network request.
 *
 * XXX: it would be much cleaner to call mount() from fsclient, but there is a
 * deadlock because mount() freezes fsclient until it returns. Once thread are
 * supported, it'll be possible to fork() and call mount() from child.
 *
 * XXX: call this function from capsule_init?*/
static void mount_virtual_dirs(int do_mount)
{
	char **dir, *source, **p, **q, *tmp;
	char target[256];
	int error;

	if (do_mount) {
		mounts = parse_fstab();
	} else {
		if (mounts == NULL)
			return;

		/* reverse mounts list to unmount directory in reverse order */
		q = mounts;
		while (*(q + 1) != NULL)
			q++;

		for (p = mounts; p < q; p++, q--) {
			tmp = *q;
			*q = *p;
			*p = tmp;
		}
	}

	if (!do_mount) {
		/* udev may automatically mount /sys/fs/fuse/connections */
		const char *path = CAPSULE_FS "/sys/fs/fuse/connections";
		if (umount(path) != 0 && errno != EINVAL)
			warn("umount %s", path);
	}

	for (dir = mounts; *dir != NULL; dir++) {
		if (strcmp(*dir, "tmp_root") == 0) {
			/* bind /tmp/ to /run/shm/ outside chroot */
			strncpy(target, "/tmp/", sizeof(target));
			source = TMPDIR;
		} else if (strcmp(*dir, "tmp_chroot") == 0) {
			/* bind /tmp/ to /run/shm/ inside chroot */
			strncpy(target, CAPSULE_FS "/tmp/", sizeof(target));
			source = TMPDIR;
		} else {
			snprintf(target, sizeof(target), CAPSULE_FS "%s", *dir);
			source = *dir;
		}
		if (do_mount)
			error = mount(source, target, NULL, MS_BIND, NULL);
		else
			error = umount(target);

		if (error != 0)
			warn("%smount %s failed", do_mount ? "": "u", target);
	}

	vmounted = do_mount;

	if (!do_mount) {
		free_mounts(mounts);
		mounts = NULL;
	}
}

static int setup_channel(void)
{
	int channel_fd;

	channel_fd = open(CHANNEL_DEVICE, O_RDWR | O_CLOEXEC);
	if (channel_fd < 0)
		err(1, "open(\"%s\")", CHANNEL_DEVICE);

	return channel_fd;
}

static void kill_and_wait(const char *name, pid_t *pid)
{
	//fprintf(stderr,"%s(%s, %d)\n", __func__, name, *pid);
	if (*pid == -1)
		return;

	if (kill(*pid, SIGKILL) == -1)
		warn("cleanup: kill %s failed", name);

	if (waitpid(*pid, NULL, 0) == -1)
		warn("waitpid");

	*pid = -1;

	/* XXX: dirty, but libfuse doesn't seem to export any function to umount
	 * fuse filesystem */
	if (strcmp(name, FSCLIENT) == 0) {
		char *argv[] = { "/bin/fusermount", "-u", CAPSULE_FS, NULL };
		char *env[] = { NULL, NULL };
		pid_t child;

		run_program(argv, &child, env, NULL, -1);
		waitpid(child, NULL, 0);
	}
}

static void update_sysctl(const char *name, int set, char *value)
{
	int fd, flags;

	/* no effect if value never set or already restored */
	if (set && !isdigit(*value))
		return;

	flags = set ? O_WRONLY : O_RDONLY;
	fd = open(name, flags);
	if (fd == -1) {
		warn("open(\"%s\")", name);
		return;
	}

	if (!set) {
		if (read(fd, value, sizeof(*value)) != sizeof(*value)) {
			warn("read(\"%s\")", name);
			*value = '\x00';
		}
	} else {
		if (write(fd, value, sizeof(*value)) != sizeof(*value))
			warn("write(\"%s\")", name);
		*value = '\x00';
	}

	close(fd);
}

static void setup_net(int start)
{
	static int net_started = 0;
	static char ip_forward = 0;
	char enable;
	int status;

	if (start) {
		update_sysctl(SYSCTL_IPV4_FORWARD, 0, &ip_forward);
		if (ip_forward == '0') {
			enable = '1';
			update_sysctl(SYSCTL_IPV4_FORWARD, 1, &enable);
		}

		status = EXEC_CMD_QUIET("iptables", "-t", "nat", "-A",
					"POSTROUTING", "-j", "MASQUERADE",
					NULL);

		if (status != 0)
			errx(1, "network error: cannot setup NAT");

		net_started = 1;
	} else if (net_started) {
		if (ip_forward == '0')
			update_sysctl(SYSCTL_IPV4_FORWARD, 1, &ip_forward);

		status = EXEC_CMD_QUIET("iptables", "-t", "nat", "-D",
					"POSTROUTING", "-j", "MASQUERADE",
					NULL);

		if (status != 0)
			errx(1, "network error: cannot remove NAT rule");

		net_started = 0;
	}
}

static int readfile(char *path, bool fatal)
{
	FILE *fp;
	int n;

	fp = fopen(path, "r");
	if (fp == NULL) {
		if (fatal)
			err(1, "can't open \"%s\"", path);
		return -1;
	}

	if (fscanf(fp, "%d", &n) != 1)
		err(1, "failed to parse \"%s\"", path);

	fclose(fp);

	return n;
}

static void update_cpu_online(int cpu, char value, bool fatal)
{
	char path[256];
	FILE *fp;

	sprintf(path, CPU_ONLINE, cpu);

	fp = fopen(path, "w");
	if (fp == NULL) {
		if (!fatal) {
			warn("can't open \"%s\"", path);
			return;
		} else {
			err(1, "can't open \"%s\"", path);
		}
	}

	if (fwrite(&value, sizeof(value), 1, fp) != sizeof(value)) {
		if (!fatal)
			warn("fwrite \"%s\"", path);
		else
			err(1, "fwrite \"%s\"", path);
	}

	fclose(fp);
}

/* wait until every CPU except current are offlined */
static void wait_for_cpus_offlined(void)
{
	int n, ret;
	FILE *fp;

	do {
		usleep(1000);

		fp = fopen("/sys/devices/system/cpu/online", "r");
		if (fp == NULL)
			err(1, "can't open \"/sys/devices/system/cpu/online\"");

		ret = fscanf(fp, "%d\n", &n);
		fclose(fp);
	} while (ret != 1);
}

/* If offline, put every CPU offline (except boot cpu). Otherwise, restore CPUs
 * to their previous state. */
static void put_cpus_offline(bool offline)
{
	unsigned int cpu, ncpus;
	char c, path[256];

	/* not ideal, but easier to parse than /sys/devices/system/cpu/online */
	ncpus = readfile(CPU_KERNEL_MAX, true);

	if (offline) {
		offlined_cpus = (int *) calloc(ncpus, sizeof(*offlined_cpus));
		if (offlined_cpus == NULL)
			err(1, "malloc");

		for (cpu = 0; cpu < ncpus; cpu++) {
			sprintf(path, CPU_ONLINE, cpu);
			c = readfile(path, false);
			if (c == 1) {
				update_cpu_online(cpu, '0', true);
				offlined_cpus[cpu] = 1;
			}
		}

		wait_for_cpus_offlined();
	} else if (offlined_cpus != NULL) {
		for (cpu = 0; cpu < ncpus; cpu++) {
			if (offlined_cpus[cpu])
				update_cpu_online(cpu, '1', false);
		}

		free(offlined_cpus);
		offlined_cpus = NULL;
	}
}

static void cleanup(void)
{
	/* atexit registrations are inherited through fork. don't let this
	 * function be called twice. */
	if (getpid() != daemon_pid)
		return;

	status_update(DAEMON_STATUS_EXIT);

	update_sysctl(SYSCTL_RCU, 1, &rcu_cpu_stall_suppress);

	/* module must be removed after having closed channel and tun fd */
	if (channel_fd != -1) {
		close(channel_fd);
		channel_fd = -1;
	}

	if (vmounted)
		mount_virtual_dirs(0);

	kill_and_wait(XORG, &xorg_pid);
	kill_and_wait(FSCLIENT, &fsclient_pid);
	kill_and_wait(GUICLIENT, &guiclient_pid);
	kill_and_wait(NETCLIENT, &netclient_pid);
	kill_and_wait(LOGGER, &logger_pid);

	if (ramfs_mounted) {
		umount_ramfs();
		ramfs_mounted = 0;
	}

	if (module_inserted) {
		rmmod(MODULE_HV_NAME);
		rmmod(MODULE_GUEST_NAME);
		module_inserted = 0;
	}

	/* directory used by fsclient */
	/* TODO: recursive rm */
	rmdir_(CAPSULE_FS);

	setup_net(0);

	put_cpus_offline(0);

	unlink(DISPLAY_ENV_FILE);

	unlink(CAPPSULE_PID_FILE);

	status_unlink();
}

static void sigterm(int UNUSED(dummy))
{
	printf("[*] got SIGTERM, exiting\n");
	if (killpg(0, SIGTERM) != 0)
		fprintf(stderr, "failed to send SIGTERM to the process group\n");
	exit(0);
}

static void usage(char *filename)
{
	fprintf(stderr, "%s [option...]\n\n", filename);
	fprintf(stderr, "  -d, --debug\trun in foreground\n");
	fprintf(stderr, "  -n, --no-gui\tdisable gui\n");
	fprintf(stderr, "  -v, --version\tdisplay the version number\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int c, debug, display, flags, no_gui, ret, status;
	struct cappsule_ioc_policies exec_policies;
	struct swap_device_list *swap_devices;
	struct devices_sockets *notif;
	struct policies *policies;
	struct allowed_pids pids;
	int pipe_device_ready[2];
	char rcu_snapshot_value;
	char drop_all_caches = '3';
	char buf[32], buf2[32];
	err_t error;

	struct option long_options[] = {
		{ "debug", no_argument, NULL, 'd' },
		{ "no-gui", no_argument, NULL, 'n' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	module_inserted = 0;
	ramfs_mounted = 0;
	vmounted = 0;
	channel_fd = -1;
	fsclient_pid = -1;
	guiclient_pid = -1;
	netclient_pid = -1;
	xorg_pid = -1;
	logger_pid = -1;
	policies = NULL;

	rcu_cpu_stall_suppress = '\x00';
	offlined_cpus = NULL;
	debug = 0;
	no_gui = 0;

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	while (1) {
		c = getopt_long(argc, argv, "dnv", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'n':
			no_gui = 1;
			break;
		case 'v':
			display_version(argv[0], version, 1);
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	if (!debug)
		daemonize();

	display_version(argv[0], version, 0);

	if (getuid() != 0)
		errx(1, "not root");

	daemon_pid = getpid();
	if (atexit(cleanup) != 0)
		errx(1, "cannot set exit function");

	/* Create the cappsule run directory. */
	if (mkdir(CAPPSULE_RUN_DIR, 0755) != 0 && errno != EEXIST)
		err(1, "mkdir");

	error = status_update(DAEMON_STATUS_INIT);
	if (error) {
		print_error(error, "failed to update status");
		exit(EXIT_FAILURE);
	}

	umask(S_IRWXG | S_IRWXO);

	/* parse policies before forking, in order to exit on error */
	error = parse_configuration_files(POLICIES_PATH, &policies);
	if (error) {
		print_error(error, "failed to parse configuration files in %s",
			    POLICIES_PATH);
		exit(EXIT_FAILURE);
	}

	error = build_exec_policies(policies, &exec_policies);
	if (error) {
		print_error(error, "failed to build exec policies");
		exit(EXIT_FAILURE);
	}

	if (signal(SIGINT, sigterm) == SIG_ERR ||
	    signal(SIGTERM, sigterm) == SIG_ERR)
		err(1, "signal");

	/* ignore SIGPIPE, otherwise daemon is killed by this signal if monitor
	 * tries to send a notification to a device which has exited */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		err(1, "signal");

	/* ignore SIGHUP, used to inform api server to reload policies */
	if (signal(SIGHUP, SIG_IGN) == SIG_ERR)
		err(1, "signal");

	/* Unshare the mount namespace. If an error occurs while unmounting
	 * RAM or FUSE filesystems, it isn't an issue.
	 *
	 * Disable it until the following issues are fixed:
	 *  - there's a bug with mount namespaces and /proc/swaps,
	 *  - it breaks Docker integration. */
	if (0) {
		if (unshare(CLONE_NEWNS) != 0)
			err(1, "failed to unshare mount namespace");
	}

	insmod(MODULE_GUEST);
	insmod(MODULE_HV);
	module_inserted = 1;

	run_logger(debug);

	/* Create communication channel between hypervisor and userland. It
	 * can't be done after snapshot, because exec policies address must be
	 * in snapshot, allowing capsules to map them later. */
	channel_fd = setup_channel();

	/* pass exec policies to kernel */
	ret = ioctl(channel_fd, CAPPSULE_IOC_SET_EXEC_POLICIES, &exec_policies);
	if (ret < 0)
		err(1, "can't set exec policies");

	free(exec_policies.buf);

	error = mount_ramfs();
	if (error == SUCCESS) {
		ramfs_mounted = 1;
	} else {
		print_error(error, "failed to mount RAM filesystem");
		exit(EXIT_FAILURE);
	}

	/* Snapshot process (capsule_init) needs to known when device clients
	 * are ready. For example, netclient set up a network interface, and
	 * capsule_init shouldn't execute the target process if this interface
	 * isn't fully configured.
	 *
	 * Share a pipe between device clients and capsule_init to allow device
	 * clients to notify capsule_init. */
	if (pipe(pipe_device_ready) == -1)
		err(1, "pipe");

	snprintf(buf, sizeof(buf), "%d", pipe_device_ready[1]);

	/* clients need to be in snapshot */
	run_fsclient();
	run_netclient(buf);
	if (!no_gui) {
		display = run_xorg(netclient_pid);
		create_display_env_file(display);
		run_guiclient(display, buf, netclient_pid);
	}

	close(pipe_device_ready[1]);

	/* pass pids to kernel before snapshot */
	pids.pids[PID_INDEX_FS] = fsclient_pid;
	pids.pids[PID_INDEX_GUI] = (!no_gui) ? guiclient_pid : -1;
	pids.pids[PID_INDEX_NET] = netclient_pid;
	pids.pids[PID_INDEX_XORG] = (!no_gui) ? xorg_pid : -1;
	ret = ioctl(channel_fd, CAPPSULE_IOC_SET_PIDS, &pids);
	if (ret < 0)
		err(1, "can't set pids");

	mount_virtual_dirs(1);

	/* disables RCU's CPU stall detector in snapshot */
	rcu_snapshot_value = '1';
	update_sysctl(SYSCTL_RCU, 0, &rcu_cpu_stall_suppress);
	update_sysctl(SYSCTL_RCU, 1, &rcu_snapshot_value);

	/* Disable swap devices and flush fs cache. */
	printf("[*] Flushing swaps and caches...\n");
	sync();
	update_sysctl(SYSCTL_VM_DROP_CACHES, 1, &drop_all_caches);

	flags = fcntl(channel_fd, F_GETFD, 0);
	if (flags < 0)
		err(1, "failed to get fd flag");

	if (fcntl(channel_fd, F_SETFD, flags & ~FD_CLOEXEC) != 0)
		err(1, "failed to remove close-on-exec flag");

	error = swap_disable(&swap_devices);
	if (error) {
		print_error(error, "failed to stop swapping devices");
		exit(EXIT_FAILURE);
	}

	/* snapshot */
	put_cpus_offline(1);
	printf("[*] creating snapshot\n");

	snprintf(buf, sizeof(buf), "%d", channel_fd);
	snprintf(buf2, sizeof(buf2), "%d", pipe_device_ready[0]);

	if (!no_gui)
		ret = EXEC_CMD_NETNS(netclient_pid, SNAPSHOT, "-f", buf, "--pipe", buf2, NULL);
	else
		ret = EXEC_CMD_NETNS(netclient_pid, SNAPSHOT, "-f", buf, "--no-gui", "--pipe", buf2, NULL);

	put_cpus_offline(0);

	close(pipe_device_ready[0]);

	update_sysctl(SYSCTL_RCU, 1, &rcu_cpu_stall_suppress);

	/* Restore swap devices. */
	error = swap_restore(swap_devices);
	if (error) {
		print_error(error, "failed to restart swapping devices");
		exit(EXIT_FAILURE);
	}

	if (ret != 0)
		exit(1);

	if (fcntl(channel_fd, F_SETFD, flags) != 0)
		err(1, "failed to restore fd flag");

	/* no need for fsclient nor guiclient in trusted guest anymore */
	mount_virtual_dirs(0);
	kill_and_wait(FSCLIENT, &fsclient_pid);
	kill_and_wait(NETCLIENT, &netclient_pid);
	if (!no_gui) {
		kill_and_wait(XORG, &xorg_pid);
		kill_and_wait(GUICLIENT, &guiclient_pid);
	}

	if (ramfs_mounted) {
		umount_ramfs();
		ramfs_mounted = 0;
	}

	/* Setup NAT and IP forwarding. */
	setup_net(1);

	/* create notification sockets */
	notif = run_devices(no_gui, false);
	if (notif == NULL) {
		fprintf(stderr, "failed to run devices\n");
		exit(EXIT_FAILURE);
	}

	/* never returns except if an error occurs */
	status = run_api_server(channel_fd, policies, notif);

	free(policies);

	if (killpg(0, SIGTERM) != 0)
		fprintf(stderr, "failed to send SIGTERM to the process group\n");

	return status;
}

// vim: noet:ts=8:sw=8:
