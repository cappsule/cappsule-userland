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

#ifndef DEVICES_H
#define DEVICES_H

#include <stdbool.h>

#define SOCKET_TIMEOUT		5

enum device_type {
	DEVICE_CONSOLE,
	DEVICE_FS,
	DEVICE_NET,
	DEVICE_GUI,

	NR_DEVICES
};

struct devices_sockets {
	unsigned nr_devices;
	int fds[NR_DEVICES];
};

enum notif_msg_type {
	NOTIFICATION_RELOAD_POLICIES,
	NOTIFICATION_CAPSULE_CREATED,
	NOTIFICATION_CAPSULE_EXIT,
};

struct notif_msg {
	enum notif_msg_type type;
	unsigned int capsule_id;
	bool no_gui;
} __attribute__((packed));

enum device_event_type {
	DEVICE_EVENT_DEVICE_READY,
	DEVICE_EVENT_CREATE_IGNORED,
	DEVICE_EVENT_CREATE_FAILURE,
};

struct device_event {
	unsigned int capsule_id;
	enum device_type type;
	enum device_event_type event;
} __attribute__((packed));

struct capsule_creds;
struct capsule_filesystems;
struct devices_sockets;
struct policies;

struct devices_sockets *run_devices(bool no_gui, bool no_console);
int notify_devices_of_capsule_exit(unsigned int capsule_id,
				   struct devices_sockets *notif);
int notify_devices_of_capsule_creation(unsigned int capsule_id,
				       struct devices_sockets *notif,
				       bool no_gui);
int notify_devices_of_policies_reload(struct devices_sockets *notif);

int get_capsule_creds(int capsule_id, struct capsule_creds *creds);
int get_capsule_rootfs(int capsule_id, struct capsule_filesystems *fs);
int get_capsule_miscfs(int capsule_id, struct capsule_filesystems *fs);
int get_capsule_display(int capsule_id, char *display, size_t size);

#endif

// vim: noet:ts=8:sw=8:
