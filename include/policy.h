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

#ifndef POLICY_H
#define POLICY_H

#include <netinet/in.h>
#include <stdbool.h>
#include <regex.h>

#include "error.h"
#include "uuid.h"

#define HOME_PATTERN	"@HOME@"

enum policy_type {
	POLICY_FS,
	POLICY_NETWORK,
};

enum fs_access_type {
	ACCESS_FILE_READ,
	ACCESS_FILE_WRITE,
	ACCESS_DIR_READ,
	ACCESS_DIR_EXEC,
};

enum net_protocol {
	NETWORK_TCP,
	NETWORK_UDP
};

struct fs_value {
	char *regexp;
	regex_t *preg;
};

struct net_value {
	in_addr_t min_ipaddr;
	in_addr_t max_ipaddr;
	short min_port;
	short max_port;
};

struct shared_value {
	char *folder;
};

struct array {
	unsigned int n;
	union {
		struct fs_value files[0];
		struct net_value hosts[0];
		struct shared_value folders[0];
	};
};

struct fs_policy {
	struct array *files_r;
	struct array *files_w;
	struct array *files_x;

	struct array *dir_r;
	struct array *dir_x;
};

struct shared_folders_policy {
	struct array *folders;
};

struct network_policy {
	struct array *tcp;
	struct array *udp;
};

struct policy {
	char *name;
	struct uuid uuid;
	int window_color;
	struct fs_policy fs;
	struct network_policy net;
	struct shared_folders_policy shared;
};

struct policies {
	struct policy **p;
	int n;
};

struct policy *get_policy_by_uuid(struct policies *policies, struct uuid *uuid);

void free_policy(struct policy *policy);
err_t parse_configuration_files(const char *path, struct policies **r_policies);
void free_policies(struct policies *policies);
err_t reload_policies(const char *policy_path, struct policies **r_policies);

struct cappsule_ioc_policies;
err_t build_exec_policies(struct policies *, struct cappsule_ioc_policies *);
char *replace_home(const char *template, const char *home);


#endif /* POLICY_H */

// vim: noet:ts=8:sw=8:
