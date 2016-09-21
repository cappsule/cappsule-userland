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

#include <err.h>
#include <stdarg.h>
#include <string.h>

#include <json-c/json.h>

#include "json.h"
#include "userland.h"
#include "devices.h"
#include "readall.h"


static int build_json_request(char *buf, size_t bufsize, ...)
{
	struct json_object *jobj, *val;
	const char *key;
	va_list argptr;
	const char *p;
	int ret;

	ret = -1;

	jobj = json_object_new_object();
	if (jobj == NULL)
		return -1;

	va_start(argptr, bufsize);
	while (1) {
		key = va_arg(argptr, const char *);
		if (key == NULL)
			break;

		val = va_arg(argptr, struct json_object *);
		if (val == NULL) {
			fprintf(stderr, "failed to get json value \"%s\"\n",
				key);
			goto out;
		}

		json_object_object_add(jobj, key, val);
	}
	va_end(argptr);

	p = json_object_to_json_string(jobj);
	if (p == NULL)
		goto out;

	strncpy(buf, p, bufsize-1);
	buf[bufsize-1] = '\x00';
	ret = 0;

out:
	if (jobj != NULL)
		json_object_put(jobj);
	return ret;
}

static struct json_object *api_request(char *req)
{
	struct json_object *json, *jobj, *result;
	char buf[4096];
	err_t error;
	bool found;
	int s;

	s = connect_to_abstract_socket(SOCK_STREAM, API_SOCKET);
	if (s == -1) {
		warn("can't connect to %s", API_SOCKET);
		return NULL;
	}

	error = send_json(s, req);
	if (error) {
		print_error(error, "failed to send json request");
		close(s);
		return NULL;
	}

	error = recv_json(s, buf, sizeof(buf));
	if (error) {
		print_error(error, "failed to receive json request");
		close(s);
		return NULL;
	}

	close(s);

	json = json_tokener_parse(buf);
	if (is_error(json)) {
		fprintf(stderr, "failed to parse json\n");
		return NULL;
	}

	found = json_object_object_get_ex(json, "success", &jobj);
	if (!found || !json_object_get_boolean(jobj)) {
		fprintf(stderr, "json request (%s) failed\n", req);
		json_object_put(json);
		return NULL;
	}

	if (!json_object_object_get_ex(json, "result", &result)) {
		fprintf(stderr, "error in json response, no result field\n");
		json_object_put(json);
		return NULL;
	}

	json_object_get(result);
	json_object_put(json);

	return result;
}

static int get_value(struct json_object *json, const char *name, int *value)
{
	struct json_object *jobj;

	if (!json_object_object_get_ex(json, name, &jobj)) {
		fprintf(stderr, "failed to get json value (%s)\n", name);
		return -1;
	}

	*value = json_object_get_int(jobj);

	return 0;
}

static const char *get_str_value(struct json_object *json, const char *name)
{
	struct json_object *jobj;
	const char *value;

	if (!json_object_object_get_ex(json, name, &jobj)) {
		fprintf(stderr, "failed to get json value (%s)\n", name);
		return NULL;
	}

	value = json_object_get_string(jobj);
	if (value == NULL) {
		fprintf(stderr, "failed to get json value (%s)\n", name);
		return NULL;
	}

	return value;
}

int get_capsule_creds(int capsule_id, struct capsule_creds *creds)
{
	struct json_object *json, *creds_obj;
	const char *uuid;
	char req[128];
	int ret;

	ret = build_json_request(req, sizeof(req),
				 "cmd", json_object_new_string("get_info"),
				 "type", json_object_new_string("creds"),
				 "id", json_object_new_int(capsule_id),
				 NULL);
	if (ret != 0)
		return -1;

	json = api_request(req);
	if (json == NULL)
		return -1;

	if (!json_object_object_get_ex(json, "creds", &creds_obj)) {
		fprintf(stderr, "no creds information for capsule %d\n", capsule_id);
		ret = -1;
		goto out;
	}

	uuid = get_str_value(creds_obj, "policy_uuid");
	if (uuid == NULL || uuid_from_str(uuid, &creds->policy_uuid) != 0) {
		ret = -1;
		goto out;
	}

	ret = 0;
	ret |= get_value(creds_obj, "pid", &creds->pid);
	ret |= get_value(creds_obj, "uid", (int *)&creds->uid);
	ret |= get_value(creds_obj, "gid", (int *)&creds->gid);

out:
	json_object_put(json);
	return ret;
}

static const char *get_string(struct json_object *rootfs_obj, const char *name)
{
	struct json_object *jobj;
	const char *p;

	if (!json_object_object_get_ex(rootfs_obj, name, &jobj)) {
		fprintf(stderr, "failed to get \"%s\"\n", name);
		return NULL;
	}

	p = json_object_get_string(jobj);
	if (p == NULL) {
		fprintf(stderr, "failed to get \"%s\" string\n", name);
		return NULL;
	}

	return p;
}

int get_capsule_rootfs(int capsule_id, struct capsule_filesystems *fs)
{
	struct json_object *json, *rootfs_obj;
	const char *p, *rootfs_type;
	char req[128];
	int ret;

	ret = build_json_request(req, sizeof(req),
				"cmd", json_object_new_string("get_info"),
				"type", json_object_new_string("rootfs"),
				"id", json_object_new_int(capsule_id),
				NULL);
	if (ret != 0)
		return -1;

	json = api_request(req);
	if (json == NULL)
		return -1;

	if (!json_object_object_get_ex(json, "rootfs", &rootfs_obj)) {
		fprintf(stderr, "no rootfs information for capsule %d\n",
			capsule_id);
		ret = -1;
		goto out;
	}

	rootfs_type = get_str_value(rootfs_obj, "type");
	if (rootfs_type == NULL) {
		ret = -1;
		goto out;
	}

	fs->rootfs.type = mount_type_from_name(rootfs_type);
	if (fs->rootfs.type == FS_MOUNT_TYPE_INVALID) {
		ret = -1;
		goto out;
	}

	p = get_string(rootfs_obj, "path");
	if (p == NULL) {
		ret = -1;
		goto out;
	}
	strncpy(fs->rootfs.path, p, sizeof(fs->rootfs.path));

	p = get_string(rootfs_obj, "basedir");
	if (p == NULL) {
		ret = -1;
		goto out;
	}
	strncpy(fs->base_dir, p, sizeof(fs->base_dir));

	ret = 0;

out:
	json_object_put(json);
	return ret;
}

int get_capsule_miscfs(int capsule_id, struct capsule_filesystems *filesystems)
{
	struct json_object *json, *miscfs_obj;
	char req[128];
	size_t i, n;
	int ret;

	ret = build_json_request(req, sizeof(req),
				"cmd", json_object_new_string("get_info"),
				"type", json_object_new_string("miscfs"),
				"id", json_object_new_int(capsule_id),
				NULL);
	if (ret != 0)
		return -1;

	json = api_request(req);
	if (json == NULL)
		return -1;

	if (!json_object_object_get_ex(json, "miscfs", &miscfs_obj)) {
		fprintf(stderr, "no miscfs information for capsule %d\n",
			capsule_id);
		ret = -1;
		goto out;
	}

	ret = 0;
	n = json_object_array_length(miscfs_obj);
	if (n == 0)
		goto out;

	if (n % 2 != 0) {
		warnx("invalid miscfs array size (%ld)", n);
		ret = -1;
		goto out;
	}

	filesystems->nmiscfs = n / 2;
	filesystems->miscfs = alloc_misc_filesystems(n / 2);
	if (filesystems->miscfs == NULL) {
		ret = -1;
		goto out;
	}

	for (i = 0; i < n; i += 2) {
		struct json_object *jobj1, *jobj2;
		const char *path, *type;
		struct capsule_fs *fs;

		jobj1 = json_object_array_get_idx(miscfs_obj, i);
		jobj2 = json_object_array_get_idx(miscfs_obj, i + 1);

		path = json_object_get_string(jobj1);
		type = json_object_get_string(jobj2);

		fs = filesystems->miscfs[i / 2];
		strncpy(fs->path, path, sizeof(fs->path));
		fs->type = mount_type_from_name(type);
		if (fs->type == FS_MOUNT_TYPE_INVALID) {
			free_misc_filesystems(filesystems);
			warnx("invalid fs->type (%s)", type);
			ret = -1;
			goto out;
		}
	}

out:
	json_object_put(json);
	return ret;
}

int get_capsule_display(int capsule_id, char *display, size_t size)
{
	struct json_object *json;
	const char *p;
	char req[128];
	int ret;

	ret = build_json_request(req, sizeof(req),
				"cmd", json_object_new_string("get_info"),
				"type", json_object_new_string("display"),
				"id", json_object_new_int(capsule_id),
				NULL);
	if (ret != 0)
		return -1;

	json = api_request(req);
	if (json == NULL)
		return -1;

	p = get_str_value(json, "display");
	if (p == NULL) {
		ret = -1;
		goto out;
	}

	strncpy(display, p, size);

	ret = 0;

out:
	json_object_put(json);
	return ret;
}
