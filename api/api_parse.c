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
#include <stdarg.h>
#include <sys/user.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <limits.h>
#include <poll.h>
#include <sys/time.h>

#include <json-c/json.h>

#include "api.h"
#include "json.h"
#include "params.h"
#include "policy.h"
#include "readall.h"
#include "fs_mount_type.h"
#include "userland.h"
#include "vm_exit.h"
#include "vmcall_str.h"
#include "cuapi/error.h"
#include "cuapi/trusted/channel.h"
#include "cuapi/common/stats.h"

/* default limit if not given by virt: 1024MB = 1GB */
#define MEM_DEFAULT_LIMIT	1024

#define ERRMSG_SIZE		256
#define SET_ERRMSG(fmt, ...)	snprintf(errmsg, ERRMSG_SIZE, fmt, ##__VA_ARGS__)

#define JSON_NO_RESPONSE	(struct json_object *)0x7

struct json_param {
	char *key;
	enum json_type type;
	int (*f)(struct context *, struct params *, struct json_object *);
	bool mandatory;
};

struct api_cmd {
	const char *name;
	struct json_object *(*f)(struct context *ctx, struct client *, int, struct json_object *);
};


static int build_string_from_json_array(struct json_object *array, char *str,
					size_t max_size)
{
	struct json_object *jobj;
	size_t i, n, len, size;
	const char *val;
	char *p;

	size = json_object_array_length(array);
	p = str;
	n = 1;	/* for last null byte */

	for (i = 0; i < size; i++) {
		jobj = json_object_array_get_idx(array, i);
		val = json_object_get_string(jobj);
		len = strlen(val) + 1;

		n += len;
		if (n >= max_size) {
			fprintf(stderr, "too much arg or env\n");
			return -1;
		}

		memcpy(p, val, len);
		p += len;
	}

	*p = '\x00';
	return 0;
}

static struct json_object *build_json_array_from_strings(const char *str)
{
	struct json_object *array_obj, *str_obj;

	array_obj = json_object_new_array();
	if (array_obj == NULL)
		return NULL;

	while (*str) {
		str_obj = json_object_new_string(str);
		if (str_obj == NULL || json_object_array_add(array_obj, str_obj) < 0) {
			json_object_put(str_obj);
			json_object_put(array_obj);
			return NULL;
		}

		str += strlen(str) + 1;
	}

	return array_obj;
}

static struct json_object *vbuild_json_object(size_t size, va_list ap)
{
	struct json_object *jobj;
	unsigned i;

	jobj = json_object_new_object();
	if (jobj == NULL)
		return NULL;

	for (i = 0; i < size; i++) {
		const char *key = va_arg(ap, const char *);
		struct json_object *val = va_arg(ap, struct json_object *);

		/* XXX: check return value once json-c returns one */
		json_object_object_add(jobj, key, val);
	}

	return jobj;
}

static struct json_object *build_json_object(size_t size, ...)
{
	va_list ap;
	struct json_object *jobj;

	va_start(ap, size);
	jobj = vbuild_json_object(size, ap);
	va_end(ap);

	return jobj;
}

/**
 * Build a json error given @msg.
 *
 * A copy of the @msg string is made and the memory is managed by the
 * json_object.
 */
struct json_object *build_json_error(const char *msg)
{
	struct json_object *jobj, *jfalse, *reason_str;

	jfalse = json_object_new_boolean(FALSE);
	if (jfalse == NULL)
		return NULL;

	reason_str = json_object_new_string(msg);
	if (reason_str == NULL) {
		json_object_put(jfalse);
		return NULL;
	}

	jobj = build_json_object(2, "success", jfalse, "error", reason_str);
	if (jobj == NULL) {
		json_object_put(jfalse);
		json_object_put(reason_str);
	}

	return jobj;
}

struct json_object *build_json_result(size_t size, ...)
{
	struct json_object *jobj, *jtrue, *result_obj;
	va_list ap;

	jtrue = json_object_new_boolean(TRUE);
	if (jtrue == NULL)
		return NULL;

	va_start(ap, size);
	result_obj = vbuild_json_object(size, ap);
	va_end(ap);

	if (result_obj == NULL) {
		json_object_put(jtrue);
		return NULL;
	}

	jobj = build_json_object(2, "success", jtrue, "result", result_obj);
	if (jobj == NULL) {
		json_object_put(jtrue);
		json_object_put(result_obj);
	}

	return jobj;
}

static int add_json_result(struct json_object *jobj, const char *key, struct json_object *val)
{
	struct json_object *result_obj;

	if (!json_object_object_get_ex(jobj, "result", &result_obj))
		return -1;

	json_object_object_add(result_obj, key, val);
	return 0;
}

static int get_policy_uuid(struct policies *policies, const char *name,
			   struct uuid *uuid)
{
	int i;

	for (i = 0; i < policies->n; i++) {
		if (strcmp(policies->p[i]->name, name) == 0) {
			*uuid = policies->p[i]->uuid;
			return 0;
		}
	}

	return -1;
}

/**
 * Ensure each array element are of type string.
 *
 * @return true if array is valid, false otherwise
 */
static bool validate_array(struct json_object *array)
{
	struct json_object *val;
	int i, len;

	len = json_object_array_length(array);
	for (i = 0; i < len; i++) {
		val = json_object_array_get_idx(array, i);
		if (json_object_get_type(val) != json_type_string)
			return false;
	}

	return true;
}

static int set_policy(struct context *ctx, struct params *params,
		      struct json_object *val)
{
	const char *p;

	if (ctx->policies == NULL)
		return -1;

	p = json_object_get_string(val);
	if (get_policy_uuid(ctx->policies, p, &params->policy_uuid) != 0) {
		//fprintf(stderr, "invalid policy \"%s\"", p);
		return -1;
	}

	return 0;
}

static int set_no_gui(struct context *UNUSED(ctx), struct params *params,
		      struct json_object *val)
{
	params->shared.no_gui = json_object_get_boolean(val);
	return 0;
}

static int set_display(struct context *UNUSED(ctx), struct params *params,
		       struct json_object *val)
{
	const char *p;
	size_t size;

	p = json_object_get_string(val);
	size = sizeof(params->display);
	strncpy(params->display, p, size);
	params->display[size-1] = '\x00';
	return 0;
}

static int set_rootfs(struct context *UNUSED(ctx), struct params *params,
		      struct json_object *val)
{
	const char *p;
	size_t size;

	p = json_object_get_string(val);
	size = sizeof(params->fs.rootfs.path);
	strncpy(params->fs.rootfs.path, p, size);
	params->fs.rootfs.path[size-1] = '\x00';

	return 0;
}

static int set_basedir(struct context *UNUSED(ctx), struct params *params,
		       struct json_object *val)
{
	const char *p;
	size_t size;

	p = json_object_get_string(val);
	size = sizeof(params->fs.base_dir);
	strncpy(params->fs.base_dir, p, size);
	params->fs.base_dir[size-1] = '\x00';

	return 0;
}

static int set_fstype(struct context *UNUSED(ctx), struct params *params,
		      struct json_object *val)
{
	const char *p;

	p = json_object_get_string(val);

	params->fs.rootfs.type = mount_type_from_name(p);
	if (params->fs.rootfs.type == FS_MOUNT_TYPE_INVALID)
		return -1;

	return 0;
}

static int set_miscfs(struct context *UNUSED(ctx), struct params *params,
		      struct json_object *val)
{
	size_t i, n;

	n = json_object_array_length(val);
	if (n == 0)
		return 0;

	if (n % 2 != 0) {
		warnx("invalid miscfs array size (%ld)", n);
		return -1;
	}

	params->fs.nmiscfs = n / 2;
	params->fs.miscfs = alloc_misc_filesystems(n / 2);
	if (params->fs.miscfs == NULL)
		return -1;

	for (i = 0; i < n; i += 2) {
		struct json_object *jobj1, *jobj2;
		const char *path, *type;
		struct capsule_fs *fs;

		jobj1 = json_object_array_get_idx(val, i);
		jobj2 = json_object_array_get_idx(val, i + 1);
		path = json_object_get_string(jobj1);
		type = json_object_get_string(jobj2);

		fs = params->fs.miscfs[i / 2];
		strncpy(fs->path, path, sizeof(fs->path));
		fs->type = mount_type_from_name(type);
		if (fs->type == FS_MOUNT_TYPE_INVALID) {
			free_misc_filesystems(&params->fs);
			return -1;
		}
	}

	return 0;
}

static int set_cwd(struct context *UNUSED(ctx), struct params *params,
		   struct json_object *val)
{
	const char *p;
	size_t size;

	p = json_object_get_string(val);
	size = sizeof(params->shared.cwd);
	strncpy(params->shared.cwd, p, size);
	params->shared.cwd[size-1] = '\x00';

	return 0;
}

static int set_groups(struct context *UNUSED(ctx), struct params *params,
		      struct json_object *val)
{
	const char *p;
	size_t size;

	p = json_object_get_string(val);
	size = sizeof(params->shared.groups);
	strncpy(params->shared.groups, p, size);
	params->shared.groups[size-1] = '\x00';

	return 0;
}

static int set_argv(struct context *UNUSED(ctx), struct params *params,
		    struct json_object *val)
{
	size_t size;

	size = sizeof(params->shared.argv);
	return build_string_from_json_array(val, params->shared.argv, size);
}

static int set_env(struct context *UNUSED(ctx), struct params *params,
		   struct json_object *val)
{
	size_t size;

	size = sizeof(params->shared.env);
	return build_string_from_json_array(val, params->shared.env, size);
}

static int set_tty(struct context *UNUSED(ctx), struct params *params,
		   struct json_object *val)
{
	char *p;
	unsigned int rows, cols;

	p = (char *) json_object_get_string(val);
	rows = strtol(p, &p, 10);

	if (*p++ != 'x')
		return -1;

	cols = strtol(p, &p, 10);
	if (*p != '\0')
		return -1;

	if (rows < 1 || rows > USHRT_MAX || cols < 1 || cols > USHRT_MAX)
		return -1;

	params->tty_size.ws_row = rows;
	params->tty_size.ws_col = cols;

	return 0;
}

static int set_memory(struct context *UNUSED(ctx), struct params *params,
		      struct json_object *val)
{
	params->memory_limit = json_object_get_int(val);
	return 0;
}

/**
 * Array of allowed parameters for "create" command.
 */
static struct json_param json_params[] = {
	{ "policy",  json_type_string,  set_policy,  true },
	{ "no-gui",  json_type_boolean, set_no_gui,  false },
	{ "display", json_type_string,  set_display, false },
	{ "rootfs",  json_type_string,  set_rootfs,  false },
	{ "basedir", json_type_string,  set_basedir, true },
	{ "fstype",  json_type_string,  set_fstype,  false },
	{ "miscfs",  json_type_array,   set_miscfs,  false },
	{ "cwd",     json_type_string,  set_cwd,     false },
	{ "groups",  json_type_string,  set_groups,  false },
	{ "argv",    json_type_array,   set_argv,    true },
	{ "env",     json_type_array,   set_env,     true },
	{ "tty",     json_type_string,  set_tty,     false },
	{ "memory",  json_type_int,     set_memory,  false },
};

static int parse_param(struct context *ctx, struct params *params, char *key,
		       struct json_object *val, bool *present, char *errmsg)
{
	struct json_param *jp;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(json_params); i++) {
		jp = &json_params[i];

		if (strcmp(jp->key, key) != 0)
			continue;

		if (present[i]) {
			SET_ERRMSG("key \"%s\" can't be set twice", key);
			return -1;
		}

		if (json_object_get_type(val) != jp->type) {
			SET_ERRMSG("bad type for \"%s\"", key);
			return -1;
		}

		if (jp->type == json_type_array) {
			if (!validate_array(val)) {
				SET_ERRMSG("invalid array \"%s\"", key);
				return -1;
			}
		}

		if (jp->f(ctx, params, val) != 0) {
			SET_ERRMSG("failed to set \"%s\"", key);
			return -1;
		}

		present[i] = true;

		return 0;
	}

	SET_ERRMSG("invalid key \"%s\"", key);
	return -1;
}

/**
 * Parse json parameters of "create" command.
 *
 * @return 0 on success, -1 on error
 */
static int parse_params(struct context *ctx, struct params *params,
			struct json_object *json, char *errmsg)
{
	bool present[ARRAY_SIZE(json_params)];
	struct json_object *jobj;
	struct json_param *jp;
	unsigned int i;
	bool exists;
	int ret;

	memset(present, 0, sizeof(present));

	exists = json_object_object_get_ex(json, "params", &jobj);
	if (!exists || json_object_get_type(jobj) != json_type_object) {
		SET_ERRMSG("failed to get params");
		return -1;
	}

	json_object_object_foreach(jobj, key, val) {
		ret = parse_param(ctx, params, key, val, present, errmsg);
		if (ret != 0)
			return -1;
	}

	/* ensure each mandatory key is present */
	for (i = 0; i < ARRAY_SIZE(json_params); i++) {
		jp = &json_params[i];
		if (jp->mandatory && !present[i]) {
			SET_ERRMSG("key \"%s\" is mandatory", jp->key);
			return -1;
		}
	}

	return 0;
}

/**
 * Create a capsule given JSON paramaters. If the capsule is successfuly
 * created, devices are notified of the creation.
 */
static struct json_object *cmd_create(struct context *ctx,
				      struct client *client,
				      int channel_fd,
				      struct json_object *json)
{
	struct pending_capsule *pending;
	char errmsg[ERRMSG_SIZE];
	struct capsule *capsule;
	struct params params;

	/* initialize params with default values */
	memset(&params, 0, sizeof(params));
	params.pid = client->ucred.pid;
	params.shared.uid = client->ucred.uid;
	params.shared.gid = client->ucred.gid;
	params.shared.no_gui = false;
	memset(params.display, '\x00', sizeof(params.display));
	strncpy(params.shared.cwd, "/", sizeof(params.shared.cwd));
	strncpy(params.shared.groups, "", sizeof(params.shared.groups));
	params.memory_limit = MEM_DEFAULT_LIMIT;

	params.fs.rootfs.type = FS_MOUNT_TYPE_OVERLAY;
	strncpy(params.fs.rootfs.path, "/", sizeof(params.fs.rootfs.path));
	params.fs.base_dir[0] = '\x00';
	params.fs.nmiscfs = 0;
	params.fs.miscfs = NULL;

	/* convert json to C structure */
	if (parse_params(ctx, &params, json, errmsg) != 0) {
		free_misc_filesystems(&params.fs);
		return build_json_error(errmsg);
	}

	capsule = create_capsule(channel_fd, &params, errmsg, sizeof(errmsg));
	if (capsule == NULL) {
		free_misc_filesystems(&params.fs);
		return build_json_error(errmsg);
	}

	if (notify_devices_of_capsule_creation(capsule->capsule_id,
					       ctx->notif,
					       params.shared.no_gui) == -1) {
		free_capsule(capsule);
		return build_json_error("cannot notify devices of capsule creation");
	}

	/* insert capsule in linked list */
	capsule->prev = NULL;
	if (ctx->capsules == NULL) {
		capsule->next = NULL;
	} else {
		ctx->capsules->prev = capsule;
		capsule->next = ctx->capsules;
	}
	ctx->capsules = capsule;

	/* insert capsule in pending list */
	pending = create_pending(ctx, capsule, client);
	if (pending == NULL) {
		free_capsule(capsule);
		return build_json_error("failed to create pending capsule");
	}

	/* This command doesn't return any json response. The capsule id (or an
	 * error) is sent later when each device is ready. */
	return JSON_NO_RESPONSE;
}

static unsigned int get_capsule_id(struct json_object *json)
{
	struct json_object *jobj;
	bool exists;

	exists = json_object_object_get_ex(json, "id", &jobj);
	if (!exists || json_object_get_type(jobj) != json_type_int)
		return (unsigned int)-1;

	return json_object_get_int(jobj);
}

static struct capsule *get_capsule(struct context *ctx,
				   struct json_object *json,
				   struct json_object **error)
{
	struct capsule *capsule;
	unsigned int capsule_id;
	char buf[128];

	capsule_id = get_capsule_id(json);
	if (capsule_id == (unsigned int)-1) {
		*error = build_json_error("failed to get capsule id");
		return NULL;
	}

	capsule = find_capsule_by_id(ctx, capsule_id);
	if (capsule == NULL) {
		snprintf(buf, sizeof(buf), "capsule id %d doesn't exist",
			 capsule_id);
		*error = build_json_error(buf);
		return NULL;
	}

	return capsule;
}

static struct json_object *build_creds_object(struct capsule *capsule)
{
	char uuid[UUID_STR_LENGTH+1];

	if (uuid_print(capsule->params.policy_uuid, uuid, sizeof(uuid)) != 0)
		return build_json_error("failed to get policy uuid");

	return build_json_object(4,
		"pid", json_object_new_int(capsule->ucred.pid),
		"uid", json_object_new_int(capsule->ucred.uid),
		"gid", json_object_new_int(capsule->ucred.gid),
		"policy_uuid", json_object_new_string(uuid));
}

static struct json_object *build_rootfs_object(struct capsule *capsule)
{
	const char *type;

	/* XXX: basedir isn't related to rootfs
	 * rootfs and miscfs may be merge into one call: fs */

	type = mount_type_to_name(capsule->params.fs.rootfs.type);
	return build_json_object(3,
		"type", json_object_new_string(type),
		"path", json_object_new_string(capsule->params.fs.rootfs.path),
		"basedir", json_object_new_string(capsule->params.fs.base_dir));
}

static struct json_object *build_miscfs_object(struct capsule *capsule)
{
	struct json_object *array_obj, *str_obj;
	struct capsule_fs *fs;
	unsigned int i, j;
	const char *p[2];

	array_obj = json_object_new_array();
	if (array_obj == NULL)
		return NULL;

	for (i = 0; i < capsule->params.fs.nmiscfs; i++) {
		fs = capsule->params.fs.miscfs[i];
		p[0] = fs->path;
		p[1] = mount_type_to_name(fs->type);

		for (j = 0; j < ARRAY_SIZE(p); j++) {
			str_obj = json_object_new_string(p[j]);
			if (str_obj == NULL) {
				json_object_put(array_obj);
				return NULL;
			}

			if (json_object_array_add(array_obj, str_obj) < 0) {
				json_object_put(str_obj);
				json_object_put(array_obj);
				return NULL;
			}
		}
	}

	return array_obj;
}

static struct json_object *cmd_get_info(struct context *ctx,
					struct client *UNUSED(client),
					int UNUSED(channel_fd),
					struct json_object *json)
{
	struct json_object *error, *type_obj, *result;
	struct capsule *capsule;
	const char *type = "*";
	static const char *valid_info_types[] = {
		"*", "creds", "display", "miscfs", "rootfs", "argv"
	};
	unsigned int i;
	bool is_valid_type;

	// Get capsule structure.
	capsule = get_capsule(ctx, json, &error);
	if (capsule == NULL)
		return error;

	// Get information type field and check it is valid.
	if (json_object_object_get_ex(json, "type", &type_obj))
		type = json_object_get_string(type_obj);

	is_valid_type = false;
	for (i = 0; i < sizeof(valid_info_types) / sizeof(valid_info_types[0]); i++) {
		if (!strcmp(type, valid_info_types[i])) {
			is_valid_type = true;
			break;
		}
	}
	if (!is_valid_type)
		return build_json_error("invalid type field");

	// Create result object.
	result = build_json_result(0);
	if (result == NULL)
		return NULL;

	// Append creds information if requested.
	if (!strcmp(type, "*") || !strcmp(type, "creds")) {
		struct json_object *creds;

		creds = build_creds_object(capsule);
		if (creds == NULL) {
			json_object_put(result);
			return NULL;
		}

		if (add_json_result(result, "creds", creds) < 0) {
			json_object_put(creds);
			json_object_put(result);
			return NULL;
		}
	}

	// Append rootfs information if requested.
	if (!strcmp(type, "*") || !strcmp(type, "rootfs")) {
		struct json_object *rootfs;

		rootfs = build_rootfs_object(capsule);
		if (rootfs == NULL) {
			json_object_put(result);
			return NULL;
		}

		if (add_json_result(result, "rootfs", rootfs) < 0) {
			json_object_put(rootfs);
			json_object_put(result);
			return NULL;
		}
	}

	// Append miscfs information if requested.
	if (!strcmp(type, "*") || !strcmp(type, "miscfs")) {
		struct json_object *miscfs;

		miscfs = build_miscfs_object(capsule);
		if (miscfs == NULL) {
			json_object_put(result);
			return NULL;
		}

		if (add_json_result(result, "miscfs", miscfs) < 0) {
			json_object_put(miscfs);
			json_object_put(result);
			return NULL;
		}
	}

	// Append argv information if requested.
	if (!strcmp(type, "*") || !strcmp(type, "argv")) {
		struct json_object *argv;

		argv = build_json_array_from_strings(capsule->params.shared.argv);
		if (argv == NULL) {
			json_object_put(result);
			return NULL;
		}

		if (add_json_result(result, "argv", argv) < 0) {
			json_object_put(argv);
			json_object_put(result);
			return NULL;
		}
	}

	// Append display information if requested.
	if (!strcmp(type, "*") || !strcmp(type, "display")) {
		struct json_object *display;

		display = json_object_new_string(capsule->params.display);
		if (display == NULL) {
			json_object_put(result);
			return NULL;
		}

		if (add_json_result(result, "display", display) < 0) {
			json_object_put(display);
			json_object_put(result);
			return NULL;
		}
	}

	return result;
}

static struct json_object *cmd_get_policies(struct context *ctx,
					    struct client *UNUSED(client),
					    int UNUSED(channel_fd),
					    struct json_object *UNUSED(json))
{
	struct policies *policies;
	json_object *policies_array;
	int i;

	policies = ctx->policies;
	policies_array = json_object_new_array();
	if (policies_array == NULL)
		return NULL;

	for (i = 0; i < policies->n; i++) {
		char uuid[UUID_STR_LENGTH+1] = {0};
		struct policy *policy = policies->p[i];
		json_object *policy_obj, *policy_name, *policy_uuid;

		policy_name = json_object_new_string(policy->name);
		if (policy_name == NULL) {
			json_object_put(policies_array);
			return NULL;
		}

		uuid_print(policy->uuid, uuid, sizeof(uuid));
		policy_uuid = json_object_new_string(uuid);
		if (policy_uuid == NULL) {
			json_object_put(policy_name);
			json_object_put(policies_array);
			return NULL;
		}

		policy_obj = build_json_object(2, "name", policy_name, "uuid", policy_uuid);
		if (policy_obj == NULL || json_object_array_add(policies_array, policy_obj) < 0) {
			json_object_put(policy_obj);
			json_object_put(policy_uuid);
			json_object_put(policy_name);
			json_object_put(policies_array);
		}
	}

	return build_json_result(1, "policies", policies_array);
}

static struct json_object *cmd_update_policies(struct context *ctx,
					       struct client *client,
					       int channel_fd,
					       struct json_object *json)
{
	if (reload_update_policies(ctx) != 0)
		return build_json_error("cannot update policies");

	return cmd_get_policies(ctx, client, channel_fd, json);
}

static inline uint64_t timespec_to_ns(struct timespec ts)
{
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static int build_intr_stats(json_object *intr_obj, struct capsule_stats *stats)
{
	json_object *nr_timer, *nr_xchan;

	nr_timer = json_object_new_int64(stats->nr_local_timer_intr);
	if (nr_timer == NULL)
		return -1;

	json_object_object_add(intr_obj, "local_timer", nr_timer);

	nr_xchan = json_object_new_int64(stats->nr_xchan_intr);
	if (nr_xchan == NULL)
		return -1;

	json_object_object_add(intr_obj, "xchan", nr_xchan);

	return 0;
}

static struct json_object *event_counter_to_jobj(struct event_counter *counter)
{
	json_object *event_obj, *count_obj, *time_obj;
	uint64_t count, elapsed;

	event_obj = json_object_new_object();
	if (event_obj == NULL)
		return NULL;

	count = counter->count;
	elapsed = timespec_to_ns(counter->elapsed_time);

	count_obj = json_object_new_int64(count);
	if (count_obj == NULL) {
		json_object_put(event_obj);
		return NULL;
	}

	json_object_object_add(event_obj, "count", count_obj);

	time_obj = json_object_new_int64(elapsed);
	if (time_obj == NULL) {
		json_object_put(event_obj);
		return NULL;
	}

	json_object_object_add(event_obj, "elapsed_time", time_obj);

	return event_obj;
}

static int build_vmcall_stats(json_object *vmcalls_obj,
			      struct capsule_stats *stats)
{
	const char *vmcall_name;
	json_object *event_obj;
	unsigned int i;

	for (i = 0; i < NR_CAPSULE_VM_CALLS; i++) {
		vmcall_name = vmcall_names[VMCALL_CAPSULE_START + i];
		event_obj = event_counter_to_jobj(&stats->vm_calls[i]);
		if (event_obj == NULL)
			return -1;

		json_object_object_add(vmcalls_obj, vmcall_name, event_obj);
	}

	return 0;
}

static int build_vmexit_stats(json_object *vmexits_obj,
			      struct event_counter *events,
			      size_t size)
{
	const char *vmexit_name;
	json_object *event_obj;
	unsigned int i;

	for (i = 0; i < size; i++) {
		event_obj = event_counter_to_jobj(&events[i]);
		if (event_obj == NULL)
			return -1;

		if (i >= ARRAY_SIZE(vm_exit_reasons) ||
		    vm_exit_reasons[i] == NULL) {
			vmexit_name = "?";
		} else {
			vmexit_name = vm_exit_reasons[i];
		}
		json_object_object_add(vmexits_obj, vmexit_name, event_obj);
	}

	return 0;
}

static struct json_object *cmd_get_stats(struct context *ctx,
					 struct client *UNUSED(client),
					 int channel_fd,
					 struct json_object *json)
{
	json_object *error, *jobj, *vmcalls_obj, *intr_obj, *switches_obj,
		*total_time_obj, *vm_exits_obj;
	struct capsule *capsule;
	struct cappsule_ioc_stats ioc_stats = {0};
	struct capsule_stats *stats = &ioc_stats.stats;
	size_t size;

	capsule = get_capsule(ctx, json, &error);
	if (capsule == NULL)
		return error;

	ioc_stats.capsule_id = capsule->capsule_id;
	if (ioctl(channel_fd, CAPPSULE_IOC_GET_CAPSULE_STATS, &ioc_stats) != 0) {
		error = build_json_error("failed to get capsule_stats");
		return error;
	}

	jobj = build_json_result(0);
	if (jobj == NULL)
		return NULL;

	// Set number of context switches.
	switches_obj = json_object_new_int64(stats->nr_switches);
	if (switches_obj == NULL || add_json_result(jobj, "context_switches", switches_obj) < 0) {
		json_object_put(switches_obj);
		json_object_put(jobj);
		return NULL;
	}

	// Set total number of time in capsule.
	total_time_obj = json_object_new_int64(timespec_to_ns(stats->total_elapsed_time));
	if (total_time_obj == NULL || add_json_result(jobj, "total_time", total_time_obj) < 0) {
		json_object_put(total_time_obj);
		json_object_put(jobj);
		return NULL;
	}

	// Build interrupt counters object.
	intr_obj = json_object_new_object();
	if (intr_obj == NULL || add_json_result(jobj, "interrupts", intr_obj) < 0) {
		json_object_put(intr_obj);
		json_object_put(jobj);
		return NULL;
	}

	if (build_intr_stats(intr_obj, stats) != 0) {
		json_object_put(jobj);
		return NULL;
	}

	// Build vmcall counters object.
	vmcalls_obj = json_object_new_object();
	if (vmcalls_obj == NULL || add_json_result(jobj, "vmcalls", vmcalls_obj) < 0) {
		json_object_put(vmcalls_obj);
		json_object_put(jobj);
		return NULL;
	}

	if (build_vmcall_stats(vmcalls_obj, stats) != 0) {
		json_object_put(jobj);
		return build_json_error("failed to build vmstats");
	}

	/* set vm_exits */
	vm_exits_obj = json_object_new_object();
	if (vm_exits_obj == NULL || add_json_result(jobj, "vmexits", vm_exits_obj) < 0) {
		json_object_put(vm_exits_obj);
		json_object_put(jobj);
		return NULL;
	}

	size = ARRAY_SIZE(stats->vm_exits);
	if (build_vmexit_stats(vm_exits_obj, stats->vm_exits, size) != 0) {
		json_object_put(jobj);
		return build_json_error("failed to build vmexits");
	}

	return jobj;
}

static struct json_object *cmd_get_capsule_ids(struct context *UNUSED(ctx),
					       struct client *UNUSED(client),
					       int channel_fd,
					       struct json_object *UNUSED(json))
{
	struct cappsule_ioc_list *ioc_list;
	struct json_object *ids_array;
	unsigned int i;
	int res;

	ioc_list = malloc(sizeof(ioc_list->nr_capsules) + MAX_CAPSULE * sizeof(unsigned int));
	if (ioc_list == NULL)
		return NULL;

	ioc_list->nr_capsules = MAX_CAPSULE;
	memset(ioc_list->capsule_ids, 0, MAX_CAPSULE * sizeof(unsigned int));

	if ((res = ioctl(channel_fd, CAPPSULE_IOC_LIST_CAPSULES, ioc_list)) < 0) {
		free(ioc_list);
		return build_json_error("failed to get capsule list");
	}

	ids_array = json_object_new_array();
	if (ids_array == NULL) {
		free(ioc_list);
		return NULL;
	}

	for (i = 0; i < ioc_list->nr_capsules; i++) {
		struct json_object *capsule_id;

		capsule_id = json_object_new_int(ioc_list->capsule_ids[i]);
		if (capsule_id == NULL || json_object_array_add(ids_array, capsule_id) < 0) {
			json_object_put(capsule_id);
			json_object_put(ids_array);
			free(ioc_list);
			return NULL;
		}
	}

	return build_json_result(1, "capsule_ids", ids_array);
}

static struct json_object *cmd_kill(struct context *ctx,
				    struct client *client,
				    int channel_fd,
				    struct json_object *json)
{
	unsigned int capsule_id;
	struct capsule *capsule;

	capsule_id = get_capsule_id(json);
	if (capsule_id == (unsigned int)-1)
		return build_json_error("missing capsule_id field");

	capsule = find_capsule_by_id(ctx, capsule_id);
	if (capsule == NULL)
		return build_json_error("invalid capsule id");

	if (client->ucred.uid != 0 && capsule->ucred.uid != client->ucred.uid)
		return build_json_error("permission denied");

	if (kill_capsule(channel_fd, capsule_id) != 0)
		return build_json_error("cannot kill capsule");

	return build_json_result(0);
}

static struct json_object *cmd_get_vmm_stats(struct context *UNUSED(ctx),
					     struct client *UNUSED(client),
					     int channel_fd,
					     struct json_object *json)
{
	json_object *error, *jobj, *xchan_obj, *vm_exits_obj;
	struct cappsule_ioc_vmm_stats ioc_stats;
	struct vmm_stats *stats;
	unsigned int cpu;
	size_t size;
	bool exists;

	exists = json_object_object_get_ex(json, "cpu", &jobj);
	if (!exists || json_object_get_type(jobj) != json_type_int)
		return build_json_error("failed to get cpu");

	cpu = json_object_get_int(jobj);

	memset(&ioc_stats, 0, sizeof(ioc_stats));
	ioc_stats.cpu = cpu;
	if (ioctl(channel_fd, CAPPSULE_IOC_GET_VMM_STATS, &ioc_stats) != 0) {
		error = build_json_error("failed to get vmm_stats");
		return error;
	}

	jobj = build_json_result(0);
	if (jobj == NULL)
		return NULL;

	/* set xchan_guest_notif */
	stats = &ioc_stats.stats;
	xchan_obj = event_counter_to_jobj(&stats->xchan_guest_notif);
	if (xchan_obj == NULL || add_json_result(jobj, "xchan_guest_notif", xchan_obj) < 0) {
		json_object_put(xchan_obj);
		json_object_put(jobj);
		return NULL;
	}

	/* set vm_exits */
	vm_exits_obj = json_object_new_object();
	if (vm_exits_obj == NULL || add_json_result(jobj, "vmexits", vm_exits_obj) < 0) {
		json_object_put(vm_exits_obj);
		json_object_put(jobj);
		return NULL;
	}

	size = ARRAY_SIZE(stats->vm_exits);
	if (build_vmexit_stats(vm_exits_obj, stats->vm_exits, size) != 0) {
		json_object_put(jobj);
		return build_json_error("failed to build vmexits");
	}

	return jobj;
}

static int create_listener(struct context *ctx, struct client *client, unsigned int capsule_id, unsigned events)
{
	struct event_listener *listener;

	listener = (struct event_listener *)malloc(sizeof(*listener));
	if (listener == NULL) {
		warn("malloc");
		return -1;
	}

	listener->client = client;
	listener->capsule_id = capsule_id;
	listener->event_bitmask = events;
	listener->prev = NULL;

	if (ctx->listeners != NULL)
		ctx->listeners->prev = listener;

	listener->next = ctx->listeners;
	ctx->listeners = listener;

	return 0;
}

struct event_listener *find_listener_by_client(struct context *ctx, struct client *client)
{
	struct event_listener *listener;

	for (listener = ctx->listeners; listener != NULL; listener = listener->next) {
		if (listener->client == client)
			return listener;
	}

	return NULL;
}

struct event_listener *find_listener_by_capsule(struct context *ctx, unsigned int capsule_id)
{
	struct event_listener *listener;

	for (listener = ctx->listeners; listener != NULL; listener = listener->next) {
		if (listener->capsule_id == capsule_id)
			return listener;
	}

	return NULL;
}

static struct json_object *cmd_listen_events(struct context *ctx,
					     struct client *client,
					     int UNUSED(channel_fd),
					     struct json_object *json)
{
	struct capsule *capsule;
	struct event_listener *listener;
	struct json_object *error;

	// Listen for events for the specified capsule.
	capsule = get_capsule(ctx, json, &error);
	if (capsule == NULL)
		return error;

	// Lookup if client is already listening for events.
	listener = find_listener_by_client(ctx, client);
	if (listener)
		return build_json_error("already listening for events");

	if (!capsule_devices_ready(ctx, capsule))
		return build_json_error("devices aren't ready");

	if (capsule_devices_error(capsule))
		return build_json_error("some device encountered an error");

	if (capsule_has_exited(capsule))
		return build_json_error("capsule has already exited");

	if (create_listener(ctx, client, capsule->capsule_id, EVENT_LISTEN_ALL) != 0)
		return build_json_error("cannot register listener for capsule");

	return build_json_result(0);
}

/**
 * Array of allowed commands.
 */
static struct api_cmd api_commands[] = {
	{ "create",          cmd_create },
	{ "kill",	     cmd_kill },
	{ "get_info",        cmd_get_info },
	{ "get_stats",       cmd_get_stats },
	{ "get_vmm_stats",   cmd_get_vmm_stats },
	{ "get_policies",    cmd_get_policies },
	{ "update_policies", cmd_update_policies },
	{ "get_capsule_ids", cmd_get_capsule_ids },
	{ "listen_events",   cmd_listen_events },
};

/**
 * Handle JSON request. JSON request string is parsed into a JSON object. Caller
 * is responsible of calling json_object_put() on the result.
 *
 * @param  buf JSON request
 * @return NULL on error, the JSON response otherwise
 */
struct json_object *api_action(struct context *ctx, struct client *client,
			       const char *buf, int channel_fd)
{
	struct json_object *json, *jcmd, *result;
	struct api_cmd *api_cmd;
	bool exists, found;
	const char *cmd;
	unsigned int i;

	/* parse json */
	json = json_tokener_parse(buf);
	if (is_error(json))
		return build_json_error("failed to parse json");

	/* ensure that the key "cmd" is present */
	exists = json_object_object_get_ex(json, "cmd", &jcmd);
	if (!exists || json_object_get_type(jcmd) != json_type_string) {
		json_object_put(json);
		return build_json_error("failed to get cmd");
	}

	/* call function associated to cmd */
	cmd = json_object_get_string(jcmd);
	found = false;
	for (i = 0; i < ARRAY_SIZE(api_commands) && !found; i++) {
		api_cmd = &api_commands[i];
		if (strcmp(api_cmd->name, cmd) == 0) {
			result = api_cmd->f(ctx, client, channel_fd, json);
			found = true;
		}
	}

	json_object_put(json);

	if (!found)
		result = build_json_error("invalid cmd");

	return result;
}

/**
 * Send response to client.
 *
 * @param  jobj JSON response object instance
 * @return 0 if response was successfuly sent, -1 otherwise
 */
int send_json_response(struct client *client, struct json_object *jobj)
{
	const char *p, *response;
	err_t error;

	if (jobj == JSON_NO_RESPONSE)
		return 0;

	response = "{\"success\": false, \"error\": \"internal error\"}";
	if (jobj != NULL) {
		p = json_object_to_json_string(jobj);
		if (p != NULL)
			response = p;
	}

	/* send response */
	error = send_json(client->c, response);

	/* release json object, response is now invalid */
	json_object_put(jobj);

	if (error) {
		print_error(error, "failed to send response to client");
		return -1;
	}

	return 0;
}
