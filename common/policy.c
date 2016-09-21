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

#define _DEFAULT_SOURCE
#include <err.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <arpa/inet.h>

#include <json-c/json.h>

#include "userland.h"
#include "policy.h"
#include "cuapi/common/exec_policy.h"

//#define DEBUG
#define CONF_EXTENSION	".json"

#define REGEXP_STAR	"[^/]*"
#define REGEXP_STARSTAR	".*"
#define REGEXP_DOT	"\\."
#define REGEXP_QUESTION	"[^/]"

/* Returns index of first delimiter found in string */
#define FIND_FIRST_DELIM(str, ...) 					\
	({ 								\
		char delims[] = { __VA_ARGS__ }; 			\
		unsigned int i; 					\
		char *found, *closest = (char *)str + strlen(str);	\
									\
		for (i = 0; i < sizeof(delims); i++ ) {			\
			found = strchr(str, delims[i]);			\
			if (found && found < closest)			\
				closest = found;			\
		}							\
									\
		(ptrdiff_t)(closest - str);				\
	})								\

/* x.x.x.x */
#define MIN_IPADDR_LENGTH 7
/* xxx.xxx.xxx.xxx */
#define MAX_IPADDR_LENGTH 15

struct policy *get_policy_by_uuid(struct policies *policies, struct uuid *uuid)
{
	struct policy *p;
	int i;

	for (i = 0; i < policies->n; i++) {
		p = policies->p[i];
		if (memcmp(&p->uuid, uuid, sizeof(p->uuid)) == 0)
			return p;
	}

	return NULL;
}

static void free_fs_array(struct array *array)
{
	int i;

	if (array == NULL)
		return;

	i = array->n;
	while (i-- > 0) {
		free(array->files[i].regexp);
		if (array->files[i].preg != NULL)
			regfree(array->files[i].preg);
	}
	free(array);
}

void free_policy(struct policy *policy)
{
	if (policy == NULL)
		return;

	free(policy->name);

	/* free filesystem arrays */
	free_fs_array(policy->fs.files_r);
	free_fs_array(policy->fs.files_w);
	free_fs_array(policy->fs.files_x);

	free_fs_array(policy->fs.dir_r);
	free_fs_array(policy->fs.dir_x);

	/* free network arrays */
	free(policy->net.tcp);
	free(policy->net.udp);

	memset(policy, 0x61, sizeof(*policy));
	free(policy);
}

#ifdef DEBUG
static void dump_fs_array(const char *name, struct array *array)
{
	unsigned int i;

	printf("[%s]\n", name);
	for (i = 0; array != NULL && i < array->n; i++)
		printf("\t%s\n", array->files[i].regexp);
	printf("\n");
}

static void dump_shared_array(const char *name, struct array *array)
{
	unsigned int i;

	printf("[%s]\n", name);
	for (i = 0; array != NULL && i < array->n; i++)
		printf("\t%s\n", array->folders[i].folder);
	printf("\n");
}

static void dump_net_array(const char *name, struct array *array)
{
	unsigned int i;
	struct sockaddr_in saddr_min, saddr_max;

	printf("[%s]\n", name);
	for (i = 0; array != NULL && i < array->n; i++) {
		saddr_min.sin_addr.s_addr = array->hosts[i].min_ipaddr;
		saddr_max.sin_addr.s_addr = array->hosts[i].max_ipaddr;

		printf("\t%s", inet_ntoa(saddr_min.sin_addr));
		printf("-%s : ", inet_ntoa(saddr_max.sin_addr));
		printf("%hu-%hu\n",
			array->hosts[i].min_port,
			array->hosts[i].max_port);
	}
	printf("\n");
}

static void dump_policy(struct policy *policy)
{
	printf("%s\n", policy->name);

	dump_fs_array("files_r", policy->fs.files_r);
	dump_fs_array("files_w", policy->fs.files_w);
	dump_fs_array("files_x", policy->fs.files_x);

	dump_fs_array("dir_r", policy->fs.dir_r);
	dump_fs_array("dir_x", policy->fs.dir_x);

	dump_shared_array("shared", policy->shared.folders);

	dump_net_array("tcp", policy->net.tcp);
	dump_net_array("udp", policy->net.udp);

	printf("--------\n\n");
}
#else
#  define dump_policy(x)	do { } while (0)
#endif

static struct array *fs_array_push(struct array *old, struct fs_value val)
{
	struct array *array;
	unsigned int n;

	if (old == NULL) {
		n = 0;
		array = (struct array *) malloc(sizeof(*array) + sizeof(val));
	}
	else {
		n = old->n;
		array = (struct array *) realloc(old, sizeof(*array) + (n+1) * sizeof(val));
	}

	if (array == NULL) {
		warn("realloc");
		return NULL;
	}

	array->files[n] = val;
	array->n = n + 1;

	return array;
}

static struct array *net_array_push(struct array *old, struct net_value val)
{
	struct array *array;
	unsigned int n;

	if (old == NULL) {
		n = 0;
		array = (struct array *) malloc(sizeof(*array) + sizeof(val));
	}
	else {
		n = old->n;
		array = (struct array *) realloc(old, sizeof(*array) + (n+1) * sizeof(val));
	}

	if (array == NULL) {
		warn("realloc");
		return NULL;
	}

	array->hosts[n] = val;
	array->n = n + 1;

	return array;
}

static struct array *shared_array_push(struct array *old, struct shared_value val)
{
	struct array *array;
	unsigned int n;

	if (old == NULL) {
		n = 0;
		array = (struct array *) malloc(sizeof(*array) + sizeof(val));
	}
	else {
		n = old->n;
		array = (struct array *) realloc(old, sizeof(*array) + (n+1) * sizeof(val));
	}

	if (array == NULL) {
		warn("realloc");
		return NULL;
	}

	array->folders[n] = val;
	array->n = n + 1;

	return array;
}

static int add_regexp_to_fs_array(struct array **orig_, char *regexp_)
{
	struct array *array, *orig;
	regex_t *preg;
	int i, n, ret;
	char *regexp;
	struct fs_value val;

	preg = NULL;
	regexp = NULL;

	preg = (regex_t *) malloc(sizeof(*preg));
	if (preg == NULL) {
		warn("malloc");
		ret = -ENOMEM;
		goto error;
	}

	ret = regcomp(preg, regexp_, REG_NOSUB | REG_EXTENDED);
	if (ret != 0) {
		warnx("regcomp failed on \"%s\" (%d)", regexp_, ret);
		free(preg);
		preg = NULL;
		ret = -EINVAL;
		goto error;
	}

	/* regexp will be compiled later, when @HOME@ is replaced by home.
	 * regcomp is still called to ensure that regex is valid. */
	if (strstr(regexp_, HOME_PATTERN) != NULL) {
		regfree(preg);
		free(preg);
		preg = NULL;
	}

	regexp = strdup(regexp_);
	if (regexp == NULL) {
		warn("strdup");
		ret = -ENOMEM;
		goto error;
	}

	orig = *orig_;
	if (orig) {
		/* don't add regexp if already in array */
		n = orig->n;
		for (i = 0; i < n; i++) {
			if (strcmp(orig->files[i].regexp, regexp) == 0) {
				ret = 0;
				goto error;
			}
		}
	}

	val.regexp = regexp;
	val.preg = preg;
	array = fs_array_push(orig, val);

	if (array == NULL) {
		ret = -ENOMEM;
		goto error;
	}

	*orig_ = array;

	return 0;

error:
	if (preg != NULL) {
		regfree(preg);
		free(preg);
	}
	free(regexp);
	return ret;
}

/* convert a glob expression to a regexp */
static char *glob_to_regexp(char *glob)
{
	char *regexp, *p, *q;
	size_t size;

	/* "**" must be between '/' */
	p = glob;
	while (1) {
		p = strstr(p, "**");
		if (p == NULL)
			break;
		if ((p > glob && p[-1] != '/') || (p[2] != '/' && p[2] != '\x00')) {
			warnx("invalid expression: \"%s\"", glob);
			return NULL;
		}
		p += 2;
	}

	/* size for '^', '$', and for glob replacements */
	size = 2;
	for (p = glob; *p != '\x00'; p++) {
		if (*p == '.') {
			size += sizeof(REGEXP_DOT)-1;
		} else if (*p == '*' && p[1] != '*') {
			size += sizeof(REGEXP_STAR)-1;
		} else if (*p == '*' && p[1] == '*') {
			size += sizeof(REGEXP_STARSTAR)-1;
			p++;
		} else if (*p == '?') {
			size += sizeof(REGEXP_QUESTION)-1;
		} else {
			size++;
		}
	}

	regexp = (char *) malloc(size + 1);
	if (regexp == NULL) {
		warn("malloc");
		return NULL;
	}

	q = regexp;
	*q++ = '^';
	for (p = glob; *p != '\x00'; p++) {
		if (*p == '.') {
			memcpy(q, REGEXP_DOT, sizeof(REGEXP_DOT)-1);
			q += sizeof(REGEXP_DOT)-1;
		} else if (*p == '*' && p[1] != '*') {
			memcpy(q, REGEXP_STAR, sizeof(REGEXP_STAR)-1);
			q += sizeof(REGEXP_STAR)-1;
		} else if (*p == '*' && p[1] == '*') {
			memcpy(q, REGEXP_STARSTAR, sizeof(REGEXP_STARSTAR)-1);
			q += sizeof(REGEXP_STARSTAR)-1;
			p++;
		} else if (*p == '?') {
			memcpy(q, REGEXP_QUESTION, sizeof(REGEXP_QUESTION)-1);
			q += sizeof(REGEXP_QUESTION)-1;
		} else {
			*q++ = *p;
		}
	}
	*q++ = '$';
	*q = '\x00';

	return regexp;
}

static int add_glob_to_fs_array(struct array **array, char *glob)
{
	char *regexp;
	int ret;

	regexp = glob_to_regexp(glob);
	if (regexp == NULL) {
		ret = -1;
	} else {
		ret = add_regexp_to_fs_array(array, regexp);
		free(regexp);
	}

	return ret;
}

static struct array **get_fs_array(struct policy *policy, char rule, bool isdir)
{
	if (!isdir) {
		switch (rule) {
		case 'r': return &policy->fs.files_r;
		case 'w': return &policy->fs.files_w;
		case 'x': return &policy->fs.files_x;
		default: return NULL;
		}
	} else {
		switch (rule) {
		case 'r': return &policy->fs.dir_r;
		case 'x': return &policy->fs.dir_x;
		default: return NULL;
		}
	}
}

/* given a path, add search permissions to its parent folders */
static int add_search_permissions(struct policy *policy, const char *path_)
{
	struct array **array;
	char *path, *p;

	path = strdup(path_);
	if (path == NULL) {
		warn("%s: strdup", __func__);
		return -1;
	}

	array = get_fs_array(policy, 'x', true);
	p = strrchr(path, '/');

	/* if path ends with |**, it needs to be added to dir_x */
	if (strcmp(p + 1, "**") == 0) {
		if (add_glob_to_fs_array(array, path) != 0) {
			free(path);
			return -1;
		}
	}

	while (1) {
		if (p > path)
			*p = '\x00';
		else
			*(p + 1) = '\x00';
		//printf("%s: %s\n", __func__, path);

		if (add_glob_to_fs_array(array, path) != 0) {
			free(path);
			return -1;
		}

		if (p == path)
			break;

		do {
			p--;
		} while (*p != '/');
	}

	free(path);
	return 0;
}

static int add_fs_rules(struct policy *policy, char *glob, const char *rules)
{
	struct array **array;
	bool isdir, xperm;
	char *p, *regexp;
	const char *r;
	size_t len;
	int ret;

	len = strlen(glob);
	if (glob[len-1] == '/') {
		isdir = 1;
		/* remove trailing slash before converting glob to regexp */
		glob[len-1] = '\x00';
	} else {
		isdir = 0;
	}

	regexp = glob_to_regexp(glob);

	/* restore trailing slash */
	if (isdir)
		glob[len-1] = '/';

	if (regexp == NULL)
		return -1;

	ret = 0;
	xperm = false;
	for (r = rules; *r != '\x00'; r++) {
		if (isdir && *r != 'r') {
			warnx("invalid rule '%c' for \"%s\" (directories only support 'r' rule)",
			      *r, glob);
			ret = -EINVAL;
			break;
		}

		array = get_fs_array(policy, *r, isdir);
		if (array == NULL) {
			warnx("invalid rule '%c' for \"%s\"", *r, glob);
			ret = -EINVAL;
			break;
		}

		/* file exec permission is special: kernel only supports glob
		 * expressions */
		p = (*r == 'x' && !isdir) ? glob : regexp;

		ret = add_regexp_to_fs_array(array, p);
		if (ret != 0)
			break;

		/* no need to add search permissions on same path twice */
		if (!xperm) {
			xperm = true;
			ret = add_search_permissions(policy, glob);
			if (ret != 0)
				break;
		}
	}

	free(regexp);
	return ret;
}

static int check_path(const char *path)
{
	size_t len;

	len = strlen(path);
	if (len == 0 || path[0] != '/') {
		warnx("invalid path %s: must be an absolute path", path);
		return -1;
	}

	if (strstr(path, "/../") != NULL) {
		warnx("invalid path %s: backward references", path);
		return -1;
	}

	if (len > 2 && strcmp(path + len - 3, "/..") == 0) {
		warnx("invalid path %s: backward references", path);
		return -1;
	}

	if (strstr(path, "//") != NULL) {
		warnx("invalid path %s: double slash", path);
		return -1;
	}

	return 0;
}

static int parse_fs_section(struct policy *policy, struct json_object *json)
{
	struct json_object *obj, *val;
	struct lh_entry *entry;
	const char *rule;
	char *key;

	if (json_object_object_get_ex(json, "filesystem", &obj) == FALSE) {
		warnx("json: no filesystem section");
		return -1;
	}

	if (json_object_get_type(obj) != json_type_object) {
		warnx("json: invalid filesystem section");
		return -1;
	}

	//json_object_object_foreach(obj_fs, key, val)
	for (entry = json_object_get_object(obj)->head;
	     (entry ? (key = (char*)entry->k, val = (struct json_object*)entry->v, entry) : 0);
	     entry = entry->next) {
		if (check_path(key) != 0)
			return -1;

		if (json_object_get_type(val) != json_type_string) {
			warnx("json: filesystem: \"%s\" value isn't a string",
				key);
			return -1;
		}

		rule = json_object_get_string(val);
		//printf("[%s] [%s]\n", key, rule);
		if (add_fs_rules(policy, key, rule) != 0)
			return -1;
	}

	return 0;
}

static int add_shared_folders(struct array **orig_, struct json_object *folders)
{
	int i;
	json_object *folder_obj;
	struct shared_value val;
	struct array *array, *orig;
	const char *folder;

	for (i = 0; i < json_object_array_length(folders); i++ ) {
		folder_obj = json_object_array_get_idx(folders, i);

		if (json_object_get_type(folder_obj) != json_type_string) {
			warnx("json: shared folder is not a string");
			return -1;
		}

		folder = json_object_get_string(folder_obj);
		if (check_path(folder) != 0)
			return -1;

		val.folder = strdup(folder);
		orig = *orig_;

		array = shared_array_push(orig, val);
		if (array == NULL)
			return -1;

		*orig_ = array;
	}

	return 0;
}

static int parse_shared_section(struct policy *policy, struct json_object *json)
{
	struct json_object *obj;

	if (json_object_object_get_ex(json, "shared", &obj) == FALSE)
		return 0;

	if (json_object_get_type(obj) != json_type_array) {
		warnx("json: invalid shared section");
		return -1;
	}

	if (add_shared_folders(&policy->shared.folders, obj) != 0)
		return -1;

	return 0;
}

static int parse_net_rule(const char *rule, struct net_value *val)
{
	const char *rule_str = rule;
	char *range_delim, *endptr;
	ptrdiff_t delim_pos;
	struct sockaddr_in saddr_in;
	long min_port, max_port;
	char ipaddr[MAX_IPADDR_LENGTH + 1];

	/* Default values. */
	val->min_ipaddr = 0;
	val->max_ipaddr = 0;
	val->min_port = 1;
	val->max_port = 65535;

	/* Parsing the IPv4 address range. */
	if (rule[0] == '*') {
		val->min_ipaddr = 0;
		val->max_ipaddr = 0xFFFFFFFF;
		rule++;
	}
	else {
		delim_pos = FIND_FIRST_DELIM(rule, ':', '-');
		if (delim_pos < MIN_IPADDR_LENGTH || delim_pos > MAX_IPADDR_LENGTH) {
			warnx("json: invalid ip address format at: '%s'", rule);
			return -1;
		}

		memcpy(ipaddr, rule, delim_pos);
		ipaddr[delim_pos] = '\0';

		if (inet_aton(ipaddr, &saddr_in.sin_addr) == 0) {
			warnx("json: invalid address format at: '%s'", rule);
			return -1;
		}

		val->min_ipaddr = val->max_ipaddr = saddr_in.sin_addr.s_addr;

		rule += delim_pos;
		if (rule[0] == '-')
		{
			rule++;
			delim_pos = FIND_FIRST_DELIM(rule, ':', '-');
			if (delim_pos < MIN_IPADDR_LENGTH || delim_pos > MAX_IPADDR_LENGTH) {
				warnx("json: invalid ip address format at: '%s'", rule);
				return -1;
			}

			memcpy(ipaddr, rule, delim_pos);
			ipaddr[delim_pos] = '\0';

			if (inet_aton(ipaddr, &saddr_in.sin_addr) == 0) {
				warnx("json: invalid address format at: '%s'", rule);
				return -1;
			}

			val->max_ipaddr = saddr_in.sin_addr.s_addr;
			rule += delim_pos;
		}

		if (val->max_ipaddr < val->min_ipaddr) {
			warnx("json: error invalid address range for rule: '%s'", rule_str);
			return -1;
		}
	}

	if (rule[0] == '\0')
		return 0;

	if (rule[0] != ':') {
		warnx("json: expected port delimiter at: '%s'", rule);
		return -1;
	}

	rule++;

	/* Parsing the port range. */
	if (rule[0] == '*')
		rule++;
	else {
		min_port = max_port = strtol(rule, &range_delim, 10);
		if (min_port <= 0 || min_port > 65535) {
			warnx("json: invalid port '%s'", rule);
			return -1;
		}

		val->min_port = min_port;
		val->max_port = max_port;

		if (range_delim[0] == '\0')
			return 0;

		if (range_delim[0] == '-') {
			rule = range_delim + 1;
			max_port = strtol(rule, &endptr, 10);

			if (max_port <= 0 || max_port > 65535) {
				warnx("json: invalid port '%s'", rule);
				return -1;
			}

			val->max_port = max_port;
			rule = endptr;
		}

		if (val->max_port < val->min_port) {
			warnx("json: error invalid port range for rule: '%s'", rule_str);
			return -1;
		}
	}

	if (*rule) {
		warnx("json: error trailing data in network rule: '%s'", rule);
		return -1;
	}

	return 0;
}

static int add_net_rules(struct array **orig_, struct json_object *rules)
{
	int i;
	json_object *rule_obj;
	struct net_value val;
	struct array *array, *orig;
	const char *rule;

	for (i = 0; i < json_object_array_length(rules); i++ ) {
		rule_obj = json_object_array_get_idx(rules, i);

		if (json_object_get_type(rule_obj) != json_type_string) {
			warnx("json: network rule is not a string");
			return -1;
		}

		rule = json_object_get_string(rule_obj);

		if (parse_net_rule(rule, &val) != 0)
			return -1;

		orig = *orig_;

		array = net_array_push(orig, val);
		if (array == NULL)
			return -1;

		*orig_ = array;
	}

	return 0;
}

static int parse_net_section(struct policy *policy, struct json_object *json)
{
	struct json_object *obj, *tcp, *udp;

	if (json_object_object_get_ex(json, "network", &obj) == FALSE)
		return 0;

	if (json_object_get_type(obj) != json_type_object) {
		warnx("json: invalid network section");
		return -1;
	}

	if (json_object_object_get_ex(obj, "tcp", &tcp)) {
		if (json_object_get_type(tcp) != json_type_array) {
			warnx("json: invalid tcp section");
			return -1;
		}

		if (add_net_rules(&policy->net.tcp, tcp) != 0)
			return -1;
	}

	if (json_object_object_get_ex(obj, "udp", &udp)) {
		if (json_object_get_type(udp) != json_type_array) {
			warnx("json: invalid udp section");
			return -1;
		}

		if (add_net_rules(&policy->net.udp, udp) != 0)
			return -1;
	}

	return 0;
}

static char *get_string_value(struct json_object *json, const char *key)
{
	struct json_object *obj;
	char *value;

	if (json_object_object_get_ex(json, key, &obj) == FALSE) {
		warnx("json: failed to get key \"%s\"\n", key);
		return NULL;
	}

	if (json_object_get_type(obj) != json_type_string) {
		warnx("json: key \"%s\" is not a string\n", key);
		return NULL;
	}

	value = strdup(json_object_get_string(obj));
	if (value == NULL)
		warn("strdup");

	return value;
}

struct color {
	const char *name;
	int code;
};

static struct color colors[] = {
	{ "black",	0x000 },
	{ "white",	0xfff },
	{ "red",	0xf00 },
	{ "lime",	0x0f0 },
	{ "blue",	0x00f },
	{ "yellow",	0xff0 },
	{ "cyan",	0x0ff },
	{ "magenta",	0xf0f },
	{ "silver",	0xccc },
	{ "gray",	0x888 },
	{ "maroon",	0x800 },
	{ "olive",	0x880 },
	{ "gren",	0x080 },
	{ "purple",	0x808 },
	{ "teal",	0x088 },
	{ "navy",	0x008 },
	{ NULL,		0x000 },
};

static int get_window_color(struct json_object *json)
{
	struct json_object *obj;
	struct color *color;
	const char *name;
	int code;

	code = 0;
	name = "red";

	if (json_object_object_get_ex(json, "color", &obj)) {
		if (json_object_get_type(obj) == json_type_string)
			name = json_object_get_string(obj);
	}

	for (color = colors; color->name != NULL; color++) {
		if (strcmp(color->name, name) == 0) {
			code = color->code;
			break;
		}
	}

	return code;
}

/*
 * Policy names can be used as filenames.
 * They must not contain any '/' nor be composed of only '.' or '..'.
 */
static int check_policy_name(const char *policy_name)
{
	if (strcmp(policy_name, ".") == 0 || strcmp(policy_name, "..") == 0) {
		warnx("invalid policy name '%s'", policy_name);
		return -1;
	}

	if (strchr(policy_name, '/')) {
		warnx("invalid policy name '%s': must not contain slashes", policy_name);
		return -1;
	}

	return 0;
}

static err_t parse_configuration_file(char *filename, struct policy **r_policy)
{
	struct json_object *json;
	struct policy *policy;
	err_t error;

#ifdef DEBUG
	printf("[*] configuration file: %s\n", filename);
#endif

	json = json_object_from_file(filename);
	if (is_error(json))
		return save_errmsg(ERROR_POLICY_INVALID_JSON, filename);

	policy = (struct policy *) calloc(1, sizeof(*policy));
	if (policy == NULL) {
		error = save_errno(ERROR_LIBC_CALLOC);
		goto error;
	}

	/* name */
	policy->name = get_string_value(json, "name");
	if (policy->name == NULL || check_policy_name(policy->name) != 0) {
		error = save_errmsg(ERROR_POLICY_INVALID, filename);
		goto error;
	}

	error = uuid_name_generate(policy->name, &policy->uuid);
	if (error)
		goto error;

	/* window_color */
	policy->window_color = get_window_color(json);

	/* filesystem */
	if (parse_fs_section(policy, json) != 0) {
		error = save_errmsg(ERROR_POLICY_INVALID, filename);
		goto error;
	}

	/* shared folders */
	if (parse_shared_section(policy, json) != 0) {
		error = save_errmsg(ERROR_POLICY_INVALID, filename);
		goto error;
	}

	/* network */
	if (parse_net_section(policy, json) != 0) {
		error = save_errmsg(ERROR_POLICY_INVALID, filename);
		goto error;
	}

	dump_policy(policy);

	json_object_put(json);
	*r_policy = policy;
	return SUCCESS;

error:
	warnx("failed to parse \"%s\"", filename);
	json_object_put(json);
	free_policy(policy);
	return error;
}

void free_policies(struct policies *policies)
{
	int n;

	if (policies == NULL)
		return;

	n = policies->n;
	while (n-- > 0) {
		free_policy(policies->p[n]);
		policies->p[n] = NULL;
	}

	free(policies->p);
	policies->p = NULL;

	memset(policies, 0x62, sizeof(*policies));
	free(policies);
}

/* walk path and parse any json file */
err_t parse_configuration_files(const char *path, struct policies **r_policies)
{
	char fullpath[PATH_MAX+1], *p;
	struct policy *policy, **tmp;
	struct policies *policies;
	size_t len, minlen;
	struct dirent *dp;
	err_t error;
	DIR *dirp;
	int i, n;

	if (path[0] != '/')
		return save_errmsg(ERROR_POLICY_INVALID_CONFIG_DIR, path);

	dirp = opendir(path);
	if (dirp == NULL)
		return save_errno_msg(ERROR_LIBC_OPENDIR, path);

	policies = (struct policies *) malloc(sizeof(*policies));
	if (policies == NULL) {
		error = save_errno(ERROR_LIBC_MALLOC);
		goto error;
	}
	policies->p = NULL;
	policies->n = 0;

	strncpy(fullpath, path, PATH_MAX-1);
	p = fullpath + strlen(fullpath);
	if (*(p-1) != '/')
		*p++ = '/';

	minlen = sizeof(CONF_EXTENSION)-1;
	while (1) {
		dp = readdir(dirp);
		if (dp == NULL)
			break;

		/* don't parse files with unexpected extension */
		len = strlen(dp->d_name);
		if (len <= minlen ||
		    strcmp(&dp->d_name[len-minlen], CONF_EXTENSION) != 0)
			continue;

		n = policies->n;
		tmp = (struct policy **) realloc(policies->p, (n + 1) * sizeof(*policies->p));
		if (tmp == NULL) {
			error = save_errno(ERROR_LIBC_REALLOC);
			goto error;
		}
		policies->p = tmp;

		/* build configuration full path, and parse it */
		*p = '\x00';
		strncat(fullpath, dp->d_name, PATH_MAX);
		error = parse_configuration_file(fullpath, &policy);
		if (error)
			goto error;

		/* all configurations name must be different */
		for (i = 0; i < n; i++) {
			if (strcmp(policies->p[i]->name, policy->name) == 0) {
				error = save_errmsg(ERROR_POLICY_PRESENT_TWICE,
						    policy->name);
				free_policy(policy);
				goto error;
			}
		}

		/* finally, add new policy to policies */
		policies->p[n] = policy;
		policies->n = n + 1;
	}

	if (policies->n == 0) {
		error = ERROR_POLICY_NO_CONFIG_FILE;
		goto error;
	}

	closedir(dirp);
	*r_policies = policies;
	return SUCCESS;

error:
	closedir(dirp);
	free_policies(policies);
	return error;
}

#ifdef DEBUG
static inline char *get_path(struct exec_policy *policy, unsigned int i)
{
	unsigned int *offsets;
	offsets = (unsigned int *)policy->data;
	return (char *)(policy->data + offsets[i]);
}

static inline struct exec_policy *get_exec_policy_by_id(struct exec_policies *policies,
					unsigned int id)
{
	unsigned int *offsets;
	offsets = (unsigned int *)policies->data;
	return (struct exec_policy *)(policies->data + offsets[id]);
}

static void dump_exec_policies(struct exec_policies *policies)
{
	struct exec_policy *policy;
	unsigned int j, id;
	char *path;

	printf("exec_policies:\n");
	for (id = 0; id < policies->n; id++) {
		policy = get_exec_policy_by_id(policies, id);
		printf("  * exec_policy %d\n", id);
		for (j = 0; j < policy->n; j++) {
			path = get_path(policy, j);
			printf("     - %s\n", path);
		}
	}
}
#else
#  define dump_exec_policies(...)	do { } while (0)
#endif

/* str_replace(template, HOME_PATTERN, home) */
/* returns a newly allocated string. */
char *replace_home(const char *template, const char *home)
{
	size_t len, n, total;
	char *p, *q, *res;
	const char *tmp;
	int i;

	/* don't insert a double slash */
	if (home[0] == '/')
		home++;

	n = sizeof(HOME_PATTERN)-1;
	len = strlen(home);
	total = strlen(template) + 1;

	if (len > n) {
		tmp = template;
		for (i = 0; ; i++) {
			tmp = strstr(tmp, HOME_PATTERN);
			if (tmp == NULL)
				break;
			tmp += n;
		}

		res = malloc(total + i * (len - n));
		if (res == NULL) {
			warn("malloc");
			return NULL;
		}
		memcpy(res, template, total);
	} else {
		res = strdup(template);
		if (res == NULL) {
			warn("strdup");
			return NULL;
		}
	}

	p = res;
	while (1) {
		q = p;
		p = strstr(p, HOME_PATTERN);
		if (p == NULL)
			break;

		total -= p - q + n;
		memmove(p + len, p + n, total);
		memcpy(p, home, len);
		p += len;
	}

	return res;
}

/* craft buffer to pass exec policies to kernel */
err_t build_exec_policies(struct policies *policies,
			  struct cappsule_ioc_policies *ioc_exec_policies)
{
	unsigned int *policies_offsets, policies_offset;
	unsigned int *policy_offsets, policy_offset;
	unsigned int j, npath, size, total_size;
	struct exec_policies *exec_policies;
	struct exec_policy *exec_policy;
	struct policy *policy;
	char *path, *tmp;
	err_t error;
	size_t len;
	int id;

	/* + sizeof(offsets[n]) */
	total_size = offsetof(struct exec_policies, data);
	total_size += sizeof(unsigned int) * policies->n;

	exec_policies = (struct exec_policies *) malloc(total_size);
	if (exec_policies == NULL)
		return save_errno(ERROR_LIBC_MALLOC);

	exec_policies->n = policies->n;
	exec_policies->size = 0;	/* set by kernel */

	/* for each policy */
	policies_offset = sizeof(unsigned int) * policies->n;
	for (id = 0; id < policies->n; id++) {
		policy = policies->p[id];
		npath = (policy->fs.files_x != NULL) ? policy->fs.files_x->n : 0;

		/* + sizeof(offsets[n]) */
		size = offsetof(struct exec_policy, data);
		size += sizeof(unsigned int) * npath;

		/* compute additional size required for each path of this
		 * policy */
		for (j = 0; j < npath; j++) {
			path = policy->fs.files_x->files[j].regexp;
			size += strlen(path) + 1;
		}

		/* realloc buffer */
		total_size += size;
		tmp = (char *) realloc(exec_policies, total_size);
		if (tmp == NULL) {
			error = save_errno(ERROR_LIBC_REALLOC);
			free(exec_policies);
			return error;
		}

		/* exec_policy */
		exec_policies = (struct exec_policies *)tmp;

		policies_offsets = (unsigned int *)exec_policies->data;
		policies_offsets[id] = policies_offset;

		exec_policy = (struct exec_policy *)(exec_policies->data + policies_offset);
		exec_policy->uuid = policy->uuid;
		exec_policy->n = npath;

		/* offsets of exec_policy */
		policy_offsets = (unsigned int *)exec_policy->data;

		/* current offset of first path */
		policy_offset = sizeof(unsigned int) * npath;

		for (j = 0; j < npath; j++) {
			policy_offsets[j] = policy_offset;

			path = policy->fs.files_x->files[j].regexp;
			len = strlen(path) + 1;
			memcpy(exec_policy->data + policy_offset, path, len);

			policy_offset += len;
		}

		policies_offset += size;
	}

	dump_exec_policies(exec_policies);

	ioc_exec_policies->size = total_size;
	ioc_exec_policies->buf = exec_policies;

	return SUCCESS;
}

/**
 * Reload all policies.
 *
 * @param  r_policies pointer to the new policies. If not null, freed before
 *         being updated.
 * @return SUCCESS if no error occured.
 */
err_t reload_policies(const char *policy_path, struct policies **r_policies)
{
	if (*r_policies != NULL) {
		free_policies(*r_policies);
		*r_policies = NULL;
	}

	return parse_configuration_files(policy_path, r_policies);
}

// vim: noet:ts=8:sw=8:
