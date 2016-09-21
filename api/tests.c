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
#include <time.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <cmocka.h>

#include "api.h"

/* we also want to test static functions */
#include "api_parse.c"
#include "api_server.c"


int __wrap_close(int fd)
{
	check_expected(fd);

	return mock_type(int);
}

int __wrap_ioctl(int UNUSED(d), int request, struct cappsule_ioc_create *create)
{
	check_expected(request);

	if (request == (int)CAPPSULE_IOC_CREATE_CAPSULE) {
		create->result_capsule_id = 1;
	}

	return mock_type(int);
}

static void test_kill_msg(void **UNUSED(state))
{
	char buf[128], *p;
	int ret;

	p = "{ \"event\": \"exit\", \"capsule_id\": 1, \"reason\": \"write invalid CR0 value\" }";
	ret = build_kill_msg(buf, sizeof(buf), 1, KILL_MOVE_TO_CR0);
	assert_int_equal(ret, 0);
	assert_string_equal(buf, p);

	p = "{ \"event\": \"exit\", \"capsule_id\": 1, \"reason\": \"\" }";
	ret = build_kill_msg(buf, sizeof(buf), 1, KILL_VMCALL_EXIT);
	assert_int_equal(ret, 0);
	assert_string_equal(buf, p);
}

/* http://stackoverflow.com/questions/6127503/shuffle-array-in-c */
static void shuffle(int *array, size_t n)
{
	size_t i, j;
	int t;

	if (n <= 1)
		return;

	for (i = 0; i < n - 1; i++) {
		j = i + rand() / (RAND_MAX / (n - i) + 1);
		t = array[j];
		array[j] = array[i];
		array[i] = t;
	}
}

#define N_CLIENTS	10

static void test_create_delete_client(void **UNUSED(state))
{
	int i, sockets[N_CLIENTS];
	struct client *client;
	struct context ctx;

	ctx.clients = NULL;

	for (i = 0; i < N_CLIENTS; i++) {
		sockets[i] = i;
		client = create_client(&ctx, sockets[i]);
		assert_non_null(client);
	}

	srand(time(NULL));
	shuffle(sockets, N_CLIENTS);

	for (i = 0; i < N_CLIENTS; i++) {
		client = find_client_by_socket(&ctx, sockets[i]);
		assert_non_null(client);

		expect_value(__wrap_close, fd, client->c);
		will_return(__wrap_close, 0);
		delete_client(&ctx, client);
	}

	assert_null(ctx.clients);
}

static int test_json_array_to_str_setup(void **state)
{
	char *strings[] = { "first", "second", "third" };
	struct json_object *array, *val;
	unsigned int i;

	array = json_object_new_array();
	if (array == NULL)
		return -1;

	for (i = 0; i < ARRAY_SIZE(strings); i++) {
		val = json_object_new_string(strings[i]);
		if (val == NULL) {
			json_object_put(array);
			return -1;
		}
		json_object_array_add(array, val);
	}

	*(struct json_object **)state = array;

	return 0;
}

static void test_json_array_to_str(void **state)
{
	char expected[] = "first\x00second\x00third\x00";
	struct json_object *array;
	char buf[256];
	int ret;

	array = *(struct json_object **)state;

	ret = build_string_from_json_array(array, buf, sizeof(buf));
	assert_int_equal(ret, 0);

	assert_memory_equal(buf, expected, sizeof(expected)-1);
}

static int test_json_array_to_str_teardown(void **state)
{
	struct json_object *array;

	array = *(struct json_object **)state;
	json_object_put(array);

	return 0;
}

static void test_api_action_helper(struct context *ctx, struct client *client,
				   const char *buf, const char *expected)
{
	struct json_object *jobj;
	const char *p;

	jobj = api_action(ctx, client, buf, -1);
	assert_non_null(jobj);

	if (jobj != JSON_NO_RESPONSE) {
		p = json_object_to_json_string(jobj);
		assert_non_null(p);
		assert_string_equal(p, expected);
		json_object_put(jobj);
	} else {
		assert_string_equal("JSON_NO_RESPONSE", expected);
	}
}

static void test_api_action_invalid_json(void **UNUSED(state))
{
	struct context ctx;
	const char *p;

	ctx.clients = NULL;

	p = "{ \"success\": false, \"error\": \"failed to parse json\" }";
	test_api_action_helper(&ctx, NULL, "invalid json string", p);
}

static void test_api_action_no_cmd(void **UNUSED(state))
{
	struct context ctx;
	const char *p;

	ctx.clients = NULL;
	p = "{ \"success\": false, \"error\": \"failed to get cmd\" }";
	test_api_action_helper(&ctx, NULL, "{}", p);
}

static void test_api_action_invalid_cmd(void **UNUSED(state))
{
	struct context ctx;
	const char *p;

	ctx.clients = NULL;
	p = "{ \"success\": false, \"error\": \"invalid cmd\" }";
	test_api_action_helper(&ctx, NULL, "{ \"cmd\": \"doesntexist\" }", p);
}

static void test_api_action_no_capsule_id(void **UNUSED(state))
{
	const char *buf, *p;
	struct context ctx;

	ctx.clients = NULL;
	buf = "{ \"cmd\": \"get_info\", \"type\": \"creds\" }";
	p = "{ \"success\": false, \"error\": \"failed to get capsule id\" }";
	test_api_action_helper(&ctx, NULL, buf, p);
}

static void test_api_action_no_capsule(void **UNUSED(state))
{
	const char *buf, *p;
	struct context ctx;

	ctx.clients = NULL;
	ctx.capsules = NULL;
	buf = "{ \"cmd\": \"get_info\", \"type\": \"creds\", \"id\": 1 }";
	p = "{ \"success\": false, \"error\": \"capsule id 1 doesn't exist\" }";
	test_api_action_helper(&ctx, NULL, buf, p);
}

static void test_api_action_get_creds(void **UNUSED(state))
{
	struct uuid uuid = { 0x12345678, 0x8765, 0xabcd, 0xef, 0x00, "abcdef" };
	struct capsule capsule;
	const char *buf, *p;
	struct context ctx;

	ctx.clients = NULL;
	ctx.capsules = &capsule;

	capsule.prev = NULL;
	capsule.next = NULL;

	capsule.capsule_id = 1;
	capsule.params.policy_uuid = uuid;
	capsule.ucred.pid = 3;
	capsule.ucred.uid = 4;
	capsule.ucred.gid = 5;

	buf = "{ \"cmd\": \"get_info\", \"type\": \"creds\", \"id\": 1 }";
	p = "{ \"success\": true, \"result\": { \"creds\": { \"pid\": 3, \"uid\": 4, \"gid\": 5, \"policy_uuid\": \"12345678-8765-abcd-ef00-616263646566\" } } }";
	test_api_action_helper(&ctx, NULL, buf, p);
}

static void test_api_action_get_rootfs(void **UNUSED(state))
{
	struct capsule capsule;
	const char *buf, *p;
	struct context ctx;
	size_t size;

	ctx.clients = NULL;
	ctx.capsules = &capsule;

	capsule.capsule_id = 1;
	capsule.prev = NULL;
	capsule.next = NULL;

	size = sizeof(capsule.params.fs.rootfs.path);
	strncpy(capsule.params.fs.rootfs.path, "/blah", size);
	capsule.params.fs.rootfs.type = FS_MOUNT_TYPE_DIRECT_ACCESS;
	size = sizeof(capsule.params.fs.base_dir);
	strncpy(capsule.params.fs.base_dir, "/lol", size);

	buf = "{ \"cmd\": \"get_info\", \"type\": \"rootfs\", \"id\": 1 }";
	p = "{ \"success\": true, \"result\": { \"rootfs\": { \"type\": \"direct\", \"path\": \"\\/blah\", \"basedir\": \"\\/lol\" } } }";
	test_api_action_helper(&ctx, NULL, buf, p);
}

static void test_api_action_create_no_params(void **UNUSED(state))
{
	struct client client;
	const char *buf, *p;

	client.c = -1;
	client.ucred.pid = 2;
	client.ucred.uid = 3;
	client.ucred.gid = 4;

	buf = "{ \"cmd\": \"create\" }";
	p = "{ \"success\": false, \"error\": \"failed to get params\" }";
	test_api_action_helper(NULL, &client, buf, p);
}

static void test_api_action_create_invalid_params(void **UNUSED(state))
{
	struct policy policy_default = { "default", { 0 }, 0, { 0 }, { 0 }, { 0 } };
	struct policy *policy = { &policy_default };
	struct policies policies = { &policy, 1 };
	struct client client;
	const char *buf, *p;
	struct context ctx;

	ctx.policies = &policies;

	client.c = -1;
	client.ucred.pid = 2;
	client.ucred.uid = 3;
	client.ucred.gid = 4;

	buf = "{ \"cmd\": \"create\", \"params\": { \"invalid\": 1 } }";
	p = "{ \"success\": false, \"error\": \"invalid key \\\"invalid\\\"\" }";
	test_api_action_helper(NULL, &client, buf, p);

	buf = "{ \"cmd\": \"create\", \"params\": { \"no-gui\": \"x\" } }";
	p = "{ \"success\": false, \"error\": \"bad type for \\\"no-gui\\\"\" }";
	test_api_action_helper(NULL, &client, buf, p);

	buf = "{ \"cmd\": \"create\", \"params\": { \"no-gui\": \"x\" } }";
	p = "{ \"success\": false, \"error\": \"bad type for \\\"no-gui\\\"\" }";
	test_api_action_helper(NULL, &client, buf, p);

	buf = "{ \"cmd\": \"create\", \"params\": { \"policy\": \"x\" } }";
	p = "{ \"success\": false, \"error\": \"failed to set \\\"policy\\\"\" }";
	test_api_action_helper(&ctx, &client, buf, p);
}

static void test_api_action_create_ok(void **UNUSED(state))
{
	struct policy policy_default = { "default", { 0 }, 0, { 0 }, { 0 }, { 0 } };
	struct policy *policy = { &policy_default };
	struct policies policies = { &policy, 1 };
	struct pending_capsule *pending;
	struct devices_sockets notif;
	struct client *client, *c;
	struct capsule *capsule;
	unsigned int capsule_id;
	struct context ctx;
	const char *buf;

	memset(notif.fds, -1, sizeof(notif.fds));
	notif.nr_devices = 0;

	ctx.clients = NULL;
	ctx.capsules = NULL;
	ctx.pending = NULL;
	ctx.listeners = NULL;
	ctx.policies = &policies;
	ctx.notif = &notif;

	/* create client */
	client = create_client(&ctx, -1);
	assert_non_null(client);

	client->ucred.pid = 2;
	client->ucred.uid = 3;
	client->ucred.gid = 4;

	buf = "{ \"cmd\": \"create\", \"params\": { \"groups\": \"0\", \"fstype\": \"overlay\", \"policy\": \"default\", \"cwd\": \"\\/home\", \"rootfs\": \"\\/etc\", \"no-gui\": true, \"argv\": [\"id\"], \"env\": [], \"basedir\": \"/tmp\\/blah\" } }";
	/* create capsule */
	expect_value(__wrap_ioctl, request, (int)CAPPSULE_IOC_CREATE_CAPSULE);
	will_return(__wrap_ioctl, 0);
	test_api_action_helper(&ctx, client, buf, "JSON_NO_RESPONSE");

	/* ensure capsule was created */
	capsule = find_capsule_by_id(&ctx, 1);
	capsule_id = capsule->capsule_id;
	assert_non_null(capsule);

	/* assume devices are initialized */
	pending = find_pending_by_capsule(&ctx, capsule);
	delete_pending(&ctx, pending);

	/* kill capsule */
	expect_value(__wrap_ioctl, request, (int)CAPPSULE_IOC_KILL_CAPSULE);
	will_return(__wrap_ioctl, 0);
	assert_int_equal(kill_capsule(-1, capsule_id), 0);

	/* delete client before calling handle_capsule_exit(), otherwise it
	 * tries to send json message  */
	expect_value(__wrap_close, fd, client->c);
	will_return(__wrap_close, 0);
	c = find_client_by_socket(&ctx, -1);
	assert_ptr_equal(c, client);
	delete_client(&ctx, client);
	assert_null(ctx.clients);

	/* simulate notification of capsule exit from kernel */
	handle_capsule_exit(&ctx, capsule_id, 0);
	delete_exited_capsules(&ctx);
	assert_null(ctx.capsules);
}

int main(void)
{
	struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_json_array_to_str,
						test_json_array_to_str_setup,
						test_json_array_to_str_teardown),
		cmocka_unit_test(test_kill_msg),
		cmocka_unit_test(test_create_delete_client),
		cmocka_unit_test(test_api_action_invalid_json),
		cmocka_unit_test(test_api_action_no_cmd),
		cmocka_unit_test(test_api_action_invalid_cmd),
		cmocka_unit_test(test_api_action_no_capsule_id),
		cmocka_unit_test(test_api_action_no_capsule),
		cmocka_unit_test(test_api_action_get_creds),
		cmocka_unit_test(test_api_action_get_rootfs),
		cmocka_unit_test(test_api_action_create_no_params),
		cmocka_unit_test(test_api_action_create_invalid_params),
		cmocka_unit_test(test_api_action_create_ok),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
