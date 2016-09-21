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
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <cmocka.h>

#include "userland.h"
#include "policy.h"
#include "error.h"


/******************************************************************************
 * errors
 ******************************************************************************/

static void error_message_standard(void **UNUSED(state))
{
	const char *p;

	p = error_message(ERROR_COMMON_DROP_PRIVS);
	assert_string_equal(p, "failed to drop privileges");
}

static void error_message_errno(void **UNUSED(state))
{
	const char *p;
	err_t error;

	errno = EPERM;
	error = save_errno(ERROR_LIBC_OPEN);
	p = error_message(error);
	assert_string_equal(p, "open failed: Operation not permitted");
}

static void error_message_msg(void **UNUSED(state))
{
	const char *p;
	err_t error;

	error = save_errmsg(ERROR_COMMON_DROP_PRIVS, "blah");
	p = error_message(error);
	assert_string_equal(p, "failed to drop privileges (blah)");
}

static void error_message_errno_msg(void **UNUSED(state))
{
	const char *p;
	err_t error;

	errno = EPERM;
	error = save_errno_msg(ERROR_LIBC_OPEN, "blah");
	p = error_message(error);
	assert_string_equal(p, "open failed (blah): Operation not permitted");
}

static int error_message_teardown(void **UNUSED(state))
{
	reset_saved_errno();
	return 0;
}

/******************************************************************************
 * filesystem
 ******************************************************************************/

static int copy_file_setup(void **UNUSED(state))
{
	struct stat st;
	return !(lstat("/doesntexist", &st) == -1 && errno == ENOENT);
}

static void copy_file_src_doesnt_exist(void **UNUSED(state))
{
	err_t error;

	error = copy_file("/doesntexist", "/tmp");
	assert_int_equal(error, ERROR_LIBC_OPEN);
}

static int make_dirs_setup(void **state)
{
	char *dirname;

	dirname = strdup("/tmp/XXXXXX");
	if (dirname == NULL) {
		warn("%s: strdup failed", __func__);
		return -1;
	}

	if (mkdtemp(dirname) == NULL) {
		warn("%s: mkdtemp failed", __func__);
		free(dirname);
		return -1;
	}

	*(char **)state = dirname;

	return 0;
}

static void make_dirs_test(void **state)
{
	char path[PATH_MAX];
	char *dirname, *p;
	struct stat st;
	err_t error;
	int ret;

	dirname = *(char **)state;
	snprintf(path, sizeof(path), "%s/a/b/c/d/blah", dirname);

	/* make dirs */
	error = make_dirs(path);
	assert_int_equal(error, SUCCESS);

	/* ensure dir is created */
	p = strrchr(path, '/');
	*p = '\x00';
	ret = lstat(path, &st);
	assert_int_equal(ret, 0);
	assert_true(S_ISDIR(st.st_mode));

	/* don't joke with rmrf */
	assert_int_equal(strncmp(dirname, "/tmp/", 5), 0);
	assert_null(strstr(dirname, ".."));

	/* rm -rf /tmp/XXXXXX */
	snprintf(path, sizeof(path), "rm -rf /tmp/%s/", dirname + 4);
	assert_int_equal(system(dirname), 0);
}

static int make_dirs_teardown(void **state)
{
	char *dirname = *(char **)state;

	free(dirname);

	return 0;
}

/******************************************************************************
 * policy
 ******************************************************************************/

struct replace_home_test {
	char *template;
	char *home;
	char *result;
};

static void replace_home_ok(void **UNUSED(state))
{
	struct replace_home_test *test, tests[] = {
		{ "@HOME@", "", "" },
		{ "@HOME@/z", "/root", "root/z" },
		{ "/@HOME@/blah", "/root", "/root/blah" },
		{ "/@HOME@/@HOME@/x", "/home/user", "/home/user/home/user/x" },
		{ "/a/b/@HOME@/c", "x", "/a/b/x/c" },
		{ NULL, NULL, NULL},
	};
	char *p;

	for (test = tests; test->template != NULL; test++) {
		p = replace_home(test->template, test->home);
		assert_non_null(p);
		assert_string_equal(p, test->result);
		free(p);
	}
}

/******************************************************************************
 * uuid
 ******************************************************************************/

static void uuid_ok(void **UNUSED(state))
{
	char str[UUID_STR_LENGTH + 1];
	struct uuid uuid, uuid2;

	assert_int_equal(uuid_name_generate("blah", &uuid), 0);
	assert_int_equal(uuid_print(uuid, str, sizeof(str)), 0);
	assert_int_equal(uuid_from_str(str, &uuid2), 0);
	assert_memory_equal(&uuid, &uuid2, sizeof(uuid));
}

/******************************************************************************
 * main
 ******************************************************************************/

int main(void)
{
	struct CMUnitTest tests[] = {
		cmocka_unit_test(error_message_standard),
		cmocka_unit_test_teardown(error_message_errno,
					  error_message_teardown),
		cmocka_unit_test_teardown(error_message_msg,
					  error_message_teardown),
		cmocka_unit_test_teardown(error_message_errno_msg,
					  error_message_teardown),

		cmocka_unit_test_setup(copy_file_src_doesnt_exist,
				       copy_file_setup),
		cmocka_unit_test_setup_teardown(make_dirs_test,
						make_dirs_setup,
						make_dirs_teardown),

		cmocka_unit_test(replace_home_ok),

		cmocka_unit_test(uuid_ok),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
