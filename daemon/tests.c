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

#include "userland.h"
#include "swap.h"


/******************************************************************************
 * swap
 ******************************************************************************/

int __wrap_swapoff(const char *path)
{
	check_expected(path);

	return mock_type(int);
}

int __wrap_swapon(const char *path, int swapflags)
{
	check_expected(path);
	check_expected(swapflags);

	return mock_type(int);
}

char *__wrap_fgets(char *s, int size, FILE *UNUSED(stream))
{
	char *ret;

	ret = mock_ptr_type(char *);
	if (ret != NULL) {
		strncpy(s, ret, size-1);
		s[size-1] = '\x00';
	}

	return ret;
}

static int compute_swapflags(int prio)
{
	int flags;

	flags = 0;
	if (prio >= 0) {
		flags = SWAP_FLAG_PREFER;
		flags |= (prio << SWAP_FLAG_PRIO_SHIFT) & SWAP_FLAG_PRIO_MASK;
	}

	return flags;
}

static void swap_no_error(void **UNUSED(state))
{
	struct swap_device_list *devices;

	will_return(__wrap_fgets, "Filename  Type      Size   Used Priority\n");
	will_return(__wrap_fgets, "/dev/sda5 partition 522236 0    -1\n");
	will_return(__wrap_fgets, "/dev/sda6 partition 522236 0    2\n");
	will_return(__wrap_fgets, NULL);

	expect_string(__wrap_swapoff, path, "/dev/sda5");
	will_return(__wrap_swapoff, 0);
	expect_string(__wrap_swapoff, path, "/dev/sda6");
	will_return(__wrap_swapoff, 0);

	assert_int_equal(swap_disable(&devices), SUCCESS);
	assert_non_null(devices);

	expect_string(__wrap_swapon, path, "/dev/sda5");
	expect_value(__wrap_swapon, swapflags, compute_swapflags(-1));
	will_return(__wrap_swapon, 0);

	expect_string(__wrap_swapon, path, "/dev/sda6");
	expect_value(__wrap_swapon, swapflags, compute_swapflags(2));
	will_return(__wrap_swapon, 0);

	assert_int_equal(swap_restore(devices), SUCCESS);
}

static void swap_error(void **UNUSED(state))
{
	struct swap_device_list *devices;

	will_return(__wrap_fgets, "Filename  Type      Size   Used Priority\n");
	will_return(__wrap_fgets, "/dev/sda5 partition 522236 0    -1\n");
	will_return(__wrap_fgets, "/dev/sda6 partition 522236 0    2\n");
	will_return(__wrap_fgets, "/dev/sda7 partition 522236 0    0\n");
	will_return(__wrap_fgets, NULL);

	expect_string(__wrap_swapoff, path, "/dev/sda5");
	will_return(__wrap_swapoff, 0);
	expect_string(__wrap_swapoff, path, "/dev/sda6");
	will_return(__wrap_swapoff, -1);

	expect_string(__wrap_swapon, path, "/dev/sda5");
	expect_value(__wrap_swapon, swapflags, compute_swapflags(-1));
	will_return(__wrap_swapon, 0);

	assert_int_equal(swap_disable(&devices), ERROR_LIBC_SWAPOFF);
	assert_null(devices);
}

static void swap_empty(void **UNUSED(state))
{
	struct swap_device_list *devices;

	will_return(__wrap_fgets, NULL);

	assert_int_equal(swap_disable(&devices), SUCCESS);
	assert_null(devices);

	assert_int_equal(swap_restore(devices), SUCCESS);
}

/******************************************************************************
 * main
 ******************************************************************************/

int main(void)
{
	struct CMUnitTest tests[] = {
		cmocka_unit_test(swap_no_error),
		cmocka_unit_test(swap_error),
		cmocka_unit_test(swap_empty),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
