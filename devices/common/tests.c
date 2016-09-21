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
#include <sys/mman.h>
#include <sys/types.h>

#include <cmocka.h>

#include "ring.h"
#include "xchan.h"


/******************************************************************************
 * xchan
 ******************************************************************************/

#define TEST_XCHAN_NPAGES	2
#define PAGE_SIZE		4096

static int ring_setup(void **state)
{
	size_t length, size;
	struct xchan *xchan;
	int flags;
	void *p;
	char *q;

	size = sizeof(*xchan) + sizeof(*xchan->ring_r) + sizeof(*xchan->ring_w);
	q = (char *)malloc(size);
	if (q == NULL) {
		warn("malloc");
		return -1;
	}

	xchan = (struct xchan *)q;
	xchan->ring_r = (struct ring *)(q + sizeof(*xchan));
	xchan->ring_w = (struct ring *)(q + sizeof(*xchan) + sizeof(*xchan->ring_r));

	length = TEST_XCHAN_NPAGES * PAGE_SIZE;
	flags = MAP_PRIVATE | MAP_ANONYMOUS;
	p = mmap(NULL, length, PROT_READ | PROT_WRITE, flags, -1, 0);
	if (p == MAP_FAILED) {
		free(xchan);
		warn("mmap");
		return -1;
	}

	ring_init(xchan->ring_r, p, length / 2);
	p = (unsigned char *)p + length / 2;
	ring_init(xchan->ring_w, p, length / 2);

	*state = xchan;

	return 0;
}

static void ring_test(void **state)
{
	unsigned char buf1[PAGE_SIZE], buf2[PAGE_SIZE];
	struct xchan *xchan;
	size_t i, size;
	err_t error;

	xchan = (struct xchan *)*state;

	error = ring_write(xchan->ring_w, "abcd", 4, &size);
	assert_int_equal(error, SUCCESS);
	assert_int_equal(size, 4);

	for (i = 0; i < sizeof(buf1); i++)
		buf1[i] = rand();
	memcpy(buf2, buf1, sizeof(buf2));

	error = ring_write(xchan->ring_w, buf1, sizeof(buf1), &size);
	assert_int_equal(error, SUCCESS);
	assert_int_not_equal(size, 0);

	error = ring_write(xchan->ring_w, buf1, sizeof(buf1), &size);
	assert_int_equal(error, SUCCESS);
	assert_int_equal(size, 0);

	error = ring_read(xchan->ring_w, buf1, 4, &size);
	assert_int_equal(error, SUCCESS);
	assert_int_equal(size, 4);
	assert_memory_equal(buf1, "abcd", 4);

	error = ring_read(xchan->ring_w, buf1, sizeof(buf1), &size);
	assert_int_equal(error, SUCCESS);
	assert_int_not_equal(size, 0);
	assert_memory_equal(buf1, buf2, size);

	error = ring_read(xchan->ring_w, buf1, sizeof(buf1), &size);
	assert_int_equal(error, SUCCESS);
	assert_int_equal(size, 0);
}

static int ring_teardown(void **state)
{
	struct xchan *xchan;
	size_t length;

	xchan = (struct xchan *)*state;

	length = TEST_XCHAN_NPAGES * PAGE_SIZE;
	if (munmap(xchan->ring_r->data, length) != 0) {
		warn("munmap");
		return -1;
	}

	free(xchan);

	return 0;
}

/******************************************************************************
 * main
 ******************************************************************************/

int main(void)
{
	struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(ring_test,
						ring_setup,
						ring_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
