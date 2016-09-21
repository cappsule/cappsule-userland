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
#include <string.h>
#include <stdbool.h>

#include "ring.h"

#define RING_WRITE_HELPER(ring, buf, end, n, size, ret) do {	\
	if (n > size)						\
		n = size;					\
	memcpy(ring->data + end, buf, n);			\
	end = (end + n) % ring->size;				\
	ret += n;						\
} while (0)

#define RING_READ_HELPER(ring, buf, start, n, size, ret) do {	\
	if (n > size)						\
		n = size;					\
	memcpy(buf, ring->data + start, n);			\
	start = (start + n) % ring->size;			\
	ret += n;						\
} while (0)

bool ring_notification_requested(struct ring *ring)
{
	return atomic_cmpxchg(ring->notified, 0, 1) == 0;
}

err_t ring_write(struct ring *ring, const void *buf, size_t size, size_t *rsize)
{
	size_t end, n, ret, start;
	bool full;

	start = *ring->start;
	end = *ring->end;

	if (start >= ring->size || end >= ring->size) {
		*rsize = -1;
		return ERROR_XCHAN_RING_WRITE;
	}

	ret = 0;
	full = false;
	if (start <= end) {
		if (start > 0) {
			n = ring->size - end;
		} else {
			/* ensure ring isn't full */
			if (end == ring->size - 1) {
				*rsize = 0;
				return SUCCESS;
			}

			/* let one slot empty to indicate that ring will be
			 * full */
			n = ring->size - end - 1;
			full = true;
		}

		RING_WRITE_HELPER(ring, buf, end, n, size, ret);
		buf = (unsigned char *)buf + n;
		size -= n;
	}

	/* ensure ring isn't full */
	if (!full && start - end > 1) {
		n = start - end - 1;
		RING_WRITE_HELPER(ring, buf, end, n, size, ret);
	}

	*ring->end = end;

	//printf("[*] %s: %ld/%ld\n", __func__, *ring->start, *ring->end);
	//printf("    (%s)\n", (char *)ring->data + *ring->start);

	*rsize = ret;
	return SUCCESS;
}

err_t ring_read(struct ring *ring, void *buf, size_t size, size_t *rsize)
{
	size_t end, n, ret, start;

	start = *ring->start;
	end = *ring->end;

	//printf("[*] %s: %ld/%ld\n", __func__, start, end);

	if (start >= ring->size || end >= ring->size) {
		*rsize = -1;
		return ERROR_XCHAN_RING_READ;
	}

	/* ensure ring isn't empty */
	if (start == end) {
		atomic_set(ring->notified, 0);
		*rsize = 0;
		return SUCCESS;
	}

	ret = 0;
	if (end < start) {
		n = ring->size - start;
		RING_READ_HELPER(ring, buf, start, n, size, ret);
		buf = (unsigned char *)buf + n;
		size -= n;
	}

	n = end - start;
	RING_READ_HELPER(ring, buf, start, n, size, ret);

	if (start == end)
		atomic_set(ring->notified, 0);

	*ring->start = start;

	*rsize = ret;
	return SUCCESS;
}

void ring_init(struct ring *ring, void *p, size_t size)
{
	size_t used;

	used = (sizeof(*ring->notified) + sizeof(*ring->start) + sizeof(*ring->end));
	ring->size = size - used;

	/* don't memset p to 0 here: if trusted guest already write something to
	 * the ring buffer, capsule would overwrite it */

	/* shared memory: [ buf... ][ start ][ end ] */
	ring->data = p;
	ring->notified = (atomic_t *)(ring->data + ring->size);
	ring->start = (size_t *)((unsigned char *)ring->notified + sizeof(*ring->notified));
	ring->end = (size_t *)((unsigned char *)ring->start + sizeof(*ring->start));
}
