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

#ifndef _RING_H
#define _RING_H

#include <sys/types.h>
#include <stdbool.h>

#include "atomic.h"
#include "error.h"

struct ring {
	size_t size;
	unsigned char *data;
	atomic_t *notified;
	size_t *start;
	size_t *end;
};

void ring_init(struct ring *ring, void *p, size_t size);
err_t ring_write(struct ring *ring, const void *buf, size_t size, size_t *rsize);
err_t ring_read(struct ring *ring, void *buf, size_t size, size_t *rsize);
bool ring_notification_requested(struct ring *);

#endif
