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

#ifndef _ATOMIC_H
#define _ATOMIC_H

#define ATOMIC_INIT(i)	{ (i) }
#define ACCESS_ONCE(x)	(*(volatile int *)&(x))

typedef struct {
	int counter;
} atomic_t;

static inline char atomic_read(const atomic_t *v)
{
	return ACCESS_ONCE((v)->counter);
}

static inline void atomic_set(atomic_t *v, int i)
{
	v->counter = i;
}

static inline char atomic_cmpxchg(atomic_t *v, int old, int new)
{
	char ret;

	ret = new;
	__asm__ volatile ("lock; cmpxchgl %2, %1"
		: "=a" (ret), "+m" (v->counter)
		: "q" (new), "0" (old)
		: "memory");

	return ret;
}

#endif
