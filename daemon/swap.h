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

#ifndef SWAP_H
#define SWAP_H

#include <linux/limits.h>

#include "error.h"

struct swap_device_list;

err_t swap_disable(struct swap_device_list **p_swap_devices);
err_t swap_restore(struct swap_device_list *swap_devices);

#endif

// vim: noet:ts=8:sw=8:
