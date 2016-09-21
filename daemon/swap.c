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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/swap.h>
#include <linux/limits.h>

#include "swap.h"

struct swap_device {
	char path[PATH_MAX];
	int priority;
	bool on;
};

struct swap_device_list {
	struct swap_device device;
	struct swap_device_list *next;
};

static void free_device_list(struct swap_device_list *devs)
{
	struct swap_device_list *it, *next;

	for (it = devs; it != NULL; it = next) {
		next = it->next;
		free(it);
	}
}

/*
 * Fetches the list of active swap devices from /proc/swaps.
 */
static err_t swap_get_active_devices(struct swap_device_list **p_swap_devs)
{
	struct swap_device_list *swap_devs, *last, *current;
	char dev_path[PATH_MAX], line[8192];
	int dev_prio, n;
	size_t size;
	err_t error;
	FILE *fp;

	*p_swap_devs = NULL;
	swap_devs = NULL;
	last = NULL;

	fp = fopen("/proc/swaps", "r");
	if (fp == NULL)
		return save_errno_msg(ERROR_LIBC_FOPEN, "/proc/swaps");

	error = SUCCESS;
	while (fgets(line, sizeof(line), fp) != NULL) {
		n = sscanf(line, "%4095s %*s %*u %*u %d", dev_path, &dev_prio);
		if (n != 2)
			continue;

		current = (struct swap_device_list *) calloc(1, sizeof(*current));
		if (current == NULL) {
			error = save_errno(ERROR_LIBC_CALLOC);
			break;
		}

		if (swap_devs == NULL) {
			last = swap_devs = current;
		} else {
			last->next = current;
			last = last->next;
		}

		size = sizeof(current->device.path) - 1;
		strncpy(current->device.path, dev_path, size);
		current->device.priority = dev_prio;
		current->device.on = true;
	}

	fclose(fp);

	if (error) {
		free_device_list(swap_devs);
		swap_devs = NULL;
	}

	*p_swap_devs = swap_devs;

	return error;
}

/*
 * Disable all swap devices.
 */
err_t swap_disable(struct swap_device_list **p_swap_devices)
{
	struct swap_device_list *devs, *it;
	int saved_errno;
	err_t error;

	error = SUCCESS;
	*p_swap_devices = NULL;
	devs = NULL;

	error = swap_get_active_devices(&devs);
	if (error)
		return error;

	for (it = devs; it != NULL; it = it->next) {
		if (swapoff(it->device.path) == 0) {
			it->device.on = false;
		} else {
			saved_errno = errno;
			if (swap_restore(devs) != SUCCESS) {
				print_error(error,
					    "failed to restore swap devices");
				reset_saved_errno();
			}
			errno = saved_errno;
			error = save_errno_msg(ERROR_LIBC_SWAPOFF,
					       it->device.path);
			break;
		}
	}

	if (!error)
		*p_swap_devices = devs;

	return error;
}


static err_t swap_restore_device(struct swap_device *device)
{
	int prio, flags;
	err_t error;

	error = SUCCESS;
	if (device->on)
		return error;

	flags = 0;
	prio = device->priority;
	if (prio >= 0) {
		flags = SWAP_FLAG_PREFER;
		flags |= (prio << SWAP_FLAG_PRIO_SHIFT) & SWAP_FLAG_PRIO_MASK;
	}

	if (swapon(device->path, flags) == -1)
		error = save_errno_msg(ERROR_LIBC_SWAPON, device->path);

	return error;
}

/*
 * Restore swap devices.
 */
err_t swap_restore(struct swap_device_list *swap_devices)
{
	struct swap_device_list *it, *next;
	err_t error, tmp;

	error = SUCCESS;
	for (it = swap_devices; it != NULL; it = next) {
		tmp = swap_restore_device(&it->device);

		/* since the restart of several devices may fail, print an error
		 * message right now, and make this function returns a broader
		 * error */
		if (tmp) {
			print_error(tmp,
				    "failed to restart swapping device \"%s\"",
				    it->device.path);
			reset_saved_errno();
			error = ERROR_SWAP_RESTORE;
		}

		next = it->next;
		free(it);
	}

	return error;
}

// vim: noet:ts=8:sw=8:
