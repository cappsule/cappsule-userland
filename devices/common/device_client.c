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

#include <unistd.h>

#include "device_client.h"
#include "readall.h"


/**
 * Notify encapsulated snapshot process that client device is ready.
 */
int client_ready(int pipe_device_ready_w)
{
	err_t error;
	char c;

	if (pipe_device_ready_w == -1)
		return 0;

	c = '\x00';
	error = writeall(pipe_device_ready_w, &c, sizeof(c));
	if (error) {
		print_error(error, "pipe device ready");
		return -1;
	}

	close(pipe_device_ready_w);

	return 0;
}
