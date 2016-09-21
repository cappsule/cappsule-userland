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

#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>

#include "json.h"
#include "readall.h"


/**
 * Send JSON request prefixed by its length in bytes.
 */
err_t send_json(int sockfd, const char *buf)
{
	char str_size[32];
	err_t error;
	size_t len;
	int ret;

	len = strlen(buf);
	ret = snprintf(str_size, sizeof(str_size), "%ld\n", len);
	error = sendall(sockfd, str_size, ret, 0);

	if (!error)
		error = sendall(sockfd, buf, len, 0);

	return error;
}

/**
 * Receive JSON request prefixed by its length in bytes.
 */
err_t recv_json(int sockfd, char *buf, size_t size)
{
	char c, str_size[10];
	unsigned int i;
	err_t error;
	size_t len;
	bool valid;

	valid = false;
	for (i = 0; i < sizeof(str_size)-1; i++) {
		error = recvall(sockfd, &c, sizeof(c), 0);
		if (error)
			return error;

		if (c == '\n') {
			if (i > 0) {
				str_size[i] = '\x00';
				valid = true;
			}
			break;
		}

		if (!isdigit(c))
			return ERROR_COMMON_INVALID_JSON_SIZE;

		str_size[i] = c;
	}

	if (!valid)
		return ERROR_COMMON_INVALID_JSON_SIZE;

	len = atoi(str_size);
	if (len == 0 || len >= size)
		return ERROR_COMMON_INVALID_JSON_SIZE;

	error = recvall(sockfd, buf, len, 0);
	if (!error)
		buf[len] = '\x00';

	return error;
}
