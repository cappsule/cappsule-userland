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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include <openssl/md5.h>

#include "uuid.h"

/**
 * Outputs a struct uuid to its string representation.
 */
int uuid_print(struct uuid uuid, char *str, size_t size)
{
	int ret;

	ret = snprintf(str, size,
		       "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		       uuid.timelow,
		       uuid.timemid,
		       uuid.version_timehigh,
		       uuid.variant_clockseqhigh,
		       uuid.clockseqlow,
		       uuid.node[0], uuid.node[1], uuid.node[2],
		       uuid.node[3], uuid.node[4], uuid.node[5]);

	return (ret < (long) size) ? 0 : -1;
}

/**
 * Convert a string representation of an uuid to a structure.
 */
int uuid_from_str(const char *str, struct uuid *uuid)
{
	int ret;

	ret = sscanf(str,
		     "%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
	             &uuid->timelow,
		     &uuid->timemid,
		     &uuid->version_timehigh,
	             &uuid->variant_clockseqhigh,
		     &uuid->clockseqlow,
		     &uuid->node[0], &uuid->node[1], &uuid->node[2],
		     &uuid->node[3], &uuid->node[4], &uuid->node[5]);

	return (ret == 11) ? 0 : -1;
}

/**
 * Generates a deterministic UUID from a null-terminated string and a namespace.
 * Follows recommandation ITU-T X.667.
 */
int uuid_name_generate_ns(struct uuid *ns, const char *name, struct uuid *uuid)
{
	MD5_CTX ctx;
	uint8_t digest[MD5_DIGEST_LENGTH];
	struct uuid ns_be;

	if (MD5_Init(&ctx) != 1)
		return -1;

	if (ns) {
		/* Hashes namespace independently of endianness. */
		ns_be = *ns;
		ns_be.timelow = htonl(ns_be.timelow);
		ns_be.timemid = htons(ns_be.timemid);
		ns_be.version_timehigh = htons(ns_be.version_timehigh);

		if (MD5_Update(&ctx, &ns_be, sizeof(ns_be)) != 1)
			return -1;
	}

	if (MD5_Update(&ctx, name, strlen(name)) != 1)
		return -1;

	if (MD5_Final(digest, &ctx) != 1)
		return -1;

	/* Copy result to uuid. */
	memcpy(uuid, digest, sizeof(*uuid));

	/* Convert to local endianness. */
	uuid->timelow = ntohl(uuid->timelow);
	uuid->timemid = ntohs(uuid->timemid);
	uuid->version_timehigh = ntohs(uuid->version_timehigh);

	/* Specify MD5 algorithm. */
	uuid->version_timehigh &= 0xfff;
	uuid->version_timehigh |= (3 << 12);

	/* MSBs of clockseqhigh must be 0b10 */
	uuid->variant_clockseqhigh &= 0x3f;
	uuid->variant_clockseqhigh |= 0x80;

	return 0;
}

/**
 * Generates a deterministic UUID from a null-terminated string.
 */
int uuid_name_generate(const char *name, struct uuid *uuid)
{
	return uuid_name_generate_ns(NULL, name, uuid);
}
