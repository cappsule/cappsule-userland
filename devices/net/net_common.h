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

#ifndef _NET_COMMON_H
#define _NET_COMMON_H

#include <sys/user.h>
#include "cuapi/common/xchan.h"
#include "cuapi/trusted/channel.h"

#define MAX_SIZE	(XCHAN_NPAGES_NET / 2 * PAGE_SIZE)

/* network byte order (172.17.0.0) */
#define GATEWAY_BASE	0xac110000
#define GATEWAY_MASK	0xffffff00

/**
 * Return capsule's ip address in network byte order.
 */
static inline uint32_t capsule_ip_address(unsigned int capsule_id)
{
	return GATEWAY_BASE | ((1 + capsule_id) & 0xff);
}

/**
 * Return gateway's ip address in network byte order.
 */
static inline uint32_t capsule_gw_address(unsigned int capsule_id)
{
	return GATEWAY_BASE | ((MAX_CAPSULE + 1 + capsule_id) & 0xff);
}

struct xchan;

void network(struct xchan *xchan, int tunfd);
int create_tun(struct ifreq *ifr);

#endif
