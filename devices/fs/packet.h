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

#ifndef _PACKET_H
#define _PACKET_H 1

#include "protocol.h"
#include "fsclient.h"

int in_capsule(int nohv);
void do_request(struct fsclient *fsclient, enum cpsl_request type, struct cli_packet *p, size_t size);
void do_response(struct fsclient *fsclient, void *buf, size_t size);

#endif /* _PACKET_H */

// vim: noet:ts=8:
