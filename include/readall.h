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

#ifndef READALL_H
#define READALL_H

#include "error.h"

err_t writeall(int fd, const void *buf, size_t count);
err_t readall(int fd, void *buf, size_t count);
err_t sendall(int sockfd, const void *buf, size_t len, int flags);
err_t recvall(int sockfd, void *buf, size_t len, int flags);

#endif /* READALL_H */
