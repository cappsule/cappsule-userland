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

#ifndef _CONSOLE_H
#define _CONSOLE_H

#define NR_CONSOLE_FDS 3

void recv_fds_from_virtexec(int fd);
int get_fds(pid_t pid, int *fds);
void delete_client_by_pid(pid_t pid);
void init_fd_pool(void);

#endif /* _CONSOLE_H */
