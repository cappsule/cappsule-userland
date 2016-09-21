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

#ifndef UUID_H
#define UUID_H

#include "cuapi/common/uuid.h"

#define UUID_STR_LENGTH 36

int uuid_name_generate_ns(struct uuid *, const char *, struct uuid *);
int uuid_name_generate(const char *, struct uuid *);
int uuid_print(struct uuid, char *, size_t);
int uuid_from_str(const char *str, struct uuid *uuid);

#endif
