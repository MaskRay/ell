/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2015-2019  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __ELL_UINTSET_H
#define __ELL_UINTSET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ell/cleanup.h>

typedef void (*l_uintset_foreach_func_t) (uint32_t number, void *user_data);

struct l_uintset;

struct l_uintset *l_uintset_new_from_range(uint32_t min, uint32_t max);
struct l_uintset *l_uintset_new(unsigned int size);
void l_uintset_free(struct l_uintset *set);
DEFINE_CLEANUP_FUNC(l_uintset_free);

bool l_uintset_contains(struct l_uintset *set, uint32_t number);
bool l_uintset_take(struct l_uintset *set, uint32_t number);
bool l_uintset_put(struct l_uintset *set, uint32_t number);

uint32_t l_uintset_get_min(struct l_uintset *set);
uint32_t l_uintset_get_max(struct l_uintset *set);

uint32_t l_uintset_find_max(struct l_uintset *set);
uint32_t l_uintset_find_min(struct l_uintset *set);

uint32_t l_uintset_find_unused_min(struct l_uintset *set);
uint32_t l_uintset_find_unused(struct l_uintset *set, uint32_t start);

void l_uintset_foreach(const struct l_uintset *set,
			l_uintset_foreach_func_t function, void *user_data);

struct l_uintset *l_uintset_clone(const struct l_uintset *original);
struct l_uintset *l_uintset_intersect(const struct l_uintset *set_a,
						const struct l_uintset *set_b);
bool l_uintset_isempty(const struct l_uintset *set);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_UINTSET_H */
