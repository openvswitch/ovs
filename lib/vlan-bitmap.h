/* Copyright (c) 2011 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef VLAN_BITMAP_H
#define VLAN_BITMAP_H 1

#include <stdbool.h>
#include <stdint.h>
#include "bitmap.h"

/* A "VLAN bitmap" is a 4096-bit bitmap that represents a set.  A 1-bit
 * indicates that the respective VLAN is a member of the set, a 0-bit indicates
 * that it is not.  There is one wrinkle: NULL is a valid value that indicates
 * either that all VLANs are or are not members, depending on the vlan_bitmap.
 *
 * This is empirically a useful data structure. */

unsigned long *vlan_bitmap_from_array(const int64_t *vlans, size_t n_vlans);
int vlan_bitmap_from_array__(const int64_t *vlans, size_t n_vlans,
                             unsigned long int *b);

bool vlan_bitmap_equal(const unsigned long *a, const unsigned long *b);

/* Returns a new copy of 'vlans'. */
static inline unsigned long *
vlan_bitmap_clone(const unsigned long *vlans)
{
    return vlans ? bitmap_clone(vlans, 4096) : NULL;
}

#endif /* lib/vlan-bitmap.h */
