/* Copyright (c) 2011 Nicira Networks
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

#include <config.h>

#include "vlan-bitmap.h"

/* Allocates and returns a new 4096-bit bitmap that has 1-bit in positions in
 * the 'n_vlans' bits indicated in 'vlans' and 0-bits everywhere else.  Returns
 * a null pointer if there are no (valid) VLANs in 'vlans'. */
unsigned long *
vlan_bitmap_from_array(const int64_t *vlans, size_t n_vlans)
{
    unsigned long *b;
    size_t i, n;

    if (!n_vlans) {
        return NULL;
    }

    b = bitmap_allocate(4096);
    n = 0;
    for (i = 0; i < n_vlans; i++) {
        int64_t vlan = vlans[i];

        if (vlan >= 0 && vlan < 4096) {
            bitmap_set1(b, vlan);
            n++;
        }
    }

    if (!n) {
        free(b);
        return NULL;
    }

    return b;
}

/* Returns true if 'a' and 'b' are the same: either both null or both the same
 * 4096-bit bitmap.
 *
 * (We assume that a nonnull bitmap is not all 0-bits.) */
bool
vlan_bitmap_equal(const unsigned long *a, const unsigned long *b)
{
    return (!a && !b) || (a && b && bitmap_equal(a, b, 4096));
}
