/* Copyright (c) 2019 Red Hat, Inc.
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

#include "ha-chassis.h"
#include "lib/sset.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"

VLOG_DEFINE_THIS_MODULE(ha_chassis);

static int
compare_chassis_prio_(const void *a_, const void *b_)
{
    const struct sbrec_ha_chassis *ch_a = a_;
    const struct sbrec_ha_chassis *ch_b = b_;
    int prio_diff = ch_b->priority - ch_a->priority;
    if (!prio_diff) {
        return strcmp(ch_b->chassis->name, ch_a->chassis->name);
    }
    return prio_diff;
}

/* Returns the ordered HA chassis list in the HA chassis group.
 * Eg. If an HA chassis group has 3 HA chassis
 *   - HA1 - pri 30
 *   - HA2 - pri 40 and
 *   - HA3 - pri 20
 * and the ref_chassis of HA chassis group is set to - C1 and C2.
 *
 * If active_tunnels is NULL, then it returns the ordered list
 *   -  (HA2, HA1, HA3)
 *
 * If active_tunnels is set to - (HA1, HA2, C1, C2) and
 * local_chassis is HA3, then it returns the ordered list
 *  - (HA2, HA1, HA3)
 *
 * If active_tunnels is set to - (HA1, C1, C2) and
 * local_chassis is HA3, then it returns the ordered list
 *  - (HA1, HA3)
 *
 * If active_tunnels is set to - (C1, C2) and
 * local_chassis is HA3, then it returns the ordered list
 *  - (HA3)
 *
 * If active_tunnels is set is empty and local_chassis is HA3,
 * then it returns NULL.
 */
static struct ha_chassis_ordered *
get_ordered_ha_chassis_list(const struct sbrec_ha_chassis_group *ha_ch_grp,
                            const struct sset *active_tunnels,
                            const struct sbrec_chassis *local_chassis)
{
    struct sbrec_ha_chassis *ha_ch_order =
        xzalloc(sizeof *ha_ch_order * ha_ch_grp->n_ha_chassis);

    size_t n_ha_ch = 0;

    for (size_t i = 0; i < ha_ch_grp->n_ha_chassis; i++) {
        if (!ha_ch_grp->ha_chassis[i]->chassis) {
            continue;
        }

        /* Don't add it to the list for ordering if it is not active. */
        if (ha_ch_grp->ha_chassis[i]->chassis != local_chassis &&
            active_tunnels &&
            !sset_contains(active_tunnels,
                           ha_ch_grp->ha_chassis[i]->chassis->name)) {
            continue;
        }

        ha_ch_order[n_ha_ch].chassis = ha_ch_grp->ha_chassis[i]->chassis;
        ha_ch_order[n_ha_ch].priority = ha_ch_grp->ha_chassis[i]->priority;
        n_ha_ch++;
    }

    if (!n_ha_ch) {
        free(ha_ch_order);
        return NULL;
    }

    struct ha_chassis_ordered *ordered_ha_ch;
    if (n_ha_ch == 1) {
        if (active_tunnels) {
            /* If n_ha_ch is 1, it means only the local chassis is in the
            * ha_ch_order list. Check if this local chassis has active
            * bfd session with any of the referenced chassis. If so,
            * then the local chassis can be active. Otherwise it can't.
            * This can happen in the following scenario.
            * Lets say we have chassis HA1 (prioirty 20) and HA2 (priority 10)
            * in the ha_chasis_group and compute chassis C1 and C2 are in the
            * reference chassis list. If HA1 chassis has lost the link and
            * when this function is called for HA2 we need to consider
            * HA2 as active since it has active BFD sessions with C1 and C2.
            * On HA1 chassis, this function won't be called since
            * active_tunnels set will be empty.
            * */
            bool can_local_chassis_be_active = false;
            for (size_t i = 0; i < ha_ch_grp->n_ref_chassis; i++) {
                if (sset_contains(active_tunnels,
                                ha_ch_grp->ref_chassis[i]->name)) {
                    can_local_chassis_be_active = true;
                    break;
                }
            }
            if (!can_local_chassis_be_active) {
                free(ha_ch_order);
                return NULL;
            }
        }
    } else {
        qsort(ha_ch_order, n_ha_ch, sizeof *ha_ch_order,
              compare_chassis_prio_);
    }

    ordered_ha_ch = xmalloc(sizeof *ordered_ha_ch);
    ordered_ha_ch->ha_ch = ha_ch_order;
    ordered_ha_ch->n_ha_ch = n_ha_ch;

    return ordered_ha_ch;
}

void
ha_chassis_destroy_ordered(struct ha_chassis_ordered *ordered_ha_ch)
{
    if (ordered_ha_ch) {
        free(ordered_ha_ch->ha_ch);
        free(ordered_ha_ch);
    }
}


/* Returns true if the local_chassis is the master of
 * the HA chassis group, false otherwise. */
bool
ha_chassis_group_is_active(
    const struct sbrec_ha_chassis_group *ha_ch_grp,
    const struct sset *active_tunnels,
    const struct sbrec_chassis *local_chassis)
{
    if (!ha_ch_grp || !ha_ch_grp->n_ha_chassis) {
        return false;
    }

    if (ha_ch_grp->n_ha_chassis == 1) {
        return (ha_ch_grp->ha_chassis[0]->chassis == local_chassis);
    }

    if (sset_is_empty(active_tunnels)) {
        /* If active tunnel sset is empty, it means it has lost
         * connectivity with other chassis. */
        return false;
    }

    struct ha_chassis_ordered *ordered_ha_ch =
        get_ordered_ha_chassis_list(ha_ch_grp, active_tunnels, local_chassis);
    if (!ordered_ha_ch) {
        return false;
    }

    struct sbrec_chassis *active_ch = ordered_ha_ch->ha_ch[0].chassis;
    ha_chassis_destroy_ordered(ordered_ha_ch);

    return (active_ch == local_chassis);
}

bool
ha_chassis_group_contains(
    const struct sbrec_ha_chassis_group *ha_chassis_grp,
    const struct sbrec_chassis *chassis)
{
    if (ha_chassis_grp && chassis) {
        for (size_t i = 0; i < ha_chassis_grp->n_ha_chassis; i++) {
            if (ha_chassis_grp->ha_chassis[i]->chassis == chassis) {
                return true;
            }
        }
    }
    return false;
}

struct ha_chassis_ordered *
ha_chassis_get_ordered(const struct sbrec_ha_chassis_group *ha_chassis_grp)
{
    if (!ha_chassis_grp || !ha_chassis_grp->n_ha_chassis) {
        return NULL;
    }

    return get_ordered_ha_chassis_list(ha_chassis_grp, NULL, NULL);
}
