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

#ifndef OVN_HA_CHASSIS_H
#define OVN_HA_CHASSIS_H 1

#include <stdint.h>
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"

struct sbrec_chassis;
struct sbrec_ha_chassis_group;
struct sset;

struct ha_chassis_ordered {
    struct sbrec_ha_chassis *ha_ch;
    size_t n_ha_ch;
};

/* Returns true if the local chassis is the active gateway among a set
 * of gateway_chassis.  Return false if the local chassis is currently a
 * backup in a set of multiple gateway_chassis. */
bool ha_chassis_group_is_active(
    const struct sbrec_ha_chassis_group *ha_chassis_grp,
    const struct sset *active_tunnels,
    const struct sbrec_chassis *local_chassis);

bool ha_chassis_group_contains(
    const struct sbrec_ha_chassis_group *ha_chassis_grp,
    const struct sbrec_chassis *chassis);

struct ha_chassis_ordered *ha_chassis_get_ordered(
    const struct sbrec_ha_chassis_group *ha_chassis_grp);

void ha_chassis_destroy_ordered(
    struct ha_chassis_ordered *ordered_ha_ch);

#endif /* OVN_HA_CHASSIS_H */
