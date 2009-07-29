/* Copyright (c) 2009 Nicira Networks
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

#ifndef VSWITCHD_PROC_NET_COMPAT_H
#define VSWITCHD_PROC_NET_COMPAT_H 1

#include "packets.h"

struct compat_bond {
    bool up;
    int updelay;
    int downdelay;

    int n_hashes;
    struct compat_bond_hash *hashes;

    int n_slaves;
    struct compat_bond_slave *slaves;
};

struct compat_bond_hash {
    int hash;
    const char *netdev_name;
};

struct compat_bond_slave {
    const char *name;
    bool up;
    uint8_t mac[ETH_ADDR_LEN];
};

int proc_net_compat_init(void);
void proc_net_compat_update_bond(const char *name, const struct compat_bond *);
void proc_net_compat_update_vlan(const char *dev, const char *vlandev,
                                 int vlan);

#endif /* vswitchd/proc-net-compat.h */
