/* Copyright (c) 2009 Nicira Networks
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, Nicira Networks gives permission
 * to link the code of its release of vswitchd with the OpenSSL project's
 * "OpenSSL" library (or with modified versions of it that use the same
 * license as the "OpenSSL" library), and distribute the linked
 * executables.  You must obey the GNU General Public License in all
 * respects for all of the code used other than "OpenSSL".  If you modify
 * this file, you may extend this exception to your version of the file,
 * but you are not obligated to do so.  If you do not wish to do so,
 * delete this exception statement from your version.
 */

#ifndef VSWITCHD_PROC_NET_COMPAT_H
#define VSWITCHD_PROC_NET_COMPAT_H 1

#include "packets.h"

struct compat_bond {
    bool up;
    int updelay;
    int downdelay;
    int n_slaves;
    struct compat_bond_slave *slaves;
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
