/*
 * Copyright (c) 2017 Red Hat Inc.
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

#ifndef NETNSID_H
#define NETNSID_H 1

#include <stdbool.h>

#ifdef HAVE_LINUX_NET_NAMESPACE_H
#include <linux/net_namespace.h>
#endif

/*
 * The network namespace ID is a positive number that identifies the namespace
 * which the netlink message was sent.  It is used to identify if a received
 * message belongs to a port attached to the bridge.
 *
 * There are three port states listed below:
 * UNSET: A port in this state means that it could be either in same network
 * namespace as the daemon (LOCAL) or in another namespace (ID).  Any operation
 * on a port in this state that requires the ID will trigger a query to the
 * kernel to find out in which namespace the port currently is.
 *
 * LOCAL: A port in this state means that it is in the same network namespace
 * as the daemons.
 *
 * ID: A port that is not LOCAL and not UNSET has a valid positive (zero
 * included) remote namespace ID.
 *
 * Possible state changes:
 *
 * Initial port's state: UNSET.
 *
 * UNSET -> LOCAL: The daemon queries the kernel and finds that it's in the
 * same network namespace as the daemon or the API is not available (older
 * kernels).
 *
 * LOCAL -> UNSET: The kernel sends a deregistering netlink message which
 * unsets the port. It happens when the port is removed (or moved to another
 * network namespace).
 *
 * UNSET -> ID: The daemon queries the kernel and finds that the port is
 * in a specific network namespace with ID assigned.
 *
 * ID -> UNSET: When it receives a deregistering netlink message from that
 * namespace indicating the device is being removed (or moved to another
 * network namespace).
 */

#ifdef NETNSA_NSID_NOT_ASSIGNED
#define NETNSID_LOCAL NETNSA_NSID_NOT_ASSIGNED
#else
#define NETNSID_LOCAL -1
#endif
#define NETNSID_UNSET (NETNSID_LOCAL - 1)

/* Prototypes */
static inline void netnsid_set_local(int *nsid);
static inline bool netnsid_is_local(int nsid);
static inline void netnsid_unset(int *nsid);
static inline bool netnsid_is_unset(int nsid);
static inline bool netnsid_is_remote(int nsid);
static inline void netnsid_set(int *nsid, int id);
static inline bool netnsid_eq(int nsid1, int nsid2);

/* Functions */
static inline void
netnsid_set_local(int *nsid)
{
    *nsid = NETNSID_LOCAL;
}

static inline bool
netnsid_is_local(int nsid)
{
    return nsid == NETNSID_LOCAL;
}

static inline void
netnsid_unset(int *nsid)
{
    *nsid = NETNSID_UNSET;
}

static inline bool
netnsid_is_unset(int nsid)
{
    return nsid == NETNSID_UNSET;
}

static inline bool
netnsid_is_remote(int nsid)
{
    if (netnsid_is_unset(nsid) || netnsid_is_local(nsid)) {
        return false;
    }

    return true;
}

static inline void
netnsid_set(int *nsid, int id)
{
    /* The kernel only sends positive numbers for valid IDs. */
    if (id != NETNSID_LOCAL) {
        ovs_assert(id >= 0);
    }

    *nsid = id;
}

static inline bool
netnsid_eq(int nsid1, int nsid2)
{
    if (netnsid_is_unset(nsid1) || netnsid_is_unset(nsid2)) {
        return false;
    }

    if (nsid1 == nsid2) {
        return true;
    }

    return false;
}

#endif
