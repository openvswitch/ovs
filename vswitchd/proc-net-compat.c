/* Copyright (c) 2009, 2010, 2011 Nicira Networks
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
#include "proc-net-compat.h"

#ifdef HAVE_NETLINK
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include "dynamic-string.h"
#include "hash.h"
#include "netlink-protocol.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "openvswitch/brcompat-netlink.h"
#include "hmap.h"
#include "shash.h"
#include "svec.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(proc_net_compat);

/* Netlink socket to bridge compatibility kernel module. */
static struct nl_sock *brc_sock;

/* The Generic Netlink family number used for bridge compatibility. */
static int brc_family = 0;

/* Rate limiting for log messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

static void flush_dir(const char *dir);
static int set_proc_file(const char *dir, const char *file, const char *data);

/* Initializes the /proc/net compatibility layer.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
proc_net_compat_init(void)
{
    if (!brc_sock) {
        int retval = nl_lookup_genl_family(BRC_GENL_FAMILY_NAME, &brc_family);
        if (retval) {
            return retval;
        }

        retval = nl_sock_create(NETLINK_GENERIC, &brc_sock);
        if (retval) {
            return retval;
        }

        flush_dir("/proc/net/vlan");
        flush_dir("/proc/net/bonding");
    }
    return 0;
}

static int
set_proc_file(const char *dir, const char *file, const char *data)
{
    struct ofpbuf request;
    int retval;

    ofpbuf_init(&request, 0);
    nl_msg_put_genlmsghdr(&request, 1024, brc_family, NLM_F_REQUEST,
                          BRC_GENL_C_SET_PROC, 1);
    nl_msg_put_string(&request, BRC_GENL_A_PROC_DIR, dir);
    nl_msg_put_string(&request, BRC_GENL_A_PROC_NAME, file);
    if (data) {
        nl_msg_put_string(&request, BRC_GENL_A_PROC_DATA, data);
    }

    retval = nl_sock_transact(brc_sock, &request, NULL);
    ofpbuf_uninit(&request);
    if (retval) {
        VLOG_WARN_RL(&rl, "failed to %s /proc/%s/%s (%s)",
                     data ? "update" : "remove", dir, file, strerror(retval));
    }
    return retval;
}

static void
flush_dir(const char *dir)
{
    const char *subdir;
    struct dirent *de;
    DIR *stream;

    assert(!memcmp(dir, "/proc/", 6));
    subdir = dir + 6;

    stream = opendir(dir);
    if (!stream) {
        if (errno != ENOENT) {
            VLOG_WARN_RL(&rl, "%s: open failed (%s)", dir, strerror(errno));
        }
        return;
    }

    while ((de = readdir(stream)) != NULL) {
        if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
            set_proc_file(subdir, de->d_name, NULL);
        }
    }
    closedir(stream);
}

/* If 'bond' is nonnull, creates a file in /proc/net/bonding for a bond with
 * the given 'name' and the details in 'bond'.  If 'bond' is null, deletes
 * the /proc/net/bonding file with the given 'name'.
 *
 * This function has no effect unless proc_net_compat_init() has been
 * called. */
void
proc_net_compat_update_bond(const char *name, const struct compat_bond *bond)
{
    struct ds ds;
    int i;

    if (!brc_sock) {
        return;
    }

    if (!bond) {
        set_proc_file("net/bonding", name, NULL);
        return;
    }

    ds_init(&ds);
    ds_put_format(
        &ds,
        "Ethernet Channel Bonding Driver: ovs-vswitchd "
        VERSION BUILDNR" ("__DATE__" "__TIME__")\n"
        "Bonding Mode: source load balancing\n"
        "Primary Slave: None\n"
        "Currently Active Slave: None\n"
        "MII Status: %s\n"
        "MII Polling Interval (ms): 100\n"
        "Up Delay (ms): %d\n"
        "Down Delay (ms): %d\n"
        "\n"
        "Source load balancing info:\n",
        bond->up ? "up" : "down", bond->updelay, bond->downdelay);

    for (i = 0; i < bond->n_hashes; i++) {
        const struct compat_bond_hash *cbh = &bond->hashes[i];
        ds_put_format(&ds, " [%03d] = %s\n", cbh->hash, cbh->netdev_name);
    }

    for (i = 0; i < bond->n_slaves; i++) {
        const struct compat_bond_slave *slave = &bond->slaves[i];
        ds_put_format(
            &ds,
            "\n"
            "Slave Interface: %s\n"
            "MII Status: %s\n"
            "Link Failure Count: 0\n"
            "Permanent HW addr: "ETH_ADDR_FMT"\n",
            slave->name, slave->up ? "up" : "down",
            ETH_ADDR_ARGS(slave->mac));
    }
    set_proc_file("net/bonding", name, ds_cstr(&ds));
    ds_destroy(&ds);
}

/* /proc/net/vlan compatibility.
 *
 * This is much more complex than I expected it to be. */

struct compat_vlan {
    /* Hash key. */
    struct hmap_node trunk_node; /* Hash map node. */
    char *trunk_dev;             /* Name of trunk network device. */
    int vid;                     /* VLAN number. */

    /* Auxiliary data. */
    char *vlan_dev;             /* sprintf("%s.%d", trunk_dev, vid); */
    struct svec tagged_devs;    /* Name of tagged network device(s). */
};

/* Current set of VLAN devices, indexed two different ways. */
static struct hmap vlans_by_trunk = HMAP_INITIALIZER(&vlans_by_trunk);
static struct shash vlans_by_tagged = SHASH_INITIALIZER(&vlans_by_tagged);

static bool remove_tagged_dev(struct shash_node *, const char *tagged_dev);
static void update_vlan_config(void);
static void set_vlan_proc_file(const struct compat_vlan *);
static uint32_t hash_vlan(const char *trunk_dev, uint32_t vid);

/* Updates the /proc/net/vlan compatibility layer's idea of what trunk device
 * and VLAN the given 'tagged_dev' is associated with.  If 'tagged_dev' has an
 * implicit VLAN tag, then 'trunk_dev' should be the name of a network device
 * on the same bridge that trunks that VLAN, and 'vid' should be the VLAN tag
 * number.  If 'tagged_dev' does not have an implicit VLAN tag, then
 * 'trunk_dev' should be NULL and 'vid' should be -1.
 *
 * This function has no effect unless proc_net_compat_init() has been
 * called. */
void
proc_net_compat_update_vlan(const char *tagged_dev, const char *trunk_dev,
                            int vid)
{
    struct compat_vlan *vlan;
    struct shash_node *node;

    if (!brc_sock) {
        return;
    }

    /* Find the compat_vlan that we currently have for 'tagged_dev' (if
     * any). */
    node = shash_find(&vlans_by_tagged, tagged_dev);
    vlan = node ? node->data : NULL;
    if (vid <= 0 || !trunk_dev) {
        if (vlan) {
            if (remove_tagged_dev(node, tagged_dev)) {
                update_vlan_config();
            }
        }
    } else {
        if (vlan) {
            if (!strcmp(trunk_dev, vlan->trunk_dev) && vid == vlan->vid) {
                /* No change. */
                return;
            } else {
                /* 'tagged_dev' is attached to the wrong compat_vlan.  Start
                 * by removing it from that one. */
                remove_tagged_dev(node, tagged_dev);
                node = NULL;
                vlan = NULL;
            }
        }

        /* 'tagged_dev' is not attached to any compat_vlan.  Find the
         * compat_vlan corresponding to (trunk_dev,vid) to attach it to, or
         * create a new compat_vlan if none exists for (trunk_dev,vid). */
        HMAP_FOR_EACH_WITH_HASH (vlan, trunk_node, hash_vlan(trunk_dev, vid),
                                 &vlans_by_trunk) {
            if (!strcmp(trunk_dev, vlan->trunk_dev) && vid == vlan->vid) {
                break;
            }
        }
        if (!vlan) {
            /* Create a new compat_vlan for (trunk_dev,vid). */
            vlan = xzalloc(sizeof *vlan);
            vlan->trunk_dev = xstrdup(trunk_dev);
            vlan->vid = vid;
            vlan->vlan_dev = xasprintf("%s.%d", trunk_dev, vid);
            svec_init(&vlan->tagged_devs);
            hmap_insert(&vlans_by_trunk, &vlan->trunk_node,
                        hash_vlan(trunk_dev, vid));
            set_vlan_proc_file(vlan);
        }

        /* Attach 'tagged_dev' to 'vlan'. */
        svec_add(&vlan->tagged_devs, tagged_dev);
        shash_add(&vlans_by_tagged, tagged_dev, vlan);
        svec_sort(&vlan->tagged_devs);
        update_vlan_config();
    }
}

/* Remove 'tagged_dev' from the compat_vlan in 'node'.  If that causes the
 * compat_vlan to have no tagged_devs left, destroy the compat_vlan too. */
static bool
remove_tagged_dev(struct shash_node *node, const char *tagged_dev)
{
    struct compat_vlan *vlan = node->data;

    svec_del(&vlan->tagged_devs, tagged_dev);
    shash_delete(&vlans_by_tagged, node);
    if (!vlan->tagged_devs.n) {
        set_proc_file("net/vlan", vlan->vlan_dev, NULL);

        hmap_remove(&vlans_by_trunk, &vlan->trunk_node);
        svec_destroy(&vlan->tagged_devs);
        free(vlan->trunk_dev);
        free(vlan->vlan_dev);
        free(vlan);
        return true;
    }
    return false;
}

/* Returns a hash value for (trunk_dev,vid). */
static uint32_t
hash_vlan(const char *trunk_dev, uint32_t vid)
{
    return hash_int(vid, hash_string(trunk_dev, 0));
}

/* Update /proc/net/vlan/<vlan_dev> for 'vlan'. */
static void
set_vlan_proc_file(const struct compat_vlan *vlan)
{
    struct ds ds;

    ds_init(&ds);
    ds_put_format(
        &ds,
        "%s  VID: %d\t REORDER_HDR: 1  dev->priv_flags: 81\n"
        "         total frames received            0\n"
        "          total bytes received            0\n"
        "      Broadcast/Multicast Rcvd            0\n"
        "\n"
        "      total frames transmitted            0\n"
        "       total bytes transmitted            0\n"
        "            total headroom inc            0\n"
        "           total encap on xmit            0\n"
        "Device: %s\n"
        "INGRESS priority mappings: 0:0  1:0  2:0  3:0  4:0  5:0  6:0 7:0\n"
        "EGRESSS priority Mappings: \n",
        vlan->vlan_dev, vlan->vid, vlan->trunk_dev);
    set_proc_file("net/vlan", vlan->vlan_dev, ds_cstr(&ds));
    ds_destroy(&ds);
}

/* Update /proc/net/vlan/config. */
static void
update_vlan_config(void)
{
    struct compat_vlan *vlan;
    struct ds ds;

    ds_init(&ds);
    ds_put_cstr(&ds, "VLAN Dev name     | VLAN ID\n"
                "Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n");
    HMAP_FOR_EACH (vlan, trunk_node, &vlans_by_trunk) {
        ds_put_format(&ds, "%-15s| %d  | %s\n",
                      vlan->vlan_dev, vlan->vid, vlan->trunk_dev);
    }
    set_proc_file("net/vlan", "config", ds_cstr(&ds));
    ds_destroy(&ds);
}
#else  /* !HAVE_NETLINK */
#include "compiler.h"

int
proc_net_compat_init(void)
{
    return 0;
}

void
proc_net_compat_update_bond(const char *name OVS_UNUSED,
                            const struct compat_bond *bond OVS_UNUSED)
{
}

void
proc_net_compat_update_vlan(const char *tagged_dev OVS_UNUSED,
                            const char *trunk_dev OVS_UNUSED,
                            int vid OVS_UNUSED)
{
}
#endif  /* !HAVE_NETLINK */
