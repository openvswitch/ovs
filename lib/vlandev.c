/*
 * Copyright (c) 2011 Nicira, Inc.
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

#include "vlandev.h"

#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "hash.h"
#include "shash.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(vlandev);

#ifdef LINUX_DATAPATH
#include "rtnetlink-link.h"
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include "netdev-linux.h"

static struct nln_notifier *vlan_cache_notifier;
static struct shash vlan_devs = SHASH_INITIALIZER(&vlan_devs);
static struct shash vlan_real_devs = SHASH_INITIALIZER(&vlan_real_devs);
static bool cache_valid;

static void
vlan_cache_cb(const struct rtnetlink_link_change *change OVS_UNUSED,
              void *aux OVS_UNUSED)
{
    cache_valid = false;
}

int
vlandev_refresh(void)
{
    const char *fn = "/proc/net/vlan/config";
    struct shash_node *node;
    char line[128];
    FILE *stream;

    if (!vlan_cache_notifier) {
        vlan_cache_notifier = rtnetlink_link_notifier_create(vlan_cache_cb,
                                                             NULL);
        if (!vlan_cache_notifier) {
            return EINVAL;
        }
    }

    if (cache_valid) {
        return 0;
    }

    /* Free old cache.
     *
     * The 'name' members point to strings owned by the "shash"es so we do not
     * free them ourselves. */
    shash_clear_free_data(&vlan_devs);
    SHASH_FOR_EACH (node, &vlan_real_devs) {
        struct vlan_real_dev *vrd = node->data;

        hmap_destroy(&vrd->vlan_devs);
    }
    shash_clear_free_data(&vlan_real_devs);

    /* Repopulate cache. */
    stream = fopen(fn, "r");
    if (!stream) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        int error = errno;
        struct stat s;

        if (error == ENOENT && !stat("/proc", &s)) {
            /* Probably the vlan module just isn't loaded, and probably that's
             * because no VLAN devices have been created.
             *
             * Not really an error. */
            return 0;
        }

        VLOG_WARN_RL(&rl, "%s: open failed (%s)", fn, strerror(error));
        return error;
    }

    while (fgets(line, sizeof line, stream)) {
        char vlan_dev[16], real_dev[16];
        int vid;

        if (sscanf(line, "%15[^ |] | %d | %15s", vlan_dev, &vid, real_dev) == 3
            && vid >= 0 && vid <= 4095
            && !shash_find(&vlan_devs, vlan_dev)) {
            struct vlan_real_dev *vrd;
            struct vlan_dev *vd;

            vrd = shash_find_data(&vlan_real_devs, real_dev);
            if (!vrd) {
                vrd = xmalloc(sizeof *vrd);
                vrd->name = xstrdup(real_dev);
                hmap_init(&vrd->vlan_devs);
                shash_add_nocopy(&vlan_real_devs, vrd->name, vrd);
            }

            vd = xmalloc(sizeof *vd);
            hmap_insert(&vrd->vlan_devs, &vd->hmap_node, hash_int(vid, 0));
            vd->name = xstrdup(vlan_dev);
            vd->vid = vid;
            vd->real_dev = vrd;
            shash_add_nocopy(&vlan_devs, vd->name, vd);
        }
    }
    fclose(stream);

    cache_valid = true;
    return 0;
}

struct shash *
vlandev_get_real_devs(void)
{
    return &vlan_real_devs;
}

const char *
vlandev_get_name(const char *real_dev_name, int vid)
{
    const struct vlan_real_dev *real_dev;

    real_dev = shash_find_data(&vlan_real_devs, real_dev_name);
    if (real_dev) {
        const struct vlan_dev *vlan_dev;

        HMAP_FOR_EACH_WITH_HASH (vlan_dev, hmap_node, hash_int(vid, 0),
                                 &real_dev->vlan_devs) {
            if (vlan_dev->vid == vid) {
                return vlan_dev->name;
            }
        }
    }

    return NULL;
}

static int
do_vlan_ioctl(const char *netdev_name, struct vlan_ioctl_args *via,
              int cmd, const char *cmd_name)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    int error;
    int sock;

    via->cmd = cmd;
    ovs_strlcpy(via->device1, netdev_name, sizeof via->device1);

    sock = netdev_linux_get_af_inet_sock();
    if (sock < 0) {
        return -sock;
    }

    error = ioctl(sock, SIOCSIFVLAN, via) < 0 ? errno : 0;
    if (error) {
        VLOG_WARN_RL(&rl, "%s: VLAN ioctl %s failed (%s)",
                     netdev_name, cmd_name, strerror(error));
    }
    return error;
}

int
vlandev_add(const char *real_dev, int vid)
{
    struct vlan_ioctl_args via;
    int error;

    memset(&via, 0, sizeof via);
    via.u.VID = vid;

    error = do_vlan_ioctl(real_dev, &via, ADD_VLAN_CMD, "ADD_VLAN_CMD");
    if (!error) {
        cache_valid = false;
    }
    return error;
}

int
vlandev_del(const char *vlan_dev)
{
    struct vlan_ioctl_args via;
    int error;

    memset(&via, 0, sizeof via);
    error = do_vlan_ioctl(vlan_dev, &via, DEL_VLAN_CMD, "DEL_VLAN_CMD");
    if (!error) {
        cache_valid = false;
    }
    return error;
}
#else  /* !LINUX_DATAPATH */
/* Stubs. */

int
vlandev_refresh(void)
{
    return 0;
}

struct shash *
vlandev_get_real_devs(void)
{
    static struct shash vlan_real_devs = SHASH_INITIALIZER(&vlan_real_devs);

    return &vlan_real_devs;
}

const char *
vlandev_get_name(const char *real_dev_name OVS_UNUSED, int vid OVS_UNUSED)
{
    return NULL;
}

int
vlandev_add(const char *real_dev OVS_UNUSED, int vid OVS_UNUSED)
{
    VLOG_ERR("not supported on non-Linux platform");
    return EOPNOTSUPP;
}

int
vlandev_del(const char *vlan_dev OVS_UNUSED)
{
    VLOG_ERR("not supported on non-Linux platform");
    return EOPNOTSUPP;
}
#endif
