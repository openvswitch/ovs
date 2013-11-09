/*
 * Copyright (c) 2011, 2013 Nicira, Inc.
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
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "dummy.h"
#include "hash.h"
#include "shash.h"
#include "socket-util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(vlandev);

/* A vlandev implementation. */
struct vlandev_class {
    int (*vd_refresh)(void);
    int (*vd_add)(const char *real_dev, int vid);
    int (*vd_del)(const char *vlan_dev);
};

#ifdef LINUX_DATAPATH
static const struct vlandev_class vlandev_linux_class;
#endif
static const struct vlandev_class vlandev_stub_class;
static const struct vlandev_class vlandev_dummy_class;

/* The in-use vlandev implementation. */
static const struct vlandev_class *vd_class;

/* Maps from a VLAN device name (e.g. "eth0.10") to struct vlan_dev. */
static struct shash vlan_devs = SHASH_INITIALIZER(&vlan_devs);

/* Maps from a VLAN real device name (e.g. "eth0") to struct vlan_real_dev. */
static struct shash vlan_real_devs = SHASH_INITIALIZER(&vlan_real_devs);

static int vlandev_add__(const char *vlan_dev, const char *real_dev, int vid);
static int vlandev_del__(const char *vlan_dev);
static void vlandev_clear__(void);

static const struct vlandev_class *
vlandev_get_class(void)
{
    if (!vd_class) {
#ifdef LINUX_DATAPATH
        vd_class = &vlandev_linux_class;
#else
        vd_class = &vlandev_stub_class;
#endif
    }
    return vd_class;
}

/* On Linux, the default implementation of VLAN devices creates and destroys
 * Linux VLAN devices.  On other OSess, the default implementation is a
 * nonfunctional stub.  In either case, this function replaces this default
 * implementation by a "dummy" implementation that simply reports back whatever
 * the client sets up with vlandev_add() and vlandev_del().
 *
 * Don't call this function directly; use dummy_enable() from dummy.h. */
void
vlandev_dummy_enable(void)
{
    if (vd_class != &vlandev_dummy_class) {
        vd_class = &vlandev_dummy_class;
        vlandev_clear__();
    }
}

/* Creates a new VLAN device for VLAN 'vid' on top of real Ethernet device
 * 'real_dev'.  Returns 0 if successful, otherwise a positive errno value.  On
 * OSes other than Linux, in the absence of dummies (see
 * vlandev_dummy_enable()), this always fails.
 *
 * The name of the new VLAN device is not easily predictable, because Linux
 * provides multiple naming schemes, does not allow the client to specify a
 * name, and does not directly report the new VLAN device's name.  Use
 * vlandev_refresh() then vlandev_get_name() to find out the new VLAN device's
 * name,. */
int
vlandev_add(const char *real_dev, int vid)
{
    return vlandev_get_class()->vd_add(real_dev, vid);
}

/* Deletes the VLAN device named 'vlan_dev'.  Returns 0 if successful,
 * otherwise a positive errno value.  On OSes other than Linux, in the absence
 * of dummies (see vlandev_dummy_enable()), this always fails. */
int
vlandev_del(const char *vlan_dev)
{
    return vlandev_get_class()->vd_del(vlan_dev);
}

/* Refreshes the cache of real device to VLAN device mappings reported by
 * vlandev_get_real_devs() and vlandev_get_name().  Without calling this
 * function, changes made by vlandev_add() and vlandev_del() may not be
 * reflected by vlandev_get_real_devs() and vlandev_get_name() output. */
int
vlandev_refresh(void)
{
    const struct vlandev_class *class = vlandev_get_class();
    return class->vd_refresh ? class->vd_refresh() : 0;
}

/* Returns a shash mapping from the name of real Ethernet devices used as the
 * basis of VLAN devices to struct vlan_real_devs.  The caller must not modify
 * or free anything in the returned shash.
 *
 * Changes made by vlandev_add() and vlandev_del() may not be reflected in this
 * function's output without an intervening call to vlandev_refresh(). */
struct shash *
vlandev_get_real_devs(void)
{
    return &vlan_real_devs;
}

/* Returns the name of the VLAN device for VLAN 'vid' on top of
 * 'real_dev_name', or NULL if there is no such VLAN device.
 *
 * Changes made by vlandev_add() and vlandev_del() may not be reflected in this
 * function's output without an intervening call to vlandev_refresh(). */
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

/* The Linux vlandev implementation. */

#ifdef LINUX_DATAPATH
#include "rtnetlink-link.h"
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include "netdev-linux.h"

static struct nln_notifier *vlan_cache_notifier;
static bool cache_valid;

static void
vlan_cache_cb(const struct rtnetlink_link_change *change OVS_UNUSED,
              void *aux OVS_UNUSED)
{
    cache_valid = false;
}

static int
vlandev_linux_refresh(void)
{
    const char *fn = "/proc/net/vlan/config";
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

    vlandev_clear__();

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

        VLOG_WARN_RL(&rl, "%s: open failed (%s)", fn, ovs_strerror(error));
        return error;
    }

    while (fgets(line, sizeof line, stream)) {
        char vlan_dev[16], real_dev[16];
        int vid;

        if (ovs_scan(line, "%15[^ |] | %d | %15s", vlan_dev, &vid, real_dev)) {
            vlandev_add__(vlan_dev, real_dev, vid);
        }
    }
    fclose(stream);

    cache_valid = true;
    return 0;
}

static int
do_vlan_ioctl(const char *netdev_name, struct vlan_ioctl_args *via,
              int cmd, const char *cmd_name)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    int error;

    via->cmd = cmd;
    ovs_strlcpy(via->device1, netdev_name, sizeof via->device1);

    error = af_inet_ioctl(SIOCSIFVLAN, via);
    if (error) {
        VLOG_WARN_RL(&rl, "%s: VLAN ioctl %s failed (%s)",
                     netdev_name, cmd_name, ovs_strerror(error));
    }
    return error;
}

static int
vlandev_linux_add(const char *real_dev, int vid)
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

static int
vlandev_linux_del(const char *vlan_dev)
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

static const struct vlandev_class vlandev_linux_class = {
    vlandev_linux_refresh,
    vlandev_linux_add,
    vlandev_linux_del
};
#endif

/* Stub implementation. */

static int
vlandev_stub_add(const char *real_dev OVS_UNUSED, int vid OVS_UNUSED)
{
    VLOG_ERR("not supported on non-Linux platform");
    return EOPNOTSUPP;
}

static int
vlandev_stub_del(const char *vlan_dev OVS_UNUSED)
{
    VLOG_ERR("not supported on non-Linux platform");
    return EOPNOTSUPP;
}

static const struct vlandev_class OVS_UNUSED vlandev_stub_class = {
    NULL,                       /* vd_refresh */
    vlandev_stub_add,
    vlandev_stub_del
};

/* Dummy implementation. */

static int
vlandev_dummy_add(const char *real_dev, int vid)
{
    char name[IFNAMSIZ];

    if (snprintf(name, sizeof name, "%s.%d", real_dev, vid) >= sizeof name) {
        return ENAMETOOLONG;
    }
    return vlandev_add__(name, real_dev, vid);
}

static int
vlandev_dummy_del(const char *vlan_dev)
{
    return vlandev_del__(vlan_dev);
}

static const struct vlandev_class vlandev_dummy_class = {
    NULL,                       /* vd_refresh */
    vlandev_dummy_add,
    vlandev_dummy_del
};

static int
vlandev_add__(const char *vlan_dev, const char *real_dev, int vid)
{
    uint32_t vid_hash = hash_int(vid, 0);
    struct vlan_real_dev *vrd;
    struct vlan_dev *vd;

    if (vid < 0 || vid > 4095) {
        return EINVAL;
    } else if (shash_find(&vlan_devs, vlan_dev)) {
        return EEXIST;
    }

    vrd = shash_find_data(&vlan_real_devs, real_dev);
    if (!vrd) {
        vrd = xmalloc(sizeof *vrd);
        vrd->name = xstrdup(real_dev);
        hmap_init(&vrd->vlan_devs);
        shash_add_nocopy(&vlan_real_devs, vrd->name, vrd);
    } else {
        HMAP_FOR_EACH_WITH_HASH (vd, hmap_node, vid_hash, &vrd->vlan_devs) {
            if (vd->vid == vid) {
                return EEXIST;
            }
        }
    }

    vd = xmalloc(sizeof *vd);
    hmap_insert(&vrd->vlan_devs, &vd->hmap_node, vid_hash);
    vd->name = xstrdup(vlan_dev);
    vd->vid = vid;
    vd->real_dev = vrd;
    shash_add_nocopy(&vlan_devs, vd->name, vd);

    return 0;
}

static int
vlandev_del__(const char *vlan_dev)
{
    struct shash_node *vd_node = shash_find(&vlan_devs, vlan_dev);
    if (!vd_node) {
        struct vlan_dev *vd = vd_node->data;
        struct vlan_real_dev *vrd = vd->real_dev;

        hmap_remove(&vrd->vlan_devs, &vd->hmap_node);
        if (hmap_is_empty(&vrd->vlan_devs)) {
            shash_find_and_delete_assert(&vlan_real_devs, vrd->name);
            free(vrd);
        }

        shash_delete(&vlan_devs, vd_node);
        free(vd);

        return 0;
    } else {
        return ENOENT;
    }
}

/* Clear 'vlan_devs' and 'vlan_real_devs' in preparation for repopulating. */
static void
vlandev_clear__(void)
{
    /* We do not free the 'name' members of struct vlan_dev and struct
     * vlan_real_dev, because the "shash"es own them.. */
    struct shash_node *node;

    shash_clear_free_data(&vlan_devs);
    SHASH_FOR_EACH (node, &vlan_real_devs) {
        struct vlan_real_dev *vrd = node->data;

        hmap_destroy(&vrd->vlan_devs);
    }
    shash_clear_free_data(&vlan_real_devs);
}
