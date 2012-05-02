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

#ifndef VLANDEV_H
#define VLANDEV_H 1

#include "hmap.h"

/* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
 *
 * This is deprecated.  It is only for compatibility with broken device
 * drivers in old versions of Linux that do not properly support VLANs when
 * VLAN devices are not used.  When broken device drivers are no longer in
 * widespread use, we will delete these interfaces. */

/* A VLAN device (e.g. "eth0.10" for VLAN 10 on eth0). */
struct vlan_dev {
    struct vlan_real_dev *real_dev; /* Parent, e.g. "eth0". */
    struct hmap_node hmap_node;     /* In vlan_real_dev's "vlan_devs" map. */
    char *name;                     /* VLAN device name, e.g. "eth0.10". */
    int vid;                        /* VLAN ID, e.g. 10. */
};

/* A device that has VLAN devices broken out of it. */
struct vlan_real_dev {
    char *name;                 /* Name, e.g. "eth0". */
    struct hmap vlan_devs;      /* All child VLAN devices, hashed by VID. */
};

int vlandev_refresh(void);

struct shash *vlandev_get_real_devs(void);

const char *vlandev_get_name(const char *real_dev_name, int vid);

int vlandev_add(const char *real_dev, int vid);
int vlandev_del(const char *vlan_dev);

#endif /* vlandev.h */
