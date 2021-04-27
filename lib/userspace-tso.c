/*
 * Copyright (c) 2020 Red Hat, Inc.
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

#include "smap.h"
#include "ovs-thread.h"
#include "openvswitch/vlog.h"
#include "dpdk.h"
#include "userspace-tso.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(userspace_tso);

static bool userspace_tso = false;

void
userspace_tso_init(const struct smap *ovs_other_config)
{
    if (smap_get_bool(ovs_other_config, "userspace-tso-enable", false)) {
        static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once)) {
            VLOG_INFO("Userspace TCP Segmentation Offloading support enabled");
            userspace_tso = true;
            ovsthread_once_done(&once);
        }
    }
}

bool
userspace_tso_enabled(void)
{
    return userspace_tso;
}
