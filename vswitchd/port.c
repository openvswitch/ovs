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

#include <config.h>

#include "bridge.h"
#include "cfg.h"
#include "netdev.h"
#include "ovs-vswitchd.h"
#include "port.h"
#include "svec.h"

#define THIS_MODULE VLM_port
#include "vlog.h"

static int
set_ingress_policing(const char *port_name) 
{
    int kbits_rate = cfg_get_int(0, "port.%s.ingress.policing-rate", 
            port_name);
    int kbits_burst = cfg_get_int(0, "port.%s.ingress.policing-burst", 
            port_name);

    return netdev_nodev_set_policing(port_name, kbits_rate, kbits_burst);
}

void
port_init(void)
{
    port_reconfigure();
}

void
port_reconfigure(void)
{
    struct svec ports;
    int i;

    svec_init(&ports);
    bridge_get_ifaces(&ports);
    for (i=0; i<ports.n; i++) {
        set_ingress_policing(ports.names[i]);
    }
}
