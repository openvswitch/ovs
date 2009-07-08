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
 *
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
