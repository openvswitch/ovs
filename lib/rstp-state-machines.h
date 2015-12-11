/*
 * Copyright (c) 2011-2015 M3S, Srl - Italy
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

/*
 * Rapid Spanning Tree Protocol (IEEE 802.1D-2004) state machines
 * implementation (header file).
 *
 * Authors:
 *         Martino Fornasa <mf@fornasa.it>
 *         Daniele Venturino <daniele.venturino@m3s.it>
 *         Carlo Andreotti <c.andreotti@m3s.it>
 *
 * References to IEEE 802.1D-2004 standard are enclosed in square brackets.
 * E.g. [17.3], [Table 17-1], etc.
 *
 */

#ifndef RSTP_STATE_MACHINES_H
#define RSTP_STATE_MACHINES_H 1

#include "rstp-common.h"

/* Methods called by the Forwarding Layer, through functions of rstp.h. */
int move_rstp__(struct rstp *)
    OVS_REQUIRES(rstp_mutex);
void decrease_rstp_port_timers__(struct rstp *)
    OVS_REQUIRES(rstp_mutex);
void process_received_bpdu__(struct rstp_port *, const void *, size_t)
    OVS_REQUIRES(rstp_mutex);

void updt_roles_tree__(struct rstp *)
    OVS_REQUIRES(rstp_mutex);

#endif /* rstp-state-machines.h */
