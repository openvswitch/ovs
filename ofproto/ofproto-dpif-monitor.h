/* Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
 * limitations under the License. */

#ifndef OFPROTO_DPIF_MONITOR_H
#define OFPROTO_DPIF_MONITOR_H 1

#include <stdint.h>

#include "openflow/openflow.h"
#include "packets.h"

struct bfd;
struct cfm;
struct lldp;
struct ofport_dpif;

void ofproto_dpif_monitor_port_send_soon(const struct ofport_dpif *);

void ofproto_dpif_monitor_port_update(const struct ofport_dpif *,
                                      struct bfd *, struct cfm *,
                                      struct lldp *, uint8_t[OFP_ETH_ALEN]);

#endif /* ofproto-dpif-monitor.h */
