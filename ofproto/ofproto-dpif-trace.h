/* Copyright (c) 2016, 2017 Nicira, Inc.
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

#ifndef OFPROTO_DPIF_TRACE_H
#define OFPROTO_DPIF_TRACE_H 1

/* Tracing
 * =======
 *
 * The Open vSwitch software datapath based switch implementation supports
 * "tracing".  A trace describes what happens to a particular kind of packet as
 * it passes through the switch, including information on each table, flow, and
 * action that would apply to the packet.  The trace is internally represented
 * as a tree that reflects control flow; for example, an OpenFlow switch
 * top-level node (of type OFT_BRIDGE) has a child node for each table visited
 * by a packet (of type OFT_TABLE), and each table node has a child node for
 * each action (OFT_ACTION) executed in the table.
 */

#include "openvswitch/compiler.h"
#include "openvswitch/list.h"

/* Type of a node within a trace. */
enum oftrace_node_type {
    /* Nodes that may have children (nonterminal nodes). */
    OFT_BRIDGE,                 /* Packet travel through an OpenFlow switch. */
    OFT_TABLE,                  /* Packet travel through a flow table. */
    OFT_THAW,                   /* Thawing a frozen state. */

    /* Nodes that never have children (terminal nodes). */
    OFT_ACTION,                 /* An action. */
    OFT_DETAIL,                 /* Some detail of an action. */
    OFT_WARN,                   /* A worrisome situation. */
    OFT_ERROR,                  /* An erroneous situation, worth logging. */
};

/* A node within a trace. */
struct oftrace_node {
    struct ovs_list node;       /* In parent. */
    struct ovs_list subs;       /* List of "struct oftrace_node" children. */

    enum oftrace_node_type type;
    char *text;
};

void ofproto_dpif_trace_init(void);

struct oftrace_node *oftrace_report(struct ovs_list *, enum oftrace_node_type,
                                    const char *text);

#endif /* ofproto-dpif-trace.h */
