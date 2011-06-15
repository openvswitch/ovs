/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
 * Copyright (c) 2009 InMon Corp.
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
#include "ofproto-dpif-sflow.h"
#include <inttypes.h>
#include <stdlib.h>
#include "collectors.h"
#include "compiler.h"
#include "dpif.h"
#include "hash.h"
#include "hmap.h"
#include "netdev.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "ofproto.h"
#include "packets.h"
#include "poll-loop.h"
#include "sflow_api.h"
#include "socket-util.h"
#include "timeval.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(sflow);

struct dpif_sflow_port {
    struct hmap_node hmap_node; /* In struct dpif_sflow's "ports" hmap. */
    struct netdev *netdev;      /* Underlying network device, for stats. */
    SFLDataSource_instance dsi; /* sFlow library's notion of port number. */
    uint16_t odp_port;          /* ODP port number. */
};

struct dpif_sflow {
    struct ofproto *ofproto;
    struct collectors *collectors;
    SFLAgent *sflow_agent;
    struct ofproto_sflow_options *options;
    struct dpif *dpif;
    time_t next_tick;
    size_t n_flood, n_all;
    struct hmap ports;          /* Contains "struct dpif_sflow_port"s. */
};

static void dpif_sflow_del_port__(struct dpif_sflow *,
                                  struct dpif_sflow_port *);

#define RECEIVER_INDEX 1

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static bool
nullable_string_is_equal(const char *a, const char *b)
{
    return a ? b && !strcmp(a, b) : !b;
}

static bool
ofproto_sflow_options_equal(const struct ofproto_sflow_options *a,
                         const struct ofproto_sflow_options *b)
{
    return (sset_equals(&a->targets, &b->targets)
            && a->sampling_rate == b->sampling_rate
            && a->polling_interval == b->polling_interval
            && a->header_len == b->header_len
            && a->sub_id == b->sub_id
            && nullable_string_is_equal(a->agent_device, b->agent_device)
            && nullable_string_is_equal(a->control_ip, b->control_ip));
}

static struct ofproto_sflow_options *
ofproto_sflow_options_clone(const struct ofproto_sflow_options *old)
{
    struct ofproto_sflow_options *new = xmemdup(old, sizeof *old);
    sset_clone(&new->targets, &old->targets);
    new->agent_device = old->agent_device ? xstrdup(old->agent_device) : NULL;
    new->control_ip = old->control_ip ? xstrdup(old->control_ip) : NULL;
    return new;
}

static void
ofproto_sflow_options_destroy(struct ofproto_sflow_options *options)
{
    if (options) {
        sset_destroy(&options->targets);
        free(options->agent_device);
        free(options->control_ip);
        free(options);
    }
}

/* sFlow library callback to allocate memory. */
static void *
sflow_agent_alloc_cb(void *magic OVS_UNUSED, SFLAgent *agent OVS_UNUSED,
                     size_t bytes)
{
    return calloc(1, bytes);
}

/* sFlow library callback to free memory. */
static int
sflow_agent_free_cb(void *magic OVS_UNUSED, SFLAgent *agent OVS_UNUSED,
                    void *obj)
{
    free(obj);
    return 0;
}

/* sFlow library callback to report error. */
static void
sflow_agent_error_cb(void *magic OVS_UNUSED, SFLAgent *agent OVS_UNUSED,
                     char *msg)
{
    VLOG_WARN("sFlow agent error: %s", msg);
}

/* sFlow library callback to send datagram. */
static void
sflow_agent_send_packet_cb(void *ds_, SFLAgent *agent OVS_UNUSED,
                           SFLReceiver *receiver OVS_UNUSED, u_char *pkt,
                           uint32_t pktLen)
{
    struct dpif_sflow *ds = ds_;
    collectors_send(ds->collectors, pkt, pktLen);
}

static struct dpif_sflow_port *
dpif_sflow_find_port(const struct dpif_sflow *ds, uint16_t odp_port)
{
    struct dpif_sflow_port *dsp;

    HMAP_FOR_EACH_IN_BUCKET (dsp, hmap_node,
                             hash_int(odp_port, 0), &ds->ports) {
        if (dsp->odp_port == odp_port) {
            return dsp;
        }
    }
    return NULL;
}

static void
sflow_agent_get_counters(void *ds_, SFLPoller *poller,
                         SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    struct dpif_sflow *ds = ds_;
    SFLCounters_sample_element elem;
    struct dpif_sflow_port *dsp;
    SFLIf_counters *counters;
    struct netdev_stats stats;
    enum netdev_flags flags;
    uint32_t current;

    dsp = dpif_sflow_find_port(ds, poller->bridgePort);
    if (!dsp) {
        return;
    }

    elem.tag = SFLCOUNTERS_GENERIC;
    counters = &elem.counterBlock.generic;
    counters->ifIndex = SFL_DS_INDEX(poller->dsi);
    counters->ifType = 6;
    if (!netdev_get_features(dsp->netdev, &current, NULL, NULL, NULL)) {
        /* The values of ifDirection come from MAU MIB (RFC 2668): 0 = unknown,
           1 = full-duplex, 2 = half-duplex, 3 = in, 4=out */
        counters->ifSpeed = netdev_features_to_bps(current);
        counters->ifDirection = (netdev_features_is_full_duplex(current)
                                 ? 1 : 2);
    } else {
        counters->ifSpeed = 100000000;
        counters->ifDirection = 0;
    }
    if (!netdev_get_flags(dsp->netdev, &flags) && flags & NETDEV_UP) {
        counters->ifStatus = 1; /* ifAdminStatus up. */
        if (netdev_get_carrier(dsp->netdev)) {
            counters->ifStatus |= 2; /* ifOperStatus us. */
        }
    } else {
        counters->ifStatus = 0;  /* Down. */
    }

    /* XXX
       1. Is the multicast counter filled in?
       2. Does the multicast counter include broadcasts?
       3. Does the rx_packets counter include multicasts/broadcasts?
    */
    netdev_get_stats(dsp->netdev, &stats);
    counters->ifInOctets = stats.rx_bytes;
    counters->ifInUcastPkts = stats.rx_packets;
    counters->ifInMulticastPkts = stats.multicast;
    counters->ifInBroadcastPkts = -1;
    counters->ifInDiscards = stats.rx_dropped;
    counters->ifInErrors = stats.rx_errors;
    counters->ifInUnknownProtos = -1;
    counters->ifOutOctets = stats.tx_bytes;
    counters->ifOutUcastPkts = stats.tx_packets;
    counters->ifOutMulticastPkts = -1;
    counters->ifOutBroadcastPkts = -1;
    counters->ifOutDiscards = stats.tx_dropped;
    counters->ifOutErrors = stats.tx_errors;
    counters->ifPromiscuousMode = 0;

    SFLADD_ELEMENT(cs, &elem);
    sfl_poller_writeCountersSample(poller, cs);
}

/* Obtains an address to use for the local sFlow agent and stores it into
 * '*agent_addr'.  Returns true if successful, false on failure.
 *
 * The sFlow agent address should be a local IP address that is persistent and
 * reachable over the network, if possible.  The IP address associated with
 * 'agent_device' is used if it has one, and otherwise 'control_ip', the IP
 * address used to talk to the controller. */
static bool
sflow_choose_agent_address(const char *agent_device, const char *control_ip,
                           SFLAddress *agent_addr)
{
    struct in_addr in4;

    memset(agent_addr, 0, sizeof *agent_addr);
    agent_addr->type = SFLADDRESSTYPE_IP_V4;

    if (agent_device) {
        struct netdev *netdev;

        if (!netdev_open_default(agent_device, &netdev)) {
            int error = netdev_get_in4(netdev, &in4, NULL);
            netdev_close(netdev);
            if (!error) {
                goto success;
            }
        }
    }

    if (control_ip && !lookup_ip(control_ip, &in4)) {
        goto success;
    }

    VLOG_ERR("could not determine IP address for sFlow agent");
    return false;

success:
    agent_addr->address.ip_v4.addr = (OVS_FORCE uint32_t) in4.s_addr;
    return true;
}

void
dpif_sflow_clear(struct dpif_sflow *ds)
{
    if (ds->sflow_agent) {
        sfl_agent_release(ds->sflow_agent);
        ds->sflow_agent = NULL;
    }
    collectors_destroy(ds->collectors);
    ds->collectors = NULL;
    ofproto_sflow_options_destroy(ds->options);
    ds->options = NULL;

    /* Turn off sampling to save CPU cycles. */
    dpif_set_sflow_probability(ds->dpif, 0);
}

bool
dpif_sflow_is_enabled(const struct dpif_sflow *ds)
{
    return ds->collectors != NULL;
}

struct dpif_sflow *
dpif_sflow_create(struct dpif *dpif)
{
    struct dpif_sflow *ds;

    ds = xcalloc(1, sizeof *ds);
    ds->dpif = dpif;
    ds->next_tick = time_now() + 1;
    hmap_init(&ds->ports);
    return ds;
}

void
dpif_sflow_destroy(struct dpif_sflow *ds)
{
    if (ds) {
        struct dpif_sflow_port *dsp, *next;

        dpif_sflow_clear(ds);
        HMAP_FOR_EACH_SAFE (dsp, next, hmap_node, &ds->ports) {
            dpif_sflow_del_port__(ds, dsp);
        }
        hmap_destroy(&ds->ports);
        free(ds);
    }
}

static void
dpif_sflow_add_poller(struct dpif_sflow *ds,
                      struct dpif_sflow_port *dsp, uint16_t odp_port)
{
    SFLPoller *poller = sfl_agent_addPoller(ds->sflow_agent, &dsp->dsi, ds,
                                            sflow_agent_get_counters);
    sfl_poller_set_sFlowCpInterval(poller, ds->options->polling_interval);
    sfl_poller_set_sFlowCpReceiver(poller, RECEIVER_INDEX);
    sfl_poller_set_bridgePort(poller, odp_port);
}

static void
dpif_sflow_add_sampler(struct dpif_sflow *ds, struct dpif_sflow_port *dsp)
{
    SFLSampler *sampler = sfl_agent_addSampler(ds->sflow_agent, &dsp->dsi);
    sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, ds->options->sampling_rate);
    sfl_sampler_set_sFlowFsMaximumHeaderSize(sampler, ds->options->header_len);
    sfl_sampler_set_sFlowFsReceiver(sampler, RECEIVER_INDEX);
}

void
dpif_sflow_add_port(struct dpif_sflow *ds, uint16_t odp_port,
                    const char *netdev_name)
{
    struct dpif_sflow_port *dsp;
    struct netdev *netdev;
    uint32_t ifindex;
    int error;

    dpif_sflow_del_port(ds, odp_port);

    /* Open network device. */
    error = netdev_open_default(netdev_name, &netdev);
    if (error) {
        VLOG_WARN_RL(&rl, "failed to open network device \"%s\": %s",
                     netdev_name, strerror(error));
        return;
    }

    /* Add to table of ports. */
    dsp = xmalloc(sizeof *dsp);
    dsp->netdev = netdev;
    ifindex = netdev_get_ifindex(netdev);
    if (ifindex <= 0) {
        ifindex = (ds->sflow_agent->subId << 16) + odp_port;
    }
    SFL_DS_SET(dsp->dsi, 0, ifindex, 0);
    dsp->odp_port = odp_port;
    hmap_insert(&ds->ports, &dsp->hmap_node, hash_int(odp_port, 0));

    /* Add poller and sampler. */
    if (ds->sflow_agent) {
        dpif_sflow_add_poller(ds, dsp, odp_port);
        dpif_sflow_add_sampler(ds, dsp);
    }
}

static void
dpif_sflow_del_port__(struct dpif_sflow *ds, struct dpif_sflow_port *dsp)
{
    if (ds->sflow_agent) {
        sfl_agent_removePoller(ds->sflow_agent, &dsp->dsi);
        sfl_agent_removeSampler(ds->sflow_agent, &dsp->dsi);
    }
    netdev_close(dsp->netdev);
    hmap_remove(&ds->ports, &dsp->hmap_node);
    free(dsp);
}

void
dpif_sflow_del_port(struct dpif_sflow *ds, uint16_t odp_port)
{
    struct dpif_sflow_port *dsp = dpif_sflow_find_port(ds, odp_port);
    if (dsp) {
        dpif_sflow_del_port__(ds, dsp);
    }
}

void
dpif_sflow_set_options(struct dpif_sflow *ds,
                       const struct ofproto_sflow_options *options)
{
    struct dpif_sflow_port *dsp;
    bool options_changed;
    SFLReceiver *receiver;
    SFLAddress agentIP;
    time_t now;

    if (sset_is_empty(&options->targets) || !options->sampling_rate) {
        /* No point in doing any work if there are no targets or nothing to
         * sample. */
        dpif_sflow_clear(ds);
        return;
    }

    options_changed = (!ds->options
                       || !ofproto_sflow_options_equal(options, ds->options));

    /* Configure collectors if options have changed or if we're shortchanged in
     * collectors (which indicates that opening one or more of the configured
     * collectors failed, so that we should retry). */
    if (options_changed
        || collectors_count(ds->collectors) < sset_count(&options->targets)) {
        collectors_destroy(ds->collectors);
        collectors_create(&options->targets, SFL_DEFAULT_COLLECTOR_PORT,
                          &ds->collectors);
        if (ds->collectors == NULL) {
            VLOG_WARN_RL(&rl, "no collectors could be initialized, "
                         "sFlow disabled");
            dpif_sflow_clear(ds);
            return;
        }
    }

    /* Avoid reconfiguring if options didn't change. */
    if (!options_changed) {
        return;
    }
    ofproto_sflow_options_destroy(ds->options);
    ds->options = ofproto_sflow_options_clone(options);

    /* Choose agent IP address. */
    if (!sflow_choose_agent_address(options->agent_device,
                                    options->control_ip, &agentIP)) {
        dpif_sflow_clear(ds);
        return;
    }

    /* Create agent. */
    VLOG_INFO("creating sFlow agent %d", options->sub_id);
    if (ds->sflow_agent) {
        sfl_agent_release(ds->sflow_agent);
    }
    ds->sflow_agent = xcalloc(1, sizeof *ds->sflow_agent);
    now = time_wall();
    sfl_agent_init(ds->sflow_agent,
                   &agentIP,
                   options->sub_id,
                   now,         /* Boot time. */
                   now,         /* Current time. */
                   ds,          /* Pointer supplied to callbacks. */
                   sflow_agent_alloc_cb,
                   sflow_agent_free_cb,
                   sflow_agent_error_cb,
                   sflow_agent_send_packet_cb);

    receiver = sfl_agent_addReceiver(ds->sflow_agent);
    sfl_receiver_set_sFlowRcvrOwner(receiver, "Open vSwitch sFlow");
    sfl_receiver_set_sFlowRcvrTimeout(receiver, 0xffffffff);

    /* Set the sampling_rate down in the datapath. */
    dpif_set_sflow_probability(ds->dpif,
                               MAX(1, UINT32_MAX / options->sampling_rate));

    /* Add samplers and pollers for the currently known ports. */
    HMAP_FOR_EACH (dsp, hmap_node, &ds->ports) {
        dpif_sflow_add_poller(ds, dsp, dsp->odp_port);
        dpif_sflow_add_sampler(ds, dsp);
    }
}

static int
dpif_sflow_odp_port_to_ifindex(const struct dpif_sflow *ds,
                               uint16_t odp_port)
{
    struct dpif_sflow_port *dsp = dpif_sflow_find_port(ds, odp_port);
    return dsp ? SFL_DS_INDEX(dsp->dsi) : 0;
}

void
dpif_sflow_received(struct dpif_sflow *ds, const struct dpif_upcall *upcall,
                    const struct flow *flow)
{
    SFL_FLOW_SAMPLE_TYPE fs;
    SFLFlow_sample_element hdrElem;
    SFLSampled_header *header;
    SFLFlow_sample_element switchElem;
    SFLSampler *sampler;
    unsigned int left;
    struct nlattr *a;
    size_t n_outputs;

    /* Build a flow sample */
    memset(&fs, 0, sizeof fs);
    fs.input = dpif_sflow_odp_port_to_ifindex(ds, flow->in_port);
    fs.output = 0;              /* Filled in correctly below. */
    fs.sample_pool = upcall->sample_pool;

    /* We are going to give it to the sampler that represents this input port.
     * By implementing "ingress-only" sampling like this we ensure that we
     * never have to offer the same sample to more than one sampler. */
    sampler = sfl_agent_getSamplerByIfIndex(ds->sflow_agent, fs.input);
    if (!sampler) {
        VLOG_WARN_RL(&rl, "no sampler for input ifIndex (%"PRIu32")",
                     fs.input);
        return;
    }

    /* Sampled header. */
    memset(&hdrElem, 0, sizeof hdrElem);
    hdrElem.tag = SFLFLOW_HEADER;
    header = &hdrElem.flowType.header;
    header->header_protocol = SFLHEADER_ETHERNET_ISO8023;
    /* The frame_length should include the Ethernet FCS (4 bytes),
       but it has already been stripped,  so we need to add 4 here. */
    header->frame_length = upcall->packet->size + 4;
    /* Ethernet FCS stripped off. */
    header->stripped = 4;
    header->header_length = MIN(upcall->packet->size,
                                sampler->sFlowFsMaximumHeaderSize);
    header->header_bytes = upcall->packet->data;

    /* Add extended switch element. */
    memset(&switchElem, 0, sizeof(switchElem));
    switchElem.tag = SFLFLOW_EX_SWITCH;
    switchElem.flowType.sw.src_vlan = vlan_tci_to_vid(flow->vlan_tci);
    switchElem.flowType.sw.src_priority = vlan_tci_to_pcp(flow->vlan_tci);
    /* Initialize the output VLAN and priority to be the same as the input,
       but these fields can be overriden below if affected by an action. */
    switchElem.flowType.sw.dst_vlan = switchElem.flowType.sw.src_vlan;
    switchElem.flowType.sw.dst_priority = switchElem.flowType.sw.src_priority;

    /* Figure out the output ports. */
    n_outputs = 0;
    NL_ATTR_FOR_EACH_UNSAFE (a, left, upcall->actions, upcall->actions_len) {
        ovs_be16 tci;

        switch (nl_attr_type(a)) {
        case ODP_ACTION_ATTR_OUTPUT:
            fs.output = dpif_sflow_odp_port_to_ifindex(ds, nl_attr_get_u32(a));
            n_outputs++;
            break;

        case ODP_ACTION_ATTR_SET_DL_TCI:
            tci = nl_attr_get_be16(a);
            switchElem.flowType.sw.dst_vlan = vlan_tci_to_vid(tci);
            switchElem.flowType.sw.dst_priority = vlan_tci_to_pcp(tci);
            break;

        default:
            break;
        }
    }

    /* Set output port, as defined by http://www.sflow.org/sflow_version_5.txt
       (search for "Input/output port information"). */
    if (!n_outputs) {
        /* This value indicates that the packet was dropped for an unknown
         * reason. */
        fs.output = 0x40000000 | 256;
    } else if (n_outputs > 1 || !fs.output) {
        /* Setting the high bit means "multiple output ports". */
        fs.output = 0x80000000 | n_outputs;
    }

    /* Submit the flow sample to be encoded into the next datagram. */
    SFLADD_ELEMENT(&fs, &hdrElem);
    SFLADD_ELEMENT(&fs, &switchElem);
    sfl_sampler_writeFlowSample(sampler, &fs);
}

void
dpif_sflow_run(struct dpif_sflow *ds)
{
    if (dpif_sflow_is_enabled(ds)) {
        time_t now = time_now();
        if (now >= ds->next_tick) {
            sfl_agent_tick(ds->sflow_agent, time_wall());
            ds->next_tick = now + 1;
        }
    }
}

void
dpif_sflow_wait(struct dpif_sflow *ds)
{
    if (dpif_sflow_is_enabled(ds)) {
        poll_timer_wait_until(ds->next_tick * 1000LL);
    }
}
