/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <config.h>
#include <stdint.h>
#include <stdbool.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <linux/netconf.h>
#include "util.h"
#include "switchlink.h"
#include "switchlink_link.h"
#include "switchlink_db.h"
#include "switchlink_sai.h"

static bool g_forwarding[2] = {true, true};
static uint8_t g_rp_filter[2] = {1, 1};
static bool g_mc_forwarding[2] = {true, true};

void process_netconf_msg(struct nlmsghdr *nlmsg, int type) {
  struct netconfmsg *ncmsg;
  struct nlattr *attr;
  int hdrlen, attrlen;
  uint32_t ifindex = 0;
  bool forwarding = false;
  uint8_t rp_filter = 0;
  bool mc_forwarding = false;
  bool forwarding_valid = false;
  bool rp_filter_valid = false;
  bool mc_forwarding_valid = false;

  ovs_assert(type == RTM_NEWNETCONF);
  ncmsg = nlmsg_data(nlmsg);

  if ((ncmsg->ncm_family != AF_INET) && (ncmsg->ncm_family != AF_INET6)) {
    NL_LOG_DEBUG(("netconf: skipping unknown address family\n"));
    return;
  }

  hdrlen = sizeof(struct netconfmsg);
  attrlen = nlmsg_attrlen(nlmsg, hdrlen);
  attr = nlmsg_attrdata(nlmsg, hdrlen);
  while (nla_ok(attr, attrlen)) {
    int attr_type = nla_type(attr);
    switch (attr_type) {
      case NETCONFA_IFINDEX:
        ifindex = nla_get_u32(attr);
        break;
      case NETCONFA_FORWARDING:
        forwarding = nla_get_u32(attr);
        forwarding_valid = true;
        break;
      case NETCONFA_RP_FILTER:
        rp_filter = nla_get_u32(attr);
        rp_filter_valid = true;
        break;
      case NETCONFA_MC_FORWARDING:
        mc_forwarding = nla_get_u32(attr);
        mc_forwarding_valid = true;
        break;
      default:
        break;
    }
    attr = nla_next(attr, &attrlen);
  }

  if (ifindex == (uint32_t)-1) {
    int af = (ncmsg->ncm_family == AF_INET) ? 0 : 1;
    if (forwarding_valid && (g_forwarding[af] != forwarding)) {
      g_forwarding[af] = forwarding;
    }
    if (mc_forwarding_valid && (g_mc_forwarding[af] != mc_forwarding)) {
      g_mc_forwarding[af] = mc_forwarding;
    }
    if (rp_filter_valid && (g_rp_filter[af] != rp_filter)) {
      g_rp_filter[af] = rp_filter;
    }
    return;
  }

  bool update_intf = false;
  switchlink_db_status_t status;
  switchlink_db_interface_info_t ifinfo;

  status = switchlink_db_interface_get_info(ifindex, &ifinfo);
  if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
    NL_LOG_DEBUG(
        ("netconf: switchlink_db_interface_get_info "
         "failed\n"));
    return;
  }
  if (ifinfo.intf_type != SWITCHLINK_INTF_TYPE_L3) {
    return;
  }

  // merge global forwarding disable configuration
  int af = (ncmsg->ncm_family == AF_INET) ? 0 : 1;
  if (forwarding_valid && !g_forwarding[af]) {
    forwarding = false;
  }
  if (mc_forwarding_valid && !g_mc_forwarding[af]) {
    mc_forwarding = false;
  }

  if (ncmsg->ncm_family == AF_INET) {
    if (forwarding_valid && (ifinfo.flags.ipv4_unicast_enabled != forwarding)) {
      switchlink_interface_forwarding_update(
          ifinfo.intf_h, ncmsg->ncm_family, forwarding);
      ifinfo.flags.ipv4_unicast_enabled = forwarding;
      update_intf = true;
    }
    if (mc_forwarding_valid &&
        (ifinfo.flags.ipv4_multicast_enabled != mc_forwarding)) {
      switchlink_interface_mc_forwarding_update(
          ifinfo.intf_h, ncmsg->ncm_family, mc_forwarding);
      ifinfo.flags.ipv4_multicast_enabled = mc_forwarding;
      update_intf = true;
    }
    if (rp_filter_valid && (ifinfo.flags.ipv4_urpf_mode != rp_filter)) {
      switchlink_interface_urpf_mode_update(
          ifinfo.intf_h, ncmsg->ncm_family, rp_filter);
      ifinfo.flags.ipv4_urpf_mode = rp_filter;
      update_intf = true;
    }
  } else {
    if (forwarding_valid && (ifinfo.flags.ipv6_unicast_enabled != forwarding)) {
      switchlink_interface_forwarding_update(
          ifinfo.intf_h, ncmsg->ncm_family, forwarding);
      ifinfo.flags.ipv6_unicast_enabled = forwarding;
      update_intf = true;
    }
    if (mc_forwarding_valid &&
        (ifinfo.flags.ipv6_multicast_enabled != mc_forwarding)) {
      switchlink_interface_mc_forwarding_update(
          ifinfo.intf_h, ncmsg->ncm_family, mc_forwarding);
      ifinfo.flags.ipv6_multicast_enabled = mc_forwarding;
      update_intf = true;
    }
    if (rp_filter_valid && (ifinfo.flags.ipv6_urpf_mode != rp_filter)) {
      switchlink_interface_urpf_mode_update(
          ifinfo.intf_h, ncmsg->ncm_family, rp_filter);
      ifinfo.flags.ipv6_urpf_mode = rp_filter;
      update_intf = true;
    }
  }

  if (update_intf) {
    switchlink_db_interface_update(ifindex, &ifinfo);
  }
}
