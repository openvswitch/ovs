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
#include <linux/if_ether.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/route/neighbour.h>
#include "util.h"
#include "switchlink.h"
#include "switchlink_link.h"
#include "switchlink_neigh.h"
#include "switchlink_route.h"
#include "switchlink_db.h"
#include "switchlink_sai.h"

static void mac_delete(switchlink_mac_addr_t mac_addr,
                       switchlink_handle_t bridge_h) {
  switchlink_handle_t intf_h;
  switchlink_db_status_t status;
  status = switchlink_db_mac_get_intf(mac_addr, bridge_h, &intf_h);
  if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
    return;
  }
  switchlink_mac_delete(mac_addr, bridge_h);
  switchlink_db_mac_delete(mac_addr, bridge_h);
}

static void mac_create(switchlink_mac_addr_t mac_addr,
                       switchlink_handle_t bridge_h,
                       switchlink_handle_t intf_h) {
  switchlink_handle_t old_intf_h;
  switchlink_db_status_t status;
  status = switchlink_db_mac_get_intf(mac_addr, bridge_h, &old_intf_h);
  if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
    if (old_intf_h != intf_h) {
      switchlink_mac_update(mac_addr, bridge_h, intf_h);
      switchlink_db_mac_set_intf(mac_addr, bridge_h, intf_h);
      return;
    }
  }

  switchlink_mac_create(mac_addr, bridge_h, intf_h);
  switchlink_db_mac_add(mac_addr, bridge_h, intf_h);
}

static void neigh_delete(switchlink_handle_t vrf_h,
                         switchlink_ip_addr_t *ipaddr,
                         switchlink_handle_t intf_h) {
  switchlink_db_neigh_info_t neigh_info;
  switchlink_db_status_t status;

  memset(&neigh_info, 0, sizeof(switchlink_db_neigh_info_t));
  neigh_info.vrf_h = vrf_h;
  neigh_info.intf_h = intf_h;
  memcpy(&(neigh_info.ip_addr), ipaddr, sizeof(switchlink_ip_addr_t));
  status = switchlink_db_neighbor_get_info(&neigh_info);
  if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
    return;
  }

  switchlink_neighbor_delete(&neigh_info);
  switchlink_nexthop_delete(&neigh_info);
  switchlink_db_neighbor_delete(&neigh_info);

  // delete the host route
  route_delete(g_default_vrf_h, ipaddr);
}

void neigh_create(switchlink_handle_t vrf_h,
                  switchlink_ip_addr_t *ipaddr,
                  switchlink_mac_addr_t mac_addr,
                  switchlink_handle_t intf_h) {
  switchlink_db_status_t status;
  switchlink_db_neigh_info_t neigh_info;

  if ((ipaddr->family == AF_INET6) &&
      IN6_IS_ADDR_MULTICAST(&(ipaddr->ip.v6addr))) {
    return;
  }

  memset(&neigh_info, 0, sizeof(switchlink_db_neigh_info_t));
  neigh_info.vrf_h = vrf_h;
  neigh_info.intf_h = intf_h;
  memcpy(&(neigh_info.ip_addr), ipaddr, sizeof(switchlink_ip_addr_t));

  status = switchlink_db_neighbor_get_info(&neigh_info);
  if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
    if (memcmp(neigh_info.mac_addr, mac_addr, sizeof(switchlink_mac_addr_t)) ==
        0) {
      // no change
      return;
    }

    // update, currently handled as a delete followed by add
    neigh_delete(vrf_h, ipaddr, intf_h);
  }

  memcpy(neigh_info.mac_addr, mac_addr, sizeof(switchlink_mac_addr_t));
  if (switchlink_nexthop_create(&neigh_info) == -1) {
    return;
  }
  if (switchlink_neighbor_create(&neigh_info) == -1) {
    switchlink_nexthop_delete(&neigh_info);
    return;
  }
  switchlink_db_neighbor_add(&neigh_info);

  // add a host route
  route_create(g_default_vrf_h, ipaddr, ipaddr, 0, intf_h);
}

/* TODO: P4-OVS: Dummy Processing of Netlink messages received
 * Support IPv4 neigh/arp
 */
void process_neigh_msg(struct nlmsghdr *nlmsg, int type) {
  int hdrlen, attrlen;
  struct nlattr *attr;
  struct ndmsg *nbh;
  switchlink_mac_addr_t mac_addr;
  bool mac_addr_valid = false;
  bool ipaddr_valid = false;
  switchlink_ip_addr_t ipaddr;

  ovs_assert((type == RTM_NEWNEIGH) || (type == RTM_DELNEIGH));
  nbh = nlmsg_data(nlmsg);
  hdrlen = sizeof(struct ndmsg);
  NL_LOG_DEBUG(
      ("%sneigh: family = %d, ifindex = %d, state = 0x%x, "
       "flags = 0x%x, type = %d\n",
       ((type == RTM_NEWNEIGH) ? "new" : "del"),
       nbh->ndm_family,
       nbh->ndm_ifindex,
       nbh->ndm_state,
       nbh->ndm_flags,
       nbh->ndm_type));

  switchlink_db_interface_info_t ifinfo;
  if (switchlink_db_interface_get_info(nbh->ndm_ifindex, &ifinfo) !=
      SWITCHLINK_DB_STATUS_SUCCESS) {
    NL_LOG_DEBUG(("neigh: switchlink_db_interface_get_info failed\n"));
    return;
  }

  if (strncmp(ifinfo.ifname,
              SWITCHLINK_CPU_INTERFACE_NAME,
              SWITCHLINK_INTERFACE_NAME_LEN_MAX) == 0) {
    NL_LOG_DEBUG(("neigh: skipping neighbor on CPU interface\n"));
    return;
  }

  memset(&ipaddr, 0, sizeof(switchlink_ip_addr_t));
  attrlen = nlmsg_attrlen(nlmsg, hdrlen);
  attr = nlmsg_attrdata(nlmsg, hdrlen);
  while (nla_ok(attr, attrlen)) {
    int attr_type = nla_type(attr);
    switch (attr_type) {
      case NDA_DST:
        ipaddr_valid = true;
        ipaddr.family = nbh->ndm_family;
        if (nbh->ndm_family == AF_INET) {
          ipaddr.ip.v4addr.s_addr = ntohl(nla_get_u32(attr));
          ipaddr.prefix_len = 32;
        } else {
          memcpy(&(ipaddr.ip.v6addr), nla_data(attr), nla_len(attr));
          ipaddr.prefix_len = 128;
        }
        break;
      case NDA_LLADDR: {
        mac_addr_valid = true;
        ovs_assert(nla_len(attr) == sizeof(switchlink_mac_addr_t));
        memcpy(mac_addr, nla_data(attr), nla_len(attr));
        break;
      }
      default:
        NL_LOG_DEBUG(("neigh: skipping attr(%d)\n", attr_type));
        break;
    }
    attr = nla_next(attr, &attrlen);
  }

  switchlink_handle_t intf_h = ifinfo.intf_h;
  switchlink_handle_t bridge_h = 0;
  if (ifinfo.intf_type == SWITCHLINK_INTF_TYPE_L2_ACCESS) {
    bridge_h = ifinfo.bridge_h;
    ovs_assert(bridge_h);
  }

  if (type == RTM_NEWNEIGH) {
    if (bridge_h && mac_addr_valid) {
      mac_create(mac_addr, bridge_h, intf_h);
    }
    if (ipaddr_valid) {
      if (mac_addr_valid) {
        neigh_create(g_default_vrf_h, &ipaddr, mac_addr, intf_h);
      } else {
        // mac address is not valid, remove the neighbor entry
        neigh_delete(g_default_vrf_h, &ipaddr, intf_h);
      }
    }
  } else {
    if (bridge_h && mac_addr_valid) {
      mac_delete(mac_addr, bridge_h);
    }
    if (ipaddr_valid) {
      neigh_delete(g_default_vrf_h, &ipaddr, intf_h);
    }
  }
}
//
//void process_neigh_msg(struct nlmsghdr *nlmsg, int type) {
//  int hdrlen, attrlen;
//  struct nlattr *attr;
//  struct ndmsg *nbh;
//  switchlink_mac_addr_t mac_addr;
//  bool mac_addr_valid = false;
//  bool ipaddr_valid = false;
//  switchlink_ip_addr_t ipaddr;
//
//  ovs_assert((type == RTM_NEWNEIGH) || (type == RTM_DELNEIGH));
//  nbh = nlmsg_data(nlmsg);
//  hdrlen = sizeof(struct ndmsg);
//  NL_LOG_DEBUG(
//      ("%sneigh: family = %d, ifindex = %d, state = 0x%x, "
//       "flags = 0x%x, type = %d\n",
//       ((type == RTM_NEWNEIGH) ? "new" : "del"),
//       nbh->ndm_family,
//       nbh->ndm_ifindex,
//       nbh->ndm_state,
//       nbh->ndm_flags,
//       nbh->ndm_type));
//
//  switchlink_db_interface_info_t ifinfo;
//  if (switchlink_db_interface_get_info(nbh->ndm_ifindex, &ifinfo) !=
//      SWITCHLINK_DB_STATUS_SUCCESS) {
//    NL_LOG_DEBUG(("neigh: switchlink_db_interface_get_info failed\n"));
//    return;
//  }
//
//  if (strncmp(ifinfo.ifname,
//              SWITCHLINK_CPU_INTERFACE_NAME,
//              SWITCHLINK_INTERFACE_NAME_LEN_MAX) == 0) {
//    NL_LOG_DEBUG(("neigh: skipping neighbor on CPU interface\n"));
//    return;
//  }
//
//  memset(&ipaddr, 0, sizeof(switchlink_ip_addr_t));
//  attrlen = nlmsg_attrlen(nlmsg, hdrlen);
//  attr = nlmsg_attrdata(nlmsg, hdrlen);
//  while (nla_ok(attr, attrlen)) {
//    int attr_type = nla_type(attr);
//    switch (attr_type) {
//      case NDA_DST:
//        ipaddr_valid = true;
//        ipaddr.family = nbh->ndm_family;
//        if (nbh->ndm_family == AF_INET) {
//          ipaddr.ip.v4addr.s_addr = ntohl(nla_get_u32(attr));
//          ipaddr.prefix_len = 32;
//        } else {
//          memcpy(&(ipaddr.ip.v6addr), nla_data(attr), nla_len(attr));
//          ipaddr.prefix_len = 128;
//        }
//        break;
//      case NDA_LLADDR: {
//        mac_addr_valid = true;
//        ovs_assert(nla_len(attr) == sizeof(switchlink_mac_addr_t));
//        memcpy(mac_addr, nla_data(attr), nla_len(attr));
//        break;
//      }
//      default:
//        NL_LOG_DEBUG(("neigh: skipping attr(%d)\n", attr_type));
//        break;
//    }
//    attr = nla_next(attr, &attrlen);
//  }
//
//  switchlink_handle_t intf_h = ifinfo.intf_h;
//  switchlink_handle_t bridge_h = 0;
//  if (ifinfo.intf_type == SWITCHLINK_INTF_TYPE_L2_ACCESS) {
//    bridge_h = ifinfo.bridge_h;
//    ovs_assert(bridge_h);
//  }
//
//  if (type == RTM_NEWNEIGH) {
//    if (bridge_h && mac_addr_valid) {
//      mac_create(mac_addr, bridge_h, intf_h);
//    }
//    if (ipaddr_valid) {
//      if (mac_addr_valid) {
//        neigh_create(g_default_vrf_h, &ipaddr, mac_addr, intf_h);
//      } else {
//        // mac address is not valid, remove the neighbor entry
//        neigh_delete(g_default_vrf_h, &ipaddr, intf_h);
//      }
//    }
//  } else {
//    if (bridge_h && mac_addr_valid) {
//      mac_delete(mac_addr, bridge_h);
//    }
//    if (ipaddr_valid) {
//      neigh_delete(g_default_vrf_h, &ipaddr, intf_h);
//    }
//  }
//}
//
void switchlink_linux_mac_update(switchlink_mac_addr_t mac_addr,
                                 switchlink_handle_t bridge_h,
                                 switchlink_handle_t intf_h,
                                 bool create) {
  switchlink_db_status_t status;
  uint32_t ifindex;

  if (!create) {
    status = switchlink_db_mac_get_intf(mac_addr, bridge_h, &intf_h);
    if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
      ovs_assert(false);
      return;
    }
  }

  status = switchlink_db_interface_get_ifindex(intf_h, &ifindex);
  if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
    return;
  }

  struct nl_sock *nlsk = switchlink_get_nl_sock();
  if (!nlsk) {
    return;
  }

  struct nl_addr *nl_addr = nl_addr_build(AF_LLC, mac_addr, ETH_ALEN);
  struct rtnl_neigh *rtnl_neigh = rtnl_neigh_alloc();
  rtnl_neigh_set_ifindex(rtnl_neigh, ifindex);
  rtnl_neigh_set_lladdr(rtnl_neigh, nl_addr);
  rtnl_neigh_set_state(rtnl_neigh, rtnl_neigh_str2state("permanent"));
  rtnl_neigh_set_family(rtnl_neigh, AF_BRIDGE);

  if (create) {
    status = switchlink_db_mac_add(mac_addr, bridge_h, intf_h);
    ovs_assert(status == SWITCHLINK_DB_STATUS_SUCCESS);
    rtnl_neigh_add(nlsk, rtnl_neigh, NLM_F_CREATE | NLM_F_REPLACE);
  } else {
    status = switchlink_db_mac_delete(mac_addr, bridge_h);
    ovs_assert(status == SWITCHLINK_DB_STATUS_SUCCESS);
    rtnl_neigh_delete(nlsk, rtnl_neigh, 0);
  }
  rtnl_neigh_put(rtnl_neigh);
  nl_addr_put(nl_addr);
}
