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
#include "util.h"
#include "switchlink.h"
#include "switchlink_link.h"
#include "switchlink_neigh.h"
#include "switchlink_route.h"
#include "switchlink_db.h"
#include "switchlink_sai.h"

/* TODO: P4-OVS: Dummy Processing of Netlink messages received
* Support IPv4 Address group
*/

void process_address_msg(struct nlmsghdr *nlmsg, int type) {
  int hdrlen, attrlen;
  struct nlattr *attr;
  struct ifaddrmsg *addrmsg;
  bool addr_valid = false;
  switchlink_ip_addr_t addr;

  ovs_assert((type == RTM_NEWADDR) || (type == RTM_DELADDR));
  addrmsg = nlmsg_data(nlmsg);
  hdrlen = sizeof(struct ifaddrmsg);
  NL_LOG_DEBUG(
      ("%saddr: family = %d, prefixlen = %d, flags = 0x%x, "
       "scope = 0x%x ifindex = %d\n",
       ((type == RTM_NEWADDR) ? "new" : "del"),
       addrmsg->ifa_family,
       addrmsg->ifa_prefixlen,
       addrmsg->ifa_flags,
       addrmsg->ifa_scope,
       addrmsg->ifa_index));

  if ((addrmsg->ifa_family != AF_INET) && (addrmsg->ifa_family != AF_INET6)) {
    // an address family that we are not interested in, skip
    return;
  }

  switchlink_db_status_t status;
  switchlink_intf_type_t intf_type = SWITCHLINK_INTF_TYPE_NONE;
  switchlink_handle_t intf_h = 0;
  bool create_l3vi = false;

  switchlink_db_interface_info_t ifinfo;
  status = switchlink_db_interface_get_info(addrmsg->ifa_index, &ifinfo);
  if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
    intf_type = ifinfo.intf_type;
    intf_h = ifinfo.intf_h;
  } else {
    switchlink_db_bridge_info_t brinfo;
    status = switchlink_db_bridge_get_info(addrmsg->ifa_index, &brinfo);
    if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
      create_l3vi = true;
    } else {
      // an interface that we are not interested in, skip
      return;
    }
  }
  if (strcmp(ifinfo.ifname, SWITCHLINK_CPU_INTERFACE_NAME) == 0) {
    // address on CPU interface, skip
    return;
  }

  attrlen = nlmsg_attrlen(nlmsg, hdrlen);
  attr = nlmsg_attrdata(nlmsg, hdrlen);
  while (nla_ok(attr, attrlen)) {
    int attr_type = nla_type(attr);
    switch (attr_type) {
      case IFA_ADDRESS:
        addr_valid = true;
        memset(&addr, 0, sizeof(switchlink_ip_addr_t));
        addr.family = addrmsg->ifa_family;
        addr.prefix_len = addrmsg->ifa_prefixlen;
        if (addrmsg->ifa_family == AF_INET) {
          addr.ip.v4addr.s_addr = ntohl(nla_get_u32(attr));
        } else {
          memcpy(&(addr.ip.v6addr), nla_data(attr), nla_len(attr));
        }
        break;
      default:
        NL_LOG_DEBUG(("addr: skipping attr(%d)\n", attr_type));
        break;
    }
    attr = nla_next(attr, &attrlen);
  }

  if (type == RTM_NEWADDR) {
    if ((addrmsg->ifa_family == AF_INET) ||
        ((addrmsg->ifa_family == AF_INET6) &&
         !IN6_IS_ADDR_LINKLOCAL(&(addr.ip.v6addr)))) {
      if (create_l3vi) {
        interface_create_l3vi(addrmsg->ifa_index);
        status = switchlink_db_interface_get_info(addrmsg->ifa_index, &ifinfo);
        ovs_assert(status == SWITCHLINK_DB_STATUS_SUCCESS);
        intf_h = ifinfo.intf_h;
      } else {
        if (intf_type == SWITCHLINK_INTF_TYPE_L2_ACCESS) {
          interface_change_type(addrmsg->ifa_index, SWITCHLINK_INTF_TYPE_L3);
        }
      }
    }
    if (addr_valid) {
      switchlink_ip_addr_t null_gateway;
      memset(&null_gateway, 0, sizeof(null_gateway));
      null_gateway.family = addr.family;

      // add the subnet route
      route_create(g_default_vrf_h, &addr, &null_gateway, 0, intf_h);

      // add the interface route
      if (addrmsg->ifa_family == AF_INET) {
        addr.prefix_len = 32;
      } else {
        addr.prefix_len = 128;
      }
      route_create(g_default_vrf_h, &addr, &null_gateway, 0, intf_h);
    }
  } else {
    if (addr_valid) {
      // remove the subnet route
      route_delete(g_default_vrf_h, &addr);

      // remove the interface route
      if (addrmsg->ifa_family == AF_INET) {
        addr.prefix_len = 32;
      } else {
        addr.prefix_len = 128;
      }
      route_delete(g_default_vrf_h, &addr);
    }
  }
}

//void process_address_msg(struct nlmsghdr *nlmsg, int type) {
//  int hdrlen, attrlen;
//  struct nlattr *attr;
//  struct ifaddrmsg *addrmsg;
//  bool addr_valid = false;
//  switchlink_ip_addr_t addr;
//
//  ovs_assert((type == RTM_NEWADDR) || (type == RTM_DELADDR));
//  addrmsg = nlmsg_data(nlmsg);
//  hdrlen = sizeof(struct ifaddrmsg);
//  NL_LOG_DEBUG(
//      ("%saddr: family = %d, prefixlen = %d, flags = 0x%x, "
//       "scope = 0x%x ifindex = %d\n",
//       ((type == RTM_NEWADDR) ? "new" : "del"),
//       addrmsg->ifa_family,
//       addrmsg->ifa_prefixlen,
//       addrmsg->ifa_flags,
//       addrmsg->ifa_scope,
//       addrmsg->ifa_index));
//
//  if ((addrmsg->ifa_family != AF_INET) && (addrmsg->ifa_family != AF_INET6)) {
//    // an address family that we are not interested in, skip
//    return;
//  }
//
//  switchlink_db_status_t status;
//  switchlink_intf_type_t intf_type = SWITCHLINK_INTF_TYPE_NONE;
//  switchlink_handle_t intf_h = 0;
//  bool create_l3vi = false;
//
//  switchlink_db_interface_info_t ifinfo;
//  status = switchlink_db_interface_get_info(addrmsg->ifa_index, &ifinfo);
//  if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
//    intf_type = ifinfo.intf_type;
//    intf_h = ifinfo.intf_h;
//  } else {
//    switchlink_db_bridge_info_t brinfo;
//    status = switchlink_db_bridge_get_info(addrmsg->ifa_index, &brinfo);
//    if (status == SWITCHLINK_DB_STATUS_SUCCESS) {
//      create_l3vi = true;
//    } else {
//      // an interface that we are not interested in, skip
//      return;
//    }
//  }
//  if (strcmp(ifinfo.ifname, SWITCHLINK_CPU_INTERFACE_NAME) == 0) {
//    // address on CPU interface, skip
//    return;
//  }
//
//  attrlen = nlmsg_attrlen(nlmsg, hdrlen);
//  attr = nlmsg_attrdata(nlmsg, hdrlen);
//  while (nla_ok(attr, attrlen)) {
//    int attr_type = nla_type(attr);
//    switch (attr_type) {
//      case IFA_ADDRESS:
//        addr_valid = true;
//        memset(&addr, 0, sizeof(switchlink_ip_addr_t));
//        addr.family = addrmsg->ifa_family;
//        addr.prefix_len = addrmsg->ifa_prefixlen;
//        if (addrmsg->ifa_family == AF_INET) {
//          addr.ip.v4addr.s_addr = ntohl(nla_get_u32(attr));
//        } else {
//          memcpy(&(addr.ip.v6addr), nla_data(attr), nla_len(attr));
//        }
//        break;
//      default:
//        NL_LOG_DEBUG(("addr: skipping attr(%d)\n", attr_type));
//        break;
//    }
//    attr = nla_next(attr, &attrlen);
//  }
//
//  if (type == RTM_NEWADDR) {
//    if ((addrmsg->ifa_family == AF_INET) ||
//        ((addrmsg->ifa_family == AF_INET6) &&
//         !IN6_IS_ADDR_LINKLOCAL(&(addr.ip.v6addr)))) {
//      if (create_l3vi) {
//        interface_create_l3vi(addrmsg->ifa_index);
//        status = switchlink_db_interface_get_info(addrmsg->ifa_index, &ifinfo);
//        ovs_assert(status == SWITCHLINK_DB_STATUS_SUCCESS);
//        intf_h = ifinfo.intf_h;
//      } else {
//        if (intf_type == SWITCHLINK_INTF_TYPE_L2_ACCESS) {
//          interface_change_type(addrmsg->ifa_index, SWITCHLINK_INTF_TYPE_L3);
//        }
//      }
//    }
//    if (addr_valid) {
//      switchlink_ip_addr_t null_gateway;
//      memset(&null_gateway, 0, sizeof(null_gateway));
//      null_gateway.family = addr.family;
//
//      // add the subnet route
//      route_create(g_default_vrf_h, &addr, &null_gateway, 0, intf_h);
//
//      // add the interface route
//      if (addrmsg->ifa_family == AF_INET) {
//        addr.prefix_len = 32;
//      } else {
//        addr.prefix_len = 128;
//      }
//      route_create(g_default_vrf_h, &addr, &null_gateway, 0, intf_h);
//    }
//  } else {
//    if (addr_valid) {
//      // remove the subnet route
//      route_delete(g_default_vrf_h, &addr);
//
//      // remove the interface route
//      if (addrmsg->ifa_family == AF_INET) {
//        addr.prefix_len = 32;
//      } else {
//        addr.prefix_len = 128;
//      }
//      route_delete(g_default_vrf_h, &addr);
//    }
//  }
//}
