/*
Copyright 2013-present Barefoot Networks, Inc.
Copyright(c) 2021 Intel Corporation.

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
#include <fcntl.h>
#include <unistd.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/route/nexthop.h>
#include <linux/if_bridge.h>
#include <linux/if.h>
#include <linux/version.h>
#include "util.h"
#include "switchlink.h"
#include "switchlink_link.h"
#include "switchlink_neigh.h"
#include "switchlink_db.h"
#include "switchlink_sai.h"
#include "openvswitch/vlog.h"

switchlink_handle_t g_default_vrf_h = 0;
switchlink_handle_t g_default_bridge_h = 0;
switchlink_handle_t g_default_stp_h = 0;
switchlink_handle_t g_cpu_rx_nhop_h = 0;

VLOG_DEFINE_THIS_MODULE(switchlink_link);

static void create_cpu_interface(switchlink_handle_t intf_h) {
  switchlink_ip_addr_t null_ip_addr;
  switchlink_mac_addr_t null_mac_addr;
  switchlink_db_status_t status;

  memset(&null_ip_addr, 0, sizeof(switchlink_ip_addr_t));
  null_ip_addr.family = AF_INET;
  memset(null_mac_addr, 0, sizeof(switchlink_mac_addr_t));

  neigh_create(g_default_vrf_h, &null_ip_addr, null_mac_addr, intf_h);
  switchlink_db_neigh_info_t neigh_info;
  memset(&neigh_info, 0, sizeof(switchlink_db_neigh_info_t));
  neigh_info.ip_addr.family = AF_INET;
  neigh_info.vrf_h = g_default_vrf_h;
  neigh_info.intf_h = intf_h;
  status = switchlink_db_neighbor_get_info(&neigh_info);
  ovs_assert(status == SWITCHLINK_DB_STATUS_SUCCESS);
  g_cpu_rx_nhop_h = neigh_info.nhop_h;
}

static void tuntap_create(switchlink_db_tuntap_info_t *tunp) {
  switchlink_db_status_t status;
  switchlink_db_tuntap_info_t tunpinfo;

  status = switchlink_db_tuntap_get_info(tunp->ifindex, &tunpinfo);
  if (status == SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    // create the tuntap port
    status = switchlink_tuntap_create(tunp, &(tunp->tunp_h));
    if (status != 0) {
        VLOG_ERR("newlink: switchlink_tuntap_create failed\n");
        return;
    }
    // add the mapping to the db
    switchlink_db_tuntap_add(tunp->ifindex, tunp);
    memcpy(&tunpinfo, tunp, sizeof(switchlink_db_tuntap_info_t));
  } else {
    // tuntap interface has already been created
    // Update mac addr, if needed?
  }
  // update bridge and other domain for the tuntap port, as needed
}

static void interface_create(switchlink_db_interface_info_t *intf) {
  switchlink_db_status_t status;
  switchlink_db_interface_info_t ifinfo;
  switchlink_handle_t old_bridge_h = 0;

  status = switchlink_db_interface_get_info(intf->ifindex, &ifinfo);
  if (status == SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    // create the interface

    if (intf->link_type == SWITCHLINK_LINK_TYPE_BOND) {
      switchlink_lag_create(&(intf->lag_h));
    } else {
      status = switchlink_db_port_get(intf->ifname, &(intf->port_id));
      if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
        // a port that we are not interested in
        return;
      }
    }

    /*
    status = switchlink_interface_create(intf, &(intf->intf_h));
    if (status != 0) {
      NL_LOG_ERROR(("newlink: switchlink_interface_create failed\n"));
      return;
    }
    */

    // add the mapping to the db
    switchlink_db_interface_add(intf->ifindex, intf);
    memcpy(&ifinfo, intf, sizeof(switchlink_db_interface_info_t));
  } else {
    // interface has already been created
    // update mac address if it has changed
    if (memcmp(&(ifinfo.mac_addr),
               &(intf->mac_addr),
               sizeof(switchlink_mac_addr_t))) {
      switchlink_db_interface_update(intf->ifindex, &ifinfo);
    }
    old_bridge_h = ifinfo.bridge_h;
    intf->intf_h = ifinfo.intf_h;
  }

  if (strcmp(intf->ifname, SWITCHLINK_CPU_INTERFACE_NAME) == 0) {
    create_cpu_interface(ifinfo.intf_h);
    return;
  }

  // update bridge domain for the interface
  if (old_bridge_h && (old_bridge_h != intf->bridge_h)) {
    int ret = switchlink_del_interface_from_bridge(intf, old_bridge_h);
    ovs_assert(ret == 0);
    ifinfo.bridge_h = 0;
    switchlink_db_interface_update(intf->ifindex, &ifinfo);
  }

  if ((intf->intf_type == SWITCHLINK_INTF_TYPE_L2_ACCESS) && intf->bridge_h &&
      (old_bridge_h != intf->bridge_h)) {
    int ret = switchlink_add_interface_to_bridge(intf);
    if (ret != 0) {
      NL_LOG_ERROR(
          ("newlink(%s): switchlink_add_interface_to_bridge "
           "failed\n",
           intf->ifname));
      return;
    }
    ifinfo.bridge_h = intf->bridge_h;
    ifinfo.vlan_member_h = intf->vlan_member_h;
    switchlink_db_interface_update(intf->ifindex, &ifinfo);
  }

  if (intf->intf_type != SWITCHLINK_INTF_TYPE_L3) {
    switchlink_stp_state_update(intf);
  }
}

static void interface_delete(switchlink_db_interface_info_t *intf) {
  switchlink_db_interface_info_t ifinfo;
  if (switchlink_db_interface_get_info(intf->ifindex, &ifinfo) ==
      SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    return;
  }
  intf->intf_h = ifinfo.intf_h;
  /*
  // remove the interface from bridge
  if (ifinfo.bridge_h) {
    switchlink_del_interface_from_bridge(intf, ifinfo.bridge_h);
  }

  if (ifinfo.intf_type != SWITCHLINK_INTF_TYPE_L3) {
    // clear stp state on interface
    intf->stp_state = SWITCHLINK_STP_STATE_BLOCKING;
    switchlink_stp_state_update(intf);
  }

  // delete the interface
  switchlink_interface_delete(intf, ifinfo.intf_h);
  */
  switchlink_db_mac_intf_delete(ifinfo.intf_h);
  switchlink_db_interface_delete(intf->ifindex);
}

void interface_change_type(uint32_t ifindex, switchlink_intf_type_t type) {
  switchlink_db_interface_info_t ifinfo;
  switchlink_db_interface_info_t intf;
  if (switchlink_db_interface_get_info(ifindex, &ifinfo) ==
      SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {
    return;
  }

  if (type == ifinfo.intf_type) {
    return;
  }

  interface_delete(&ifinfo);
  if (type == SWITCHLINK_INTF_TYPE_L3) {
    memset(&intf, 0, sizeof(switchlink_db_interface_info_t));
    strncpy(intf.ifname, ifinfo.ifname, SWITCHLINK_INTERFACE_NAME_LEN_MAX);
    intf.ifindex = ifinfo.ifindex;
    intf.intf_type = SWITCHLINK_INTF_TYPE_L3;
    intf.vrf_h = ifinfo.vrf_h;
    intf.flags.ipv4_unicast_enabled = true;
    intf.flags.ipv6_unicast_enabled = true;
    intf.flags.ipv4_multicast_enabled = false;
    intf.flags.ipv6_multicast_enabled = false;
    intf.flags.ipv4_urpf_mode = SWITCHLINK_URPF_MODE_NONE;
    intf.flags.ipv6_urpf_mode = SWITCHLINK_URPF_MODE_NONE;
    memcpy(&(intf.mac_addr), &ifinfo.mac_addr, sizeof(switchlink_mac_addr_t));
    interface_create(&intf);
  }
}

void interface_create_l3vi(uint32_t ifindex) {
  switchlink_db_bridge_info_t bridge_db_info;
  switchlink_db_interface_info_t intf_info;
  switchlink_db_status_t status;

  status = switchlink_db_bridge_get_info(ifindex, &bridge_db_info);
  ovs_assert(status == SWITCHLINK_DB_STATUS_SUCCESS);

  memset(&intf_info, 0, sizeof(intf_info));
  intf_info.ifindex = ifindex;
  intf_info.stp_h = bridge_db_info.stp_h;
  intf_info.stp_state = SWITCHLINK_STP_STATE_NONE;
  intf_info.bridge_h = bridge_db_info.bridge_h;
  intf_info.vrf_h = g_default_vrf_h;
  intf_info.intf_type = SWITCHLINK_INTF_TYPE_L3VI;
  intf_info.link_type = SWITCHLINK_LINK_TYPE_BRIDGE;
  intf_info.flags.ipv4_unicast_enabled = true;
  intf_info.flags.ipv6_unicast_enabled = true;
  intf_info.flags.ipv4_multicast_enabled = false;
  intf_info.flags.ipv6_multicast_enabled = false;
  intf_info.flags.ipv4_urpf_mode = SWITCHLINK_URPF_MODE_NONE;
  intf_info.flags.ipv6_urpf_mode = SWITCHLINK_URPF_MODE_NONE;
  memcpy(&(intf_info.mac_addr),
         &(bridge_db_info.mac_addr),
         sizeof(switchlink_mac_addr_t));

  status = switchlink_interface_create(&intf_info, &(intf_info.intf_h));
  if (status != 0) {
    NL_LOG_ERROR(("newlink: switchlink_interface_create failed\n"));
    return;
  }
  // add the mapping to the db
  switchlink_db_interface_add(intf_info.ifindex, &intf_info);
}

static switchlink_handle_t bridge_create(uint32_t ifindex,
                                         switchlink_mac_addr_t *mac_addr) {
  switchlink_db_bridge_info_t bridge_db_info;
  switchlink_db_status_t status;

  status = switchlink_db_bridge_get_info(ifindex, &bridge_db_info);
  if (status == SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND) {

    memset(&bridge_db_info, 0, sizeof(switchlink_db_bridge_info_t));
    bridge_db_info.vrf_h = g_default_vrf_h;
    //switchlink_bridge_create(&bridge_db_info);
    //switchlink_db_bridge_add(ifindex, &bridge_db_info);

  } else {
    /*
    if (mac_addr) {
      memcpy(
          &(bridge_db_info.mac_addr), mac_addr, sizeof(switchlink_mac_addr_t));
      switchlink_bridge_update(&bridge_db_info);
    }
    switchlink_db_bridge_update(ifindex, &bridge_db_info);
    */
  }

  return bridge_db_info.bridge_h;
}

static void bridge_delete(uint32_t ifindex,
                          switchlink_db_bridge_info_t *bridge_info) {
  //switchlink_bridge_delete(bridge_info);
  switchlink_db_bridge_delete(ifindex);
}

static inline switchlink_stp_state_t convert_stp_state(
    uint8_t linux_stp_state) {
  switchlink_stp_state_t stp_state = SWITCHLINK_STP_STATE_NONE;
  switch (linux_stp_state) {
    case BR_STATE_DISABLED:
      stp_state = SWITCHLINK_STP_STATE_DISABLED;
      break;
    case BR_STATE_LEARNING:
      stp_state = SWITCHLINK_STP_STATE_LEARNING;
      break;
    case BR_STATE_FORWARDING:
      stp_state = SWITCHLINK_STP_STATE_FORWARDING;
      break;
    case BR_STATE_BLOCKING:
      stp_state = SWITCHLINK_STP_STATE_BLOCKING;
      break;
    default:
      stp_state = SWITCHLINK_STP_STATE_NONE;
      break;
  }
  return stp_state;
}

static switchlink_stp_state_t get_stp_state(char *link_name) {
  switchlink_stp_state_t stp_state = SWITCHLINK_STP_STATE_NONE;
  char path[128];
  int fd;
  uint8_t linux_stp_state;

  snprintf(path, 128, "/sys/devices/virtual/net/%s/brport/state", link_name);
  if ((fd = open(path, O_RDONLY)) < 0) {
    return stp_state;
  }

  if (read(fd, &linux_stp_state, sizeof(linux_stp_state)) <
      (int)sizeof(linux_stp_state)) {
    close(fd);
    return stp_state;
  }

  close(fd);
  stp_state = convert_stp_state(linux_stp_state - '0');
  return stp_state;
}

static switchlink_link_type_t get_link_type(char *info_kind) {
  switchlink_link_type_t link_type = SWITCHLINK_LINK_TYPE_ETH;

  if (!strcmp(info_kind, "bridge")) {
    link_type = SWITCHLINK_LINK_TYPE_BRIDGE;
  } else if (!strcmp(info_kind, "vxlan")) {
    link_type = SWITCHLINK_LINK_TYPE_VXLAN;
  } else if (!strcmp(info_kind, "bond")) {
    link_type = SWITCHLINK_LINK_TYPE_BOND;
  } else if (!strcmp(info_kind, "tun")) {
    link_type = SWITCHLINK_LINK_TYPE_TUN;
  }

  return link_type;
}

// little helper to parsing message using netlink macroses
void parseRtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {  // while not end of the message
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta; // read attr
        }
        rta = RTA_NEXT(rta,len);    // get next attr
    }
}

/*
TODO: P4-OVS: Process Received Netlink messages here
*/

// Support Port(tuntap), Routing and Vxlan features
void process_link_msg(struct nlmsghdr *nlmsg, int type) {
  int hdrlen, attrlen;
  struct nlattr *attr, *nest_attr;
  struct ifinfomsg *ifmsg;
  uint32_t master = 0;
  bool mac_addr_valid = false;
  bool prot_info_valid = false;
  int nest_attr_type;

  struct rtattr *tb[IFLA_MAX + 1];

  switchlink_db_interface_info_t intf_info;
  switchlink_db_tuntap_info_t tunp;
  switchlink_link_type_t link_type = SWITCHLINK_LINK_TYPE_NONE;
  switchlink_stp_state_t stp_state = SWITCHLINK_STP_STATE_NONE;
  switchlink_handle_t bridge_h = 0;
  switchlink_handle_t stp_h = 0;

  ovs_assert((type == RTM_NEWLINK) || (type == RTM_DELLINK));
  ifmsg = nlmsg_data(nlmsg);
  hdrlen = sizeof(struct ifinfomsg);

  VLOG_INFO("%slink: family = %d, type = %d, ifindex = %d, flags = 0x%x,"\
       "change = 0x%x\n", ((type == RTM_NEWLINK) ? "new" : "del"),
       ifmsg->ifi_family,
       ifmsg->ifi_type,
       ifmsg->ifi_index,
       ifmsg->ifi_flags,
       ifmsg->ifi_change);

  /* P4-OVS: Only for Testing
  parseRtattr(tb, IFLA_MAX, IFLA_RTA(ifmsg), nlmsg->nlmsg_len);  // get attributes

  // Print interface name
  char *ifName;
  if (tb[IFLA_IFNAME]) {  // validation
    ifName = (char*)RTA_DATA(tb[IFLA_IFNAME]); // get network interface name
  }

  printf("Interface name is %s\n", ifName);

  // Other Interface details can be printed same way using IFLA_* attrs
  https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_link.h

  // To get VLAN interface details:

  # the message structure:
    [ nlmsg fields ]
    [ ifinfmsg fields ]
    nla chain:
        [ IFLA_IFNAME ]
        [ IFLA_… ]
        [ IFLA_LINKINFO ]
        nla chain:
            [ IFLA_INFO_KIND ]
            ...
            [ IFLA_INFO_DATA ]
            nla chain:
                [ IFLA_VLAN_ID ]
    # Pseudo Code
    nlmsg = links->ifindex(0) // assuming ifindex contains VLAN interface index
    vid = nlmsg->get_attr('IFLA_LINKINFO').\
    get_attr('IFLA_INFO_DATA').\
    get_attr('IFLA_VLAN_ID')

  */
  char *linkname;

  memset(&intf_info, 0, sizeof(switchlink_db_interface_info_t));
  attrlen = nlmsg_attrlen(nlmsg, hdrlen);
  attr = nlmsg_attrdata(nlmsg, hdrlen);
  while (nla_ok(attr, attrlen)) {
    int attr_type = nla_type(attr);
    switch (attr_type) {
      case IFLA_IFNAME:
        ovs_strzcpy(intf_info.ifname,
                nla_get_string(attr),
                SWITCHLINK_INTERFACE_NAME_LEN_MAX);
        VLOG_INFO("Interface name is %s\n", intf_info.ifname);
        break;
      case IFLA_LINKINFO:
        /*
        For VXLAN, follow the below sequence of parsing:
        IFLA_LINKINFO ->
        {IFLA_INFO_KIND | IFLA_INFO_DATA} ->
        {IFLA_VXLAN_ID | IFLA_VXLAN_PORT | IFLA_VXLAN_LINK | IFLA_VXLAN_ID}
        */
        nla_for_each_nested(nest_attr, attr, attrlen) {
          nest_attr_type = nla_type(nest_attr);
          switch (nest_attr_type) {
            case IFLA_INFO_KIND:
              link_type = get_link_type(nla_get_string(nest_attr));
              linkname = nla_get_string(nest_attr);
              VLOG_INFO("LINK INFO KIND: %s\n", linkname);
              break;
            default:
              break;
          }
        }
        break;
      case IFLA_ADDRESS: {
        mac_addr_valid = true;
        ovs_assert(nla_len(attr) == sizeof(switchlink_mac_addr_t));
        memcpy(&(intf_info.mac_addr), nla_data(attr), nla_len(attr));

        VLOG_INFO("Interface Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
               (unsigned char) intf_info.mac_addr[0],
               (unsigned char) intf_info.mac_addr[1],
               (unsigned char) intf_info.mac_addr[2],
               (unsigned char) intf_info.mac_addr[3],
               (unsigned char) intf_info.mac_addr[4],
               (unsigned char) intf_info.mac_addr[5]
               );

        break;
      }
      case IFLA_MASTER:
        master = nla_get_u32(attr);
        break;
      case IFLA_PROTINFO:
        /*
        prot_info_valid = true;
        link_type = SWITCHLINK_LINK_TYPE_ETH;
        nla_for_each_nested(nest_attr, attr, attrlen) {
          switch (nla_type(nest_attr)) {
            case IFLA_BRPORT_STATE:
              stp_state = convert_stp_state(nla_get_u8(nest_attr));
              break;
            default:
              break;
          }
        }
        */
        break;
      case IFLA_AF_SPEC:
        break;
      default:
        //NL_LOG_DEBUG(("link: skipping attr(%d)\n", attr_type));
        break;
    }
    attr = nla_next(attr, &attrlen);
  }

  //printf("LINK INFO KIND: %s\n", linkname);

  if (type == RTM_NEWLINK) {
    switch (link_type) {
      case SWITCHLINK_LINK_TYPE_TUN:
        if(strstr(intf_info.ifname, "swp") != NULL) {
          memset(&tunp, 0, sizeof(switchlink_db_tuntap_info_t));
          ovs_strzcpy(tunp.ifname, intf_info.ifname,
                          SWITCHLINK_INTERFACE_NAME_LEN_MAX);
          tunp.ifindex = ifmsg->ifi_index;
          memcpy(&(tunp.mac_addr), intf_info.mac_addr,
                          sizeof(switchlink_mac_addr_t));
          tunp.link_type = link_type;
          tuntap_create(&tunp);
        }
        break;
      case SWITCHLINK_LINK_TYPE_BRIDGE:
        //bridge_create(ifmsg->ifi_index,
          //            (mac_addr_valid ? &(intf_info.mac_addr) : NULL));
        break;
      case SWITCHLINK_LINK_TYPE_ETH:
      case SWITCHLINK_LINK_TYPE_BOND:
        break;
        /*
        if (master) {
          if (!prot_info_valid) {
            stp_state = get_stp_state(intf_info.ifname);
          }
          if (ifmsg->ifi_flags & IFF_SLAVE) {
          } else {
            switchlink_db_bridge_info_t bridge_info;
            bridge_h = bridge_create(master, NULL);
            switchlink_db_bridge_get_info(master, &bridge_info);
            stp_h = bridge_info.stp_h;
          }
        } else {
          bridge_h = g_default_bridge_h;
          stp_h = g_default_stp_h;
        }
        intf_info.ifindex = ifmsg->ifi_index;
        intf_info.stp_h = stp_h;
        intf_info.stp_state = stp_state;
        intf_info.bridge_h = bridge_h;
        intf_info.vrf_h = g_default_vrf_h;
        if (!strcmp(intf_info.ifname, SWITCHLINK_CPU_INTERFACE_NAME)) {
          intf_info.intf_type = SWITCHLINK_INTF_TYPE_L3;
        } else {
          intf_info.intf_type = SWITCHLINK_INTF_TYPE_L2_ACCESS;
        }
        intf_info.link_type = link_type;
        ovs_assert(bridge_h != 0);
        interface_create(&intf_info);
        if (mac_addr_valid) {
           update packet driver
        }
        break;
      case SWITCHLINK_LINK_TYPE_VXLAN:
        break;
      default:
        break;
    */
    }
  } //else {
//    ovs_assert(type == RTM_DELLINK);
//
//    switchlink_db_bridge_info_t bridge_db_info;
//    switchlink_handle_t bridge_h = 0;
//    switchlink_handle_t stp_h = 0;
//    int ret;
//    ret = switchlink_db_bridge_get_info(ifmsg->ifi_index, &bridge_db_info);
//    if (ret == 0) {
//      bridge_h = bridge_db_info.bridge_h;
//      stp_h = bridge_db_info.stp_h;
//    }
//
//    if (link_type == SWITCHLINK_LINK_TYPE_BRIDGE) {
//      ovs_assert(bridge_h != 0);
//      bridge_delete(ifmsg->ifi_index, &bridge_db_info);
//    } else {
//      intf_info.bridge_h = bridge_h;
//      intf_info.stp_h = stp_h;
//      intf_info.ifindex = ifmsg->ifi_index;
//      interface_delete(&intf_info);
//    }
//  }
}

//void process_link_msg(struct nlmsghdr *nlmsg, int type) {
//  int hdrlen, attrlen;
//  struct nlattr *attr, *nest_attr;
//  struct ifinfomsg *ifmsg;
//  uint32_t master = 0;
//  bool mac_addr_valid = false;
//  bool prot_info_valid = false;
//  int nest_attr_type;
//  switchlink_db_interface_info_t intf_info;
//  switchlink_link_type_t link_type = SWITCHLINK_LINK_TYPE_NONE;
//  switchlink_stp_state_t stp_state = SWITCHLINK_STP_STATE_NONE;
//  switchlink_handle_t bridge_h = 0;
//  switchlink_handle_t stp_h = 0;
//
//  ovs_assert((type == RTM_NEWLINK) || (type == RTM_DELLINK));
//  ifmsg = nlmsg_data(nlmsg);
//  hdrlen = sizeof(struct ifinfomsg);
//  NL_LOG_DEBUG(
//      ("%slink: family = %d, type = %d, ifindex = %d, flags = 0x%x, "
//       "change = 0x%x\n",
//       ((type == RTM_NEWLINK) ? "new" : "del"),
//       ifmsg->ifi_family,
//       ifmsg->ifi_type,
//       ifmsg->ifi_index,
//       ifmsg->ifi_flags,
//       ifmsg->ifi_change));
//
//  memset(&intf_info, 0, sizeof(switchlink_db_interface_info_t));
//  attrlen = nlmsg_attrlen(nlmsg, hdrlen);
//  attr = nlmsg_attrdata(nlmsg, hdrlen);
//  while (nla_ok(attr, attrlen)) {
//    int attr_type = nla_type(attr);
//    switch (attr_type) {
//      case IFLA_IFNAME:
//        strncpy(intf_info.ifname,
//                nla_get_string(attr),
//                SWITCHLINK_INTERFACE_NAME_LEN_MAX);
//        break;
//      case IFLA_LINKINFO:
//        nla_for_each_nested(nest_attr, attr, attrlen) {
//          nest_attr_type = nla_type(nest_attr);
//          switch (nest_attr_type) {
//            case IFLA_INFO_KIND:
//              link_type = get_link_type(nla_get_string(nest_attr));
//              break;
//            default:
//              break;
//          }
//        }
//        break;
//      case IFLA_ADDRESS: {
//        mac_addr_valid = true;
//        ovs_assert(nla_len(attr) == sizeof(switchlink_mac_addr_t));
//        memcpy(&(intf_info.mac_addr), nla_data(attr), nla_len(attr));
//        break;
//      }
//      case IFLA_MASTER:
//        master = nla_get_u32(attr);
//        break;
//      case IFLA_PROTINFO:
//        prot_info_valid = true;
//        link_type = SWITCHLINK_LINK_TYPE_ETH;
//        nla_for_each_nested(nest_attr, attr, attrlen) {
//          switch (nla_type(nest_attr)) {
//            case IFLA_BRPORT_STATE:
//              stp_state = convert_stp_state(nla_get_u8(nest_attr));
//              break;
//            default:
//              break;
//          }
//        }
//        break;
//      case IFLA_AF_SPEC:
//        break;
//      default:
//        NL_LOG_DEBUG(("link: skipping attr(%d)\n", attr_type));
//        break;
//    }
//    attr = nla_next(attr, &attrlen);
//  }
//
//  if (type == RTM_NEWLINK) {
//    switch (link_type) {
//      case SWITCHLINK_LINK_TYPE_BRIDGE:
//        bridge_create(ifmsg->ifi_index,
//                      (mac_addr_valid ? &(intf_info.mac_addr) : NULL));
//        break;
//      case SWITCHLINK_LINK_TYPE_ETH:
//      case SWITCHLINK_LINK_TYPE_BOND:
//        if (master) {
//          if (!prot_info_valid) {
//            stp_state = get_stp_state(intf_info.ifname);
//          }
//          if (ifmsg->ifi_flags & IFF_SLAVE) {
//          } else {
//            switchlink_db_bridge_info_t bridge_info;
//            bridge_h = bridge_create(master, NULL);
//            switchlink_db_bridge_get_info(master, &bridge_info);
//            stp_h = bridge_info.stp_h;
//          }
//        } else {
//          bridge_h = g_default_bridge_h;
//          stp_h = g_default_stp_h;
//        }
//        intf_info.ifindex = ifmsg->ifi_index;
//        intf_info.stp_h = stp_h;
//        intf_info.stp_state = stp_state;
//        intf_info.bridge_h = bridge_h;
//        intf_info.vrf_h = g_default_vrf_h;
//        if (!strcmp(intf_info.ifname, SWITCHLINK_CPU_INTERFACE_NAME)) {
//          intf_info.intf_type = SWITCHLINK_INTF_TYPE_L3;
//        } else {
//          intf_info.intf_type = SWITCHLINK_INTF_TYPE_L2_ACCESS;
//        }
//        intf_info.link_type = link_type;
//        ovs_assert(bridge_h != 0);
//        interface_create(&intf_info);
//        if (mac_addr_valid) {
//          // update packet driver
//        }
//        break;
//      case SWITCHLINK_LINK_TYPE_VXLAN:
//        break;
//      default:
//        break;
//    }
//  } else {
//    ovs_assert(type == RTM_DELLINK);
//
//    switchlink_db_bridge_info_t bridge_db_info;
//    switchlink_handle_t bridge_h = 0;
//    switchlink_handle_t stp_h = 0;
//    int ret;
//    ret = switchlink_db_bridge_get_info(ifmsg->ifi_index, &bridge_db_info);
//    if (ret == 0) {
//      bridge_h = bridge_db_info.bridge_h;
//      stp_h = bridge_db_info.stp_h;
//    }
//
//    if (link_type == SWITCHLINK_LINK_TYPE_BRIDGE) {
//      ovs_assert(bridge_h != 0);
//      bridge_delete(ifmsg->ifi_index, &bridge_db_info);
//    } else {
//      intf_info.bridge_h = bridge_h;
//      intf_info.stp_h = stp_h;
//      intf_info.ifindex = ifmsg->ifi_index;
//      interface_delete(&intf_info);
//    }
//  }
//}
//
void switchlink_link_init() {
  /* P4OVS: create default vrf*/
  //switchlink_vrf_create(SWITCHLINK_DEFAULT_VRF_ID, &g_default_vrf_h);

  /* P4OVS: Placeholder dummy value for now to bypass real vrf_create
   * Proper assignement need to happen once SAI layer is integrated
   * Will store VRF handle returned via create_virtual_router API
   */
  g_default_vrf_h = 0;

  /* P4OVS: create default bridge */
  switchlink_db_bridge_info_t bridge_db_info;
  memset(&bridge_db_info, 0, sizeof(switchlink_db_bridge_info_t));
  bridge_db_info.vrf_h = g_default_vrf_h;

  /* P4OVS: Placeholder dummy values for now to bypass real lbridge_create
   * SAI API need to implement vlan and stp as well?
   */
  //switchlink_bridge_create(&bridge_db_info);
  bridge_db_info.bridge_h = 0;
  bridge_db_info.stp_h = 0;

  g_default_bridge_h = bridge_db_info.bridge_h;
  g_default_stp_h = bridge_db_info.stp_h;
}
