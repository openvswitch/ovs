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
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include "util.h"
#include "switchlink.h"
#include "switchlink_link.h"
#include "switchlink_db.h"
#include "switchlink_sai.h"

static void switchlink_mdb_mroute_notify(
    switchlink_db_mroute_info_t *mroute_info) {
  switchlink_mroute_delete(mroute_info);
  switchlink_mroute_create(mroute_info);
}

static void process_mdb_entry(int type, int ifindex, struct br_mdb_entry *bre) {
  switchlink_db_mdb_info_t mdb_info;
  switchlink_db_bridge_info_t bridge_info;
  switchlink_db_interface_info_t intf_info;
  switchlink_db_status_t status;
  bool notify = false;

  memset(&bridge_info, 0, sizeof(bridge_info));
  status = switchlink_db_bridge_get_info(ifindex, &bridge_info);
  if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
    return;
  }

  memset(&intf_info, 0, sizeof(intf_info));
  status = switchlink_db_interface_get_info(bre->ifindex, &intf_info);
  if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
    return;
  }

  memset(&mdb_info, 0, sizeof(mdb_info));
  mdb_info.bridge_h = bridge_info.bridge_h;
  if (ntohs(bre->addr.proto) == ETH_P_IP) {
    mdb_info.grp_ip.family = AF_INET;
    mdb_info.grp_ip.prefix_len = 32;
    mdb_info.grp_ip.ip.v4addr.s_addr = ntohl(bre->addr.u.ip4);
  } else if (ntohs(bre->addr.proto) == ETH_P_IPV6) {
    mdb_info.grp_ip.family = AF_INET6;
    mdb_info.grp_ip.prefix_len = 128;
    memcpy(&(mdb_info.grp_ip.ip.v6addr),
           &(bre->addr.u.ip6),
           sizeof(struct in6_addr));
  } else {
    return;
  }

  if (type == RTM_NEWMDB) {
    status = switchlink_db_mdb_get_info(&mdb_info);
    if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
      mdb_info.intfs[mdb_info.num_intfs] = intf_info.intf_h;
      mdb_info.num_intfs++;
      status = switchlink_db_mdb_add(&mdb_info);
      ovs_assert(status == SWITCHLINK_DB_STATUS_SUCCESS);
      switchlink_mdb_create(&mdb_info);
      notify = true;
    } else {
      bool found = false;
      for (int i = 0; i < mdb_info.num_intfs; i++) {
        if (mdb_info.intfs[i] == intf_info.intf_h) {
          found = true;
          break;
        }
      }
      if (!found) {
        mdb_info.intfs[mdb_info.num_intfs] = intf_info.intf_h;
        mdb_info.num_intfs++;
        switchlink_mdb_delete(&mdb_info);
        switchlink_mdb_create(&mdb_info);
        status = switchlink_db_mdb_update(&mdb_info);
        ovs_assert(status == SWITCHLINK_DB_STATUS_SUCCESS);
        notify = true;
      }
    }
  } else {
    status = switchlink_db_mdb_get_info(&mdb_info);
    if (status != SWITCHLINK_DB_STATUS_SUCCESS) {
      return;
    }
    bool found = false;
    int entry_index = -1;
    for (int i = 0; i < mdb_info.num_intfs; i++) {
      if (mdb_info.intfs[i] == intf_info.intf_h) {
        found = true;
        entry_index = i;
        break;
      }
    }
    if (!found) {
      return;
    }
    mdb_info.intfs[entry_index] = mdb_info.intfs[mdb_info.num_intfs - 1];
    mdb_info.intfs[mdb_info.num_intfs - 1] = 0;
    mdb_info.num_intfs--;
    if (mdb_info.num_intfs == 0) {
      switchlink_mdb_delete(&mdb_info);
      status = switchlink_db_mdb_delete(&mdb_info);
      ovs_assert(status == SWITCHLINK_DB_STATUS_SUCCESS);
    } else {
      switchlink_mdb_delete(&mdb_info);
      switchlink_mdb_create(&mdb_info);
      status = switchlink_db_mdb_update(&mdb_info);
      ovs_assert(status == SWITCHLINK_DB_STATUS_SUCCESS);
    }
    notify = true;
  }

  if (notify) {
    switchlink_db_mroute_mdb_walk(&mdb_info, switchlink_mdb_mroute_notify);
  }
}

void process_mdb_msg(struct nlmsghdr *nlmsg, int type) {
  int hdrlen, attrlen;
  struct nlattr *attr, *nest_attr, *info_attr;
  struct br_port_msg *brp_msg;
  struct br_mdb_entry *bre;

  ovs_assert((type == RTM_GETMDB) || (type == RTM_NEWMDB) || (type == RTM_DELMDB));
  if (type == RTM_GETMDB) {
    type = RTM_NEWMDB;
  }

  brp_msg = nlmsg_data(nlmsg);
  hdrlen = sizeof(struct br_port_msg);
  NL_LOG_DEBUG(("%smdb: family = %d, ifindex = %d\n",
                ((type == RTM_NEWMDB) ? "new" : "del"),
                brp_msg->family,
                brp_msg->ifindex));

  attrlen = nlmsg_attrlen(nlmsg, hdrlen);
  attr = nlmsg_attrdata(nlmsg, hdrlen);
  while (nla_ok(attr, attrlen)) {
    int attr_type = nla_type(attr);
    switch (attr_type) {
      case MDBA_MDB:
        nla_for_each_nested(nest_attr, attr, attrlen) {
          int nest_attr_type;
          nest_attr_type = nla_type(nest_attr);
          switch (nest_attr_type) {
            case MDBA_MDB_ENTRY:
              info_attr = nla_data(nest_attr);
              if (nla_type(info_attr) == MDBA_MDB_ENTRY_INFO) {
                bre = (struct br_mdb_entry *)nla_data(info_attr);
                process_mdb_entry(type, brp_msg->ifindex, bre);
              }
              break;
            default:
              break;
          }
        }
        break;
      case MDBA_ROUTER:
        break;
      default:
        NL_LOG_DEBUG(("mdb: skipping attr(%d)\n", attr_type));
        break;
    }
    attr = nla_next(attr, &attrlen);
  }
}
