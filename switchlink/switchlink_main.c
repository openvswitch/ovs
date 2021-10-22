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
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include "util.h"
#include "switchlink.h"
#include "switchlink_int.h"
#include "openvswitch/vlog.h"

static struct nl_sock *g_nlsk = NULL;
static pthread_t switchlink_thread;
static pthread_mutex_t cookie_mutex;
static pthread_cond_t cookie_cv;
static int cookie = 0;

VLOG_DEFINE_THIS_MODULE(switchlink_main);

//uint8_t g_log_level = SWITCHLINK_LOG_ERR;
uint8_t g_log_level = SWITCHLINK_LOG_DEBUG;

enum {
  SWITCHLINK_MSG_LINK,
  SWITCHLINK_MSG_ADDR,
  SWITCHLINK_MSG_NETCONF,
  SWITCHLINK_MSG_NETCONF6,
  SWITCHLINK_MSG_NEIGH_MAC,
  SWITCHLINK_MSG_NEIGH_IP,
  SWITCHLINK_MSG_NEIGH_IP6,
  SWITCHLINK_MSG_MDB,
  SWITCHLINK_MSG_UNICAST_ROUTE,
  SWITCHLINK_MSG_UNICAST_ROUTE6,
  SWITCHLINK_MSG_MULTICAST_ROUTE,
  SWITCHLINK_MSG_MULTICAST_ROUTE6,
  SWITCHLINK_MSG_MAX,
} switchlink_msg_t;

static void nl_sync_state() {
  static uint8_t msg_idx = SWITCHLINK_MSG_LINK;
  if (msg_idx == SWITCHLINK_MSG_MAX) {
    return;
  }

  struct rtgenmsg rt_hdr = {
      .rtgen_family = AF_UNSPEC,
  };

  int msg_type = -1;
  switch (msg_idx) {
    case SWITCHLINK_MSG_LINK:
      msg_type = RTM_GETLINK;
      break;

    case SWITCHLINK_MSG_ADDR:
      msg_type = RTM_GETADDR;
      break;

    case SWITCHLINK_MSG_NETCONF:
      msg_type = RTM_GETNETCONF;
      rt_hdr.rtgen_family = AF_INET;
      break;

    case SWITCHLINK_MSG_NETCONF6:
      msg_type = RTM_GETNETCONF;
      rt_hdr.rtgen_family = AF_INET6;
      break;

    case SWITCHLINK_MSG_NEIGH_MAC:
      msg_type = RTM_GETNEIGH;
      rt_hdr.rtgen_family = AF_BRIDGE;
      break;

    case SWITCHLINK_MSG_NEIGH_IP:
      msg_type = RTM_GETNEIGH;
      rt_hdr.rtgen_family = AF_INET;
      break;

    case SWITCHLINK_MSG_NEIGH_IP6:
      msg_type = RTM_GETNEIGH;
      rt_hdr.rtgen_family = AF_INET6;
      break;

    case SWITCHLINK_MSG_MDB:
      msg_type = RTM_GETMDB;
      rt_hdr.rtgen_family = AF_BRIDGE;
      break;

    case SWITCHLINK_MSG_UNICAST_ROUTE:
      msg_type = RTM_GETROUTE;
      rt_hdr.rtgen_family = AF_INET;
      break;

    case SWITCHLINK_MSG_UNICAST_ROUTE6:
      msg_type = RTM_GETROUTE;
      rt_hdr.rtgen_family = AF_INET6;
      break;

    case SWITCHLINK_MSG_MULTICAST_ROUTE:
      msg_type = RTM_GETROUTE;
      rt_hdr.rtgen_family = RTNL_FAMILY_IPMR;
      break;

    case SWITCHLINK_MSG_MULTICAST_ROUTE6:
      msg_type = RTM_GETROUTE;
      rt_hdr.rtgen_family = RTNL_FAMILY_IP6MR;
      break;
  }

  if (msg_type != -1) {
    nl_send_simple(g_nlsk, msg_type, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
    msg_idx++;
  }
}

static void process_nl_message(struct nlmsghdr *nlmsg) {
  /* TODO: P4OVS: Enabling callback for link msg type only and prints for
     few protocol families to avoid flood of messages. Enable, as needed.
  */
  switch (nlmsg->nlmsg_type) {
    case RTM_NEWLINK:
      VLOG_INFO("Switchlink Notification RTM_NEWLINK\n");
      process_link_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_DELLINK:
      VLOG_INFO("Switchlink Notification RTM_DELLINK\n");
      //process_link_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_NEWADDR:
      //printf("Switchlink Notification RTM_NEWADDR\n");
     // process_address_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_DELADDR:
     // printf("Switchlink Notification RTM_DELADDR\n");
     // process_address_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_NEWROUTE:
     // printf("Switchlink Notification RTM_NEWROUTE\n");
     // process_route_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_DELROUTE:
     // printf("Switchlink Notification RTM_DELROUTE\n");
     // process_route_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_NEWNEIGH:
     // printf("Switchlink Notification RTM_NEWNEIGH\n");
     // process_neigh_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_DELNEIGH:
     // printf("Switchlink Notification RTM_DELNEIGH\n");
     // process_neigh_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_NEWNETCONF:
     // process_netconf_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case RTM_GETMDB:
    case RTM_NEWMDB:
    case RTM_DELMDB:
     // process_mdb_msg(nlmsg, nlmsg->nlmsg_type);
      break;
    case NLMSG_DONE:
      nl_sync_state();
      break;
    default:
      VLOG_INFO("Unknown netlink message(%d). Ignoring\n", nlmsg->nlmsg_type);
      break;
  }
}

static int nl_sock_recv_msg(struct nl_msg *msg, void *arg) {
  struct nlmsghdr *nl_msg = nlmsg_hdr(msg);
  int nl_msg_sz = nlmsg_get_max_size(msg);
  while (nlmsg_ok(nl_msg, nl_msg_sz)) {
    process_nl_message(nl_msg);
    nl_msg = nlmsg_next(nl_msg, &nl_msg_sz);
  }

  return 0;
}

static void cleanup_nl_sock() {
  // free the socket
  nl_socket_free(g_nlsk);
  g_nlsk = NULL;
}

static void switchlink_nl_sock_intf_init() {
  int nlsk_fd, sock_flags;

  // allocate a new socket
  g_nlsk = nl_socket_alloc();
  if (g_nlsk == NULL) {
    perror("nl_socket_alloc");
    return;
  }

  nl_socket_set_local_port(g_nlsk, 0);

  // disable sequence number checking
  nl_socket_disable_seq_check(g_nlsk);

  // set the callback function
  nl_socket_modify_cb(
      g_nlsk, NL_CB_VALID, NL_CB_CUSTOM, nl_sock_recv_msg, NULL);
  nl_socket_modify_cb(
      g_nlsk, NL_CB_FINISH, NL_CB_CUSTOM, nl_sock_recv_msg, NULL);

  // connect to the netlink route socket
  if (nl_connect(g_nlsk, NETLINK_ROUTE) < 0) {
    perror("nl_connect:NETLINK_ROUTE");
    cleanup_nl_sock();
    return;
  }

  // register for the following messages
  nl_socket_add_memberships(g_nlsk, RTNLGRP_LINK, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_NOTIFY, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_NEIGH, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV4_IFADDR, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV4_MROUTE, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV4_ROUTE, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV4_RULE, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV4_NETCONF, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV6_IFADDR, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV6_MROUTE, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV6_ROUTE, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV6_RULE, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_IPV6_NETCONF, 0);
  nl_socket_add_memberships(g_nlsk, RTNLGRP_MDB, 0);

  // set socket to be non-blocking
  nlsk_fd = nl_socket_get_fd(g_nlsk);
  if (nlsk_fd < 0) {
    perror("nl_socket_get_fd");
    cleanup_nl_sock();
    return;
  }
  sock_flags = fcntl(nlsk_fd, F_GETFL, 0);
  if (fcntl(nlsk_fd, F_SETFL, sock_flags | O_NONBLOCK) < 0) {
    perror("fcntl");
    cleanup_nl_sock();
    return;
  }

  // start building state from the kernel
  nl_sync_state();
}

static void process_nl_event_loop() {
  int nlsk_fd;
  nlsk_fd = nl_socket_get_fd(g_nlsk);
  ovs_assert(nlsk_fd > 0);

  while (1) {
    int ret, num_fds;
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(nlsk_fd, &read_fds);
    num_fds = nlsk_fd + 1;

    ret = select(num_fds, &read_fds, NULL, NULL, NULL);
    if (ret == -1) {
      perror("pselect");
      return;
    } else if (ret == 0) {
    } else {
      if (FD_ISSET(nlsk_fd, &read_fds)) {
        nl_recvmsgs_default(g_nlsk);
      }
    }
  }
}

struct nl_sock *switchlink_get_nl_sock() {
  return g_nlsk;
}

static void *switchlink_main(void *args) {
    /* P4 OVS: Switchlink Database maintain (Cache Optimized Trie like struct)
     * 1. Obj map stores handle for other objects (intf, bridge, ecmp, etc)
     * 2. Seperate Interface and Bridge Object maps (Trie inplace)
     * 3. Mac object struct is hashable as well as maintain a linked list
     * 4. All other objects (mac, neigh, route, etc) maintains as linked list
     * 5. Every object need to have a handle so to get reference anywhere
    */

  switchlink_db_init();

    /* TODO - P4OVS:
    1. SAI initialization happens here
        - API callbacks registration for each use case (port, bridge, etc)
        - API can deal with creation, removal, get and set attrs, etc
    2. SAI API are maintained in API ID and Method Table pairs (sai_api_query)
    3. SAI switch gets created (with switch id) - Receive FDB & Packet events
        Q: Do we need the (4) below ??
    4. Interfaces need to be configured by SAI to deal with traps it receives.
        - For each use case (STP, OSPF, etc), Traps needs to be handled
        - Each Trap has Type, Action and Priority (SAI Attrs)
        - A Host Interface Trap object is created
            : Host intf id maps with swith id
            : For each attr, SAI to API mapping (SAI code to API reason code)
    5. Port list need to be prepared using SAI switch attributes
        - Three attrs for Ports (CPU Port, Port number and Port List)
        - Covert SAI attrs to real switch attrs (API backend map - dpdk,bm,etc)
            : Need to implement "get_switch_attribute" API in backend
            : SAI Adapter speciic metadata will be received here.
    6. Bypassing function totally for netlink compilation
    */
   switchlink_api_init();

    /* TODO - P4OVS:
    1. Function need to fill/create VRF and Bridge structures
        - create_vrf, create_bridge (Further calls into SAI layer)
    2. P4 OVS: Filled with dummy values to bypass for netlink compilation
    */
  switchlink_link_init();

  /* TODO: P4 OVS: Switchlink Packet Driver
    1. Register a seperate thread to deal with packet received on tuntap ports
        - switchlink_port_map maintaints the list of "swp*" interfaces
        - Num of total ports can be obtained from here
    2. packet_driver_init prepares the switchlink_packet_intf structure
        - switchlink_packet_intf have name, port, file desc and mac addr
        - Initialize switch ports (CPU_INTF_NAME) and assign port_id
        - Monitor the file descriprots to become "ready" (Select call)
        - tunnel_alloc is called
            :Open tap intf for "swp" port
            :Set connection to non-blocking
            :Update mac addr for received pkt in switchlink_packet_int struct
    3. Packet recieved from userspace on tuntap interfaces are processed
        - Read packet for all of these switch ports
        - Ignore if it's not in port map (*Not on "swp" interface")
        - switchlink_send_packet:
            :Trasnmsit the packet to SAI layer
            :SAI Attrs (HOSTIF_TX_TYPE & HOSTIF_PACKET_ATTR_EGRESS_PORT_OR_LAG)
            :Get port object from port_id
            :Callback into relevant Host intf callback from SAI to API layer.
    */

  //switchlink_packet_driver_init();

  /* P4OVS: Switchlink receive Netlink Kernel Notifications */
  switchlink_nl_sock_intf_init();

  if (g_nlsk) {
    usleep(20000);
    process_nl_event_loop();
    cleanup_nl_sock();
  }

  pthread_mutex_lock(&cookie_mutex);
  cookie = 1;
  pthread_cond_signal(&cookie_cv);
  pthread_mutex_unlock(&cookie_mutex);

  return NULL;
}

void *switchlink_init(void *args) {

  pthread_mutex_init(&cookie_mutex, NULL);
  pthread_cond_init(&cookie_cv, NULL);
  int status = pthread_create(&switchlink_thread, NULL, switchlink_main, NULL);
  if (status) return status;
  pthread_mutex_lock(&cookie_mutex);
  while (!cookie) {
    pthread_cond_wait(&cookie_cv, &cookie_mutex);
  }
  pthread_mutex_unlock(&cookie_mutex);
  pthread_mutex_destroy(&cookie_mutex);
  pthread_cond_destroy(&cookie_cv);
  return status;

  return 0;
}

int switchlink_stop() {
  int status = pthread_cancel(switchlink_thread);
  if (status == 0) {
    int s = pthread_join(switchlink_thread, NULL);
    return s;
  }
  return status;
}
