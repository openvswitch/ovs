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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include "util.h"
#include "switchlink.h"
#include "switchlink_link.h"
#include "switchlink_neigh.h"
#include "switchlink_route.h"
#include "switchlink_db.h"
#include "switchlink_sai.h"

static pthread_t switchlink_packet_driver_thread;

typedef struct switchlink_packet_intf_ {
  char name[128];
  uint16_t port_id;
  int fd;
  char mac_addr[6];
} switchlink_packet_intf_t;

uint16_t g_num_intfs;
static switchlink_packet_intf_t *g_intf;

static void process_packet_from_user(int intf) {
  int ret, fd, i;
  char buf[2000];

  // read packet from switch port
  fd = g_intf[intf].fd;
  while ((ret = read(fd, buf, sizeof(buf))) > 0) {
    // ignore the packet if it is not sourced from one of the
    // device's interface
    char *src_mac_addr = buf + 6;
    bool src_found = false;
    for (i = 0; i < g_num_intfs; i++) {
      if (memcmp(src_mac_addr, g_intf[i].mac_addr, 6) == 0) {
        src_found = true;
        break;
      }
    }
    if (!src_found) {
      NL_LOG_DEBUG(("Tx: Dropped %d bytes from %s\n", ret, g_intf[intf].name));
      continue;
    }

    // transmit the packet
    if (switchlink_send_packet(buf, ret, g_intf[intf].port_id) != 0) {
      NL_LOG_ERROR(
          ("Tx: Sending %d bytes from %s failed\n", ret, g_intf[intf].name));
      continue;
    }
  }
}

static int tunnel_alloc(int intf) {
  int fd;
  char *dev = g_intf[intf].name;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    return -1;
  }

  // open the tap interface
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
    perror("tunsetiff");
    close(fd);
    return -1;
  }

  // set connection to be non-blocking
  int sock_flags = fcntl(fd, F_GETFL, 0);
  if (fcntl(fd, F_SETFL, sock_flags | O_NONBLOCK) < 0) {
    perror("f_setfl");
    close(fd);
    return -1;
  }

  // fetch the mac address
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  if (ioctl(fd, SIOCGIFHWADDR, (void *)&ifr) < 0) {
    perror("ioctl:mac");
    close(fd);
    return -1;
  }
  memcpy(g_intf[intf].mac_addr, ifr.ifr_addr.sa_data, 6);
  g_intf[intf].fd = fd;

  return 0;
}

static void packet_driver_init() {
  int i, ret;

  switchlink_db_port_obj_t *port_map;
  uint16_t num_ports;
  switchlink_db_port_get_all_ports(&num_ports, &port_map);
  g_intf = switchlink_malloc(sizeof(switchlink_packet_intf_t), num_ports);

  // initialize switch ports
  for (i = 0; i < num_ports; i++) {
    if (strncmp(port_map[i].name,
                SWITCHLINK_CPU_INTERFACE_NAME,
                SWITCHLINK_INTERFACE_NAME_LEN_MAX) == 0) {
      continue;
    }
    strncpy(g_intf[g_num_intfs].name,
            port_map[i].name,
            SWITCHLINK_INTERFACE_NAME_LEN_MAX);
    g_intf[g_num_intfs].port_id = port_map[i].port_id;
    ret = tunnel_alloc(g_num_intfs);
    ovs_assert(ret == 0);
    g_num_intfs++;
  }
  switchlink_free(port_map);
}

static void *switchlink_packet_driver_main(void *args) {
  int i;

  packet_driver_init();

  while (true) {
    int ret, nfds = -1;
    fd_set read_fds;
    FD_ZERO(&read_fds);
    for (i = 0; i < g_num_intfs; i++) {
      FD_SET(g_intf[i].fd, &read_fds);
      nfds = (g_intf[i].fd > nfds) ? g_intf[i].fd : nfds;
    }
    nfds++;

    ret = select(nfds, &read_fds, NULL, NULL, NULL);
    if (ret == -1) {
      perror("select");
      break;
    } else if (ret == 0) {
    } else {
      for (i = 0; i < g_num_intfs; i++) {
        if (FD_ISSET(g_intf[i].fd, &read_fds)) {
          process_packet_from_user(i);
        }
      }
    }
  }
  return NULL;
}

void switchlink_packet_driver_update_mac(char *link_name, uint8_t *lladdr) {
  int i;
  for (i = 0; i < g_num_intfs; i++) {
    if (strncmp(g_intf[i].name, link_name, SWITCHLINK_INTERFACE_NAME_LEN_MAX) ==
        0) {
      memcpy(g_intf[i].mac_addr, lladdr, 6);
    }
  }
}

void switchlink_packet_from_hardware(const void *buf,
                                     uint32_t buf_size,
                                     uint16_t port_id) {
  int i;
  for (i = 0; i < g_num_intfs; i++) {
    if (g_intf[i].port_id == port_id) {
      if (write(g_intf[i].fd, buf, buf_size) < 0) {
        NL_LOG_ERROR(
            ("Rx: Sending %d bytes to %s failed\n", buf_size, g_intf[i].name));
      }
      break;
    }
  }
}
/*
int switchlink_packet_driver_init() {
  return pthread_create(&switchlink_packet_driver_thread,
                        NULL,
                        switchlink_packet_driver_main,
                        NULL);
}*/
