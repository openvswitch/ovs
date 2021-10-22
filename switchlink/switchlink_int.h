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

#ifndef __SWITCHLINK_INT_H__
#define __SWITCHLINK_INT_H__

extern void switchlink_db_init();
//extern void switchlink_api_init();
extern void switchlink_link_init();
//extern void switchlink_packet_driver_init();

extern void process_link_msg(struct nlmsghdr *nlmsg, int type);
extern void process_neigh_msg(struct nlmsghdr *nlmsg, int type);
extern void process_address_msg(struct nlmsghdr *nlmsg, int type);
extern void process_route_msg(struct nlmsghdr *nlmsg, int type);
extern void process_netconf_msg(struct nlmsghdr *nlmsg, int type);
extern void process_mdb_msg(struct nlmsghdr *nlmsg, int type);

#endif /* __SWITCHLINK_INT_H__ */
