# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import math
import time

import ovstest.util as util

DEFAULT_TEST_BRIDGE = "ovstestbr0"
DEFAULT_TEST_PORT = "ovstestport0"
DEFAULT_TEST_TUN = "ovstestport1"
NO_HANDLE = -1


def do_udp_tests(receiver, sender, tbwidth, duration, port_sizes):
    """Schedule UDP tests between receiver and sender"""
    server1 = util.rpc_client(receiver[0], receiver[1])
    server2 = util.rpc_client(sender[0], sender[1])

    udpformat = '{0:>15} {1:>15} {2:>15} {3:>15} {4:>15}'

    print("UDP test from %s:%u to %s:%u with target bandwidth %s" %
                            (sender[0], sender[1], receiver[0], receiver[1],
                             util.bandwidth_to_string(tbwidth)))
    print(udpformat.format("Datagram Size", "Snt Datagrams", "Rcv Datagrams",
                            "Datagram Loss", "Bandwidth"))

    for size in port_sizes:
        listen_handle = NO_HANDLE
        send_handle = NO_HANDLE
        try:
            packetcnt = (tbwidth * duration) / size

            listen_handle = server1.create_udp_listener(receiver[3])
            if listen_handle == NO_HANDLE:
                print("Server could not open UDP listening socket on port"
                      " %u. Try to restart the server.\n" % receiver[3])
                return
            send_handle = server2.create_udp_sender(
                                            (util.ip_from_cidr(receiver[2]),
                                             receiver[3]), packetcnt, size,
                                             duration)

            # Using sleep here because there is no other synchronization
            # source that would notify us when all sent packets were received
            time.sleep(duration + 1)

            rcv_packets = server1.get_udp_listener_results(listen_handle)
            snt_packets = server2.get_udp_sender_results(send_handle)

            loss = math.ceil(((snt_packets - rcv_packets) * 10000.0) /
                                                        snt_packets) / 100
            bwidth = (rcv_packets * size) / duration

            print(udpformat.format(size, snt_packets, rcv_packets,
                          '%.2f%%' % loss, util.bandwidth_to_string(bwidth)))
        finally:
            if listen_handle != NO_HANDLE:
                server1.close_udp_listener(listen_handle)
            if send_handle != NO_HANDLE:
                server2.close_udp_sender(send_handle)
    print("\n")


def do_tcp_tests(receiver, sender, duration):
    """Schedule TCP tests between receiver and sender"""
    server1 = util.rpc_client(receiver[0], receiver[1])
    server2 = util.rpc_client(sender[0], sender[1])

    tcpformat = '{0:>15} {1:>15} {2:>15}'
    print("TCP test from %s:%u to %s:%u (full speed)" % (sender[0], sender[1],
                                                    receiver[0], receiver[1]))
    print(tcpformat.format("Snt Bytes", "Rcv Bytes", "Bandwidth"))

    listen_handle = NO_HANDLE
    send_handle = NO_HANDLE
    try:
        listen_handle = server1.create_tcp_listener(receiver[3])
        if listen_handle == NO_HANDLE:
            print("Server was unable to open TCP listening socket on port"
                  " %u. Try to restart the server.\n" % receiver[3])
            return
        send_handle = server2.create_tcp_sender(util.ip_from_cidr(receiver[2]),
                                                receiver[3], duration)

        time.sleep(duration + 1)

        rcv_bytes = int(server1.get_tcp_listener_results(listen_handle))
        snt_bytes = int(server2.get_tcp_sender_results(send_handle))

        bwidth = rcv_bytes / duration

        print(tcpformat.format(snt_bytes, rcv_bytes,
                               util.bandwidth_to_string(bwidth)))
    finally:
        if listen_handle != NO_HANDLE:
            server1.close_tcp_listener(listen_handle)
        if send_handle != NO_HANDLE:
            server2.close_tcp_sender(send_handle)
    print("\n")


def do_l3_tests(node1, node2, bandwidth, duration, ps, type):
    """
    Do L3 tunneling tests. Each node is given as 4 tuple - physical
    interface IP, control port, test IP and test port.
    """
    server1 = util.rpc_client(node1[0], node1[1])
    server2 = util.rpc_client(node2[0], node2[1])
    servers_with_bridges = []
    try:
        server1.create_bridge(DEFAULT_TEST_BRIDGE)
        servers_with_bridges.append(server1)
        server2.create_bridge(DEFAULT_TEST_BRIDGE)
        servers_with_bridges.append(server2)

        server1.interface_up(DEFAULT_TEST_BRIDGE)
        server2.interface_up(DEFAULT_TEST_BRIDGE)

        server1.interface_assign_ip(DEFAULT_TEST_BRIDGE, node1[2], None)
        server2.interface_assign_ip(DEFAULT_TEST_BRIDGE, node2[2], None)

        server1.add_port_to_bridge(DEFAULT_TEST_BRIDGE, DEFAULT_TEST_TUN)
        server2.add_port_to_bridge(DEFAULT_TEST_BRIDGE, DEFAULT_TEST_TUN)

        server1.ovs_vsctl_set("Interface", DEFAULT_TEST_TUN, "type",
                              None, type)
        server2.ovs_vsctl_set("Interface", DEFAULT_TEST_TUN, "type",
                              None, type)
        server1.ovs_vsctl_set("Interface", DEFAULT_TEST_TUN, "options",
                              "remote_ip", node2[0])
        server2.ovs_vsctl_set("Interface", DEFAULT_TEST_TUN, "options",
                              "remote_ip", node1[0])

        do_udp_tests(node1, node2, bandwidth, duration, ps)
        do_udp_tests(node2, node1, bandwidth, duration, ps)
        do_tcp_tests(node1, node2, duration)
        do_tcp_tests(node2, node1, duration)

    finally:
        for server in servers_with_bridges:
            server.del_bridge(DEFAULT_TEST_BRIDGE)


def do_vlan_tests(node1, node2, bandwidth, duration, ps, tag):
    """
    Do VLAN tests between node1 and node2. Each node is given
    as 4 tuple - physical interface IP, control port, test IP and
    test port.
    """
    server1 = util.rpc_client(node1[0], node1[1])
    server2 = util.rpc_client(node2[0], node2[1])

    br_name1 = None
    br_name2 = None

    servers_with_test_ports = []

    try:
        interface_node1 = server1.get_interface(node1[0])
        interface_node2 = server2.get_interface(node2[0])

        if server1.is_ovs_bridge(interface_node1):
            br_name1 = interface_node1
        else:
            br_name1 = DEFAULT_TEST_BRIDGE
            server1.create_test_bridge(br_name1, interface_node1)

        if server2.is_ovs_bridge(interface_node2):
            br_name2 = interface_node2
        else:
            br_name2 = DEFAULT_TEST_BRIDGE
            server2.create_test_bridge(br_name2, interface_node2)

        server1.add_port_to_bridge(br_name1, DEFAULT_TEST_PORT)
        servers_with_test_ports.append(server1)
        server2.add_port_to_bridge(br_name2, DEFAULT_TEST_PORT)
        servers_with_test_ports.append(server2)

        server1.ovs_vsctl_set("Port", DEFAULT_TEST_PORT, "tag", None, tag)
        server2.ovs_vsctl_set("Port", DEFAULT_TEST_PORT, "tag", None, tag)

        server1.ovs_vsctl_set("Interface", DEFAULT_TEST_PORT, "type", None,
                              "internal")
        server2.ovs_vsctl_set("Interface", DEFAULT_TEST_PORT, "type", None,
                              "internal")

        server1.interface_assign_ip(DEFAULT_TEST_PORT, node1[2], None)
        server2.interface_assign_ip(DEFAULT_TEST_PORT, node2[2], None)

        server1.interface_up(DEFAULT_TEST_PORT)
        server2.interface_up(DEFAULT_TEST_PORT)

        do_udp_tests(node1, node2, bandwidth, duration, ps)
        do_udp_tests(node2, node1, bandwidth, duration, ps)
        do_tcp_tests(node1, node2, duration)
        do_tcp_tests(node2, node1, duration)

    finally:
        for server in servers_with_test_ports:
            server.del_port_from_bridge(DEFAULT_TEST_PORT)
        if br_name1 == DEFAULT_TEST_BRIDGE:
            server1.del_test_bridge(br_name1, interface_node1)
        if br_name2 == DEFAULT_TEST_BRIDGE:
            server2.del_test_bridge(br_name2, interface_node2)


def do_direct_tests(node1, node2, bandwidth, duration, ps):
    """
    Do tests between outer IPs without involving Open vSwitch. Each
    node is given as 4 tuple - physical interface IP, control port,
    test IP and test port. Direct tests will use physical interface
    IP as the test IP address.
    """
    n1 = (node1[0], node1[1], node1[0], node1[3])
    n2 = (node2[0], node2[1], node2[0], node2[3])

    do_udp_tests(n1, n2, bandwidth, duration, ps)
    do_udp_tests(n2, n1, bandwidth, duration, ps)
    do_tcp_tests(n1, n2, duration)
    do_tcp_tests(n2, n1, duration)


def configure_l3(conf, tunnel_mode):
    """
    This function creates a temporary test bridge and adds an L3 tunnel.
    """
    s = util.start_local_server(conf[1][1])
    server = util.rpc_client("127.0.0.1", conf[1][1])
    server.create_bridge(DEFAULT_TEST_BRIDGE)
    server.add_port_to_bridge(DEFAULT_TEST_BRIDGE, DEFAULT_TEST_PORT)
    server.interface_up(DEFAULT_TEST_BRIDGE)
    server.interface_assign_ip(DEFAULT_TEST_BRIDGE, conf[1][0],
                               None)
    server.ovs_vsctl_set("Interface", DEFAULT_TEST_PORT, "type",
                         None, tunnel_mode)
    server.ovs_vsctl_set("Interface", DEFAULT_TEST_PORT, "options",
                         "remote_ip", conf[0])
    return s
