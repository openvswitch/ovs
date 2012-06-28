# Copyright (c) 2011, 2012 Nicira, Inc.
#
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

"""
rpcserver is an XML RPC server that allows RPC client to initiate tests
"""

import exceptions
import sys
import xmlrpclib

from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.web import xmlrpc
from twisted.web import server

import tcp
import udp
import util
import vswitch


class TestArena(xmlrpc.XMLRPC):
    """
    This class contains all the functions that ovs-test client will call
    remotely. The caller is responsible to use designated handleIds
    for designated methods (e.g. do not mix UDP and TCP handles).
    """

    def __init__(self):
        xmlrpc.XMLRPC.__init__(self, allowNone=True)
        self.handle_id = 1
        self.handle_map = {}
        self.bridges = set()
        self.pbridges = set()
        self.ports = set()
        self.request = None

    def __acquire_handle(self, value):
        """
        Allocates new handle and assigns value object to it
        """
        handle = self.handle_id
        self.handle_map[handle] = value
        self.handle_id += 1
        return handle

    def __get_handle_resources(self, handle):
        """
        Return resources that were assigned to handle
        """
        return self.handle_map[handle]

    def __delete_handle(self, handle):
        """
        Releases handle from handle_map
        """
        del self.handle_map[handle]

    def cleanup(self):
        """
        Delete all remaining bridges and ports if ovs-test client did not had
        a chance to remove them. It is necessary to call this function if
        ovs-test server is abruptly terminated when doing the tests.
        """
        for port in self.ports:
            # Remove ports that were added to existing bridges
            vswitch.ovs_vsctl_del_port_from_bridge(port)

        for bridge in self.bridges:
            # Remove bridges that were added for L3 tests
            vswitch.ovs_vsctl_del_bridge(bridge)

        for pbridge in self.pbridges:
            # Remove bridges that were added for VLAN tests
            vswitch.ovs_vsctl_del_pbridge(pbridge[0], pbridge[1])

    def render(self, request):
        """
        This method overrides the original XMLRPC.render method so that it
        would be possible to get the XML RPC client IP address from the
        request object.
        """
        self.request = request
        return xmlrpc.XMLRPC.render(self, request)

    def xmlrpc_get_my_address(self):
        """
        Returns the RPC client's IP address.
        """
        return self.request.getClientIP()

    def xmlrpc_get_my_address_from(self, his_ip, his_port):
        """
        Returns the ovs-test server IP address that the other ovs-test server
        with the given ip will see.
        """
        server1 = xmlrpclib.Server("http://%s:%u/" % (his_ip, his_port))
        return server1.get_my_address()

    def xmlrpc_create_udp_listener(self, port):
        """
        Creates a UDP listener that will receive packets from UDP sender
        """
        try:
            listener = udp.UdpListener()
            reactor.listenUDP(port, listener)
            handle_id = self.__acquire_handle(listener)
        except CannotListenError:
            return -1
        return handle_id

    def xmlrpc_create_udp_sender(self, host, count, size, duration):
        """
        Send UDP datagrams to UDP listener
        """
        sender = udp.UdpSender(tuple(host), count, size, duration)
        reactor.listenUDP(0, sender)
        handle_id = self.__acquire_handle(sender)
        return handle_id

    def xmlrpc_get_udp_listener_results(self, handle):
        """
        Returns number of datagrams that were received
        """
        listener = self.__get_handle_resources(handle)
        return listener.getResults()

    def xmlrpc_get_udp_sender_results(self, handle):
        """
        Returns number of datagrams that were sent
        """
        sender = self.__get_handle_resources(handle)
        return sender.getResults()

    def xmlrpc_close_udp_listener(self, handle):
        """
        Releases UdpListener and all its resources
        """
        listener = self.__get_handle_resources(handle)
        listener.transport.stopListening()
        self.__delete_handle(handle)
        return 0

    def xmlrpc_close_udp_sender(self, handle):
        """
        Releases UdpSender and all its resources
        """
        sender = self.__get_handle_resources(handle)
        sender.transport.stopListening()
        self.__delete_handle(handle)
        return 0

    def xmlrpc_create_tcp_listener(self, port):
        """
        Creates a TcpListener that will accept connection from TcpSender
        """
        try:
            listener = tcp.TcpListenerFactory()
            port = reactor.listenTCP(port, listener)
            handle_id = self.__acquire_handle((listener, port))
            return handle_id
        except CannotListenError:
            return -1

    def xmlrpc_create_tcp_sender(self, his_ip, his_port, duration):
        """
        Creates a TcpSender that will connect to TcpListener
        """
        sender = tcp.TcpSenderFactory(duration)
        connector = reactor.connectTCP(his_ip, his_port, sender)
        handle_id = self.__acquire_handle((sender, connector))
        return handle_id

    def xmlrpc_get_tcp_listener_results(self, handle):
        """
        Returns number of bytes received
        """
        (listener, _) = self.__get_handle_resources(handle)
        return listener.getResults()

    def xmlrpc_get_tcp_sender_results(self, handle):
        """
        Returns number of bytes sent
        """
        (sender, _) = self.__get_handle_resources(handle)
        return sender.getResults()

    def xmlrpc_close_tcp_listener(self, handle):
        """
        Releases TcpListener and all its resources
        """
        try:
            (_, port) = self.__get_handle_resources(handle)
            port.loseConnection()
            self.__delete_handle(handle)
        except exceptions.KeyError:
            return -1
        return 0

    def xmlrpc_close_tcp_sender(self, handle):
        """
        Releases TcpSender and all its resources
        """
        try:
            (_, connector) = self.__get_handle_resources(handle)
            connector.disconnect()
            self.__delete_handle(handle)
        except exceptions.KeyError:
            return -1
        return 0

    def xmlrpc_create_test_bridge(self, bridge, iface):
        """
        This function creates a physical bridge from iface. It moves the
        IP configuration from the physical interface to the bridge.
        """
        ret = vswitch.ovs_vsctl_add_bridge(bridge)
        if ret == 0:
            self.pbridges.add((bridge, iface))
            util.interface_up(bridge)
            (ip_addr, mask) = util.interface_get_ip(iface)
            util.interface_assign_ip(bridge, ip_addr, mask)
            util.move_routes(iface, bridge)
            util.interface_assign_ip(iface, "0.0.0.0", "255.255.255.255")
            ret = vswitch.ovs_vsctl_add_port_to_bridge(bridge, iface)
            if ret == 0:
                self.ports.add(iface)
            else:
                util.interface_assign_ip(iface, ip_addr, mask)
                util.move_routes(bridge, iface)
                vswitch.ovs_vsctl_del_bridge(bridge)

        return ret

    def xmlrpc_del_test_bridge(self, bridge, iface):
        """
        This function deletes the test bridge and moves its IP configuration
        back to the physical interface.
        """
        ret = vswitch.ovs_vsctl_del_pbridge(bridge, iface)
        self.pbridges.discard((bridge, iface))
        return ret

    def xmlrpc_get_iface_from_bridge(self, brname):
        """
        Tries to figure out physical interface from bridge.
        """
        return vswitch.ovs_get_physical_interface(brname)

    def xmlrpc_create_bridge(self, brname):
        """
        Creates an OVS bridge.
        """
        ret = vswitch.ovs_vsctl_add_bridge(brname)
        if ret == 0:
            self.bridges.add(brname)
        return ret

    def xmlrpc_del_bridge(self, brname):
        """
        Deletes an OVS bridge.
        """
        ret = vswitch.ovs_vsctl_del_bridge(brname)
        if ret == 0:
            self.bridges.discard(brname)
        return ret

    def xmlrpc_is_ovs_bridge(self, bridge):
        """
        This function verifies whether given interface is an ovs bridge.
        """
        return vswitch.ovs_vsctl_is_ovs_bridge(bridge)

    def xmlrpc_add_port_to_bridge(self, bridge, port):
        """
        Adds a port to the OVS bridge.
        """
        ret = vswitch.ovs_vsctl_add_port_to_bridge(bridge, port)
        if ret == 0:
            self.ports.add(port)
        return ret

    def xmlrpc_del_port_from_bridge(self, port):
        """
        Removes a port from OVS bridge.
        """
        ret = vswitch.ovs_vsctl_del_port_from_bridge(port)
        if ret == 0:
            self.ports.discard(port)
        return ret

    def xmlrpc_ovs_vsctl_set(self, table, record, column, key, value):
        """
        This function allows to alter OVS database.
        """
        return vswitch.ovs_vsctl_set(table, record, column, key, value)

    def xmlrpc_interface_up(self, iface):
        """
        This function brings up given interface.
        """
        return util.interface_up(iface)

    def xmlrpc_interface_assign_ip(self, iface, ip_address, mask):
        """
        This function allows to assing ip address to the given interface.
        """
        return util.interface_assign_ip(iface, ip_address, mask)

    def xmlrpc_get_interface(self, address):
        """
        Finds first interface that has given address
        """
        return util.get_interface(address)

    def xmlrpc_get_interface_mtu(self, iface):
        """
        Returns MTU of the given interface
        """
        return util.get_interface_mtu(iface)

    def xmlrpc_uname(self):
        """
        Return information about running kernel
        """
        return util.uname()

    def xmlrpc_get_driver(self, iface):
        """
        Returns driver version
        """
        return util.get_driver(iface)

    def xmlrpc_get_interface_from_routing_decision(self, ip):
        """
        Returns driver version
        """
        return util.get_interface_from_routing_decision(ip)


def start_rpc_server(port):
    """
    This function creates a RPC server and adds it to the Twisted Reactor.
    """
    rpc_server = TestArena()
    reactor.listenTCP(port, server.Site(rpc_server))
    try:
        print "Starting RPC server\n"
        sys.stdout.flush()
         # If this server was started from ovs-test client then we must flush
         # STDOUT so that client would know that server is ready to accept
         # XML RPC connections.
        reactor.run()
    finally:
        rpc_server.cleanup()
