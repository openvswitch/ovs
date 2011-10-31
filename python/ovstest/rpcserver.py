# Copyright (c) 2011 Nicira Networks
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

from twisted.internet import reactor
from twisted.web import xmlrpc, server
from twisted.internet.error import CannotListenError
import udp
import tcp
import args
import util


class TestArena(xmlrpc.XMLRPC):
    """
    This class contains all the functions that ovstest will call
    remotely. The caller is responsible to use designated handleIds
    for designated methods (e.g. do not mix UDP and TCP handles).
    """

    def __init__(self):
        xmlrpc.XMLRPC.__init__(self)
        self.handle_id = 1
        self.handle_map = {}

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


def start_rpc_server(port):
    RPC_SERVER = TestArena()
    reactor.listenTCP(port, server.Site(RPC_SERVER))
    reactor.run()
