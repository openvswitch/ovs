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
tcp module contains listener and sender classes for TCP protocol
"""

import time

from twisted.internet import interfaces
from twisted.internet.protocol import ClientFactory, Factory, Protocol

from zope.interface.declarations import implementer


class TcpListenerConnection(Protocol):
    """
    This per-connection class is instantiated each time sender connects
    """
    def __init__(self):
        self.stats = 0

    def dataReceived(self, data):
        self.stats += len(data)

    def connectionLost(self, reason):
        self.factory.stats += self.stats


class TcpListenerFactory(Factory):
    """
    This per-listening socket class is used to
    instantiate TcpListenerConnections
    """
    protocol = TcpListenerConnection

    def __init__(self):
        self.stats = 0

    def getResults(self):
        """ returns the number of bytes received as string"""
        # XML RPC does not support 64bit int (http://bugs.python.org/issue2985)
        # so we have to convert the amount of bytes into a string
        return str(self.stats)


@implementer(interfaces.IPushProducer)
class Producer(object):
    """
    This producer class generates infinite byte stream for a specified time
    duration
    """
    def __init__(self, proto, duration):
        self.proto = proto
        self.start = time.time()
        self.produced = 0
        self.paused = False
        self.data = "X" * 65535
        self.duration = duration

    def pauseProducing(self):
        """This function is called whenever write() to socket would block"""
        self.paused = True

    def resumeProducing(self):
        """This function is called whenever socket becomes writable"""
        self.paused = False
        current = time.time()
        while (not self.paused) and (current < self.start + self.duration):
            self.proto.transport.write(self.data)
            self.produced += len(self.data)
            current = time.time()
        if current >= self.start + self.duration:
            self.proto.factory.stats += self.produced
            self.proto.transport.unregisterProducer()
            self.proto.transport.loseConnection()

    def stopProducing(self):
        pass


class TcpSenderConnection(Protocol):
    """
    TCP connection instance class that sends all traffic at full speed.
    """

    def connectionMade(self):
        producer = Producer(self, self.factory.duration)
        self.transport.registerProducer(producer, True)
        producer.resumeProducing()

    def dataReceived(self, data):
        self.transport.loseConnection()


class TcpSenderFactory(ClientFactory):
    """
    This factory is responsible to instantiate TcpSenderConnection classes
    each time sender initiates connection
    """
    protocol = TcpSenderConnection

    def __init__(self, duration):
        self.duration = duration
        self.stats = 0

    def getResults(self):
        """Returns amount of bytes sent to the Listener (as a string)"""
        return str(self.stats)
