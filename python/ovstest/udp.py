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
ovsudp contains listener and sender classes for UDP protocol
"""

import array
import struct
import time

from twisted.internet.protocol import DatagramProtocol
from twisted.internet.task import LoopingCall


class UdpListener(DatagramProtocol):
    """
    Class that will listen for incoming UDP packets
    """
    def __init__(self):
        self.stats = []

    def datagramReceived(self, data, _1_2):
        """This function is called each time datagram is received"""
        try:
            self.stats.append(struct.unpack_from("Q", data, 0))
        except struct.error:
            pass  # ignore packets that are less than 8 bytes of size

    def getResults(self):
        """Returns number of packets that were actually received"""
        return len(self.stats)


class UdpSender(DatagramProtocol):
    """
    Class that will send UDP packets to UDP Listener
    """
    def __init__(self, host, count, size, duration):
        # LoopingCall does not know whether UDP socket is actually writable
        self.looper = None
        self.host = host
        self.count = count
        self.duration = duration
        self.start = time.time()
        self.sent = 0
        self.data = array.array('c', 'X' * size)

    def startProtocol(self):
        self.looper = LoopingCall(self.sendData)
        period = self.duration / float(self.count)
        self.looper.start(period, now=False)

    def stopProtocol(self):
        if (self.looper is not None):
            self.looper.stop()
            self.looper = None

    def datagramReceived(self, data, host_port):
        pass

    def sendData(self):
        """This function is called from LoopingCall"""
        if self.start + self.duration < time.time():
            self.looper.stop()
            self.looper = None

        self.sent += 1
        struct.pack_into('Q', self.data, 0, self.sent)
        self.transport.write(self.data, self.host)

    def getResults(self):
        """Returns number of packets that were sent"""
        return self.sent
