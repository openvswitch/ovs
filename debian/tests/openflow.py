import unittest
import logging
from mininet.net import Mininet
import mininet.log as log
from mininet.node import OVSController, OVSKernelSwitch

Switch = OVSKernelSwitch
Controller = OVSController
logging.basicConfig(level=logging.DEBUG)
log.setLogLevel('info')


class BasicOpenflowTest(unittest.TestCase):

    def addHost(self, N):
        logging.debug("Creating host h%s and add to net.", N)
        name = 'h%d' % N
        ip = '10.0.0.%d' % N
        return self.net.addHost(name, ip=ip)

    def setUp(self):
        self.net = Mininet(controller=Controller, switch=Switch)

        logging.info("Creating controllers")
        self.net.addController('c1', command='ovs-testcontroller')

        logging.info("Creating switches")
        s1 = self.net.addSwitch('s1', protocols="OpenFlow10")
        s2 = self.net.addSwitch('s2', protocols="OpenFlow10")

        logging.info("Creating hosts (7 on each switch)")
        hosts1 = [self.addHost(n) for n in (1, 2, 3, 4, 5, 6, 7)]
        hosts2 = [self.addHost(n) for n in (8, 9, 10, 11, 12, 13, 14)]

        logging.info("Creating links")
        for h in hosts1:
            self.net.addLink(s1, h)
        for h in hosts2:
            self.net.addLink(s2, h)
        self.net.addLink(s1, s2)

        logging.info("Starting network")
        self.net.start()

    def testPingAll(self):
        logging.info("Testing network")
        packetLoss = self.net.pingAll()
        self.assertTrue(
            packetLoss == 0,
            "Packet loss during ping test %s" %
            packetLoss)

    def testIPerfTCP(self):
        logging.info("Running TCP performance test")
        self.net.iperf()

    def testIPerfUDP(self):
        logging.info("Running UDP performance test")
        self.net.iperf(l4Type='UDP')

    def tearDown(self):
        logging.info("Stopping network")
        self.net.stop()

if __name__ == '__main__':
    unittest.main()
