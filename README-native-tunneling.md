Native Tunneling in Open vSwitch userspace
------------------------------------------

Open vSwitch supports tunneling in userspace. Tunneling is implemented in
platform independent way.

Setup:
======
Setup physical bridges for all physical interfaces. Create integration bridge.
Add VXLAN port to int-bridge. Assign IP address to physical bridge where
VXLAN traffic is expected.

Example:
========
Connect to VXLAN tunnel endpoint logical ip: 192.168.1.2 and 192.168.1.1.

Configure OVS bridges as follows.

1. Lets assume 172.168.1.2/24 network is reachable via eth1 create physical bridge br-eth1
   assign ip address (172.168.1.1/24) to br-eth1, Add eth1 to br-eth1
2. Check ovs cached routes using appctl command
   ovs-appctl ovs/route/show
   Add tunnel route if not present in OVS route table.
   ovs-appctl ovs/route/add 172.168.1.1/24 br-eth1
3. Add integration brdge int-br and add tunnel port using standard syntax.
   ovs-vsctl add-port int-br vxlan0 -- set interface vxlan0 type=vxlan  options:remote_ip=172.168.1.2
4. Assign IP address to int-br, So final topology looks like:


       192.168.1.1/24
       +--------------+
       |    int-br    |                                   192.168.1.2/24
       +--------------+                                  +--------------+
       |    vxlan0    |                                  |    vxlan0    |
       +--------------+                                  +--------------+
             |                                                 |
             |                                                 |
             |                                                 |
        172.168.1.1/24                                         |
       +--------------+                                        |
       |    br-eth1   |                                  172.168.1.2/24
       +--------------+                                  +---------------+
       |    eth1      |----------------------------------|    eth1       |
       +--------------+                                  +----------------

       Host A with OVS.                                      Remote host.

With this setup, ping to VXLAN target device (192.168.1.2) should work
There are following commands that shows internal tables:

Tunneling related commands:
===========================
Tunnel routing table:
    To Add route:
       ovs-appctl ovs/route/add <IP address>/<prefix length> <output-bridge-name> <gw>
    To see all routes configured:
       ovs-appctl ovs/route/show
    To del route:
       ovs-appctl ovs/route/del <IP address>/<prefix length>
    To look up and display the route for a destination:
       ovs-appctl ovs/route/lookup <IP address>

ARP:
    To see arp cache content:
       ovs-appctl tnl/arp/show
    To flush arp cache:
       ovs-appctl tnl/arp/flush

To check tunnel ports listening in vswitchd:
     ovs-appctl tnl/ports/show

To set range for VxLan udp source port:
     To set:
         ovs-appctl tnl/egress_port_range <num1> <num2>
     Shows Current range:
         ovs-appctl tnl/egress_port_range

To check datapath ports:
     ovs-appctl dpif/show

To check datapath flows:
     ovs-appctl dpif/dump-flows

Contact
=======
bugs@openvswitch.org
