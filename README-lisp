Using LISP tunneling
====================

LISP is a layer 3 tunneling mechanism, meaning that encapsulated packets do
not carry Ethernet headers, and ARP requests shouldn't be sent over the
tunnel.  Because of this, there are some additional steps required for setting
up LISP tunnels in Open vSwitch, until support for L3 tunnels will improve.

This guide assumes tunneling between two VMs connected to OVS bridges on
different hypervisors reachable over IPv4.  Of course, more than one VM may be
connected to any of the hypervisors, and a hypervisor may communicate with
several different hypervisors over the same lisp tunneling interface.  A LISP
"map-cache" can be implemented using flows, see example at the bottom of this
file.

There are several scenarios:

  1) the VMs have IP addresses in the same subnet and the hypervisors are also
     in a single subnet (although one different from the VM's);
  2) the VMs have IP addresses in the same subnet but the hypervisors are
     separated by a router;
  3) the VMs are in different subnets.

In cases 1) and 3) ARP resolution can work as normal: ARP traffic is
configured not to go through the LISP tunnel.  For case 1) ARP is able to
reach the other VM, if both OVS instances default to MAC address learning.
Case 3) requires the hypervisor be configured as the default router for the
VMs.

In case 2) the VMs expect ARP replies from each other, but this is not
possible over a layer 3 tunnel.  One solution is to have static MAC address
entries preconfigured on the VMs (e.g., `arp -f /etc/ethers` on startup on
Unix based VMs), or have the hypervisor do proxy ARP.  In this scenario, the
eth0 interfaces need not be added to the br0 bridge in the examples below.

On the receiving side, the packet arrives without the original MAC header.
The LISP tunneling code attaches a header with harcoded source and destination
MAC address 02:00:00:00:00:00.  This address has all bits set to 0, except the
locally administered bit, in order to avoid potential collisions with existing
allocations.  In order for packets to reach their intended destination, the
destination MAC address needs to be rewritten.  This can be done using the
flow table.

See below for an example setup, and the associated flow rules to enable LISP
tunneling.

               +---+                               +---+
               |VM1|                               |VM2|
               +---+                               +---+
                 |                                   |
            +--[tap0]--+                       +--[tap0]---+
            |          |                       |           |
        [lisp0] OVS1 [eth0]-----------------[eth0] OVS2 [lisp0]
            |          |                       |           |
            +----------+                       +-----------+

On each hypervisor, interfaces tap0, eth0, and lisp0 are added to a single
bridge instance, and become numbered 1, 2, and 3 respectively:

    ovs-vsctl add-br br0
    ovs-vsctl add-port br0 tap0
    ovs-vsctl add-port br0 eth0
    ovs-vsctl add-port br0 lisp0 -- set Interface lisp0 type=lisp options:remote_ip=flow options:key=flow

The last command sets up flow based tunneling on the lisp0 interface.  From
the LISP point of view, this is like having the Tunnel Router map cache
implemented as flow rules.

Flows on br0 should be configured as follows:

    priority=3,dl_dst=02:00:00:00:00:00,action=mod_dl_dst:<VMx_MAC>,output:1
    priority=2,in_port=1,dl_type=0x0806,action=NORMAL
    priority=1,in_port=1,dl_type=0x0800,vlan_tci=0,nw_src=<EID_prefix>,action=set_field:<OVSx_IP>->tun_dst,output:3
    priority=0,action=NORMAL

The third rule is like a map cache entry:  the <EID_prefix> specified by the
nw_src match field is mapped to the RLOC <OVSx_IP>, which is set as the tunnel
destination for this particular flow.

Optionally, if you want to use Instance ID in a flow, you can add
"set_tunnel:<IID>" to the action list.
