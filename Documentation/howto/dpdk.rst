..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

============================
Using Open vSwitch with DPDK
============================

This document describes how to use Open vSwitch with DPDK datapath.

.. important::

   Using the DPDK datapath requires building OVS with DPDK support. Refer to
   :doc:`/intro/install/dpdk` for more information.

Ports and Bridges
-----------------

ovs-vsctl can be used to set up bridges and other Open vSwitch features.
Bridges should be created with a ``datapath_type=netdev``::

    $ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

ovs-vsctl can also be used to add DPDK devices. ovs-vswitchd should print the
number of dpdk devices found in the log file::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
        options:dpdk-devargs=0000:01:00.0
    $ ovs-vsctl add-port br0 dpdk-p1 -- set Interface dpdk-p1 type=dpdk \
        options:dpdk-devargs=0000:01:00.1

After the DPDK ports get added to switch, a polling thread continuously polls
DPDK devices and consumes 100% of the core, as can be checked from ``top`` and
``ps`` commands::

    $ top -H
    $ ps -eLo pid,psr,comm | grep pmd

Creating bonds of DPDK interfaces is slightly different to creating bonds of
system interfaces. For DPDK, the interface type and devargs must be explicitly
set. For example::

    $ ovs-vsctl add-bond br0 dpdkbond p0 p1 \
        -- set Interface p0 type=dpdk options:dpdk-devargs=0000:01:00.0 \
        -- set Interface p1 type=dpdk options:dpdk-devargs=0000:01:00.1

To stop ovs-vswitchd & delete bridge, run::

    $ ovs-appctl -t ovs-vswitchd exit
    $ ovs-appctl -t ovsdb-server exit
    $ ovs-vsctl del-br br0

PMD Thread Statistics
---------------------

To show current stats::

    $ ovs-appctl dpif-netdev/pmd-stats-show

To clear previous stats::

    $ ovs-appctl dpif-netdev/pmd-stats-clear

Port/RXQ Assigment to PMD Threads
---------------------------------

To show port/rxq assignment::

    $ ovs-appctl dpif-netdev/pmd-rxq-show

To change default rxq assignment to pmd threads, rxqs may be manually pinned to
desired cores using::

    $ ovs-vsctl set Interface <iface> \
        other_config:pmd-rxq-affinity=<rxq-affinity-list>

where:

- ``<rxq-affinity-list>`` is a CSV list of ``<queue-id>:<core-id>`` values

For example::

    $ ovs-vsctl set interface dpdk-p0 options:n_rxq=4 \
        other_config:pmd-rxq-affinity="0:3,1:7,3:8"

This will ensure:

- Queue #0 pinned to core 3
- Queue #1 pinned to core 7
- Queue #2 not pinned
- Queue #3 pinned to core 8

After that PMD threads on cores where RX queues was pinned will become
``isolated``. This means that this thread will poll only pinned RX queues.

.. warning::
  If there are no ``non-isolated`` PMD threads, ``non-pinned`` RX queues will
  not be polled. Also, if provided ``core_id`` is not available (ex. this
  ``core_id`` not in ``pmd-cpu-mask``), RX queue will not be polled by any PMD
  thread.

QoS
---

Assuming you have a vhost-user port transmitting traffic consisting of packets
of size 64 bytes, the following command would limit the egress transmission
rate of the port to ~1,000,000 packets per second::

    $ ovs-vsctl set port vhost-user0 qos=@newqos -- \
        --id=@newqos create qos type=egress-policer other-config:cir=46000000 \
        other-config:cbs=2048`

To examine the QoS configuration of the port, run::

    $ ovs-appctl -t ovs-vswitchd qos/show vhost-user0

To clear the QoS configuration from the port and ovsdb, run::

    $ ovs-vsctl destroy QoS vhost-user0 -- clear Port vhost-user0 qos

Refer to vswitch.xml for more details on egress-policer.

Rate Limiting
--------------

Here is an example on Ingress Policing usage. Assuming you have a vhost-user
port receiving traffic consisting of packets of size 64 bytes, the following
command would limit the reception rate of the port to ~1,000,000 packets per
second::

    $ ovs-vsctl set interface vhost-user0 ingress_policing_rate=368000 \
        ingress_policing_burst=1000`

To examine the ingress policer configuration of the port::

    $ ovs-vsctl list interface vhost-user0

To clear the ingress policer configuration from the port::

    $ ovs-vsctl set interface vhost-user0 ingress_policing_rate=0

Refer to vswitch.xml for more details on ingress-policer.

Flow Control
------------

Flow control can be enabled only on DPDK physical ports. To enable flow control
support at tx side while adding a port, run::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
        options:dpdk-devargs=0000:01:00.0 options:tx-flow-ctrl=true

Similarly, to enable rx flow control, run::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
        options:dpdk-devargs=0000:01:00.0 options:rx-flow-ctrl=true

To enable flow control auto-negotiation, run::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
        options:dpdk-devargs=0000:01:00.0 options:flow-ctrl-autoneg=true

To turn ON the tx flow control at run time for an existing port, run::

    $ ovs-vsctl set Interface dpdk-p0 options:tx-flow-ctrl=true

The flow control parameters can be turned off by setting ``false`` to the
respective parameter. To disable the flow control at tx side, run::

    $ ovs-vsctl set Interface dpdk-p0 options:tx-flow-ctrl=false

pdump
-----

pdump allows you to listen on DPDK ports and view the traffic that is passing
on them. To use this utility, one must have libpcap installed on the system.
Furthermore, DPDK must be built with ``CONFIG_RTE_LIBRTE_PDUMP=y`` and
``CONFIG_RTE_LIBRTE_PMD_PCAP=y``.

.. warning::
  A performance decrease is expected when using a monitoring application like
  the DPDK pdump app.

To use pdump, simply launch OVS as usual, then navigate to the ``app/pdump``
directory in DPDK, ``make`` the application and run like so::

    $ sudo ./build/app/dpdk-pdump -- \
        --pdump port=0,queue=0,rx-dev=/tmp/pkts.pcap \
        --server-socket-path=/usr/local/var/run/openvswitch

The above command captures traffic received on queue 0 of port 0 and stores it
in ``/tmp/pkts.pcap``. Other combinations of port numbers, queues numbers and
pcap locations are of course also available to use. For example, to capture all
packets that traverse port 0 in a single pcap file::

    $ sudo ./build/app/dpdk-pdump -- \
        --pdump 'port=0,queue=*,rx-dev=/tmp/pkts.pcap,tx-dev=/tmp/pkts.pcap' \
        --server-socket-path=/usr/local/var/run/openvswitch

``server-socket-path`` must be set to the value of ``ovs_rundir()`` which
typically resolves to ``/usr/local/var/run/openvswitch``.

Many tools are available to view the contents of the pcap file. Once example is
tcpdump. Issue the following command to view the contents of ``pkts.pcap``::

    $ tcpdump -r pkts.pcap

More information on the pdump app and its usage can be found in the `DPDK docs
<http://dpdk.org/doc/guides/tools/pdump.html>`__.

Jumbo Frames
------------

By default, DPDK ports are configured with standard Ethernet MTU (1500B). To
enable Jumbo Frames support for a DPDK port, change the Interface's
``mtu_request`` attribute to a sufficiently large value. For example, to add a
DPDK Phy port with MTU of 9000::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
          options:dpdk-devargs=0000:01:00.0 mtu_request=9000

Similarly, to change the MTU of an existing port to 6200::

    $ ovs-vsctl set Interface dpdk-p0 mtu_request=6200

Some additional configuration is needed to take advantage of jumbo frames with
vHost ports:

1. *mergeable buffers* must be enabled for vHost ports, as demonstrated in the
   QEMU command line snippet below::

       -netdev type=vhost-user,id=mynet1,chardev=char0,vhostforce \
       -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,mrg_rxbuf=on

2. Where virtio devices are bound to the Linux kernel driver in a guest
   environment (i.e. interfaces are not bound to an in-guest DPDK driver), the
   MTU of those logical network interfaces must also be increased to a
   sufficiently large value. This avoids segmentation of Jumbo Frames received
   in the guest. Note that 'MTU' refers to the length of the IP packet only,
   and not that of the entire frame.

   To calculate the exact MTU of a standard IPv4 frame, subtract the L2 header
   and CRC lengths (i.e. 18B) from the max supported frame size.  So, to set
   the MTU for a 9018B Jumbo Frame::

       $ ip link set eth1 mtu 9000

When Jumbo Frames are enabled, the size of a DPDK port's mbuf segments are
increased, such that a full Jumbo Frame of a specific size may be accommodated
within a single mbuf segment.

Jumbo frame support has been validated against 9728B frames, which is the
largest frame size supported by Fortville NIC using the DPDK i40e driver, but
larger frames and other DPDK NIC drivers may be supported. These cases are
common for use cases involving East-West traffic only.

Rx Checksum Offload
-------------------

By default, DPDK physical ports are enabled with Rx checksum offload.

Rx checksum offload can offer performance improvement only for tunneling
traffic in OVS-DPDK because the checksum validation of tunnel packets is
offloaded to the NIC. Also enabling Rx checksum may slightly reduce the
performance of non-tunnel traffic, specifically for smaller size packet.

.. _extended-statistics:

Extended Statistics
-------------------

DPDK Extended Statistics API allows PMD to expose unique set of statistics.
The Extended statistics are implemented and supported only for DPDK physical
and vHost ports.

To enable statistics, you have to enable OpenFlow 1.4 support for OVS.
Configure bridge br0 to support OpenFlow version 1.4::

    $ ovs-vsctl set bridge br0 datapath_type=netdev \
      protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13,OpenFlow14

Check the OVSDB protocols column in the bridge table if OpenFlow 1.4 support
is enabled for OVS::

    $ ovsdb-client dump Bridge protocols

Query the port statistics by explicitly specifying -O OpenFlow14 option::

    $ ovs-ofctl -O OpenFlow14 dump-ports br0

Note: vHost ports supports only partial statistics. RX packet size based
counter are only supported and doesn't include TX packet size counters.

.. _port-hotplug:

Port Hotplug
------------

OVS supports port hotplugging, allowing the use of ports that were not bound
to DPDK when vswitchd was started.
In order to attach a port, it has to be bound to DPDK using the
``dpdk_nic_bind.py`` script::

    $ $DPDK_DIR/tools/dpdk_nic_bind.py --bind=igb_uio 0000:01:00.0

Then it can be attached to OVS::

    $ ovs-vsctl add-port br0 dpdkx -- set Interface dpdkx type=dpdk \
        options:dpdk-devargs=0000:01:00.0

Detaching will be performed while processing del-port command::

    $ ovs-vsctl del-port dpdkx

Sometimes, the del-port command may not detach the device.
Detaching can be confirmed by the appearance of an INFO log.
For example::

    INFO|Device '0000:04:00.1' has been detached

If the log is not seen, then the port can be detached using::

$ ovs-appctl netdev-dpdk/detach 0000:01:00.0

Detaching can be confirmed by console output::

    Device '0000:04:00.1' has been detached

.. warning::
    Detaching should not be done if a device is known to be non-detachable, as
    this may cause the device to behave improperly when added back with
    add-port. The Chelsio Terminator adapters which use the cxgbe driver seem
    to be an example of this behavior; check the driver documentation if this
    is suspected.

This feature does not work with some NICs.
For more information please refer to the `DPDK Port Hotplug Framework
<http://dpdk.org/doc/guides/prog_guide/port_hotplug_framework.html#hotplug>`__.

.. _vdev-support:

Vdev Support
------------

DPDK provides drivers for both physical and virtual devices. Physical DPDK
devices are added to OVS by specifying a valid PCI address in 'dpdk-devargs'.
Virtual DPDK devices which do not have PCI addresses can be added using a
different format for 'dpdk-devargs'.

Typically, the format expected is 'eth_<driver_name><x>' where 'x' is a
unique identifier of your choice for the given port.

For example to add a dpdk port that uses the 'null' DPDK PMD driver::

       $ ovs-vsctl add-port br0 null0 -- set Interface null0 type=dpdk \
           options:dpdk-devargs=eth_null0

Similarly, to add a dpdk port that uses the 'af_packet' DPDK PMD driver::

       $ ovs-vsctl add-port br0 myeth0 -- set Interface myeth0 type=dpdk \
           options:dpdk-devargs=eth_af_packet0,iface=eth0

More information on the different types of virtual DPDK PMDs can be found in
the `DPDK documentation
<http://dpdk.org/doc/guides/nics/overview.html>`__.

Note: Not all DPDK virtual PMD drivers have been tested and verified to work.

EMC Insertion Probability
-------------------------
By default 1 in every 100 flows are inserted into the Exact Match Cache (EMC).
It is possible to change this insertion probability by setting the
``emc-insert-inv-prob`` option::

    $ ovs-vsctl --no-wait set Open_vSwitch . other_config:emc-insert-inv-prob=N

where:

``N``
  is a positive integer representing the inverse probability of insertion ie.
  on average 1 in every N packets with a unique flow will generate an EMC
  insertion.

If ``N`` is set to 1, an insertion will be performed for every flow. If set to
0, no insertions will be performed and the EMC will effectively be disabled.

With default ``N`` set to 100, higher megaflow hits will occur initially
as observed with pmd stats::

    $ ovs-appctl dpif-netdev/pmd-stats-show

For certain traffic profiles with many parallel flows, it's recommended to set
``N`` to '0' to achieve higher forwarding performance.

For more information on the EMC refer to :doc:`/intro/install/dpdk` .

.. _dpdk-ovs-in-guest:

OVS with DPDK Inside VMs
------------------------

Additional configuration is required if you want to run ovs-vswitchd with DPDK
backend inside a QEMU virtual machine. ovs-vswitchd creates separate DPDK TX
queues for each CPU core available. This operation fails inside QEMU virtual
machine because, by default, VirtIO NIC provided to the guest is configured to
support only single TX queue and single RX queue. To change this behavior, you
need to turn on ``mq`` (multiqueue) property of all ``virtio-net-pci`` devices
emulated by QEMU and used by DPDK.  You may do it manually (by changing QEMU
command line) or, if you use Libvirt, by adding the following string to
``<interface>`` sections of all network devices used by DPDK::

    <driver name='vhost' queues='N'/>

where:

``N``
  determines how many queues can be used by the guest.

This requires QEMU >= 2.2.

.. _dpdk-phy-phy:

PHY-PHY
-------

Add a userspace bridge and two ``dpdk`` (PHY) ports::

    # Add userspace bridge
    $ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

    # Add two dpdk ports
    $ ovs-vsctl add-port br0 phy0 -- set Interface phy0 type=dpdk \
          options:dpdk-devargs=0000:01:00.0 ofport_request=1

    $ ovs-vsctl add-port br0 phy1 -- set Interface phy1 type=dpdk
          options:dpdk-devargs=0000:01:00.1 ofport_request=2

Add test flows to forward packets betwen DPDK port 0 and port 1::

    # Clear current flows
    $ ovs-ofctl del-flows br0

    # Add flows between port 1 (phy0) to port 2 (phy1)
    $ ovs-ofctl add-flow br0 in_port=1,action=output:2
    $ ovs-ofctl add-flow br0 in_port=2,action=output:1

Transmit traffic into either port. You should see it returned via the other.

.. _dpdk-vhost-loopback:

PHY-VM-PHY (vHost Loopback)
---------------------------

Add a userspace bridge, two ``dpdk`` (PHY) ports, and two ``dpdkvhostuser``
ports::

    # Add userspace bridge
    $ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

    # Add two dpdk ports
    $ ovs-vsctl add-port br0 phy0 -- set Interface phy0 type=dpdk \
          options:dpdk-devargs=0000:01:00.0 ofport_request=1

    $ ovs-vsctl add-port br0 phy1 -- set Interface phy1 type=dpdk
          options:dpdk-devargs=0000:01:00.1 ofport_request=2

    # Add two dpdkvhostuser ports
    $ ovs-vsctl add-port br0 dpdkvhostuser0 \
        -- set Interface dpdkvhostuser0 type=dpdkvhostuser ofport_request=3
    $ ovs-vsctl add-port br0 dpdkvhostuser1 \
        -- set Interface dpdkvhostuser1 type=dpdkvhostuser ofport_request=4

Add test flows to forward packets betwen DPDK devices and VM ports::

    # Clear current flows
    $ ovs-ofctl del-flows br0

    # Add flows
    $ ovs-ofctl add-flow br0 in_port=1,action=output:3
    $ ovs-ofctl add-flow br0 in_port=3,action=output:1
    $ ovs-ofctl add-flow br0 in_port=4,action=output:2
    $ ovs-ofctl add-flow br0 in_port=2,action=output:4

    # Dump flows
    $ ovs-ofctl dump-flows br0

Create a VM using the following configuration:

+----------------------+--------+-----------------+
| configuration        | values | comments        |
+----------------------+--------+-----------------+
| qemu version         | 2.2.0  | n/a             |
| qemu thread affinity | core 5 | taskset 0x20    |
| memory               | 4GB    | n/a             |
| cores                | 2      | n/a             |
| Qcow2 image          | CentOS7| n/a             |
| mrg_rxbuf            | off    | n/a             |
+----------------------+--------+-----------------+

You can do this directly with QEMU via the ``qemu-system-x86_64`` application::

    $ export VM_NAME=vhost-vm
    $ export GUEST_MEM=3072M
    $ export QCOW2_IMAGE=/root/CentOS7_x86_64.qcow2
    $ export VHOST_SOCK_DIR=/usr/local/var/run/openvswitch

    $ taskset 0x20 qemu-system-x86_64 -name $VM_NAME -cpu host -enable-kvm \
      -m $GUEST_MEM -drive file=$QCOW2_IMAGE --nographic -snapshot \
      -numa node,memdev=mem -mem-prealloc -smp sockets=1,cores=2 \
      -object memory-backend-file,id=mem,size=$GUEST_MEM,mem-path=/dev/hugepages,share=on \
      -chardev socket,id=char0,path=$VHOST_SOCK_DIR/dpdkvhostuser0 \
      -netdev type=vhost-user,id=mynet1,chardev=char0,vhostforce \
      -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,mrg_rxbuf=off \
      -chardev socket,id=char1,path=$VHOST_SOCK_DIR/dpdkvhostuser1 \
      -netdev type=vhost-user,id=mynet2,chardev=char1,vhostforce \
      -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2,mrg_rxbuf=off

For a explanation of this command, along with alternative approaches such as
booting the VM via libvirt, refer to :doc:`/topics/dpdk/vhost-user`.

Once the guest is configured and booted, configure DPDK packet forwarding
within the guest. To accomplish this, build the ``testpmd`` application as
described in :ref:`dpdk-testpmd`. Once compiled, run the application::

    $ cd $DPDK_DIR/app/test-pmd;
    $ ./testpmd -c 0x3 -n 4 --socket-mem 1024 -- \
        --burst=64 -i --txqflags=0xf00 --disable-hw-vlan
    $ set fwd mac retry
    $ start

When you finish testing, bind the vNICs back to kernel::

    $ $DPDK_DIR/usertools/dpdk-devbind.py --bind=virtio-pci 0000:00:03.0
    $ $DPDK_DIR/usertools/dpdk-devbind.py --bind=virtio-pci 0000:00:04.0

.. note::

  Valid PCI IDs must be passed in above example. The PCI IDs can be retrieved
  like so::

      $ $DPDK_DIR/usertools/dpdk-devbind.py --status

More information on the dpdkvhostuser ports can be found in
:doc:`/topics/dpdk/vhost-user`.

PHY-VM-PHY (vHost Loopback) (Kernel Forwarding)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:ref:`dpdk-vhost-loopback` details steps for PHY-VM-PHY loopback
testcase and packet forwarding using DPDK testpmd application in the Guest VM.
For users wishing to do packet forwarding using kernel stack below, you need to
run the below commands on the guest::

    $ ip addr add 1.1.1.2/24 dev eth1
    $ ip addr add 1.1.2.2/24 dev eth2
    $ ip link set eth1 up
    $ ip link set eth2 up
    $ systemctl stop firewalld.service
    $ systemctl stop iptables.service
    $ sysctl -w net.ipv4.ip_forward=1
    $ sysctl -w net.ipv4.conf.all.rp_filter=0
    $ sysctl -w net.ipv4.conf.eth1.rp_filter=0
    $ sysctl -w net.ipv4.conf.eth2.rp_filter=0
    $ route add -net 1.1.2.0/24 eth2
    $ route add -net 1.1.1.0/24 eth1
    $ arp -s 1.1.2.99 DE:AD:BE:EF:CA:FE
    $ arp -s 1.1.1.99 DE:AD:BE:EF:CA:EE

PHY-VM-PHY (vHost Multiqueue)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

vHost Multiqueue functionality can also be validated using the PHY-VM-PHY
configuration. To begin, follow the steps described in :ref:`dpdk-phy-phy` to
create and initialize the database, start ovs-vswitchd and add ``dpdk``-type
devices to bridge ``br0``. Once complete, follow the below steps:

1. Configure PMD and RXQs.

   For example, set the number of dpdk port rx queues to at least 2  The number
   of rx queues at vhost-user interface gets automatically configured after
   virtio device connection and doesn't need manual configuration::

       $ ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=0xc
       $ ovs-vsctl set Interface phy0 options:n_rxq=2
       $ ovs-vsctl set Interface phy1 options:n_rxq=2

2. Instantiate Guest VM using QEMU cmdline

   We must configure with appropriate software versions to ensure this feature
   is supported.

   .. list-table:: Recommended BIOS Settings
      :header-rows: 1

      * - Setting
        - Value
      * - QEMU version
        - 2.5.0
      * - QEMU thread affinity
        - 2 cores (taskset 0x30)
      * - Memory
        - 4 GB
      * - Cores
        - 2
      * - Distro
        - Fedora 22
      * - Multiqueue
        - Enabled

   To do this, instantiate the guest as follows::

       $ export VM_NAME=vhost-vm
       $ export GUEST_MEM=4096M
       $ export QCOW2_IMAGE=/root/Fedora22_x86_64.qcow2
       $ export VHOST_SOCK_DIR=/usr/local/var/run/openvswitch
       $ taskset 0x30 qemu-system-x86_64 -cpu host -smp 2,cores=2 -m 4096M \
           -drive file=$QCOW2_IMAGE --enable-kvm -name $VM_NAME \
           -nographic -numa node,memdev=mem -mem-prealloc \
           -object memory-backend-file,id=mem,size=$GUEST_MEM,mem-path=/dev/hugepages,share=on \
           -chardev socket,id=char1,path=$VHOST_SOCK_DIR/dpdkvhostuser0 \
           -netdev type=vhost-user,id=mynet1,chardev=char1,vhostforce,queues=2 \
           -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,mq=on,vectors=6 \
           -chardev socket,id=char2,path=$VHOST_SOCK_DIR/dpdkvhostuser1 \
           -netdev type=vhost-user,id=mynet2,chardev=char2,vhostforce,queues=2 \
           -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2,mq=on,vectors=6

   .. note::
     Queue value above should match the queues configured in OVS, The vector
     value should be set to "number of queues x 2 + 2"

3. Configure the guest interface

   Assuming there are 2 interfaces in the guest named eth0, eth1 check the
   channel configuration and set the number of combined channels to 2 for
   virtio devices::

       $ ethtool -l eth0
       $ ethtool -L eth0 combined 2
       $ ethtool -L eth1 combined 2

   More information can be found in vHost walkthrough section.

4. Configure kernel packet forwarding

   Configure IP and enable interfaces::

       $ ip addr add 5.5.5.1/24 dev eth0
       $ ip addr add 90.90.90.1/24 dev eth1
       $ ip link set eth0 up
       $ ip link set eth1 up

   Configure IP forwarding and add route entries::

       $ sysctl -w net.ipv4.ip_forward=1
       $ sysctl -w net.ipv4.conf.all.rp_filter=0
       $ sysctl -w net.ipv4.conf.eth0.rp_filter=0
       $ sysctl -w net.ipv4.conf.eth1.rp_filter=0
       $ ip route add 2.1.1.0/24 dev eth1
       $ route add default gw 2.1.1.2 eth1
       $ route add default gw 90.90.90.90 eth1
       $ arp -s 90.90.90.90 DE:AD:BE:EF:CA:FE
       $ arp -s 2.1.1.2 DE:AD:BE:EF:CA:FA

   Check traffic on multiple queues::

       $ cat /proc/interrupts | grep virtio
