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

   Using the DPDK datapath requires building OVS with DPDK support. The
   mapping of OVS version to DPDK can vary between releases. For version
   mapping information refer to :doc:`releases FAQ </faq/releases>`. For
   build instructions refer to :doc:`/intro/install/dpdk`.

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

Some NICs (i.e. Mellanox ConnectX-3) have only one PCI address associated with
multiple ports. Using a PCI device like above won't work. Instead, below usage
is suggested::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
        options:dpdk-devargs="class=eth,mac=00:11:22:33:44:55"
    $ ovs-vsctl add-port br0 dpdk-p1 -- set Interface dpdk-p1 type=dpdk \
        options:dpdk-devargs="class=eth,mac=00:11:22:33:44:56"

.. important::

    Hotplugging physical interfaces is not supported using the above syntax.
    This is expected to change with the release of DPDK v18.05. For information
    on hotplugging physical interfaces, you should instead refer to
    :ref:`port-hotplug`.

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

Add test flows to forward packets between DPDK port 0 and port 1::

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

Add test flows to forward packets between DPDK devices and VM ports::

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

.. table::

    ===================== ======== ============
        Configuration      Values    Comments
    ===================== ======== ============
    QEMU version          2.2.0    n/a
    QEMU thread affinity  core 5   taskset 0x20
    Memory                4GB      n/a
    Cores                 2        n/a
    Qcow2 image           CentOS7  n/a
    mrg_rxbuf             off      n/a
    ===================== ======== ============

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

.. _dpdk-flow-hardware-offload:

Flow Hardware Offload (Experimental)
------------------------------------

The flow hardware offload is disabled by default and can be enabled by::

    $ ovs-vsctl set Open_vSwitch . other_config:hw-offload=true

So far only partial flow offload is implemented. Moreover, it only works
with PMD drivers have the rte_flow action "MARK + RSS" support.

The validated NICs are:

- Mellanox (ConnectX-4, ConnectX-4 Lx, ConnectX-5)
- Napatech (NT200B01)

Supported protocols for hardware offload are:
- L2: Ethernet, VLAN
- L3: IPv4, IPv6
- L4: TCP, UDP, SCTP, ICMP

Further Reading
---------------

More detailed information can be found in the :doc:`DPDK topics section
</topics/dpdk/index>` of the documentation. These guides are listed below.

.. NOTE(stephenfin): Remember to keep this in sync with topics/dpdk/index

.. include:: ../topics/dpdk/index.rst
   :start-line: 30
