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

=================================
Open vSwitch with DPDK (Advanced)
=================================

The Advanced Install Guide explains how to improve OVS performance when using
DPDK datapath. This guide provides information on tuning, system configuration,
troubleshooting, static code analysis and testcases.

Building as a Shared Library
----------------------------

DPDK can be built as a static or a shared library and shall be linked by
applications using DPDK datapath. When building OVS with DPDK, you can link
Open vSwitch against the shared DPDK library.

.. note::
  Minor performance loss is seen with OVS when using shared DPDK library as
  compared to static library.

To build Open vSwitch using DPDK as a shared library, first refer to the `DPDK
installation guide`_ for download instructions for DPDK and OVS.

Once DPDK and OVS have been downloaded, you must configure the DPDK library
accordingly. Simply set ``CONFIG_RTE_BUILD_SHARED_LIB=y`` in
``config/common_base``, then build and install DPDK. Once done, DPDK can be
built as usual. For example::

    $ export DPDK_TARGET=x86_64-native-linuxapp-gcc
    $ export DPDK_BUILD=$DPDK_DIR/$DPDK_TARGET
    $ make install T=$DPDK_TARGET DESTDIR=install

Once DPDK is built, export the DPDK shared library location and setup OVS as
detailed in the `DPDK installation guide`_::

    $ export LD_LIBRARY_PATH=$DPDK_DIR/x86_64-native-linuxapp-gcc/lib

System Configuration
--------------------

To achieve optimal OVS performance, the system can be configured and that
includes BIOS tweaks, Grub cmdline additions, better understanding of NUMA
nodes and apt selection of PCIe slots for NIC placement.

Recommended BIOS Settings
~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table:: Recommended BIOS Settings
   :header-rows: 1

   * - Setting
     - Value
   * - C3 Power State
     - Disabled
   * - C6 Power State
     - Disabled
   * - MLC Streamer
     - Enabled
   * - MLC Spacial Prefetcher
     - Enabled
   * - DCU Data Prefetcher
     - Enabled
   * - DCA
     - Enabled
   * - CPU Power and Performance
     - Performance
   * - Memeory RAS and Performance Config -> NUMA optimized
     - Enabled

PCIe Slot Selection
~~~~~~~~~~~~~~~~~~~

The fastpath performance can be affected by factors related to the placement of
the NIC, such as channel speeds between PCIe slot and CPU or the proximity of
PCIe slot to the CPU cores running the DPDK application. Listed below are the
steps to identify right PCIe slot.

#. Retrieve host details using ``dmidecode``. For example::

       $ dmidecode -t baseboard | grep "Product Name"

#. Download the technical specification for product listed, e.g: S2600WT2

#. Check the Product Architecture Overview on the Riser slot placement, CPU
   sharing info and also PCIe channel speeds

   For example: On S2600WT, CPU1 and CPU2 share Riser Slot 1 with Channel speed
   between CPU1 and Riser Slot1 at 32GB/s, CPU2 and Riser Slot1 at 16GB/s.
   Running DPDK app on CPU1 cores and NIC inserted in to Riser card Slots will
   optimize OVS performance in this case.

#. Check the Riser Card #1 - Root Port mapping information, on the available
   slots and individual bus speeds. In S2600WT slot 1, slot 2 has high bus
   speeds and are potential slots for NIC placement.

Advanced Hugepage Setup
~~~~~~~~~~~~~~~~~~~~~~~

Allocate and mount 1 GB hugepages.

- For persistent allocation of huge pages, add the following options to the
  kernel bootline::

      default_hugepagesz=1GB hugepagesz=1G hugepages=N

  For platforms supporting multiple huge page sizes, add multiple options::

      default_hugepagesz=<size> hugepagesz=<size> hugepages=N

  where:

  ``N``
    number of huge pages requested
  ``size``
    huge page size with an optional suffix ``[kKmMgG]``

- For run-time allocation of huge pages::

      $ echo N > /sys/devices/system/node/nodeX/hugepages/hugepages-1048576kB/nr_hugepages

  where:

  ``N``
    number of huge pages requested
  ``X``
    NUMA Node

  .. note::
    For run-time allocation of 1G huge pages, Contiguous Memory Allocator
    (``CONFIG_CMA``) has to be supported by kernel, check your Linux distro.

Now mount the huge pages, if not already done so::

    $ mount -t hugetlbfs -o pagesize=1G none /dev/hugepages

Enable HyperThreading
~~~~~~~~~~~~~~~~~~~~~

With HyperThreading, or SMT, enabled, a physical core appears as two logical
cores. SMT can be utilized to spawn worker threads on logical cores of the same
physical core there by saving additional cores.

With DPDK, when pinning pmd threads to logical cores, care must be taken to set
the correct bits of the ``pmd-cpu-mask`` to ensure that the pmd threads are
pinned to SMT siblings.

Take a sample system configuration, with 2 sockets, 2 * 10 core processors, HT
enabled. This gives us a total of 40 logical cores. To identify the physical
core shared by two logical cores, run::

    $ cat /sys/devices/system/cpu/cpuN/topology/thread_siblings_list

where ``N`` is the logical core number.

In this example, it would show that cores ``1`` and ``21`` share the same
physical core., thus, the ``pmd-cpu-mask`` can be used to enable these two pmd
threads running on these two logical cores (one physical core) is::

    $ ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=100002

Isolate Cores
~~~~~~~~~~~~~

The ``isolcpus`` option can be used to isolate cores from the Linux scheduler.
The isolated cores can then be used to dedicatedly run HPC applications or
threads.  This helps in better application performance due to zero context
switching and minimal cache thrashing. To run platform logic on core 0 and
isolate cores between 1 and 19 from scheduler, add  ``isolcpus=1-19`` to GRUB
cmdline.

.. note::
  It has been verified that core isolation has minimal advantage due to mature
  Linux scheduler in some circumstances.

NUMA/Cluster-on-Die
~~~~~~~~~~~~~~~~~~~

Ideally inter-NUMA datapaths should be avoided where possible as packets will
go across QPI and there may be a slight performance penalty when compared with
intra NUMA datapaths. On Intel Xeon Processor E5 v3, Cluster On Die is
introduced on models that have 10 cores or more.  This makes it possible to
logically split a socket into two NUMA regions and again it is preferred where
possible to keep critical datapaths within the one cluster.

It is good practice to ensure that threads that are in the datapath are pinned
to cores in the same NUMA area. e.g. pmd threads and QEMU vCPUs responsible for
forwarding. If DPDK is built with ``CONFIG_RTE_LIBRTE_VHOST_NUMA=y``, vHost
User ports automatically detect the NUMA socket of the QEMU vCPUs and will be
serviced by a PMD from the same node provided a core on this node is enabled in
the ``pmd-cpu-mask``. ``libnuma`` packages are required for this feature.

Compiler Optimizations
~~~~~~~~~~~~~~~~~~~~~~

The default compiler optimization level is ``-O2``. Changing this to more
aggressive compiler optimization such as ``-O3 -march=native`` with
gcc (verified on 5.3.1) can produce performance gains though not siginificant.
``-march=native`` will produce optimized code on local machine and should be
used when software compilation is done on Testbed.

Performance Tuning
------------------

Affinity
~~~~~~~~

For superior performance, DPDK pmd threads and Qemu vCPU threads needs to be
affinitized accordingly.

- PMD thread Affinity

  A poll mode driver (pmd) thread handles the I/O of all DPDK interfaces
  assigned to it. A pmd thread shall poll the ports for incoming packets,
  switch the packets and send to tx port.  pmd thread is CPU bound, and needs
  to be affinitized to isolated cores for optimum performance.

  By setting a bit in the mask, a pmd thread is created and pinned to the
  corresponding CPU core. e.g. to run a pmd thread on core 2::

      $ ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=4

  .. note::
    pmd thread on a NUMA node is only created if there is at least one DPDK
    interface from that NUMA node added to OVS.

- QEMU vCPU thread Affinity

  A VM performing simple packet forwarding or running complex packet pipelines
  has to ensure that the vCPU threads performing the work has as much CPU
  occupancy as possible.

  For example, on a multicore VM, multiple QEMU vCPU threads shall be spawned.
  When the DPDK ``testpmd`` application that does packet forwarding is invoked,
  the ``taskset`` command should be used to affinitize the vCPU threads to the
  dedicated isolated cores on the host system.

Multiple Poll-Mode Driver Threads
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With pmd multi-threading support, OVS creates one pmd thread for each NUMA node
by default. However, in cases where there are multiple ports/rxq's producing
traffic, performance can be improved by creating multiple pmd threads running
on separate cores. These pmd threads can share the workload by each being
responsible for different ports/rxq's. Assignment of ports/rxq's to pmd threads
is done automatically.

A set bit in the mask means a pmd thread is created and pinned to the
corresponding CPU core. For example, to run pmd threads on core 1 and 2::

    $ ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=6

When using dpdk and dpdkvhostuser ports in a bi-directional VM loopback as
shown below, spreading the workload over 2 or 4 pmd threads shows significant
improvements as there will be more total CPU occupancy available::

    NIC port0 <-> OVS <-> VM <-> OVS <-> NIC port 1

DPDK Physical Port Rx Queues
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    $ ovs-vsctl set Interface <DPDK interface> options:n_rxq=<integer>

The command above sets the number of rx queues for DPDK physical interface.
The rx queues are assigned to pmd threads on the same NUMA node in a
round-robin fashion.

DPDK Physical Port Queue Sizes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    $ ovs-vsctl set Interface dpdk0 options:n_rxq_desc=<integer>
    $ ovs-vsctl set Interface dpdk0 options:n_txq_desc=<integer>

The command above sets the number of rx/tx descriptors that the NIC associated
with dpdk0 will be initialised with.

Different ``n_rxq_desc`` and ``n_txq_desc`` configurations yield different
benefits in terms of throughput and latency for different scenarios.
Generally, smaller queue sizes can have a positive impact for latency at the
expense of throughput. The opposite is often true for larger queue sizes.
Note: increasing the number of rx descriptors eg. to 4096  may have a negative
impact on performance due to the fact that non-vectorised DPDK rx functions may
be used. This is dependant on the driver in use, but is true for the commonly
used i40e and ixgbe DPDK drivers.

Exact Match Cache
~~~~~~~~~~~~~~~~~

Each pmd thread contains one Exact Match Cache (EMC). After initial flow setup
in the datapath, the EMC contains a single table and provides the lowest level
(fastest) switching for DPDK ports. If there is a miss in the EMC then the next
level where switching will occur is the datapath classifier.  Missing in the
EMC and looking up in the datapath classifier incurs a significant performance
penalty.  If lookup misses occur in the EMC because it is too small to handle
the number of flows, its size can be increased. The EMC size can be modified by
editing the define ``EM_FLOW_HASH_SHIFT`` in ``lib/dpif-netdev.c``.

As mentioned above, an EMC is per pmd thread. An alternative way of increasing
the aggregate amount of possible flow entries in EMC and avoiding datapath
classifier lookups is to have multiple pmd threads running.

Rx Mergeable Buffers
~~~~~~~~~~~~~~~~~~~~

Rx mergeable buffers is a virtio feature that allows chaining of multiple
virtio descriptors to handle large packet sizes. Large packets are handled by
reserving and chaining multiple free descriptors together. Mergeable buffer
support is negotiated between the virtio driver and virtio device and is
supported by the DPDK vhost library.  This behavior is supported and enabled by
default, however in the case where the user knows that rx mergeable buffers are
not needed i.e. jumbo frames are not needed, it can be forced off by adding
``mrg_rxbuf=off`` to the QEMU command line options. By not reserving multiple
chains of descriptors it will make more individual virtio descriptors available
for rx to the guest using dpdkvhost ports and this can improve performance.

OVS Testcases
-------------

PHY-VM-PHY (vHost Loopback)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The `DPDK installation guide`_ details steps for PHY-VM-PHY loopback testcase
and packet forwarding using DPDK testpmd application in the Guest VM. For users
wishing to do packet forwarding using kernel stack below, you need to run the
below commands on the guest::

    $ ifconfig eth1 1.1.1.2/24
    $ ifconfig eth2 1.1.2.2/24
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

PHY-VM-PHY (IVSHMEM)
~~~~~~~~~~~~~~~~~~~~

IVSHMEM can also be validated using the PHY-VM-PHY configuration. To begin,
follow the steps described in the `DPDK installation guide`_ to create and
initialize the database, start ovs-vswitchd and add ``dpdk``-type devices to
bridge ``br0``. Once complete, follow the below steps:

1. Add DPDK ring port to the bridge::

       $ ovs-vsctl add-port br0 dpdkr0 -- set Interface dpdkr0 type=dpdkr

2. Build modified QEMU

   QEMU must be patched to enable IVSHMEM support::

       $ cd /usr/src/
       $ wget http://wiki.qemu.org/download/qemu-2.2.1.tar.bz2
       $ tar -jxvf qemu-2.2.1.tar.bz2
       $ cd /usr/src/qemu-2.2.1
       $ wget https://raw.githubusercontent.com/netgroup-polito/un-orchestrator/master/orchestrator/compute_controller/plugins/kvm-libvirt/patches/ivshmem-qemu-2.2.1.patch
       $ patch -p1 < ivshmem-qemu-2.2.1.patch
       $ ./configure --target-list=x86_64-softmmu --enable-debug --extra-cflags='-g'
       $ make -j 4

3. Generate QEMU commandline::

       $ mkdir -p /usr/src/cmdline_generator
       $ cd /usr/src/cmdline_generator
       $ wget https://raw.githubusercontent.com/netgroup-polito/un-orchestrator/master/orchestrator/compute_controller/plugins/kvm-libvirt/cmdline_generator/cmdline_generator.c
       $ wget https://raw.githubusercontent.com/netgroup-polito/un-orchestrator/master/orchestrator/compute_controller/plugins/kvm-libvirt/cmdline_generator/Makefile
       $ export RTE_SDK=/usr/src/dpdk-16.11
       $ export RTE_TARGET=x86_64-ivshmem-linuxapp-gcc
       $ make
       $ ./build/cmdline_generator -m -p dpdkr0 XXX
       $ cmdline=`cat OVSMEMPOOL`

4. Start guest VM::

       $ export VM_NAME=ivshmem-vm
       $ export QCOW2_IMAGE=/root/CentOS7_x86_64.qcow2
       $ export QEMU_BIN=/usr/src/qemu-2.2.1/x86_64-softmmu/qemu-system-x86_64
       $ taskset 0x20 $QEMU_BIN -cpu host -smp 2,cores=2 -hda $QCOW2_IMAGE \
           -m 4096 --enable-kvm -name $VM_NAME -nographic -vnc :2 \
           -pidfile /tmp/vm1.pid $cmdline

5. Build and run the sample ``dpdkr`` app in VM::

       $ echo 1024 > /proc/sys/vm/nr_hugepages
       $ mount -t hugetlbfs nodev /dev/hugepages (if not already mounted)

       # Build the DPDK ring application in the VM
       $ export RTE_SDK=/root/dpdk-16.11
       $ export RTE_TARGET=x86_64-ivshmem-linuxapp-gcc
       $ make

       # Run dpdkring application
       $ ./build/dpdkr -c 1 -n 4 -- -n 0
       # where "-n 0" refers to ring '0' i.e dpdkr0

PHY-VM-PHY (vHost Multiqueue)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

vHost Multique functionality can also be validated using the PHY-VM-PHY
configuration. To begin, follow the steps described in the `DPDK installation
guide`_ to create and initialize the database, start ovs-vswitchd and add
``dpdk``-type devices to bridge ``br0``. Once complete, follow the below steps:

1. Configure PMD and RXQs.

   For example, set the number of dpdk port rx queues to at least 2  The number
   of rx queues at vhost-user interface gets automatically configured after
   virtio device connection and doesn't need manual configuration::

       $ ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=c
       $ ovs-vsctl set Interface dpdk0 options:n_rxq=2
       $ ovs-vsctl set Interface dpdk1 options:n_rxq=2

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

       $ ifconfig eth0 5.5.5.1/24 up
       $ ifconfig eth1 90.90.90.1/24 up

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

vHost Walkthrough
-----------------

Two types of vHost User ports are available in OVS:

- vhost-user (``dpdkvhostuser``)

- vhost-user-client (``dpdkvhostuserclient``)

vHost User uses a client-server model. The server creates/manages/destroys the
vHost User sockets, and the client connects to the server. Depending on which
port type you use, ``dpdkvhostuser`` or ``dpdkvhostuserclient``, a different
configuration of the client-server model is used.

For vhost-user ports, Open vSwitch acts as the server and QEMU the client.  For
vhost-user-client ports, Open vSwitch acts as the client and QEMU the server.

vhost-user
~~~~~~~~~~

1. Install the prerequisites:

   - QEMU version >= 2.2

2. Add vhost-user ports to the switch.

   Unlike DPDK ring ports, DPDK vhost-user ports can have arbitrary names,
   except that forward and backward slashes are prohibited in the names.

   For vhost-user, the name of the port type is ``dpdkvhostuser``::

       $ ovs-vsctl add-port br0 vhost-user-1 -- set Interface vhost-user-1 \
           type=dpdkvhostuser

   This action creates a socket located at
   ``/usr/local/var/run/openvswitch/vhost-user-1``, which you must provide to
   your VM on the QEMU command line. More instructions on this can be found in
   the next section "Adding vhost-user ports to VM"

   .. note::
     If you wish for the vhost-user sockets to be created in a sub-directory of
     ``/usr/local/var/run/openvswitch``, you may specify this directory in the
     ovsdb like so::

         $ ovs-vsctl --no-wait \
             set Open_vSwitch . other_config:vhost-sock-dir=subdir`

3. Add vhost-user ports to VM

   1. Configure sockets

      Pass the following parameters to QEMU to attach a vhost-user device::

          -chardev socket,id=char1,path=/usr/local/var/run/openvswitch/vhost-user-1
          -netdev type=vhost-user,id=mynet1,chardev=char1,vhostforce
          -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1

      where ``vhost-user-1`` is the name of the vhost-user port added to the
      switch.

      Repeat the above parameters for multiple devices, changing the chardev
      ``path`` and ``id`` as necessary. Note that a separate and different
      chardev ``path`` needs to be specified for each vhost-user device. For
      example you have a second vhost-user port named ``vhost-user-2``, you
      append your QEMU command line with an additional set of parameters::

          -chardev socket,id=char2,path=/usr/local/var/run/openvswitch/vhost-user-2
          -netdev type=vhost-user,id=mynet2,chardev=char2,vhostforce
          -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2

    2. Configure hugepages

       QEMU must allocate the VM's memory on hugetlbfs. vhost-user ports access
       a virtio-net device's virtual rings and packet buffers mapping the VM's
       physical memory on hugetlbfs. To enable vhost-user ports to map the VM's
       memory into their process address space, pass the following parameters
       to QEMU::

           -object memory-backend-file,id=mem,size=4096M,mem-path=/dev/hugepages,share=on
           -numa node,memdev=mem -mem-prealloc

    3. Enable multiqueue support (optional)

       QEMU needs to be configured to use multiqueue::

           -chardev socket,id=char2,path=/usr/local/var/run/openvswitch/vhost-user-2
           -netdev type=vhost-user,id=mynet2,chardev=char2,vhostforce,queues=$q
           -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2,mq=on,vectors=$v

       where:

       ``$q``
         The number of queues
       ``$v``
         The number of vectors, which is ``$q`` * 2 + 2

       The vhost-user interface will be automatically reconfigured with
       required number of rx and tx queues after connection of virtio device.
       Manual configuration of ``n_rxq`` is not supported because OVS will work
       properly only if ``n_rxq`` will match number of queues configured in
       QEMU.

       A least 2 PMDs should be configured for the vswitch when using
       multiqueue.  Using a single PMD will cause traffic to be enqueued to the
       same vhost queue rather than being distributed among different vhost
       queues for a vhost-user interface.

       If traffic destined for a VM configured with multiqueue arrives to the
       vswitch via a physical DPDK port, then the number of rxqs should also be
       set to at least 2 for that physical DPDK port. This is required to
       increase the probability that a different PMD will handle the multiqueue
       transmission to the guest using a different vhost queue.

       If one wishes to use multiple queues for an interface in the guest, the
       driver in the guest operating system must be configured to do so. It is
       recommended that the number of queues configured be equal to ``$q``.

       For example, this can be done for the Linux kernel virtio-net driver
       with::

           $ ethtool -L <DEV> combined <$q>

       where:

       ``-L``
         Changes the numbers of channels of the specified network device
       ``combined``
         Changes the number of multi-purpose channels.

Configure the VM using libvirt
++++++++++++++++++++++++++++++

You can also build and configure the VM using libvirt rather than QEMU by
itself.

1. Change the user/group, access control policty and restart libvirtd.

   - In ``/etc/libvirt/qemu.conf`` add/edit the following lines::

         user = "root"
         group = "root"

   - Disable SELinux or set to permissive mode::

         $ setenforce 0

   - Restart the libvirtd process, For example, on Fedora::

         $ systemctl restart libvirtd.service

2. Instantiate the VM

   - Copy the XML configuration described in the `DPDK installation guide`_.

   - Start the VM::

         $ virsh create demovm.xml

   - Connect to the guest console::

         $ virsh console demovm

3. Configure the VM

   The demovm xml configuration is aimed at achieving out of box performance on
   VM.

   - The vcpus are pinned to the cores of the CPU socket 0 using ``vcpupin``.

   - Configure NUMA cell and memory shared using ``memAccess='shared'``.

   - Disable ``mrg_rxbuf='off'``

Refer to the `libvirt documentation <http://libvirt.org/formatdomain.html>`__
for more information.

vhost-user-client
~~~~~~~~~~~~~~~~~

1. Install the prerequisites:

   - QEMU version >= 2.7

2. Add vhost-user-client ports to the switch.

   Unlike vhost-user ports, the name given to port does not govern the name of
   the socket device. ``vhost-server-path`` reflects the full path of the
   socket that has been or will be created by QEMU for the given vHost User
   client port.

   For vhost-user-client, the name of the port type is
   ``dpdkvhostuserclient``::

       $ VHOST_USER_SOCKET_PATH=/path/to/socker
       $ ovs-vsctl add-port br0 vhost-client-1 \
           -- set Interface vhost-client-1 type=dpdkvhostuserclient \
                options:vhost-server-path=$VHOST_USER_SOCKET_PATH

3. Add vhost-user-client ports to VM

   1. Configure sockets

      Pass the following parameters to QEMU to attach a vhost-user device::

          -chardev socket,id=char1,path=$VHOST_USER_SOCKET_PATH,server
          -netdev type=vhost-user,id=mynet1,chardev=char1,vhostforce
          -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1

      where ``vhost-user-1`` is the name of the vhost-user port added to the
      switch.

      If the corresponding dpdkvhostuserclient port has not yet been configured
      in OVS with ``vhost-server-path=/path/to/socket``, QEMU will print a log
      similar to the following::

          QEMU waiting for connection on: disconnected:unix:/path/to/socket,server

      QEMU will wait until the port is created sucessfully in OVS to boot the VM.

      One benefit of using this mode is the ability for vHost ports to
      'reconnect' in event of the switch crashing or being brought down. Once
      it is brought back up, the vHost ports will reconnect automatically and
      normal service will resume.

DPDK Backend Inside VM
~~~~~~~~~~~~~~~~~~~~~~

Additional configuration is required if you want to run ovs-vswitchd with DPDK
backend inside a QEMU virtual machine. Ovs-vswitchd creates separate DPDK TX
queues for each CPU core available. This operation fails inside QEMU virtual
machine because, by default, VirtIO NIC provided to the guest is configured to
support only single TX queue and single RX queue. To change this behavior, you
need to turn on ``mq`` (multiqueue) property of all ``virtio-net-pci`` devices
emulated by QEMU and used by DPDK.  You may do it manually (by changing QEMU
command line) or, if you use Libvirt, by adding the following string to
``<interface>`` sections of all network devices used by DPDK::

    <driver name='vhost' queues='N'/>

Where:

``N``
  determines how many queues can be used by the guest.

This requires QEMU >= 2.2.

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

Here is an example on Ingress Policing usage.  Assuming you have a vhost-user
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

Flow control can be enabled only on DPDK physical ports.  To enable flow
control support at tx side while adding a port, run::

    $ ovs-vsctl add-port br0 dpdk0 -- \
        set Interface dpdk0 type=dpdk options:tx-flow-ctrl=true

Similarly, to enable rx flow control, run::

    $ ovs-vsctl add-port br0 dpdk0 -- \
        set Interface dpdk0 type=dpdk options:rx-flow-ctrl=true

To enable flow control auto-negotiation, run::

    $ ovs-vsctl add-port br0 dpdk0 -- \
        set Interface dpdk0 type=dpdk options:flow-ctrl-autoneg=true

To turn ON the tx flow control at run time(After the port is being added to
OVS)::

    $ ovs-vsctl set Interface dpdk0 options:tx-flow-ctrl=true

The flow control parameters can be turned off by setting ``false`` to the
respective parameter. To disable the flow control at tx side, run::

    $ ovs-vsctl set Interface dpdk0 options:tx-flow-ctrl=false

pdump
-----

Pdump allows you to listen on DPDK ports and view the traffic that is passing
on them. To use this utility, one must have libpcap installed on the system.
Furthermore, DPDK must be built with ``CONFIG_RTE_LIBRTE_PDUMP=y`` and
``CONFIG_RTE_LIBRTE_PMD_PCAP=y``.

.. warning::
  A performance decrease is expected when using a monitoring application like
  the DPDK pdump app.

To use pdump, simply launch OVS as usual. Then, navigate to the ``app/pdump``
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

``server-socket-path`` must be set to the value of ovs_rundir() which typically
resolves to ``/usr/local/var/run/openvswitch``.

Many tools are available to view the contents of the pcap file. Once example is
tcpdump. Issue the following command to view the contents of ``pkts.pcap``::

    $ tcpdump -r pkts.pcap

More information on the pdump app and its usage can be found in the `DPDK docs
<http://dpdk.org/doc/guides/sample_app_ug/pdump.html>`__.

Jumbo Frames
------------

By default, DPDK ports are configured with standard Ethernet MTU (1500B). To
enable Jumbo Frames support for a DPDK port, change the Interface's
``mtu_request`` attribute to a sufficiently large value. For example, to add a
DPDK Phy port with MTU of 9000::

    $ ovs-vsctl add-port br0 dpdk0 \
      -- set Interface dpdk0 type=dpdk \
      -- set Interface dpdk0 mtu_request=9000`

Similarly, to change the MTU of an existing port to 6200::

    $ ovs-vsctl set Interface dpdk0 mtu_request=6200

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

       $ ifconfig eth1 mtu 9000

When Jumbo Frames are enabled, the size of a DPDK port's mbuf segments are
increased, such that a full Jumbo Frame of a specific size may be accommodated
within a single mbuf segment.

Jumbo frame support has been validated against 9728B frames, which is the
largest frame size supported by Fortville NIC using the DPDK i40e driver, but
larger frames and other DPDK NIC drivers may be supported. These cases are
common for use cases involving East-West traffic only.

vsperf
------

The vsperf project aims to develop a vSwitch test framework that can be used to
validate the suitability of different vSwitch implementations in a telco
deployment environment. More information can be found on the `OPNFV wiki
<https://wiki.opnfv.org/display/vsperf/VSperf+Home>`__.

Bug Reporting
-------------

Report problems to bugs@openvswitch.org.

.. _DPDK installation guide: INSTALL.DPDK.rst
