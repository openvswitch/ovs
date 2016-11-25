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

======================
Open vSwitch with DPDK
======================

This document describes how to build and install Open vSwitch using a DPDK
datapath. Open vSwitch can use the DPDK library to operate entirely in
userspace.

.. warning::
  The DPDK support of Open vSwitch is considered 'experimental'.

Build requirements
------------------

In addition to the requirements described in the `installation guide
<INSTALL.rst>`__, building Open vSwitch with DPDK will require the following:

- DPDK 16.11

- A `DPDK supported NIC`_

  Only required when physical ports are in use

- A suitable kernel

  On Linux Distros running kernel version >= 3.0, only `IOMMU` needs to enabled
  via the grub cmdline, assuming you are using **VFIO**. For older kernels,
  ensure the kernel is built with ``UIO``, ``HUGETLBFS``,
  ``PROC_PAGE_MONITOR``, ``HPET``, ``HPET_MMAP`` support. If these are not
  present, it will be necessary to upgrade your kernel or build a custom kernel
  with these flags enabled.

Detailed system requirements can be found at `DPDK requirements`_, while more
detailed install information can be found in the `advanced installation guide
<INSTALL.DPDK-ADVANCED.rst>`__.

.. _DPDK supported NIC: http://dpdk.org/doc/nics
.. _DPDK requirements: http://dpdk.org/doc/guides/linux_gsg/sys_reqs.html

Installing
----------

DPDK
~~~~

1. Download the `DPDK sources`_, extract the file and set ``DPDK_DIR``::

       $ cd /usr/src/
       $ wget http://dpdk.org/browse/dpdk/snapshot/dpdk-16.11.zip
       $ unzip dpdk-16.11.zip
       $ export DPDK_DIR=/usr/src/dpdk-16.11
       $ cd $DPDK_DIR

2. Configure and install DPDK

   Build and install the DPDK library::

       $ export DPDK_TARGET=x86_64-native-linuxapp-gcc
       $ export DPDK_BUILD=$DPDK_DIR/$DPDK_TARGET
       $ make install T=$DPDK_TARGET DESTDIR=install

   If IVSHMEM support is required, use a different target::

       $ export DPDK_TARGET=x86_64-ivshmem-linuxapp-gcc

.. _DPDK sources: http://dpdk.org/browse/dpdk/refs/

Install OVS
~~~~~~~~~~~

OVS can be installed using different methods. For OVS to use DPDK datapath, it
has to be configured with DPDK support (``--with-dpdk``).

.. note::
  This section focuses on generic recipe that suits most cases. For
  distribution specific instructions, refer to one of the more relevant guides.

.. _OVS sources: http://openvswitch.org/releases/

1. Ensure the standard OVS requirements, described in the `installation guide
   <INSTALL.rst>`__, are installed.

2. Bootstrap, if required, as described in the `installation guide
   <INSTALL.rst>`__.

3. Configure the package using the ``--with-dpdk`` flag::

       $ ./configure --with-dpdk=$DPDK_BUILD

   where ``DPDK_BUILD`` is the path to the built DPDK library. This can be
   skipped if DPDK library is installed in its default location.

   .. note::
     While ``--with-dpdk`` is required, you can pass any other configuration
     option described in the `installation guide <INSTALL.rst>`__.

4. Build and install OVS, as described in the `installation guide
   <INSTALL.rst>`__.

Additional information can be found in the `installation guide
<INSTALL.rst>`__.

Setup
-----

Setup Hugepages
~~~~~~~~~~~~~~~

Allocate a number of 2M Huge pages:

-  For persistent allocation of huge pages, write to hugepages.conf file
   in `/etc/sysctl.d`::

       $ echo 'vm.nr_hugepages=2048' > /etc/sysctl.d/hugepages.conf

-  For run-time allocation of huge pages, use the ``sysctl`` utility::

       $ sysctl -w vm.nr_hugepages=N  # where N = No. of 2M huge pages

To verify hugepage configuration::

    $ grep HugePages_ /proc/meminfo

Mount the hugepages, if not already mounted by default::

    $ mount -t hugetlbfs none /dev/hugepages``

.. _dpdk-vfio:

Setup DPDK devices using VFIO
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

VFIO is prefered to the UIO driver when using recent versions of DPDK. VFIO
support required support from both the kernel and BIOS. For the former, kernel
version > 3.6 must be used. For the latter, you must enable VT-d in the BIOS
and ensure this is configured via grub. To ensure VT-d is enabled via the BIOS,
run::

    $ dmesg | grep -e DMAR -e IOMMU

If VT-d is not enabled in the BIOS, enable it now.

To ensure VT-d is enabled in the kernel, run::

    $ cat /proc/cmdline | grep iommu=pt
    $ cat /proc/cmdline | grep intel_iommu=on

If VT-d is not enabled in the kernel, enable it now.

Once VT-d is correctly configured, load the required modules and bind the NIC
to the VFIO driver::

    $ modprobe vfio-pci
    $ /usr/bin/chmod a+x /dev/vfio
    $ /usr/bin/chmod 0666 /dev/vfio/*
    $ $DPDK_DIR/tools/dpdk-devbind.py --bind=vfio-pci eth1
    $ $DPDK_DIR/tools/dpdk-devbind.py --status

Setup OVS
~~~~~~~~~

Open vSwitch should be started as described in the `installation guide
<INSTALL.rst>`__ with the exception of ovs-vswitchd, which requires some
special configuration to enable DPDK functionality. DPDK configuration
arguments can be passed to ovs-vswitchd via the ``other_config`` column of the
``Open_vSwitch`` table. At a minimum, the ``dpdk-init`` option must be set to
``true``. For example::

    $ export DB_SOCK=/usr/local/var/run/openvswitch/db.sock
    $ ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-init=true
    $ ovs-vswitchd unix:$DB_SOCK --pidfile --detach

There are many other configuration options, the most important of which are
listed below. Defaults will be provided for all values not explicitly set.

``dpdk-init``
  Specifies whether OVS should initialize and support DPDK ports. This is a
  boolean, and defaults to false.

``dpdk-lcore-mask``
  Specifies the CPU cores on which dpdk lcore threads should be spawned and
  expects hex string (eg '0x123').

``dpdk-socket-mem``
  Comma separated list of memory to pre-allocate from hugepages on specific
  sockets.

``dpdk-hugepage-dir``
  Directory where hugetlbfs is mounted

``vhost-sock-dir``
  Option to set the path to the vhost-user unix socket files.

If allocating more than one GB hugepage (as for IVSHMEM), you can configure the
amount of memory used from any given NUMA nodes. For example, to use 1GB from
NUMA node 0, run::

    $ ovs-vsctl --no-wait set Open_vSwitch . \
        other_config:dpdk-socket-mem="1024,0"

Similarly, if you wish to better scale the workloads across cores, then
multiple pmd threads can be created and pinned to CPU cores by explicity
specifying ``pmd-cpu-mask``. For example, to spawn two pmd threads and pin
them to cores 1,2, run::

    $ ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=6

For details on using ivshmem with DPDK, refer to `the advanced installation
guide <INSTALL.DPDK-ADVANCED.rst>`__.

Refer to ovs-vswitchd.conf.db(5) for additional information on configuration
options.

.. note::
  Changing any of these options requires restarting the ovs-vswitchd
  application

Validating
----------

Creating bridges and ports
~~~~~~~~~~~~~~~~~~~~~~~~~~

You can now use ovs-vsctl to set up bridges and other Open vSwitch features.
Bridges should be created with a ``datapath_type=netdev``::

    $ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

Now you can add DPDK devices. OVS expects DPDK device names to start with
``dpdk`` and end with a portid. ovs-vswitchd should print the number of dpdk
devices found in the log file::

    $ ovs-vsctl add-port br0 dpdk0 -- set Interface dpdk0 type=dpdk
    $ ovs-vsctl add-port br0 dpdk1 -- set Interface dpdk1 type=dpdk

After the DPDK ports get added to switch, a polling thread continuously polls
DPDK devices and consumes 100% of the core, as can be checked from 'top' and
'ps' cmds::

    $ top -H
    $ ps -eLo pid,psr,comm | grep pmd

Creating bonds of DPDK interfaces is slightly different to creating bonds of
system interfaces. For DPDK, the interface type must be explicitly set. For
example::

    $ ovs-vsctl add-bond br0 dpdkbond dpdk0 dpdk1 \
        -- set Interface dpdk0 type=dpdk \
        -- set Interface dpdk1 type=dpdk

To stop ovs-vswitchd & delete bridge, run::

    $ ovs-appctl -t ovs-vswitchd exit
    $ ovs-appctl -t ovsdb-server exit
    $ ovs-vsctl del-br br0

PMD thread statistics
~~~~~~~~~~~~~~~~~~~~~

To show current stats::

    $ ovs-appctl dpif-netdev/pmd-stats-show

To clear previous stats::

    $ ovs-appctl dpif-netdev/pmd-stats-clear

Port/rxq assigment to PMD threads
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To show port/rxq assignment::

    $ ovs-appctl dpif-netdev/pmd-rxq-show

To change default rxq assignment to pmd threads, rxqs may be manually pinned to
desired cores using::

    $ ovs-vsctl set Interface <iface> \
        other_config:pmd-rxq-affinity=<rxq-affinity-list>

where:

- ``<rxq-affinity-list>`` ::= ``NULL`` | ``<non-empty-list>``
- ``<non-empty-list>`` ::= ``<affinity-pair>`` |
                           ``<affinity-pair>`` , ``<non-empty-list>``
- ``<affinity-pair>`` ::= ``<queue-id>`` : ``<core-id>``

For example::

    $ ovs-vsctl set interface dpdk0 options:n_rxq=4 \
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

.. _dpdk-guest-setup:

DPDK in the VM
--------------

DPDK 'testpmd' application can be run in the Guest VM for high speed packet
forwarding between vhostuser ports. DPDK and testpmd application has to be
compiled on the guest VM. Below are the steps for setting up the testpmd
application in the VM. More information on the vhostuser ports can be found in
the `advanced install guide <INSTALL.DPDK-ADVANCED.rst>`__.

.. note::
  Support for DPDK in the guest requires QEMU >= 2.2.0.

To being, instantiate the guest::

    $ export VM_NAME=Centos-vm export GUEST_MEM=3072M
    $ export QCOW2_IMAGE=/root/CentOS7_x86_64.qcow2
    $ export VHOST_SOCK_DIR=/usr/local/var/run/openvswitch

    $ qemu-system-x86_64 -name $VM_NAME -cpu host -enable-kvm \
        -m $GUEST_MEM -drive file=$QCOW2_IMAGE --nographic -snapshot \
        -numa node,memdev=mem -mem-prealloc -smp sockets=1,cores=2 \
        -object memory-backend-file,id=mem,size=$GUEST_MEM,mem-path=/dev/hugepages,share=on \
        -chardev socket,id=char0,path=$VHOST_SOCK_DIR/dpdkvhostuser0 \
        -netdev type=vhost-user,id=mynet1,chardev=char0,vhostforce \
        -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,mrg_rxbuf=off \
        -chardev socket,id=char1,path=$VHOST_SOCK_DIR/dpdkvhostuser1 \
        -netdev type=vhost-user,id=mynet2,chardev=char1,vhostforce \
        -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2,mrg_rxbuf=off \

Download the DPDK sourcs to VM and build DPDK::

    $ cd /root/dpdk/
    $ wget http://dpdk.org/browse/dpdk/snapshot/dpdk-16.11.zip
    $ unzip dpdk-16.11.zip
    $ export DPDK_DIR=/root/dpdk/dpdk-16.11
    $ export DPDK_TARGET=x86_64-native-linuxapp-gcc
    $ export DPDK_BUILD=$DPDK_DIR/$DPDK_TARGET
    $ cd $DPDK_DIR
    $ make install T=$DPDK_TARGET DESTDIR=install

Build the test-pmd application::

    $ cd app/test-pmd
    $ export RTE_SDK=$DPDK_DIR
    $ export RTE_TARGET=$DPDK_TARGET
    $ make

Setup huge pages and DPDK devices using UIO::

    $ sysctl vm.nr_hugepages=1024
    $ mkdir -p /dev/hugepages
    $ mount -t hugetlbfs hugetlbfs /dev/hugepages  # only if not already mounted
    $ modprobe uio
    $ insmod $DPDK_BUILD/kmod/igb_uio.ko
    $ $DPDK_DIR/tools/dpdk-devbind.py --status
    $ $DPDK_DIR/tools/dpdk-devbind.py -b igb_uio 00:03.0 00:04.0

.. note::

  vhost ports pci ids can be retrieved using::

      lspci | grep Ethernet

Testing
-------

Below are few testcases and the list of steps to be followed. Before beginning,
ensure a userspace bridge has been created and two DPDK ports added::

    $ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev
    $ ovs-vsctl add-port br0 dpdk0 -- set Interface dpdk0 type=dpdk
    $ ovs-vsctl add-port br0 dpdk1 -- set Interface dpdk1 type=dpdk

PHY-PHY
~~~~~~~

Add test flows to forward packets betwen DPDK port 0 and port 1::

    # Clear current flows
    $ ovs-ofctl del-flows br0

    # Add flows between port 1 (dpdk0) to port 2 (dpdk1)
    $ ovs-ofctl add-flow br0 in_port=1,action=output:2
    $ ovs-ofctl add-flow br0 in_port=2,action=output:1

Transmit traffic into either port. You should see it returned via the other.

PHY-VM-PHY (vhost loopback)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add two ``dpdkvhostuser`` ports to bridge ``br0``::

    $ ovs-vsctl add-port br0 dpdkvhostuser0 \
        -- set Interface dpdkvhostuser0 type=dpdkvhostuser
    $ ovs-vsctl add-port br0 dpdkvhostuser1 \
        -- set Interface dpdkvhostuser1 type=dpdkvhostuser

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

You can do this directly with QEMU via the ``qemu-system-x86_64``
application::

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

Alternatively, you can configure the guest using libvirt. Below is an XML
configuration for a 'demovm' guest that can be instantiated using `virsh`::

    <domain type='kvm'>
      <name>demovm</name>
      <uuid>4a9b3f53-fa2a-47f3-a757-dd87720d9d1d</uuid>
      <memory unit='KiB'>4194304</memory>
      <currentMemory unit='KiB'>4194304</currentMemory>
      <memoryBacking>
        <hugepages>
          <page size='2' unit='M' nodeset='0'/>
        </hugepages>
      </memoryBacking>
      <vcpu placement='static'>2</vcpu>
      <cputune>
        <shares>4096</shares>
        <vcpupin vcpu='0' cpuset='4'/>
        <vcpupin vcpu='1' cpuset='5'/>
        <emulatorpin cpuset='4,5'/>
      </cputune>
      <os>
        <type arch='x86_64' machine='pc'>hvm</type>
        <boot dev='hd'/>
      </os>
      <features>
        <acpi/>
        <apic/>
      </features>
      <cpu mode='host-model'>
        <model fallback='allow'/>
        <topology sockets='2' cores='1' threads='1'/>
        <numa>
          <cell id='0' cpus='0-1' memory='4194304' unit='KiB' memAccess='shared'/>
        </numa>
      </cpu>
      <on_poweroff>destroy</on_poweroff>
      <on_reboot>restart</on_reboot>
      <on_crash>destroy</on_crash>
      <devices>
        <emulator>/usr/bin/qemu-kvm</emulator>
        <disk type='file' device='disk'>
          <driver name='qemu' type='qcow2' cache='none'/>
          <source file='/root/CentOS7_x86_64.qcow2'/>
          <target dev='vda' bus='virtio'/>
        </disk>
        <disk type='dir' device='disk'>
          <driver name='qemu' type='fat'/>
          <source dir='/usr/src/dpdk-16.11'/>
          <target dev='vdb' bus='virtio'/>
          <readonly/>
        </disk>
        <interface type='vhostuser'>
          <mac address='00:00:00:00:00:01'/>
          <source type='unix' path='/usr/local/var/run/openvswitch/dpdkvhostuser0' mode='client'/>
           <model type='virtio'/>
          <driver queues='2'>
            <host mrg_rxbuf='off'/>
          </driver>
        </interface>
        <interface type='vhostuser'>
          <mac address='00:00:00:00:00:02'/>
          <source type='unix' path='/usr/local/var/run/openvswitch/dpdkvhostuser1' mode='client'/>
          <model type='virtio'/>
          <driver queues='2'>
            <host mrg_rxbuf='off'/>
          </driver>
        </interface>
        <serial type='pty'>
          <target port='0'/>
        </serial>
        <console type='pty'>
          <target type='serial' port='0'/>
        </console>
      </devices>
    </domain>

Once the guest is configured and booted, configure DPDK packet forwarding
within the guest. To accomplish this, DPDK and testpmd application have to
be first compiled on the VM as described in **Guest Setup**. Once compiled, run
the ``test-pmd`` application::

    $ cd $DPDK_DIR/app/test-pmd;
    $ ./testpmd -c 0x3 -n 4 --socket-mem 1024 -- \
        --burst=64 -i --txqflags=0xf00 --disable-hw-vlan
    $ set fwd mac retry
    $ start

When you finish testing, bind the vNICs back to kernel::

    $ $DPDK_DIR/tools/dpdk-devbind.py --bind=virtio-pci 0000:00:03.0
    $ $DPDK_DIR/tools/dpdk-devbind.py --bind=virtio-pci 0000:00:04.0

.. note::
  Appropriate PCI IDs to be passed in above example. The PCI IDs can be
  retrieved like so::

      $ $DPDK_DIR/tools/dpdk-devbind.py --status

.. note::
  More information on the dpdkvhostuser ports can be found in the `advanced
  installation guide <INSTALL.DPDK-ADVANCED.rst>`__.

PHY-VM-PHY (IVSHMEM loopback)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Refer to the `advanced installation guide <INSTALL.DPDK-ADVANCED.rst>`__.

Limitations
------------

- Currently DPDK ports does not use HW offload functionality.
- Network Interface Firmware requirements: Each release of DPDK is
  validated against a specific firmware version for a supported Network
  Interface. New firmware versions introduce bug fixes, performance
  improvements and new functionality that DPDK leverages. The validated
  firmware versions are available as part of the release notes for
  DPDK. It is recommended that users update Network Interface firmware
  to match what has been validated for the DPDK release.

  The latest list of validated firmware versions can be found in the `DPDK
  release notes`_.

.. _DPDK release notes: http://dpdk.org/doc/guides/rel_notes/release_16_11.html

Bug Reporting
-------------

Please report problems to bugs@openvswitch.org.
