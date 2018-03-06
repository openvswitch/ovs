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

=====================
DPDK vHost User Ports
=====================

The DPDK datapath provides DPDK-backed vHost user ports as a primary way to
interact with guests. For more information on vHost User, refer to the `QEMU
documentation`_ on same.

Quick Example
-------------

This example demonstrates how to add two ``dpdkvhostuserclient`` ports to an
existing bridge called ``br0``::

    $ ovs-vsctl add-port br0 dpdkvhostclient0 \
        -- set Interface dpdkvhostclient0 type=dpdkvhostuserclient \
           options:vhost-server-path=/tmp/dpdkvhostclient0
    $ ovs-vsctl add-port br0 dpdkvhostclient1 \
        -- set Interface dpdkvhostclient1 type=dpdkvhostuserclient \
           options:vhost-server-path=/tmp/dpdkvhostclient1

For the above examples to work, an appropriate server socket must be created
at the paths specified (``/tmp/dpdkvhostclient0`` and
``/tmp/dpdkvhostclient1``).  These sockets can be created with QEMU; see the
:ref:`vhost-user client <dpdk-vhost-user-client>` section for details.

vhost-user vs. vhost-user-client
--------------------------------

Open vSwitch provides two types of vHost User ports:

- vhost-user (``dpdkvhostuser``)

- vhost-user-client (``dpdkvhostuserclient``)

vHost User uses a client-server model. The server creates/manages/destroys the
vHost User sockets, and the client connects to the server. Depending on which
port type you use, ``dpdkvhostuser`` or ``dpdkvhostuserclient``, a different
configuration of the client-server model is used.

For vhost-user ports, Open vSwitch acts as the server and QEMU the client. This
means if OVS dies, all VMs **must** be restarted. On the other hand, for
vhost-user-client ports, OVS acts as the client and QEMU the server. This means
OVS can die and be restarted without issue, and it is also possible to restart
an instance itself. For this reason, vhost-user-client ports are the preferred
type for all known use cases; the only limitation is that vhost-user client
mode ports require QEMU version 2.7.  Ports of type vhost-user are currently
deprecated and will be removed in a future release.

.. _dpdk-vhost-user:

vhost-user
----------

.. important::

   Use of vhost-user ports requires QEMU >= 2.2;  vhost-user ports are
   *deprecated*.

To use vhost-user ports, you must first add said ports to the switch. DPDK
vhost-user ports can have arbitrary names with the exception of forward and
backward slashes, which are prohibited. For vhost-user, the port type is
``dpdkvhostuser``::

    $ ovs-vsctl add-port br0 vhost-user-1 -- set Interface vhost-user-1 \
        type=dpdkvhostuser

This action creates a socket located at
``/usr/local/var/run/openvswitch/vhost-user-1``, which you must provide to your
VM on the QEMU command line.

.. note::

   If you wish for the vhost-user sockets to be created in a sub-directory of
   ``/usr/local/var/run/openvswitch``, you may specify this directory in the
   ovsdb like so::

       $ ovs-vsctl --no-wait \
           set Open_vSwitch . other_config:vhost-sock-dir=subdir

Once the vhost-user ports have been added to the switch, they must be added to
the guest. There are two ways to do this: using QEMU directly, or using
libvirt.

.. note::
   IOMMU is not supported with vhost-user ports.

Adding vhost-user ports to the guest (QEMU)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To begin, you must attach the vhost-user device sockets to the guest. To do
this, you must pass the following parameters to QEMU::

    -chardev socket,id=char1,path=/usr/local/var/run/openvswitch/vhost-user-1
    -netdev type=vhost-user,id=mynet1,chardev=char1,vhostforce
    -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1

where ``vhost-user-1`` is the name of the vhost-user port added to the switch.

Repeat the above parameters for multiple devices, changing the chardev ``path``
and ``id`` as necessary. Note that a separate and different chardev ``path``
needs to be specified for each vhost-user device. For example you have a second
vhost-user port named ``vhost-user-2``, you append your QEMU command line with
an additional set of parameters::

    -chardev socket,id=char2,path=/usr/local/var/run/openvswitch/vhost-user-2
    -netdev type=vhost-user,id=mynet2,chardev=char2,vhostforce
    -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2

In addition,       QEMU must allocate the VM's memory on hugetlbfs. vhost-user
ports access a virtio-net device's virtual rings and packet buffers mapping the
VM's physical memory on hugetlbfs. To enable vhost-user ports to map the VM's
memory into their process address space, pass the following parameters to
QEMU::

    -object memory-backend-file,id=mem,size=4096M,mem-path=/dev/hugepages,share=on
    -numa node,memdev=mem -mem-prealloc

Finally, you may wish to enable multiqueue support. This is optional but,
should you wish to enable it, run::

    -chardev socket,id=char2,path=/usr/local/var/run/openvswitch/vhost-user-2
    -netdev type=vhost-user,id=mynet2,chardev=char2,vhostforce,queues=$q
    -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2,mq=on,vectors=$v

where:

``$q``
  The number of queues
``$v``
  The number of vectors, which is ``$q`` * 2 + 2

The vhost-user interface will be automatically reconfigured with required
number of rx and tx queues after connection of virtio device.  Manual
configuration of ``n_rxq`` is not supported because OVS will work properly only
if ``n_rxq`` will match number of queues configured in QEMU.

A least 2 PMDs should be configured for the vswitch when using multiqueue.
Using a single PMD will cause traffic to be enqueued to the same vhost queue
rather than being distributed among different vhost queues for a vhost-user
interface.

If traffic destined for a VM configured with multiqueue arrives to the vswitch
via a physical DPDK port, then the number of rxqs should also be set to at
least 2 for that physical DPDK port. This is required to increase the
probability that a different PMD will handle the multiqueue transmission to the
guest using a different vhost queue.

If one wishes to use multiple queues for an interface in the guest, the driver
in the guest operating system must be configured to do so. It is recommended
that the number of queues configured be equal to ``$q``.

For example, this can be done for the Linux kernel virtio-net driver with::

    $ ethtool -L <DEV> combined <$q>

where:

``-L``
  Changes the numbers of channels of the specified network device
``combined``
  Changes the number of multi-purpose channels.

Adding vhost-user ports to the guest (libvirt)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. TODO(stephenfin): This seems like something that wouldn't be acceptable in
   production. Is this really required?

To begin, you must change the user and group that libvirt runs under, configure
access control policy and restart libvirtd.

- In ``/etc/libvirt/qemu.conf`` add/edit the following lines::

      user = "root"
      group = "root"

- Disable SELinux or set to permissive mode::

      $ setenforce 0

- Finally, restart the libvirtd process, For example, on Fedora::

      $ systemctl restart libvirtd.service

Once complete, instantiate the VM. A sample XML configuration file is provided
at the :ref:`end of this file <dpdk-vhost-user-xml>`. Save this file, then
create a VM using this file::

    $ virsh create demovm.xml

Once created, you can connect to the guest console::

    $ virsh console demovm

The demovm xml configuration is aimed at achieving out of box performance on
VM. These enhancements include:

- The vcpus are pinned to the cores of the CPU socket 0 using ``vcpupin``.

- Configure NUMA cell and memory shared using ``memAccess='shared'``.

- Disable ``mrg_rxbuf='off'``

Refer to the `libvirt documentation <http://libvirt.org/formatdomain.html>`__
for more information.

.. _dpdk-vhost-user-client:

vhost-user-client
-----------------

.. important::

   Use of vhost-user ports requires QEMU >= 2.7

To use vhost-user-client ports, you must first add said ports to the switch.
Like DPDK vhost-user ports, DPDK vhost-user-client ports can have mostly
arbitrary names. However, the name given to the port does not govern the name
of the socket device. Instead, this must be configured by the user by way of a
``vhost-server-path`` option. For vhost-user-client, the port type is
``dpdkvhostuserclient``::

    $ VHOST_USER_SOCKET_PATH=/path/to/socket
    $ ovs-vsctl add-port br0 vhost-client-1 \
        -- set Interface vhost-client-1 type=dpdkvhostuserclient \
             options:vhost-server-path=$VHOST_USER_SOCKET_PATH

Once the vhost-user-client ports have been added to the switch, they must be
added to the guest. Like vhost-user ports, there are two ways to do this: using
QEMU directly, or using libvirt. Only the QEMU case is covered here.

Adding vhost-user-client ports to the guest (QEMU)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Attach the vhost-user device sockets to the guest. To do this, you must pass
the following parameters to QEMU::

    -chardev socket,id=char1,path=$VHOST_USER_SOCKET_PATH,server
    -netdev type=vhost-user,id=mynet1,chardev=char1,vhostforce
    -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1

where ``vhost-user-1`` is the name of the vhost-user port added to the switch.

If the corresponding ``dpdkvhostuserclient`` port has not yet been configured
in OVS with ``vhost-server-path=/path/to/socket``, QEMU will print a log
similar to the following::

    QEMU waiting for connection on: disconnected:unix:/path/to/socket,server

QEMU will wait until the port is created sucessfully in OVS to boot the VM.
One benefit of using this mode is the ability for vHost ports to 'reconnect' in
event of the switch crashing or being brought down. Once it is brought back up,
the vHost ports will reconnect automatically and normal service will resume.

vhost-user-client IOMMU Support
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

vhost IOMMU is a feature which restricts the vhost memory that a virtio device
can access, and as such is useful in deployments in which security is a
concern.

IOMMU support may be enabled via a global config value,
```vhost-iommu-support```. Setting this to true enables vhost IOMMU support for
all vhost ports when/where available::

    $ ovs-vsctl set Open_vSwitch . other_config:vhost-iommu-support=true

The default value is false.

.. important::

    Changing this value requires restarting the daemon.

.. important::

    Enabling the IOMMU feature also enables the vhost user reply-ack protocol;
    this is known to work on QEMU v2.10.0, but is buggy on older versions
    (2.7.0 - 2.9.0, inclusive). Consequently, the IOMMU feature is disabled by
    default (and should remain so if using the aforementioned versions of
    QEMU). Starting with QEMU v2.9.1, vhost-iommu-support can safely be
    enabled, even without having an IOMMU device, with no performance penalty.

.. _dpdk-testpmd:

DPDK in the Guest
-----------------

The DPDK ``testpmd`` application can be run in guest VMs for high speed packet
forwarding between vhostuser ports. DPDK and testpmd application has to be
compiled on the guest VM. Below are the steps for setting up the testpmd
application in the VM.

.. note::

  Support for DPDK in the guest requires QEMU >= 2.2

To begin, instantiate a guest as described in :ref:`dpdk-vhost-user` or
:ref:`dpdk-vhost-user-client`. Once started, connect to the VM, download the
DPDK sources to VM and build DPDK::

    $ cd /root/dpdk/
    $ wget http://fast.dpdk.org/rel/dpdk-17.11.1.tar.xz
    $ tar xf dpdk-17.11.1.tar.xz
    $ export DPDK_DIR=/root/dpdk/dpdk-stable-17.11.1
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
    $ $DPDK_DIR/usertools/dpdk-devbind.py --status
    $ $DPDK_DIR/usertools/dpdk-devbind.py -b igb_uio 00:03.0 00:04.0

.. note::

  vhost ports pci ids can be retrieved using::

      lspci | grep Ethernet

Finally, start the application::

    # TODO

.. _dpdk-vhost-user-xml:

Sample XML
----------

::

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
          <source dir='/usr/src/dpdk-stable-17.11.1'/>
          <target dev='vdb' bus='virtio'/>
          <readonly/>
        </disk>
        <interface type='vhostuser'>
          <mac address='00:00:00:00:00:01'/>
          <source type='unix' path='/usr/local/var/run/openvswitch/dpdkvhostuser0' mode='client'/>
           <model type='virtio'/>
          <driver queues='2'>
            <host mrg_rxbuf='on'/>
          </driver>
        </interface>
        <interface type='vhostuser'>
          <mac address='00:00:00:00:00:02'/>
          <source type='unix' path='/usr/local/var/run/openvswitch/dpdkvhostuser1' mode='client'/>
          <model type='virtio'/>
          <driver queues='2'>
            <host mrg_rxbuf='on'/>
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

.. _QEMU documentation: http://git.qemu-project.org/?p=qemu.git;a=blob;f=docs/specs/vhost-user.txt;h=7890d7169;hb=HEAD

vhost-user Dequeue Zero Copy (experimental)
-------------------------------------------

Normally when dequeuing a packet from a vHost User device, a memcpy operation
must be used to copy that packet from guest address space to host address
space. This memcpy can be removed by enabling dequeue zero-copy like so::

    $ ovs-vsctl add-port br0 dpdkvhostuserclient0 -- set Interface \
        dpdkvhostuserclient0 type=dpdkvhostuserclient \
        options:vhost-server-path=/tmp/dpdkvhostclient0 \
        options:dq-zero-copy=true

With this feature enabled, a reference (pointer) to the packet is passed to
the host, instead of a copy of the packet. Removing this memcpy can give a
performance improvement for some use cases, for example switching large packets
between different VMs. However additional packet loss may be observed.

Note that the feature is disabled by default and must be explicitly enabled
by setting the ``dq-zero-copy`` option to ``true`` while specifying the
``vhost-server-path`` option as above. If you wish to split out the command
into multiple commands as below, ensure ``dq-zero-copy`` is set before
``vhost-server-path``::

    $ ovs-vsctl set Interface dpdkvhostuserclient0 options:dq-zero-copy=true
    $ ovs-vsctl set Interface dpdkvhostuserclient0 \
        options:vhost-server-path=/tmp/dpdkvhostclient0

The feature is only available to ``dpdkvhostuserclient`` port types.

A limitation exists whereby if packets from a vHost port with
``dq-zero-copy=true`` are destined for a ``dpdk`` type port, the number of tx
descriptors (``n_txq_desc``) for that port must be reduced to a smaller number,
128 being the recommended value. This can be achieved by issuing the following
command::

    $ ovs-vsctl set Interface dpdkport options:n_txq_desc=128

Note: The sum of the tx descriptors of all ``dpdk`` ports the VM will send to
should not exceed 128. For example, in case of a bond over two physical ports
in balance-tcp mode, one must divide 128 by the number of links in the bond.

Refer to :ref:`dpdk-queues-sizes` for more information.

The reason for this limitation is due to how the zero copy functionality is
implemented. The vHost device's 'tx used vring', a virtio structure used for
tracking used ie. sent descriptors, will only be updated when the NIC frees
the corresponding mbuf. If we don't free the mbufs frequently enough, that
vring will be starved and packets will no longer be processed. One way to
ensure we don't encounter this scenario, is to configure ``n_txq_desc`` to a
small enough number such that the 'mbuf free threshold' for the NIC will be hit
more often and thus free mbufs more frequently. The value of 128 is suggested,
but values of 64 and 256 have been tested and verified to work too, with
differing performance characteristics. A value of 512 can be used too, if the
virtio queue size in the guest is increased to 1024 (available to configure in
QEMU versions v2.10 and greater). This value can be set like so::

    $ qemu-system-x86_64 ... -chardev socket,id=char1,path=<sockpath>,server
      -netdev type=vhost-user,id=mynet1,chardev=char1,vhostforce
      -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,
      tx_queue_size=1024

Because of this limitation, this feature is considered 'experimental'.

The feature currently does not fully work with QEMU >= v2.7 due to a bug in
DPDK which will be addressed in an upcoming release. The patch to fix this
issue can be found on
`Patchwork
<http://dpdk.org/dev/patchwork/patch/32198/>`__

Further information can be found in the
`DPDK documentation
<http://dpdk.readthedocs.io/en/v17.11/prog_guide/vhost_lib.html>`__
