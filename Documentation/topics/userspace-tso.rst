..
      Copyright 2020, Red Hat, Inc.

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

========================
Userspace Datapath - TSO
========================

**Note:** This feature is considered experimental.

TCP Segmentation Offload (TSO) enables a network stack to delegate segmentation
of an oversized TCP segment to the underlying physical NIC. Offload of frame
segmentation achieves computational savings in the core, freeing up CPU cycles
for more useful work.

A common use case for TSO is when using virtualization, where traffic that's
coming in from a VM can offload the TCP segmentation, thus avoiding the
fragmentation in software. Additionally, if the traffic is headed to a VM
within the same host further optimization can be expected. As the traffic never
leaves the machine, no MTU needs to be accounted for, and thus no segmentation
and checksum calculations are required, which saves yet more cycles. Only when
the traffic actually leaves the host the segmentation needs to happen, in which
case it will be performed by the egress NIC. Consult your controller's
datasheet for compatibility. Secondly, the NIC must have an associated DPDK
Poll Mode Driver (PMD) which supports `TSO`. For a list of features per PMD,
refer to the `DPDK documentation`__.

__ https://doc.dpdk.org/guides-20.11/nics/overview.html

Enabling TSO
~~~~~~~~~~~~

The TSO support may be enabled via a global config value
``userspace-tso-enable``.  Setting this to ``true`` enables TSO support for
all ports.::

    $ ovs-vsctl set Open_vSwitch . other_config:userspace-tso-enable=true

The default value is ``false``.

Changing ``userspace-tso-enable`` requires restarting the daemon.

When using :doc:`vHost User ports <dpdk/vhost-user>`, TSO may be enabled
as follows.

`TSO` is enabled in OvS by the DPDK vHost User backend; when a new guest
connection is established, `TSO` is thus advertised to the guest as an
available feature:

QEMU Command Line Parameter::

    $ sudo $QEMU_DIR/x86_64-softmmu/qemu-system-x86_64 \
    ...
    -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,\
    csum=on,guest_csum=on,guest_tso4=on,guest_tso6=on\
    ...

2. Ethtool. Assuming that the guest's OS also supports `TSO`, ethtool can be
used to enable same::

    $ ethtool -K eth0 sg on     # scatter-gather is a prerequisite for TSO
    $ ethtool -K eth0 tso on
    $ ethtool -k eth0

~~~~~~~~~~~
Limitations
~~~~~~~~~~~

The current OvS userspace `TSO` implementation supports flat and VLAN networks
only (i.e. no support for `TSO` over tunneled connection [VxLAN, GRE, IPinIP,
etc.]).

The NIC driver must support and advertise checksum offload for TCP and UDP.
However, SCTP is not mandatory because very few drivers advertised support
and it wasn't a widely used protocol at the moment this feature was introduced
in Open vSwitch. Currently, if the NIC supports that, then the feature is
enabled, otherwise TSO can still be enabled but SCTP packets sent to the NIC
will be dropped.

There is no software implementation of TSO, so all ports attached to the
datapath must support TSO or packets using that feature will be dropped
on ports without TSO support.  That also means guests using vhost-user
in client mode will receive TSO packet regardless of TSO being enabled
or disabled within the guest.

All kernel devices that use the raw socket interface (veth, for example)
require the kernel commit 9d2f67e43b73 ("net/packet: fix packet drop as of
virtio gso") in order to work properly. This commit was merged in upstream
kernel 4.19-rc7, so make sure your kernel is either newer or contains the
backport.

~~~~~~~~~~~~~~~~~~
Performance Tuning
~~~~~~~~~~~~~~~~~~

iperf is often used to test TSO performance. Care needs to be taken when
configuring the environment in which the iperf server process is being run.
Since the iperf server uses the NIC's kernel driver, IRQs will be generated.
By default with some NICs eg. i40e, the IRQs will land on the same core as that
which is being used by the server process, provided the number of NIC queues is
greater or equal to that lcoreid. This causes contention between the iperf
server process and the IRQs. For optimal performance, it is suggested to pin
the IRQs to their own core. To change the affinity associated with a given IRQ
number, you can 'echo' the desired coremask to the file
/proc/irq/<number>/smp_affinity
For more on SMP affinity, refer to the `Linux kernel documentation`__.

__ https://www.kernel.org/doc/Documentation/IRQ-affinity.txt
