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

__ https://doc.dpdk.org/guides-19.11/nics/overview.html

Enabling TSO
~~~~~~~~~~~~

The TSO support may be enabled via a global config value
``userspace-tso-enable``.  Setting this to ``true`` enables TSO support for
all ports.

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

There is no software implementation of TSO, so all ports attached to the
datapath must support TSO or packets using that feature will be dropped
on ports without TSO support.  That also means guests using vhost-user
in client mode will receive TSO packet regardless of TSO being enabled
or disabled within the guest.
