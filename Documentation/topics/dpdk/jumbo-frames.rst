..
      Copyright 2018, Red Hat, Inc.

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

============
Jumbo Frames
============

.. versionadded:: 2.6.0

By default, DPDK ports are configured with standard Ethernet MTU (1500B). To
enable Jumbo Frames support for a DPDK port, change the Interface's
``mtu_request`` attribute to a sufficiently large value. For example, to add a
:doc:`DPDK physical port <phy>` with an MTU of 9000, run::

    $ ovs-vsctl add-port br0 dpdk-p0 -- set Interface dpdk-p0 type=dpdk \
          options:dpdk-devargs=0000:01:00.0 mtu_request=9000

Similarly, to change the MTU of an existing port to 6200, run::

    $ ovs-vsctl set Interface dpdk-p0 mtu_request=6200

Some additional configuration is needed to take advantage of jumbo frames with
:doc:`vHost User ports <vhost-user>`:

- *Mergeable buffers* must be enabled for vHost User ports, as demonstrated in
  the QEMU command line snippet below::

      -netdev type=vhost-user,id=mynet1,chardev=char0,vhostforce \
      -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,mrg_rxbuf=on

- Where virtio devices are bound to the Linux kernel driver in a guest
  environment (i.e. interfaces are not bound to an in-guest DPDK driver), the
  MTU of those logical network interfaces must also be increased to a
  sufficiently large value. This avoids segmentation of Jumbo Frames received
  in the guest. Note that 'MTU' refers to the length of the IP packet only, and
  not that of the entire frame.

  To calculate the exact MTU of a standard IPv4 frame, subtract the L2 header
  and CRC lengths (i.e. 18B) from the max supported frame size. So, to set the
  MTU for a 9018B Jumbo Frame::

      $ ip link set eth1 mtu 9000

When Jumbo Frames are enabled, the size of a DPDK port's mbuf segments are
increased, such that a full Jumbo Frame of a specific size may be accommodated
within a single mbuf segment.

Jumbo frame support has been validated against 9728B frames, which is the
largest frame size supported by Fortville NIC using the DPDK i40e driver, but
larger frames and other DPDK NIC drivers may be supported. These cases are
common for use cases involving East-West traffic only.
