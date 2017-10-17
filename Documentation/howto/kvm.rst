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
Open vSwitch with KVM
=====================

This document describes how to use Open vSwitch with the Kernel-based Virtual
Machine (KVM).

.. note::

  This document assumes that you have Open vSwitch set up on a Linux system.

Setup
-----

KVM uses tunctl to handle various bridging modes, which you can install with
the Debian/Ubuntu package ``uml-utilities``::

    $ apt-get install uml-utilities

Next, you will need to modify or create custom versions of the ``qemu-ifup``
and ``qemu-ifdown`` scripts. In this guide, we'll create custom versions that
make use of example Open vSwitch bridges that we'll describe in this guide.

Create the following two files and store them in known locations. For example::

    $ cat << 'EOF' > /etc/ovs-ifup
    #!/bin/sh

    switch='br0'
    ip link set $1 up
    ovs-vsctl add-port ${switch} $1
    EOF

::

    $ cat << 'EOF' > /etc/ovs-ifdown
    #!/bin/sh

    switch='br0'
    ip addr flush dev $1
    ip link set $1 down
    ovs-vsctl del-port ${switch} $1
    EOF

The basic usage of Open vSwitch is described at the end of
:doc:`/intro/install/general`. If you haven't already, create a bridge named
``br0`` with the following command::

    $ ovs-vsctl add-br br0

Then, add a port to the bridge for the NIC that you want your guests to
communicate over (e.g. ``eth0``)::

    $ ovs-vsctl add-port br0 eth0

Refer to ovs-vsctl(8) for more details.

Next, we'll start a guest that will use our ifup and ifdown scripts::

    $ kvm -m 512 -net nic,macaddr=00:11:22:EE:EE:EE -net \
        tap,script=/etc/ovs-ifup,downscript=/etc/ovs-ifdown -drive \
        file=/path/to/disk-image,boot=on

This will start the guest and associate a tap device with it. The ``ovs-ifup``
script will add a port on the br0 bridge so that the guest will be able to
communicate over that bridge.

To get some more information and for debugging you can use Open vSwitch
utilities such as ovs-dpctl and ovs-ofctl, For example::

    $ ovs-dpctl show
    $ ovs-ofctl show br0

You should see tap devices for each KVM guest added as ports to the bridge
(e.g. tap0)

Refer to ovs-dpctl(8) and ovs-ofctl(8) for more details.

Bug Reporting
-------------

Please report problems to bugs@openvswitch.org.
