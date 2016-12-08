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

=========================
Open vSwitch with Libvirt
=========================

This document describes how to use Open vSwitch with Libvirt 0.9.11 or later.
This document assumes that you followed :doc:`/intro/install/general` or
installed Open vSwitch from distribution packaging such as a .deb or .rpm.  The
Open vSwitch support is included by default in Libvirt 0.9.11. Consult
www.libvirt.org for instructions on how to build the latest Libvirt, if your
Linux distribution by default comes with an older Libvirt release.

Limitations
-----------

Currently there is no Open vSwitch support for networks that are managed by
libvirt (e.g. NAT). As of now, only bridged networks are supported (those where
the user has to manually create the bridge).

Setup
-----

First, create the Open vSwitch bridge by using the ovs-vsctl utility (this must
be done with administrative privileges)::

    $ ovs-vsctl add-br ovsbr

Once that is done, create a VM, if necessary, and edit its Domain XML file::

    $ virsh edit <vm>

Lookup in the Domain XML file the ``<interface>`` section. There should be one
such XML section for each interface the VM has::

    <interface type='network'>
     <mac address='52:54:00:71:b1:b6'/>
     <source network='default'/>
     <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>

And change it to something like this::

    <interface type='bridge'>
     <mac address='52:54:00:71:b1:b6'/>
     <source bridge='ovsbr'/>
     <virtualport type='openvswitch'/>
     <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>

The interface type must be set to ``bridge``. The ``<source>`` XML element
specifies to which bridge this interface will be attached to. The
``<virtualport>`` element indicates that the bridge in ``<source>`` element is
an Open vSwitch bridge.

Then (re)start the VM and verify if the guest's vnet interface is attached to
the ovsbr bridge::

    $ ovs-vsctl show

Troubleshooting
---------------

If the VM does not want to start, then try to run the libvirtd process either
from the terminal, so that all errors are printed in console, or inspect
Libvirt/Open vSwitch log files for possible root cause.

Bug Reporting
-------------

Report problems to bugs@openvswitch.org.
