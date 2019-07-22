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

====================================
Distributions packaging Open vSwitch
====================================

This document lists various popular distributions packaging Open vSwitch.
Open vSwitch is packaged by various distributions for multiple platforms and
architectures.

.. note::
  The packaged version available with distributions may not be latest
  Open vSwitch release.

Debian
-------

You can use ``apt-get`` or ``aptitude`` to install the .deb packages and must
be superuser.

1. Debian has ``openvswitch-switch`` and ``openvswitch-common`` .deb packages
that includes the core userspace components of the switch.

2. For kernel datapath, ``openvswitch-datapath-dkms`` can be installed to
automatically build and install Open vSwitch kernel module for your running
kernel.  This package is only available when the .deb packages are built from
the Open vSwitch repository; it is not downstream in Debian or Ubuntu releases.

3. For fast userspace switching, Open vSwitch with DPDK support is
bundled in the package ``openvswitch-switch-dpdk``.  This package is only
available in the Ubuntu distribution; it is not upstream in the Open vSwitch
repository or downstream in Debian.

Fedora
------

Fedora provides ``openvswitch``, ``openvswitch-devel``, ``openvswitch-test``
and ``openvswitch-debuginfo`` rpm packages. You can install ``openvswitch``
package in minimum installation. Use ``yum`` or ``dnf`` to install the rpm
packages and must be superuser.

Red Hat
-------

RHEL distributes ``openvswitch`` rpm package that supports kernel datapath.
DPDK accelerated Open vSwitch can be installed using ``openvswitch-dpdk``
package.

OpenSuSE
--------

OpenSUSE provides ``openvswitch``, ``openvswitch-switch`` rpm packages. Also
``openvswitch-dpdk`` and ``openvswitch-dpdk-switch`` can be installed for
Open vSwitch using DPDK accelerated datapath.
