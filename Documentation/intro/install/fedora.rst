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

===========================================
Fedora, RHEL 7.x Packaging for Open vSwitch
===========================================

This document provides instructions for building and installing Open vSwitch
RPM packages on a Fedora Linux host. Instructions for the installation of Open
vSwitch on a Fedora Linux host without using RPM packages can be found in the
:doc:`general`.

These instructions have been tested with Fedora 23, and are also applicable for
RHEL 7.x and its derivatives, including CentOS 7.x and Scientific Linux 7.x.

Build Requirements
------------------

You will need to install all required packages to build the RPMs.
Newer distributions use ``dnf`` but if it's not available, then use
``yum`` instructions.

The command below will install RPM tools and generic build dependencies.
And (optionally) include these packages: libcap-ng libcap-ng-devel dpdk-devel.

DNF:
::

    $ dnf install @'Development Tools' rpm-build dnf-plugins-core

YUM:
::

    $ yum install @'Development Tools' rpm-build yum-utils

Then it is necessary to install Open vSwitch specific build dependencies.
The dependencies are listed in the SPEC file, but first it is necessary
to replace the VERSION tag to be a valid SPEC.

The command below will create a temporary SPEC file::

    $ sed -e 's/@VERSION@/0.0.1/' rhel/openvswitch-fedora.spec.in \
      > /tmp/ovs.spec

And to install specific dependencies, use the corresponding tool below.
For some of the dependencies on RHEL you may need to add two additional
repositories to help yum-builddep, e.g.::

    $ subscription-manager repos --enable=rhel-7-server-extras-rpms
    $ subscription-manager repos --enable=rhel-7-server-optional-rpms

DNF::

    $ dnf builddep /tmp/ovs.spec

YUM::

    $ yum-builddep /tmp/ovs.spec

Once that is completed, remove the file ``/tmp/ovs.spec``.

Bootstraping
------------

Refer to :ref:`general-bootstrapping`.

Configuring
-----------

Refer to :ref:`general-configuring`.

Building
--------

User Space RPMs
~~~~~~~~~~~~~~~

To build Open vSwitch user-space RPMs, execute the following from the directory
in which `./configure` was executed:

::

    $ make rpm-fedora

This will create the RPMs `openvswitch`, `python-openvswitch`,
`openvswitch-test`, `openvswitch-devel`, `openvswitch-ovn-common`,
`openvswitch-ovn-central`, `openvswitch-ovn-host`, `openvswitch-ovn-vtep`,
`openvswitch-ovn-docker`, and `openvswitch-debuginfo`.

To enable DPDK support in the openvswitch package, the ``--with dpdk`` option
can be added:

::

    $ make rpm-fedora RPMBUILD_OPT="--with dpdk --without check"

You can also have the above commands automatically run the Open vSwitch unit
tests.  This can take several minutes.

::

    $ make rpm-fedora RPMBUILD_OPT="--with check"

Kernel OVS Tree Datapath RPM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To build the Open vSwitch kernel module for the currently running kernel
version, run:

::

    $ make rpm-fedora-kmod

To build the Open vSwitch kernel module for another kernel version, the desired
kernel version can be specified via the `kversion` macro.  For example:

::

    $ make rpm-fedora-kmod \
         RPMBUILD_OPT='-D "kversion 4.3.4-300.fc23.x86_64"'

Installing
----------

RPM packages can be installed by using the command ``rpm -i``. Package
installation requires superuser privileges.

The `openvswitch-kmod` RPM should be installed first if the Linux OVS tree
datapath module is to be used. The `openvswitch-kmod` RPM should not be
installed if only the in-tree Linux datapath or user-space datapath is needed.
Refer to the :doc:`/faq/index` for more information about the various Open
vSwitch datapath options.

In most cases only the `openvswitch` RPM will need to be installed. The
`python-openvswitch`, `openvswitch-test`, `openvswitch-devel`, and
`openvswitch-debuginfo` RPMs are optional unless required for a specific
purpose.

The `openvswitch-ovn-*` packages are only needed when using OVN.

Refer to the `RHEL README`__ for additional usage and configuration
information.

__ https://github.com/openvswitch/ovs/blob/master/rhel/README.RHEL.rst

Reporting Bugs
--------------

Report problems to bugs@openvswitch.org.
