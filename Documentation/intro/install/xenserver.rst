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

================================
Open vSwitch on Citrix XenServer
================================

This document describes how to build and install Open vSwitch on a Citrix
XenServer host.  If you want to install Open vSwitch on a generic Linux or BSD
host, refer to :doc:`general` instead.

Open vSwitch should work with XenServer 5.6.100 and later.  However, Open
vSwitch requires Python 3.4 or later, so using Open vSwitch with XenServer 6.5
or earlier requires installing Python 3.x.

Building
--------

You may build from an Open vSwitch distribution tarball or from an Open vSwitch
Git tree.  The recommended build environment to build RPMs for Citrix XenServer
is the DDK VM available from Citrix.

1. If you are building from an Open vSwitch Git tree, then you will need to
   first create a distribution tarball by running::

       $ ./boot.sh
       $ ./configure
       $ make dist

   You cannot run this in the DDK VM, because it lacks tools that are necessary
   to bootstrap the Open vSwitch distribution.  Instead, you must run this on a
   machine that has the tools listed in :ref:`general-install-reqs` as
   prerequisites for building from a Git tree.

2. Copy the distribution tarball into ``/usr/src/redhat/SOURCES`` inside
   the DDK VM.

3. In the DDK VM, unpack the distribution tarball into a temporary directory
   and "cd" into the root of the distribution tarball.

4. To build Open vSwitch userspace, run::

       $ rpmbuild -bb xenserver/openvswitch-xen.spec

   This produces three RPMs in ``/usr/src/redhat/RPMS/i386``:

   - ``openvswitch``
   - ``openvswitch-modules-xen``
   - ``openvswitch-debuginfo``

   The above command automatically runs the Open vSwitch unit tests.  To
   disable the unit tests, run::

       $ rpmbuild -bb --without check xenserver/openvswitch-xen.spec

Build Parameters
----------------

``openvswitch-xen.spec`` needs to know a number of pieces of information about
the XenServer kernel.  Usually, it can figure these out for itself, but if it
does not do it correctly then you can specify them yourself as parameters to
the build.  Thus, the final ``rpmbuild`` step above can be elaborated as::

    $ VERSION=<Open vSwitch version>
    $ KERNEL_NAME=<Xen Kernel name>
    $ KERNEL_VERSION=<Xen Kernel version>
    $ KERNEL_FLAVOR=<Xen Kernel flavor(suffix)>
    $ rpmbuild \
         -D "openvswitch_version $VERSION" \
         -D "kernel_name $KERNEL_NAME" \
         -D "kernel_version $KERNEL_VERSION" \
         -D "kernel_flavor $KERNEL_FLAVOR" \
         -bb xenserver/openvswitch-xen.spec

where:

``<openvswitch version>``
  is the version number that appears in the name of the Open vSwitch tarball,
  e.g. 0.90.0.

``<Xen Kernel name>``
  is the name of the XenServer kernel package, e.g. ``kernel-xen`` or
  ``kernel-NAME-xen``, without the ``kernel-`` prefix.

``<Xen Kernel version>``
  is the output of::

      $ rpm -q --queryformat "%{Version}-%{Release}" <kernel-devel-package>,

  e.g. ``2.6.32.12-0.7.1.xs5.6.100.323.170596``, where
  ``<kernel-devel-package>`` is the name of the ``-devel`` package
  corresponding to ``<Xen Kernel name>``.

``<Xen Kernel flavor (suffix)>``
  is either ``xen`` or ``kdump``, where ``xen`` flavor is the main running
  kernel flavor and the ``kdump`` flavor is the crashdump kernel flavor.
  Commonly, one would specify ``xen`` here.

For XenServer 6.5 or above, the kernel version naming no longer contains
KERNEL_FLAVOR.  In fact, only providing the ``uname -r`` output is enough.  So,
the final ``rpmbuild`` step changes to::

    $ KERNEL_UNAME=<`uname -r` output>
    $ rpmbuild \
        -D "kenel_uname $KERNEL_UNAME" \
        -bb xenserver/openvswitch-xen.spec

Installing Open vSwitch for XenServer
-------------------------------------

To install Open vSwitch on a XenServer host, or to upgrade to a newer version,
copy the ``openvswitch`` and ``openvswitch-modules-xen`` RPMs to that host with
``scp``, then install them with ``rpm -U``, e.g.::

    $ scp openvswitch-$VERSION-1.i386.rpm \
        openvswitch-modules-xen-$XEN_KERNEL_VERSION-$VERSION-1.i386.rpm \
        root@<host>:
    # Enter <host>'s root password.
    $ ssh root@<host>
    # Enter <host>'s root password again.
    $ rpm -U openvswitch-$VERSION-1.i386.rpm \
        openvswitch-modules-xen-$XEN_KERNEL_VERSION-$VERSION-1.i386.rpm

To uninstall Open vSwitch from a XenServer host, remove the packages::

    $ ssh root@<host>
    # Enter <host>'s root password again.
    $ rpm -e openvswitch openvswitch-modules-xen-$XEN_KERNEL_VERSION

After installing or uninstalling Open vSwitch, the XenServer should be rebooted
as soon as possible.

Open vSwitch Boot Sequence on XenServer
---------------------------------------

When Open vSwitch is installed on XenServer, its startup script
``/etc/init.d/openvswitch`` runs early in boot.  It does roughly the following:

* Loads the OVS kernel module, openvswitch.

* Starts ovsdb-server, the OVS configuration database.

* XenServer expects there to be no bridges configured at startup, but the OVS
  configuration database likely still has bridges configured from before
  reboot.  To match XenServer expectations, the startup script deletes all
  configured bridges from the database.

* Starts ovs-vswitchd, the OVS switching daemon.

At this point in the boot process, then, there are no Open vSwitch bridges,
even though all of the Open vSwitch daemons are running.  Later on in boot,
``/etc/init.d/management-interface`` (part of XenServer, not Open vSwitch)
creates the bridge for the XAPI management interface by invoking
``/opt/xensource/libexec/interface-reconfigure``.  Normally this program
consults XAPI's database to obtain information about how to configure the
bridge, but XAPI is not running yet(\*) so it instead consults
``/var/xapi/network.dbcache``, which is a cached copy of the most recent
network configuration.

(\*) Even if XAPI were running, if this XenServer node is a pool slave then the
     query would have to consult the master, which requires network access,
     which begs the question of how to configure the management interface.

XAPI starts later on in the boot process.  XAPI can then create other bridges
on demand using ``/opt/xensource/libexec/interface-reconfigure``.  Now that
XAPI is running, that program consults XAPI directly instead of reading the
cache.

As part of its own startup, XAPI invokes the Open vSwitch XAPI plugin script
``/etc/xapi.d/openvswitch-cfg-update`` passing the ``update`` command.  The
plugin script does roughly the following:

* Calls ``/opt/xensource/libexec/interface-reconfigure`` with the ``rewrite``
  command, to ensure that the network cache is up-to-date.

* Queries the Open vSwitch manager setting (named ``vswitch_controller``) from
  the XAPI database for the XenServer pool.

* If XAPI and OVS are configured for different managers, or if OVS is
  configured for a manager but XAPI is not, runs ``ovs-vsctl emer-reset`` to
  bring the Open vSwitch configuration to a known state.  One effect of
  emer-reset is to deconfigure any manager from the OVS database.

* If XAPI is configured for a manager, configures the OVS manager to match with
  ``ovs-vsctl set-manager``.

Notes
-----

* The Open vSwitch boot sequence only configures an OVS configuration database
  manager.  There is no way to directly configure an OpenFlow controller on
  XenServer and, as a consequence of the step above that deletes all of the
  bridges at boot time, controller configuration only persists until XenServer
  reboot.  The configuration database manager can, however, configure
  controllers for bridges.  See the BUGS section of ovs-testcontroller(8) for
  more information on this topic.

* The Open vSwitch startup script automatically adds a firewall rule to allow
  GRE traffic. This rule is needed for the XenServer feature called "Cross-Host
  Internal Networks" (CHIN) that uses GRE. If a user configures tunnels other
  than GRE (ex: Geneve, VXLAN, LISP), they will have to either manually add a
  iptables firewall rule to allow the tunnel traffic or add it through a
  startup script (Please refer to the "enable-protocol" command in the
  ovs-ctl(8) manpage).

Reporting Bugs
--------------

Please report problems to bugs@openvswitch.org.
