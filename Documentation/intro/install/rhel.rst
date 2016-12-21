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

========================================
RHEL 5.6, 6.x Packaging for Open vSwitch
========================================

This document describes how to build and install Open vSwitch on a Red Hat
Enterprise Linux (RHEL) host.  If you want to install Open vSwitch on a generic
Linux host, refer to :doc:`general` instead.

We have tested these instructions with RHEL 5.6 and RHEL 6.0.

For RHEL 7.x (or derivatives, such as CentOS 7.x), you should follow the
instructions in the :doc:`fedora`.  The Fedora spec files are used for RHEL
7.x.

.. _rhel-prerequisites:

Prerequisites
-------------

You may build from an Open vSwitch distribution tarball or from an Open vSwitch
Git tree.

The default RPM build directory, ``_topdir``, has five directories in the
top-level.

BUILD/
  where the software is unpacked and built
RPMS/
  where the newly created binary package files are written
SOURCES/
  contains the original sources, patches, and icon files
SPECS/
  contains the spec files for each package to be built
SRPMS/
  where the newly created source package files are written

Before you begin, note the RPM sources directory on your version of RHEL.  The
command ``rpmbuild --showrc`` will show the configuration for each of those
directories. Alternatively, the command ``rpm --eval '%{_topdir}'`` shows the
current configuration for the top level directory and the command ``rpm --eval
'%{_sourcedir}'`` does the same for the sources directory. On RHEL 5, the
default RPM ``_topdir`` is ``/usr/src/redhat`` and the default RPM sources
directory is ``/usr/src/redhat/SOURCES``. On RHEL 6, the default ``_topdir`` is
``$HOME/rpmbuild`` and the default RPM sources directory is
``$HOME/rpmbuild/SOURCES``.

Build Requirements
------------------

To compile the RPMs, you will need to install the packages described in the
:doc:`general` along with some additional packages. These can be installed with
the below command::

    $ yum install gcc make python-devel openssl-devel kernel-devel graphviz \
        kernel-debug-devel autoconf automake rpm-build redhat-rpm-config \
        libtool checkpolicy selinux-policy-devel

.. _rhel-bootstrapping:

Bootstrapping and Configuring
-----------------------------

If you are building from a distribution tarball, skip to :ref:`rhel-building`.
If not, you must be building from an Open vSwitch Git tree.  Determine what
version of Autoconf is installed (e.g. run ``autoconf --version``).  If it is
not at least version 2.63, then you must upgrade or use another machine to
build the packages.

Assuming all requirements have been met, build the tarball by running::

    $ ./boot.sh
    $ ./configure
    $ make dist

You must run this on a machine that has the tools listed in
:ref:`general-build-reqs` as prerequisites for building from a Git tree.
Afterward, proceed with the rest of the instructions using the distribution
tarball.

Now you have a distribution tarball, named something like
``openvswitch-x.y.z.tar.gz``.  Copy this file into the RPM sources directory,
e.g.::

    $ cp openvswitch-x.y.z.tar.gz $HOME/rpmbuild/SOURCES

Broken ``build`` symlink
~~~~~~~~~~~~~~~~~~~~~~~~

Some versions of the RHEL 6 kernel-devel package contain a broken ``build``
symlink.  If you are using such a version, you must fix the problem before
continuing.

To find out whether you are affected, run::

    $ cd /lib/modules/<version>
    $ ls -l build/

where ``<version>`` is the version number of the RHEL 6 kernel.

.. note::
  The trailing slash in the final command is important.  Be sure to include
  it.

If the ``ls`` command produces a directory listing, your kernel-devel package
is OK.  If it produces a ``No such file or directory`` error, your kernel-devel
package is buggy.

If your kernel-devel package is buggy, then you can fix it with::

    $ cd /lib/modules/<version>
    $ rm build
    $ ln -s /usr/src/kernels/<target> build

where ``<target>`` is the name of an existing directory under
``/usr/src/kernels``, whose name should be similar to ``<version>`` but may
contain some extra parts.  Once you have done this, verify the fix with the
same procedure you used above to check for the problem.

.. _rhel-building:

Building
--------

You should have a distribution tarball named something like
openvswitch-x.y.z.tar.gz.  Copy this file into the RPM sources directory::

    $ cp openvswitch-x.y.z.tar.gz $HOME/rpmbuild/SOURCES

Make another copy of the distribution tarball in a temporary directory.  Then
unpack the tarball and ``cd`` into its root::

    $ tar xzf openvswitch-x.y.z.tar.gz
    $ cd openvswitch-x.y.z

Userspace
~~~~~~~~~

To build Open vSwitch userspace, run::

    $ rpmbuild -bb rhel/openvswitch.spec

This produces two RPMs: "openvswitch" and "openvswitch-debuginfo".

The above command automatically runs the Open vSwitch unit tests.  To disable
the unit tests, run::

    $ rpmbuild -bb --without check rhel/openvswitch.spec

.. note::
   If the build fails with ``configure: error: source dir
   /lib/modules/2.6.32-279.el6.x86_64/build doesn't exist`` or similar, then
   the kernel-devel package is missing or buggy.

Kernel Module
~~~~~~~~~~~~~

On RHEL 6, to build the Open vSwitch kernel module, copy
rhel/openvswitch-kmod.files into the RPM sources directory and run::

    $ rpmbuild -bb rhel/openvswitch-kmod-rhel6.spec

You might have to specify a kernel version and/or variants, e.g.:

    $ rpmbuild -bb \
        -D "kversion 2.6.32-131.6.1.el6.x86_64" \
        -D "kflavors default debug kdump" \
        rhel/openvswitch-kmod-rhel6.spec

This produces an "kmod-openvswitch" RPM for each kernel variant, in this
example: "kmod-openvswitch", "kmod-openvswitch-debug", and
"kmod-openvswitch-kdump".

.. _rhel-script-integrations:

Red Hat Network Scripts Integration
-----------------------------------

A RHEL host has default firewall rules that prevent any Open vSwitch tunnel
traffic from passing through. If a user configures Open vSwitch tunnels like
Geneve, GRE, VXLAN, LISP etc., they will either have to manually add iptables
firewall rules to allow the tunnel traffic or add it through a startup script
Refer to the "enable-protocol" command in the ovs-ctl(8) manpage for more
information.

In addition, simple integration with Red Hat network scripts has been
implemented.  Refer to `README.RHEL.rst`__ in the source tree or
/usr/share/doc/openvswitch/README.RHEL.rst in the installed openvswitch package
for details.

__ https://github.com/openvswitch/ovs/blob/master/rhel/README.RHEL.rst

Reporting Bugs
--------------

Report problems to bugs@openvswitch.org.
