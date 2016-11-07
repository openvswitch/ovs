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

=========================================
Open vSwitch on Linux, FreeBSD and NetBSD
=========================================

This document describes how to build and install Open vSwitch on a generic
Linux, FreeBSD, or NetBSD host. For specifics around installation on a specific
platform, refer to one of these installation guides:

- `Debian <INSTALL.Debian.rst>`__
- `Fedora <INSTALL.Fedora.rst>`__
- `RHEL <INSTALL.RHEL.rst>`__
- `XenServer <INSTALL.XenServer.rst>`__
- `NetBSD <INSTALL.NetBSD.rst>`__
- `Windows <INSTALL.Windows.rst>`__
- `DPDK <INSTALL.DPDK.rst>`__

.. _general-build-reqs:

Build Requirements
------------------

To compile the userspace programs in the Open vSwitch distribution, you will
need the following software:

- GNU make

- A C compiler, such as:

  - GCC 4.x.

  - Clang. Clang 3.4 and later provide useful static semantic analysis and
    thread-safety checks. For Ubuntu, there are nightly built packages
    available on clang's website.

  - MSVC 2013. See the `Windows installation guide <INSTALL.Windows>`__
    for additional Windows build instructions.

  While OVS may be compatible with other compilers, optimal support for atomic
  operations may be missing, making OVS very slow (see ``lib/ovs-atomic.h``).

- libssl, from OpenSSL, is optional but recommended if you plan to connect the
  Open vSwitch to an OpenFlow controller. libssl is required to establish
  confidentiality and authenticity in the connections from an Open vSwitch to
  an OpenFlow controller. If libssl is installed, then Open vSwitch will
  automatically build with support for it.

- libcap-ng, written by Steve Grubb, is optional but recommended. It is
  required to run OVS daemons as a non-root user with dropped root privileges.
  If libcap-ng is installed, then Open vSwitch will automatically build with
  support for it.

- Python 2.7. You must also have the Python ``six`` library.

On Linux, you may choose to compile the kernel module that comes with the Open
vSwitch distribution or to use the kernel module built into the Linux kernel
(version 3.3 or later). See the `FAQ <FAQ.rst>`__ question "What features
are not available in the Open vSwitch kernel datapath that ships as part of the
upstream Linux kernel?" for more information on this trade-off. You may also
use the userspace-only implementation, at some cost in features and performance
(see the `userspace installation guide <INSTALL.userspace.rst>`__ for details).

To compile the kernel module on Linux, you must also install the
following:

- A supported Linux kernel version. Refer to the `README <README.rst>`__
  for a list of supported versions.

  For optional support of ingress policing, you must enable kernel
  configuration options ``NET_CLS_BASIC``, ``NET_SCH_INGRESS``, and
  ``NET_ACT_POLICE``, either built-in or as modules. ``NET_CLS_POLICE`` is
  obsolete and not needed.)

  On kernels before 3.11, the ``ip_gre`` module, for GRE tunnels over IP
  (``NET_IPGRE``), must not be loaded or compiled in.

  To configure HTB or HFSC quality of service with Open vSwitch, you must
  enable the respective configuration options.

  To use Open vSwitch support for TAP devices, you must enable ``CONFIG_TUN``.

- To build a kernel module, you need the same version of GCC that was used to
  build that kernel.

- A kernel build directory corresponding to the Linux kernel image the module
  is to run on. Under Debian and Ubuntu, for example, each linux-image package
  containing a kernel binary has a corresponding linux-headers package with
  the required build infrastructure.

If you are working from a Git tree or snapshot (instead of from a distribution
tarball), or if you modify the Open vSwitch build system or the database
schema, you will also need the following software:

- Autoconf version 2.63 or later.

- Automake version 1.10 or later.

- libtool version 2.4 or later. (Older versions might work too.)

To run the unit tests, you also need:

- Perl. Version 5.10.1 is known to work. Earlier versions should also
  work.

The datapath tests for userspace and Linux datapaths also rely upon:

- pyftpdlib. Version 1.2.0 is known to work. Earlier versions should
  also work.

- GNU wget. Version 1.16 is known to work. Earlier versions should also
  work.

The ovs-vswitchd.conf.db(5) manpage will include an E-R diagram, in formats
other than plain text, only if you have the following:

- dot from graphviz (http://www.graphviz.org/).

- Perl. Version 5.10.1 is known to work. Earlier versions should also
  work.

If you are going to extensively modify Open vSwitch, consider installing the
following to obtain better warnings:

- "sparse" version 0.4.4 or later
  (http://www.kernel.org/pub/software/devel/sparse/dist/).

- GNU make.

- clang, version 3.4 or later

- flake8, version 2.X, along with the hacking flake8 plugin (for Python code).
  The automatic flake8 check that runs against Python code has some warnings
  enabled that come from the "hacking" flake8 plugin. If it's not installed,
  the warnings just won't occur until it's run on a system with "hacking"
  installed. Note that there are problems with flake8 3.0 and the "hacking"
  plugin. To ensure you get flake8 2.X, you can use::

      $ pip install 'flake8<3.0'

You may find the ovs-dev script found in ``utilities/ovs-dev.py`` useful.

.. _general-install-reqs:

Installation Requirements
-------------------------

The machine you build Open vSwitch on may not be the one you run it on. To
simply install and run Open vSwitch you require the following software:

- libc compatible with the libc used for build.

- libssl compatible with the libssl used for build, if OpenSSL was used
  for the build.

- On Linux, the same kernel version configured as part of the build.

- For optional support of ingress policing on Linux, the "tc" program
  from iproute2 (part of all major distributions and available at
  http://www.linux-foundation.org/en/Net:Iproute2).

- Python 2.7. You must also have the Python six library.

On Linux you should ensure that ``/dev/urandom`` exists. To support TAP
devices, you must also ensure that ``/dev/net/tun`` exists.

.. _general-bootstrapping:

Bootstrapping
-------------

This step is not needed if you have downloaded a released tarball. If
you pulled the sources directly from an Open vSwitch Git tree or got a
Git tree snapshot, then run boot.sh in the top source directory to build
the "configure" script::

    $ ./boot.sh

.. _general-configuring:

Configuring
-----------

Configure the package by running the configure script. You can usually
invoke configure without any arguments. For example::

    $ ./configure

By default all files are installed under ``/usr/local``. Open vSwitch also
expects to find its database in ``/usr/local/etc/openvswitch`` by default. If
you want to install all files into, e.g., ``/usr`` and ``/var`` instead of
``/usr/local`` and ``/usr/local/var`` and expect to use ``/etc/openvswitch`` as
the default database directory, add options as shown here::

    $ ./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc

.. note::

  Open vSwitch installed with packages like .rpm (e.g. via ``yum install`` or
  ``rpm -ivh``) and .deb (e.g. via ``apt-get install`` or ``dpkg -i``) use the
  above configure options.

By default, static libraries are built and linked against. If you want to use
shared libraries instead::

    $ ./configure --enable-shared

To use a specific C compiler for compiling Open vSwitch user programs, also
specify it on the configure command line, like so::

    $ ./configure CC=gcc-4.2

To use 'clang' compiler::

    $ ./configure CC=clang

To supply special flags to the C compiler, specify them as ``CFLAGS`` on the
configure command line. If you want the default CFLAGS, which include ``-g`` to
build debug symbols and ``-O2`` to enable optimizations, you must include them
yourself. For example, to build with the default CFLAGS plus ``-mssse3``, you
might run configure as follows::

    $ ./configure CFLAGS="-g -O2 -mssse3"

For efficient hash computation special flags can be passed to leverage built-in
intrinsics. For example on X86_64 with SSE4.2 instruction set support, CRC32
intrinsics can be used by passing ``-msse4.2``::

    $ ./configure CFLAGS="-g -O2 -msse4.2"`

If you are on a different processor and don't know what flags to choose, it is
recommended to use ``-march=native`` settings::

    $ ./configure CFLAGS="-g -O2 -march=native"

With this, GCC will detect the processor and automatically set appropriate
flags for it. This should not be used if you are compiling OVS outside the
target machine.

.. note::
  CFLAGS are not applied when building the Linux kernel module. Custom CFLAGS
  for the kernel module are supplied using the ``EXTRA_CFLAGS`` variable when
  running make. For example::

      $ make EXTRA_CFLAGS="-Wno-error=date-time"

To build the Linux kernel module, so that you can run the kernel-based switch,
pass the location of the kernel build directory on ``--with-linux``. For
example, to build for a running instance of Linux::

    $ ./configure --with-linux=/lib/modules/$(uname -r)/build

.. note::
  If ``--with-linux`` requests building for an unsupported version of Linux,
  then ``configure`` will fail with an error message. Refer to the `FAQ
  <FAQ.rst>`__ for advice in that case.

If you wish to build the kernel module for an architecture other than the
architecture of the machine used for the build, you may specify the kernel
architecture string using the KARCH variable when invoking the configure
script. For example, to build for MIPS with Linux::

    $ ./configure --with-linux=/path/to/linux KARCH=mips

If you plan to do much Open vSwitch development, you might want to add
``--enable-Werror``, which adds the ``-Werror`` option to the compiler command
line, turning warnings into errors. That makes it impossible to miss warnings
generated by the build. For example::

    $ ./configure --enable-Werror

To build with gcov code coverage support, add ``--enable-coverage``::

    $ ./configure --enable-coverage

The configure script accepts a number of other options and honors additional
environment variables. For a full list, invoke configure with the ``--help``
option::

    $ ./configure --help

You can also run configure from a separate build directory. This is helpful if
you want to build Open vSwitch in more than one way from a single source
directory, e.g. to try out both GCC and Clang builds, or to build kernel
modules for more than one Linux version. For example::

    $ mkdir _gcc && (cd _gcc && ./configure CC=gcc)
    $ mkdir _clang && (cd _clang && ./configure CC=clang)

Under certains loads the ovsdb-server and other components perform better when
using the jemalloc memory allocator, instead of the glibc memory allocator. If
you wish to link with jemalloc add it to LIBS::

    $ ./configure LIBS=-ljemalloc

.. _general-building:

Building
--------

1. Run GNU make in the build directory, e.g.::

       $ make

   or if GNU make is installed as "gmake"::

       $ gmake

   If you used a separate build directory, run make or gmake from that
   directory, e.g.::

       $ make -C _gcc
       $ make -C _clang

   For improved warnings if you installed ``sparse`` (see "Prerequisites"), add
   ``C=1`` to the command line.

   .. note::
     Some versions of Clang and ccache are not completely compatible. If you
     see unusual warnings when you use both together, consider disabling
     ccache.

2. Consider running the testsuite. Refer to **Testing** for instructions.

3. Run ``make install`` to install the executables and manpages into the
   running system, by default under ``/usr/local``::

       $ make install

5. If you built kernel modules, you may install them, e.g.::

       $ make modules_install

   It is possible that you already had a Open vSwitch kernel module installed
   on your machine that came from upstream Linux (in a different directory). To
   make sure that you load the Open vSwitch kernel module you built from this
   repository, you should create a ``depmod.d`` file that prefers your newly
   installed kernel modules over the kernel modules from upstream Linux. The
   following snippet of code achieves the same::

       $ config_file="/etc/depmod.d/openvswitch.conf"
       $ for module in datapath/linux/*.ko; do
         modname="$(basename ${module})"
         echo "override ${modname%.ko} * extra" >> "$config_file"
         echo "override ${modname%.ko} * weak-updates" >> "$config_file"
         done
       $ depmod -a

   Finally, load the kernel modules that you need. e.g.::

       $ /sbin/modprobe openvswitch

   To verify that the modules have been loaded, run ``/sbin/lsmod`` and check
   that openvswitch is listed::

       $ /sbin/lsmod | grep openvswitch

   .. note::
     If the ``modprobe`` operation fails, look at the last few kernel log
     messages (e.g. with ``dmesg | tail``). Generally, issues like this occur
     when Open vSwitch is built for a kernel different from the one into which
     you are trying to load it.  Run ``modinfo`` on ``openvswitch.ko`` and on a
     module built for the running kernel, e.g.::

         $ /sbin/modinfo openvswitch.ko
         $ /sbin/modinfo /lib/modules/$(uname -r)/kernel/net/bridge/bridge.ko

     Compare the "vermagic" lines output by the two commands.  If they differ,
     then Open vSwitch was built for the wrong kernel.

     If you decide to report a bug or ask a question related to module loading,
     include the output from the ``dmesg`` and ``modinfo`` commands mentioned
     above.

.. _general-starting:

Starting
--------

Before starting ovs-vswitchd itself, you need to start its configuration
database, ovsdb-server. Each machine on which Open vSwitch is installed should
run its own copy of ovsdb-server. Before ovsdb-server itself can be started,
configure a database that it can use::

       $ mkdir -p /usr/local/etc/openvswitch
       $ ovsdb-tool create /usr/local/etc/openvswitch/conf.db \
           vswitchd/vswitch.ovsschema

Configure ovsdb-server to use database created above, to listen on a Unix
domain socket, to connect to any managers specified in the database itself, and
to use the SSL configuration in the database::

    $ mkdir -p /usr/local/var/run/openvswitch
    $ ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
        --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
        --private-key=db:Open_vSwitch,SSL,private_key \
        --certificate=db:Open_vSwitch,SSL,certificate \
        --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
        --pidfile --detach

.. note::
  If you built Open vSwitch without SSL support, then omit ``--private-key``,
  ``--certificate``, and ``--bootstrap-ca-cert``.)

Initialize the database using ovs-vsctl. This is only necessary the first time
after you create the database with ovsdb-tool, though running it at any time is
harmless::

    $ ovs-vsctl --no-wait init

Start the main Open vSwitch daemon, telling it to connect to the same Unix
domain socket::

    $ ovs-vswitchd --pidfile --detach

Validating
----------

At this point you can use ovs-vsctl to set up bridges and other Open vSwitch
features.  For example, to create a bridge named ``br0`` and add ports ``eth0``
and ``vif1.0`` to it::

    $ ovs-vsctl add-br br0
    $ ovs-vsctl add-port br0 eth0
    $ ovs-vsctl add-port br0 vif1.0

Refer to ovs-vsctl(8) for more details.

Upgrading
---------

When you upgrade Open vSwitch from one version to another you should also
upgrade the database schema:

1. Stop the Open vSwitch daemons, e.g.::

       $ kill `cd /usr/local/var/run/openvswitch && cat ovsdb-server.pid ovs-vswitchd.pid`

2. Install the new Open vSwitch release by using the same configure options as
   was used for installing the previous version. If you do not use the same
   configure options, you can end up with two different versions of Open
   vSwitch executables installed in different locations.

3. Upgrade the database, in one of the following two ways:

   -  If there is no important data in your database, then you may delete the
      database file and recreate it with ovsdb-tool, following the instructions
      under "Building and Installing Open vSwitch for Linux, FreeBSD or NetBSD".

   -  If you want to preserve the contents of your database, back it up first,
      then use ``ovsdb-tool convert`` to upgrade it, e.g.::

          $ ovsdb-tool convert /usr/local/etc/openvswitch/conf.db \
              vswitchd/vswitch.ovsschema

4. Start the Open vSwitch daemons as described under **Starting** above.

Hot Upgrading
-------------

Upgrading Open vSwitch from one version to the next version with minimum
disruption of traffic going through the system that is using that Open vSwitch
needs some considerations:

1. If the upgrade only involves upgrading the userspace utilities and daemons
   of Open vSwitch, make sure that the new userspace version is compatible with
   the previously loaded kernel module.

2. An upgrade of userspace daemons means that they have to be restarted.
   Restarting the daemons means that the OpenFlow flows in the ovs-vswitchd
   daemon will be lost. One way to restore the flows is to let the controller
   re-populate it. Another way is to save the previous flows using a utility
   like ovs-ofctl and then re-add them after the restart. Restoring the old
   flows is accurate only if the new Open vSwitch interfaces retain the old
   'ofport' values.

3. When the new userspace daemons get restarted, they automatically flush the
   old flows setup in the kernel. This can be expensive if there are hundreds
   of new flows that are entering the kernel but userspace daemons are busy
   setting up new userspace flows from either the controller or an utility like
   ovs-ofctl. Open vSwitch database provides an option to solve this problem
   through the ``other_config:flow-restore-wait`` column of the
   ``Open_vSwitch`` table. Refer to the ovs-vswitchd.conf.db(5) manpage for
   details.

4. If the upgrade also involves upgrading the kernel module, the old kernel
   module needs to be unloaded and the new kernel module should be loaded. This
   means that the kernel network devices belonging to Open vSwitch is recreated
   and the kernel flows are lost. The downtime of the traffic can be reduced if
   the userspace daemons are restarted immediately and the userspace flows are
   restored as soon as possible.

The ovs-ctl utility's ``restart`` function only restarts the userspace daemons,
makes sure that the 'ofport' values remain consistent across restarts, restores
userspace flows using the ovs-ofctl utility and also uses the
``other_config:flow-restore-wait`` column to keep the traffic downtime to the
minimum. The ovs-ctl utility's ``force-reload-kmod`` function does all of the
above, but also replaces the old kernel module with the new one. Open vSwitch
startup scripts for Debian, XenServer and RHEL use ovs-ctl's functions and it
is recommended that these functions be used for other software platforms too.

.. _general-testing:

Testing
-------

This section describe Open vSwitch's built-in support for various test
suites. You must bootstrap, configure and build Open vSwitch (steps are
in "Building and Installing Open vSwitch for Linux, FreeBSD or NetBSD"
above) before you run the tests described here. You do not need to
install Open vSwitch or to build or load the kernel module to run these
test suites. You do not need supervisor privilege to run these test
suites.

Unit Tests
~~~~~~~~~~

Open vSwitch includes a suite of self-tests. Before you submit patches
upstream, we advise that you run the tests and ensure that they pass. If you
add new features to Open vSwitch, then adding tests for those features will
ensure your features don't break as developers modify other areas of Open
vSwitch.

To run all the unit tests in Open vSwitch, one at a time, run::

    $ make check

This takes under 5 minutes on a modern desktop system.

To run all the unit tests in Open vSwitch in parallel, run::

    $ make check TESTSUITEFLAGS=-j8

You can run up to eight threads. This takes under a minute on a modern 4-core
desktop system.

To see a list of all the available tests, run:

    $ make check TESTSUITEFLAGS=--list

To run only a subset of tests, e.g. test 123 and tests 477 through 484, run::

    $ make check TESTSUITEFLAGS='123 477-484'

Tests do not have inter-dependencies, so you may run any subset.

To run tests matching a keyword, e.g. ``ovsdb``, run::

    $ make check TESTSUITEFLAGS='-k ovsdb'

To see a complete list of test options, run::

    $ make check TESTSUITEFLAGS=--help

The results of a testing run are reported in ``tests/testsuite.log``. Report
report test failures as bugs and include the ``testsuite.log`` in your report.

.. note::
  Sometimes a few tests may fail on some runs but not others. This is usually a
  bug in the testsuite, not a bug in Open vSwitch itself. If you find that a
  test fails intermittently, please report it, since the developers may not
  have noticed. You can make the testsuite automatically rerun tests that fail,
  by adding ``RECHECK=yes`` to the ``make`` command line, e.g.::

      $ make check TESTSUITEFLAGS=-j8 RECHECK=yes

Coverage
++++++++

If the build was configured with ``--enable-coverage`` and the ``lcov`` utility
is installed, you can run the testsuite and generate a code coverage report by
using the ``check-lcoc`` target::

    $ make check-lcov

All the same options are avaiable via TESTSUITEFLAGS. For example::

    $ make check-lcov TESTSUITEFLAGS=-j8 -k ovn

Valgrind
++++++++

If you have ``valgrind`` installed, you can run the testsuite under
valgrind by using the ``check-valgrind`` target::

    $ make check-valgrind

When you do this, the "valgrind" results for test ``<N>`` are reported in files
named ``tests/testsuite.dir/<N>/valgrind.*``.

All the same options are available via TESTSUITEFLAGS.

.. hint::
  You may find that the valgrind results are easier to interpret if you put
  ``-q`` in ``~/.valgrindrc``, since that reduces the amount of output.

.. _general-oftest:

OFTest
~~~~~~

OFTest is an OpenFlow protocol testing suite. Open vSwitch includes a Makefile
target to run OFTest with Open vSwitch in "dummy mode". In this mode of
testing, no packets travel across physical or virtual networks.  Instead, Unix
domain sockets stand in as simulated networks. This simulation is imperfect,
but it is much easier to set up, does not require extra physical or virtual
hardware, and does not require supervisor privileges.

To run OFTest with Open vSwitch, first read and follow the instructions under
**Testing** above. Second, obtain a copy of OFTest and install its
prerequisites. You need a copy of OFTest that includes commit 406614846c5 (make
ovs-dummy platform work again). This commit was merged into the OFTest
repository on Feb 1, 2013, so any copy of OFTest more recent than that should
work. Testing OVS in dummy mode does not require root privilege, so you may
ignore that requirement.

Optionally, add the top-level OFTest directory (containing the ``oft`` program)
to your ``$PATH``. This slightly simplifies running OFTest later.

To run OFTest in dummy mode, run the following command from your Open vSwitch
build directory::

    $ make check-oftest OFT=<oft-binary>

where ``<oft-binary>`` is the absolute path to the ``oft`` program in OFTest.
If you added "oft" to your $PATH, you may omit the OFT variable
assignment

By default, ``check-oftest`` passes ``oft`` just enough options to enable dummy
mode. You can use ``OFTFLAGS`` to pass additional options. For example, to run
just the ``basic.Echo`` test instead of all tests (the default) and enable
verbose logging, run::

    $ make check-oftest OFT=<oft-binary> OFTFLAGS='--verbose -T basic.Echo'

If you use OFTest that does not include commit 4d1f3eb2c792 (oft: change
default port to 6653), merged into the OFTest repository in October 2013, then
you need to add an option to use the IETF-assigned controller port::

    $ make check-oftest OFT=<oft-binary> OFTFLAGS='--port=6653'

Interpret OFTest results cautiously. Open vSwitch can fail a given test in
OFTest for many reasons, including bugs in Open vSwitch, bugs in OFTest, bugs
in the "dummy mode" integration, and differing interpretations of the OpenFlow
standard and other standards.

.. note::
  Open vSwitch has not been validated against OFTest. Report test failures that
  you believe to represent bugs in Open vSwitch. Include the precise versions
  of Open vSwitch and OFTest in your bug report, plus any other information
  needed to reproduce the problem.

Ryu
~~~

Ryu is an OpenFlow controller written in Python that includes an extensive
OpenFlow testsuite. Open vSwitch includes a Makefile target to run Ryu in
"dummy mode". See **OFTest** above for an explanation of dummy mode.

To run Ryu tests with Open vSwitch, first read and follow the instructions
under **Testing** above. Second, obtain a copy of Ryu, install its
prerequisites, and build it. You do not need to install Ryu (some of the tests
do not get installed, so it does not help).

To run Ryu tests, run the following command from your Open vSwitch build
directory::

    $ make check-ryu RYUDIR=<ryu-source-dir>``

where ``<ryu-source-dir>`` is the absolute path to the root of the Ryu source
distribution. The default ``<ryu-source-dir>`` is ``$srcdir/../ryu``
where ``$srcdir`` is your Open vSwitch source directory. If this is correct,
omit ``RYUDIR``

.. note::
  Open vSwitch has not been validated against Ryu. Report test failures that
  you believe to represent bugs in Open vSwitch. Include the precise versions
  of Open vSwitch and Ryu in your bug report, plus any other information
  needed to reproduce the problem.

Datapath testing
~~~~~~~~~~~~~~~~

Open vSwitch includes a suite of tests specifically for datapath functionality,
which can be run against the userspace or kernel datapaths. If you are
developing datapath features, it is recommended that you use these tests and
build upon them to verify your implementation.

The datapath tests make some assumptions about the environment. They must be
run under root privileges on a Linux system with support for network
namespaces. For ease of use, the OVS source tree includes a vagrant box to
invoke these tests. Running the tests inside Vagrant provides kernel isolation,
protecting your development host from kernel panics or configuration conflicts
in the testsuite. If you wish to run the tests without using the vagrant box,
there are further instructions below.

Vagrant
+++++++

.. important::

  Requires Vagrant (version 1.7.0 or later) and a compatible hypervisor

.. note::
  You must **Bootstrap** and **Configure** the sources before you run the steps
  described here.

A Vagrantfile is provided allowing to compile and provision the source tree as
found locally in a virtual machine using the following command::

    $ vagrant up

This will bring up a Fedora 23 VM by default. If you wish to use a different
box or a vagrant backend not supported by the default box, the ``Vagrantfile``
can be modified to use a different box as base.

The VM can be reprovisioned at any time::

    $ vagrant provision

OVS out-of-tree compilation environment can be set up with::

    $ ./boot.sh
    $ vagrant provision --provision-with configure_ovs,build_ovs

This will set up an out-of-tree build environment inside the VM in
``/root/build``.  The source code can be found in ``/vagrant``.

To recompile and reinstall OVS in the VM using RPM::

    $ ./boot.sh
    $ vagrant provision --provision-with configure_ovs,install_rpm

Two provisioners are included to run system tests with the OVS kernel module or
with a userspace datapath. This tests are different from the self-tests
mentioned above. To run them::

    $ ./boot.sh
    $ vagrant provision --provision-with \
        configure_ovs,test_ovs_kmod,test_ovs_system_userspace

The results of the testsuite reside in the VM root user's home directory::

    $ vagrant ssh
    $ sudo -s
    $ cd /root/build
    $ ls tests/system*

Native
++++++

The datapath testsuite as invoked by Vagrant above may also be run manually on
a Linux system with root privileges. These tests may take several minutes to
complete, and cannot be run in parallel.

Userspace datapath
'''''''''''''''''''

To invoke the datapath testsuite with the userspace datapath, run::

    $ make check-system-userspace

The results of the testsuite are in ``tests/system-userspace-traffic.dir``.

Kernel datapath
'''''''''''''''

Make targets are also provided for testing the Linux kernel module. Note that
these tests operate by inserting modules into the running Linux kernel, so if
the tests are able to trigger a bug in the OVS kernel module or in the upstream
kernel then the kernel may panic.

To run the testsuite against the kernel module which is currently installed on
your system, run::

    $ make check-kernel

To install the kernel module from the current build directory and run the
testsuite against that kernel module::

    $ make check-kmod

The results of the testsuite are in ``tests/system-kmod-traffic.dir``.

Continuous Integration with Travis-CI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A .travis.yml file is provided to automatically build Open vSwitch with various
build configurations and run the testsuite using travis-ci. Builds will be
performed with gcc, sparse and clang with the -Werror compiler flag included,
therefore the build will fail if a new warning has been introduced.

The CI build is triggered via git push (regardless of the specific branch) or
pull request against any Open vSwitch GitHub repository that is linked to
travis-ci.

Instructions to setup travis-ci for your GitHub repository:

1. Go to http://travis-ci.org/ and sign in using your GitHub ID.
2. Go to the "Repositories" tab and enable the ovs repository. You may disable
   builds for pushes or pull requests.
3. In order to avoid forks sending build failures to the upstream mailing list,
   the notification email recipient is encrypted. If you want to receive email
   notification for build failures, replace the the encrypted string:

   1. Install the travis-ci CLI (Requires ruby >=2.0): gem install travis
   2. In your Open vSwitch repository: travis encrypt mylist@mydomain.org
   3. Add/replace the notifications section in .travis.yml and fill in the
      secure string as returned by travis encrypt::

          notifications:
            email:
              recipients:
                - secure: "....."

  .. note::
    You may remove/omit the notifications section to fall back to default
    notification behaviour which is to send an email directly to the author and
    committer of the failing commit. Note that the email is only sent if the
    author/committer have commit rights for the particular GitHub repository.

4. Pushing a commit to the repository which breaks the build or the
   testsuite will now trigger a email sent to mylist@mydomain.org

Static Code Analysis
~~~~~~~~~~~~~~~~~~~~

Static Analysis is a method of debugging Software by examining code rather than
actually executing it. This can be done through 'scan-build' commandline
utility which internally uses clang (or) gcc to compile the code and also
invokes a static analyzer to do the code analysis. At the end of the build, the
reports are aggregated in to a common folder and can later be analyzed using
'scan-view'.

Open vSwitch includes a Makefile target to trigger static code analysis::

    $ ./boot.sh
    $ ./configure CC=clang  # clang
    # or
    $ ./configure CC=gcc CFLAGS="-std=gnu99"  # gcc
    $ make clang-analyze

You should invoke scan-view to view analysis results. The last line of output
from ``clang-analyze`` will list the command (containing results directory)
that you should invoke to view the results on a browser.

Bug Reporting
-------------

Please report problems to bugs@openvswitch.org.
