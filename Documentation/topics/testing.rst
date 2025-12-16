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

=======
Testing
=======

It is possible to test Open vSwitch using both tooling provided with Open
vSwitch and using a variety of third party tooling.

Built-in Tooling
----------------

Open vSwitch provides a number of different test suites and other tooling for
validating basic functionality of OVS. Before running any of the tests
described here, you must bootstrap, configure and build Open vSwitch as
described in :doc:`/intro/install/general`. You do not need to install Open
vSwitch or to build or load the kernel module to run these test suites. You do
not need supervisor privilege to run these test suites.

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

To see a list of all the available tests, run::

    $ make check TESTSUITEFLAGS=--list

To run only a subset of tests, e.g. test 123 and tests 477 through 484, run::

    $ make check TESTSUITEFLAGS='123 477-484'

Tests do not have inter-dependencies, so you may run any subset.

To run tests matching a keyword, e.g. ``ovsdb``, run::

    $ make check TESTSUITEFLAGS='-k ovsdb'

To see a complete list of test options, run::

    $ make check TESTSUITEFLAGS=--help

The results of a testing run are reported in ``tests/testsuite.log``. Report
test failures as bugs and include the ``testsuite.log`` in your report.

.. note::
  Sometimes a few tests may fail on some runs but not others. This is usually a
  bug in the testsuite, not a bug in Open vSwitch itself. If you find that a
  test fails intermittently, please report it, since the developers may not
  have noticed. You can make the testsuite automatically rerun tests that fail,
  by adding ``RECHECK=yes`` to the ``make`` command line, e.g.::

      $ make check TESTSUITEFLAGS=-j8 RECHECK=yes

Debugging unit tests
++++++++++++++++++++

To initiate debugging from artifacts generated from `make check` run, set the
``OVS_PAUSE_TEST`` environment variable to 1.  For example, to run test case
139 and pause on error::

  $ OVS_PAUSE_TEST=1 make check TESTSUITEFLAGS='-v 139'

When error occurs, above command would display something like this::

   Set environment variable to use various ovs utilities
   export OVS_RUNDIR=<dir>/ovs/_build-gcc/tests/testsuite.dir/0139
   Press ENTER to continue:

And from another window, one can execute ovs-xxx commands like::

   export OVS_RUNDIR=/opt/vdasari/Developer/ovs/_build-gcc/tests/testsuite.dir/0139
   $ ovs-ofctl dump-ports br0
   .
   .

Once done with investigation, press ENTER to perform cleanup operation.

.. _testing-coverage:

Coverage
~~~~~~~~

If the build was configured with ``--enable-coverage`` and the ``lcov`` utility
is installed, you can run the testsuite and generate a code coverage report by
using the ``check-lcov`` target::

    $ make check-lcov

All the same options are available via TESTSUITEFLAGS. For example::

    $ make check-lcov TESTSUITEFLAGS='-j8 -k ovsdb'

.. _testing-valgrind:

Valgrind
~~~~~~~~

If you have ``valgrind`` installed, you can run the testsuite under
valgrind by using the ``check-valgrind`` target::

    $ make check-valgrind

When you do this, the "valgrind" results for test ``<N>`` are reported in files
named ``tests/testsuite.dir/<N>/valgrind.*``.

To test the testsuite of kernel datapath under valgrind, you can use the
``check-kernel-valgrind`` target and find the "valgrind" results under
directory ``tests/system-kmod-testsuite.dir/``.

All the same options are available via TESTSUITEFLAGS.

.. hint::
  You may find that the valgrind results are easier to interpret if you put
  ``-q`` in ``~/.valgrindrc``, since that reduces the amount of output.

OFTest
~~~~~~

OFTest is an OpenFlow protocol testing suite. Open vSwitch includes a Makefile
target to run OFTest with Open vSwitch in "dummy mode". In this mode of
testing, no packets travel across physical or virtual networks.  Instead, Unix
domain sockets stand in as simulated networks. This simulation is imperfect,
but it is much easier to set up, does not require extra physical or virtual
hardware, and does not require supervisor privileges.

To run OFTest with Open vSwitch, you must obtain a copy of OFTest and install
its prerequisites. You need a copy of OFTest that includes commit 406614846c5
(make ovs-dummy platform work again). This commit was merged into the OFTest
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
"dummy mode". See `OFTest`_ above for an explanation of dummy mode.

To run Ryu tests with Open vSwitch, first read and follow the instructions
under **Testing** above. Second, obtain a copy of Ryu, install its
prerequisites, and build it. You do not need to install Ryu (some of the tests
do not get installed, so it does not help).

To run Ryu tests, run the following command from your Open vSwitch build
directory::

    $ make check-ryu RYUDIR=<ryu-source-dir>

where ``<ryu-source-dir>`` is the absolute path to the root of the Ryu source
distribution. The default ``<ryu-source-dir>`` is ``$srcdir/../ryu``
where ``$srcdir`` is your Open vSwitch source directory. If this is correct,
omit ``RYUDIR``

.. note::
  Open vSwitch has not been validated against Ryu. Report test failures that
  you believe to represent bugs in Open vSwitch. Include the precise versions
  of Open vSwitch and Ryu in your bug report, plus any other information
  needed to reproduce the problem.

.. _datapath-testing:

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
  You must bootstrap and configure the sources (see
  doc:`/intro/install/general`) before you run the steps described
  here.

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
a Linux system with root privileges. Make sure, no other Open vSwitch instance
is running on the test suite. These tests may take several minutes to complete,
and cannot be run in parallel.

Userspace datapath
'''''''''''''''''''

To invoke the datapath testsuite with the userspace datapath, run::

    $ make check-system-userspace

The results of the testsuite are in ``tests/system-userspace-testsuite.dir``.

All the features documented under `Unit Tests`_ are available for the userspace
datapath testsuite.

Userspace datapath with DPDK
''''''''''''''''''''''''''''

To test :doc:`/intro/install/dpdk` (i.e., the build was configured with
``--with-dpdk``, the DPDK is installed), run the testsuite and generate
a report by using the ``check-dpdk`` target::

    # make check-dpdk

or if you are not a root, but a sudo user::

    $ sudo -E make check-dpdk

To see a list of all the available tests, run::

    # make check-dpdk TESTSUITEFLAGS=--list

These tests support a `DPDK supported NIC`_. The tests operate on a wider set of
environments, for instance, when a virtual port is used.
Moreover you need to have root privileges to load the required modules and to bind
a PCI device to the DPDK-compatible driver.

.. _DPDK supported NIC: https://core.dpdk.org/supported/#nics

The phy test will skip if no suitable PCI device is found.
It is possible to select which PCI device is used for this test by setting the
DPDK_PCI_ADDR environment variable, which is especially useful when testing
with a mlx5 device::

    # DPDK_PCI_ADDR=0000:82:00.0 make check-dpdk

All tests are skipped if no hugepages are configured. User must look into the DPDK
manual to figure out how to `Configure hugepages`_.

.. _Configure hugepages: https://doc.dpdk.org/guides-25.11/linux_gsg/sys_reqs.html

All the features documented under `Unit Tests`_ are available for the DPDK
testsuite.

Userspace datapath: Testing and Validation of CPU-specific Optimizations
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

.. note::
  The AVX512 CPU-specific optimization features are deprecated and will be
  removed in a future release.

As multiple versions of the datapath classifier, packet parsing functions and
actions can co-exist, each with different CPU ISA optimizations, it is
important to validate that they all give the exact same results.  To easily
test all the implementations, an ``autovalidator`` implementation of them
exists. This implementation runs all other available implementations, and
verifies that the results are identical.

Running the OVS unit tests with the autovalidator enabled ensures all
implementations provide the same results.  Note that the performance of the
autovalidator is lower than all other implementations, as it tests the scalar
implementation against itself, and against all other enabled implementations.

To adjust the autovalidator priority for a datapath classifier, use this
command::

    $ ovs-appctl dpif-netdev/subtable-lookup-prio-set autovalidator 7

To set the autovalidator for the packet parser, use this command::

    $ ovs-appctl dpif-netdev/miniflow-parser-set autovalidator

To set the autovalidator for actions, use this command::

    $ ovs-appctl odp-execute/action-impl-set autovalidator

To run the OVS unit test suite with the autovalidator as the default
implementation, it is required to recompile OVS.  During the recompilation,
the default priority of the `autovalidator` implementation is set to the
maximum priority, ensuring every test will be run with every implementation.
Priority is only related to mfex autovalidator and not the actions
autovalidator.::

    $ ./configure --enable-autovalidator --enable-mfex-default-autovalidator \
        --enable-actions-default-autovalidator

The following line should be seen in the configuration log when the above
options are used::

    checking whether DPCLS Autovalidator is default implementation... yes
    checking whether MFEX Autovalidator is default implementation... yes
    checking whether actions Autovalidator is default implementation... yes

Compile OVS in debug mode to have `ovs_assert` statements error out if
there is a mismatch in the datapath classifier lookup or packet parser
implementations.

Since the AVX512 implementation of the datapath interface is disabled by
default, a compile time option is available in order to test it with the OVS
unit test suite::

    $ ./configure --enable-dpif-default-avx512

The following line should be seen in the configuration log when the above
option is used::

    checking whether DPIF AVX512 is default implementation... yes

.. note::
  Run all the available testsuites including `make check`,
  `make check-system-userspace` and `make check-dpdk` to ensure the optimal
  test coverage.

Kernel datapath
'''''''''''''''

Make targets are also provided for testing the Linux kernel module. Note that
these tests operate by inserting modules into the running Linux kernel, so if
the tests are able to trigger a bug in the OVS kernel module or in the upstream
kernel then the kernel may panic.

To run the testsuite against the kernel module which is currently installed on
your system, run::

    $ make check-kernel

All the features documented under `Unit Tests`_ are available for the kernel
datapath testsuite.

.. note::
  Many of the kernel tests are dependent on the utilities present in the
  iproute2 package, especially the 'ip' command.  If there are many
  otherwise unexplained errors it may be necessary to update the iproute2
  package utilities on the system.  It is beyond the scope of this
  documentation to explain all that is necessary to build and install
  an updated iproute2 utilities package.  The package is available from
  the Linux kernel organization open source git repositories.

  https://git.kernel.org/pub/scm/network/iproute2/iproute2.git

It is also possible to run `retis`_ capture along with the `check-kernel` and
`check-offloads` tests by setting `OVS_TEST_WITH_RETIS` environment variable
to 'yes'.  This can be useful for debugging the test cases.  For example, the
following command can be used to run the test 167 under `retis`::

    $ make check-kernel OVS_TEST_WITH_RETIS=yes TESTSUITEFLAGS='167 -d'

After the test is completed, the following data will be available in the test
directory:

* `retis.err` - standard error stream of the `retis collect`.
* `retis.log` - standard output of the `retis collect`, contains all captured
  events in the order they appeared.
* `retis.data` - raw events collected by retis, `retis sort` or other commands
  can be used on this file for further analysis.
* `retis.sorted` - text file containing the output of `retis sort` executed on
  the `retis.data`, for convenience.

Requires retis version 1.5 or newer and enabling support for
:doc:`/topics/usdt-probes`.

.. _retis: https://github.com/retis-org/retis

.. _testing-static-analysis:

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

ViNePerf
--------

The ViNePerf project, formerly known as VswitchPerf or vsperf, aims to
develop a vSwitch test framework that can be used to validate the
suitability of different vSwitch implementations in a telco deployment
environment. More information can be found on the `Anuket project wiki`_.

.. _Anuket project wiki: https://wiki.anuket.io/display/HOME/ViNePERF

Proof of Concepts
~~~~~~~~~~~~~~~~~

Proof of Concepts are documentation materialized into Ansible recipes
executed in VirtualBox or Libvirt environments orchestrated by Vagrant.
Proof of Concepts allow developers to create small virtualized setups that
demonstrate how certain Open vSwitch features are intended to work avoiding
user introduced errors by overlooking instructions.  Proof of Concepts
are also helpful when integrating with thirdparty software, because standard
unit tests with make check are limited.

Vagrant by default uses VirtualBox provider.  However, if Libvirt is your
choice of virtualization technology, then you can use it by installing Libvirt
plugin::

    $ vagrant plugin install vagrant-libvirt

And then appending ``--provider=libvirt`` flag to vagrant commands.

The host where Vagrant runs does not need to have any special software
installed besides vagrant, virtualbox (or libvirt and libvirt-dev) and
ansible.

The following Proof of Concepts are supported:

Builders
++++++++

This particular Proof of Concept demonstrates integration with Debian and RPM
packaging tools::

    $ cd ./poc/builders
    $ vagrant up

Once that command finished you can get packages from ``/var/www/html``
directory.  Since those hosts are also configured as repositories then
you can add them to ``/etc/apt/sources.list.d`` or ``/etc/yum.repos.d``
configuration files on another host to retrieve packages with yum or
apt-get.

When you have made changes to OVS source code and want to rebuild packages
run::

    $ git commit -a
    $ vagrant rsync && vagrant provision

Whenever packages are rebuilt the Open vSwitch release number increases
by one and you can simply upgrade Open vSwitch by running ``yum`` or
``apt-get`` update commands.

Once you are done with experimenting you can tear down setup with::

    $ vagrant destroy

Sometimes deployment of Proof of Concept may fail, if, for example, VMs
don't have network reachability to the Internet.
