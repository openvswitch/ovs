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
report test failures as bugs and include the ``testsuite.log`` in your report.

.. note::
  Sometimes a few tests may fail on some runs but not others. This is usually a
  bug in the testsuite, not a bug in Open vSwitch itself. If you find that a
  test fails intermittently, please report it, since the developers may not
  have noticed. You can make the testsuite automatically rerun tests that fail,
  by adding ``RECHECK=yes`` to the ``make`` command line, e.g.::

      $ make check TESTSUITEFLAGS=-j8 RECHECK=yes

.. _testing-coverage:

Coverage
~~~~~~~~

If the build was configured with ``--enable-coverage`` and the ``lcov`` utility
is installed, you can run the testsuite and generate a code coverage report by
using the ``check-lcov`` target::

    $ make check-lcov

All the same options are avaiable via TESTSUITEFLAGS. For example::

    $ make check-lcov TESTSUITEFLAGS='-j8 -k ovn'

.. _testing-valgrind:

Valgrind
~~~~~~~~

If you have ``valgrind`` installed, you can run the testsuite under
valgrind by using the ``check-valgrind`` target::

    $ make check-valgrind

When you do this, the "valgrind" results for test ``<N>`` are reported in files
named ``tests/testsuite.dir/<N>/valgrind.*``.

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

Continuous Integration with Travis CI
-------------------------------------

A .travis.yml file is provided to automatically build Open vSwitch with various
build configurations and run the testsuite using Travis CI. Builds will be
performed with gcc, sparse and clang with the -Werror compiler flag included,
therefore the build will fail if a new warning has been introduced.

The CI build is triggered via git push (regardless of the specific branch) or
pull request against any Open vSwitch GitHub repository that is linked to
travis-ci.

Instructions to setup travis-ci for your GitHub repository:

1. Go to https://travis-ci.org/ and sign in using your GitHub ID.
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

vsperf
------

The vsperf project aims to develop a vSwitch test framework that can be used to
validate the suitability of different vSwitch implementations in a telco
deployment environment. More information can be found on the `OPNFV wiki`_.

.. _OPNFV wiki: https://wiki.opnfv.org/display/vsperf/VSperf+Home
