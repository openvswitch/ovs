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

=================================
Debian Packaging for Open vSwitch
=================================

This document describes how to build Debian packages for Open vSwitch. To
install Open vSwitch on Debian without building Debian packages, refer to
:doc:`general` instead.

.. note::
  These instructions should also work on Ubuntu and other Debian derivative
  distributions.

Before You Begin
----------------

Before you begin, consider whether you really need to build packages yourself.
Debian "wheezy" and "sid", as well as recent versions of Ubuntu, contain
pre-built Debian packages for Open vSwitch. It is easier to install these than
to build your own. To use packages from your distribution, skip ahead to
"Installing .deb Packages", below.

Building Open vSwitch Debian packages
-------------------------------------

You may build from an Open vSwitch distribution tarball or from an Open vSwitch
Git tree with these instructions.

You do not need to be the superuser to build the Debian packages.

1. Install the "build-essential" and "fakeroot" packages. For example::

       $ apt-get install build-essential fakeroot

2. Obtain and unpack an Open vSwitch source distribution and ``cd`` into its
   top level directory.

3. Install the build dependencies listed under "Build-Depends:" near the top of
   ``debian/control``. You can install these any way you like, e.g.  with
   ``apt-get install``.

Check your work by running ``dpkg-checkbuilddeps`` in the top level of your ovs
directory. If you've installed all the dependencies properly,
``dpkg-checkbuilddeps`` will exit without printing anything. If you forgot to
install some dependencies, it will tell you which ones.

4. Build the package::

       $ fakeroot debian/rules binary

   This will do a serial build that runs the unit tests. This will take
   approximately 8 to 10 minutes. If you prefer, you can run a faster parallel
   build::

       $ DEB_BUILD_OPTIONS='parallel=8' fakeroot debian/rules binary

   If you are in a big hurry, you can even skip the unit tests::

       $ DEB_BUILD_OPTIONS='parallel=8 nocheck' fakeroot debian/rules binary

.. note::

  There are a few pitfalls in the Debian packaging building system so that,
  occasionally, you may find that in a tree that you have using for a while,
  the build command above exits immediately without actually building anything.
  To fix the problem, run::

      $ fakeroot debian/rules clean

  or start over from a fresh copy of the source tree.

5. The generated .deb files will be in the parent directory of the Open vSwitch
   source distribution.

Installing .deb Packages
------------------------

These instructions apply to installing from Debian packages that you built
yourself, as described in the previous section.  In this case, use a command
such as ``dpkg -i`` to install the .deb files that you build.  You will have to
manually install any missing dependencies.

You can also use these instruction to install from packages provided by Debian
or a Debian derivative distribution such as Ubuntu.  In this case, use a
program such as ``apt-get`` or ``aptitude`` to download and install the
provided packages.  These programs will also automatically download and install
any missing dependencies.

.. important::
  You must be superuser to install Debian packages.

1. Start by installing an Open vSwitch kernel module. See
   ``debian/openvswitch-switch.README.Debian`` for the available options.

2. Install the ``openvswitch-switch`` and ``openvswitch-common`` packages.
   These packages include the core userspace components of the switch.

Open vSwitch ``.deb`` packages not mentioned above are rarely useful. Refer to
their individual package descriptions to find out whether any of them are
useful to you.

Reporting Bugs
--------------

Report problems to bugs@openvswitch.org.
