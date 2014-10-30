How to Build Debian Packages for Open vSwitch
=============================================

This document describes how to build Debian packages for Open vSwitch.
To install Open vSwitch on Debian without building Debian packages,
see [INSTALL.md] instead.

These instructions should also work on Ubuntu and other Debian
derivative distributions.


Before You Begin
----------------

Before you begin, consider whether you really need to build packages
yourself.  Debian "wheezy" and "sid", as well as recent versions of
Ubuntu, contain pre-built Debian packages for Open vSwitch.  It is
easier to install these than to build your own.  To use packages from
your distribution, skip ahead to "Installing .deb Packages", below.


Building Open vSwitch Debian packages
-------------------------------------

You may build from an Open vSwitch distribution tarball or from an
Open vSwitch Git tree with these instructions.

You do not need to be the superuser to build the Debian packages.

1. Install the "build-essential" and "fakeroot" packages, e.g. with
   `apt-get install build-essential fakeroot`.

2. Obtain and unpack an Open vSwitch source distribution and `cd` into
   its top level directory.

3. Install the build dependencies listed under "Build-Depends:" near
   the top of debian/control.  You can install these any way you like,
   e.g. with `apt-get install`.

   Check your work by running `dpkg-checkbuilddeps` in the top level of
   your ovs directory.  If you've installed all the dependencies
   properly, dpkg-checkbuilddeps will exit without printing anything.
   If you forgot to install some dependencies, it will tell you which ones.

4. Run:

       `fakeroot debian/rules binary`

   This will do a serial build that runs the unit tests. This will take
   approximately 8 to 10 minutes. If you prefer, you can run a faster
   parallel build, e.g.:

       `DEB_BUILD_OPTIONS='parallel=8' fakeroot debian/rules binary`

   If you are in a big hurry, you can even skip the unit tests:

       `DEB_BUILD_OPTIONS='parallel=8 nocheck' fakeroot debian/rules binary`

5. The generated .deb files will be in the parent directory of the
   Open vSwitch source distribution.


Installing .deb Packages
------------------------

These instructions apply to installing from Debian packages that you
built yourself, as described in the previous section, or from packages
provided by Debian or a Debian derivative distribution such as Ubuntu.
In the former case, use a command such as `dpkg -i` to install the
.deb files that you build, and in the latter case use a program such
as `apt-get` or `aptitude` to download and install the provided
packages.

You must be superuser to install Debian packages.

1. Start by installing an Open vSwitch kernel module.  See
   debian/openvswitch-switch.README.Debian for the available options.

2. Install the "openvswitch-switch" and "openvswitch-common" packages.
   These packages include the core userspace components of the switch.

Open vSwitch .deb packages not mentioned above are rarely useful.
Please refer to their individual package descriptions to find out
whether any of them are useful to you.


Bug Reporting
-------------

Please report problems to bugs@openvswitch.org.

[INSTALL.md]:INSTALL.md
