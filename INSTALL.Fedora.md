How to Install Open vSwitch on Fedora Linux
===========================================

This document provides instructions for building and installing Open vSwitch
RPM packages on a Fedora Linux host.  Instructions for the installation of
Open vSwitch on a Fedora Linux host without using RPM packages can be found
in [INSTALL.md].

These instructions have been tested with Fedora 23, and are also applicable
for RHEL 7.x and its derivatives, including CentOS 7.x and Scientific Linux
7.x.

Build Requirements
------------------
The tools and packages that are required for building Open vSwitch are
documented in [INSTALL.md]. Specific packages (by package name) include:

  - rpm-build
  - autoconf automake libtool
  - systemd-units openssl openssl-devel
  - python python-twisted-core python-zope-interface python-six
  - desktop-file-utils
  - groff graphviz
  - procps-ng
  - checkpolicy selinux-policy-devel

And (optionally):

  - libcap-ng libcap-ng-devel
  - dpdk-devel

Building Open vSwitch RPMs for Fedora
-------------------------------------

RPMs may be built from an Open vSwitch distribution tarball or from an
Open vSwitch Git tree. The build procedure for each scenario is described
below.

### Preparing to Build Open vSwitch RPMs with a GIT Tree
From the top-level directory of the git tree, execute the following
commands:

```
./boot.sh
./configure
```

### Preparing to Build Open vSwitch RPMs from a Tarball
From a directory with appropriate permissions, execute the following commands
(substituting the relevant Open vSwitch release version for "x.y.z"):

```
tar xzf openvswitch-x.y.z.tar.gz
cd openvswitch-x.y.z
./configure
```

### Building the User-Space RPMs
To build Open vSwitch user-space RPMs, after having completed the appropriate
preparation steps described above, execute the following from the directory
in which `./configure` was executed:

```
make rpm-fedora
```

This will create the RPMs `openvswitch`, `python-openvswitch`,
`openvswitch-test`, `openvswitch-devel`, `openvswitch-ovn-common`,
`openvswitch-ovn-central`, `openvswitch-ovn-host`, `openvswitch-ovn-vtep`,
`openvswitch-ovn-docker`, and `openvswitch-debuginfo`.

To enable DPDK support in the openvswitch package,
the `--with dpdk` option can be added:

```
make rpm-fedora RPMBUILD_OPT="--with dpdk"
```

The above commands automatically run the Open vSwitch unit tests,
which can take several minutes.  To reduce the build time by
disabling the execution of these tests, the `--without check`
option can be added:

```
make rpm-fedora RPMBUILD_OPT="--without check"
```

### Building the Kernel OVS Tree Datapath RPM
To build the Open vSwitch kernel module for the currently running
kernel version, execute:

```
make rpm-fedora-kmod
```

To build the Open vSwitch kernel module for another kernel version,
the desired kernel version can be specified via the `kversion` macro.
For example:

```
make rpm-fedora-kmod \
     RPMBUILD_OPT='-D "kversion 4.3.4-300.fc23.x86_64"'
```

Installing Open vSwitch RPMs
----------------------------
RPM packages can be installed by using the command `rpm -i`. Package
installation requires superuser privileges.

The openvswitch-kmod RPM should be installed first if the Linux OVS tree datapath
module is to be used. The openvswitch-kmod RPM should not be installed if
only the in-tree Linux datapath or user-space datapath is needed. See [FAQ.md]
for more information about the various Open vSwitch datapath options.

In most cases only the `openvswitch` RPM will need to be installed. The
`python-openvswitch`, `openvswitch-test`, `openvswitch-devel`, and
`openvswitch-debuginfo` RPMs are optional unless required for a specific
purpose.

The `openvswitch-ovn-*` packages are only needed when using OVN.

See [rhel/README.RHEL] for additional usage and configuration information.

Reporting Bugs
--------------

Please report problems to bugs@openvswitch.org.

[INSTALL.md]:INSTALL.md
[FAQ.md]:FAQ.md
[README.RHEL]:rhel/README.RHEL
