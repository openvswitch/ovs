How to Install Open vSwitch on Fedora Linux
===========================================

This document describes how to build and install Open vSwitch on a Fedora
Linux host.  If you want to install Open vSwitch on a generic Linux host,
see [INSTALL.md] instead.

We have tested these instructions with Fedora 16 and Fedora 17.

Building Open vSwitch for Fedora
--------------------------------

You may build from an Open vSwitch distribution tarball or from an
Open vSwitch Git tree.

The default RPM build directory (_topdir) has five directories in
the top-level:
1. BUILD/ Where the software is unpacked and built.
2. RPMS/ Where the newly created binary package files are written.
3. SOURCES/ Contains the original sources, patches, and icon files.
4. SPECS/ Contains the spec files for each package to be built.
5. SRPMS/ Where the newly created source package files are written.

Before you begin, note the RPM sources directory on your version of
Fedora.  The command "rpmbuild --showrc" will show the configuration
for each of those directories. Alternatively, the command "rpm --eval
 '%{_topdir}'" shows the current configuration for the top level
directory and the command "rpm --eval '%{_sourcedir}'" does the same
for the sources directory.  On Fedora 17, the default RPM _topdir is
$HOME/rpmbuild and the default RPM sources directory is
$HOME/rpmbuild/SOURCES.

1. If you are building from a distribution tarball, skip to step 2.
   Otherwise, you must be building from an Open vSwitch Git tree.
   Create a distribution tarball from the root of the Git tree by
   running:

       ```
       ./boot.sh
       ./configure
       make dist
	   ```

2. Now you have a distribution tarball, named something like
   openvswitch-x.y.z.tar.gz.  Copy this file into the RPM sources
   directory, e.g.:

       `cp openvswitch-x.y.z.tar.gz $HOME/rpmbuild/SOURCES`

3. Make another copy of the distribution tarball in a temporary
   directory.  Then unpack the tarball and "cd" into its root, e.g.:

       ```
       tar xzf openvswitch-x.y.z.tar.gz
       cd openvswitch-x.y.z
	   ```

4. To build Open vSwitch userspace, run:

       `rpmbuild -bb rhel/openvswitch-fedora.spec`

   This produces one RPM: "openvswitch".

   The above command automatically runs the Open vSwitch unit tests.
   To disable the unit tests, run:

       `rpmbuild -bb --without check rhel/openvswitch-fedora.spec`

5. On Fedora 17, to build the Open vSwitch kernel module, run:

	`rpmbuild -bb rhel/openvswitch-kmod-fedora.spec`

    You might have to specify a kernel version and/or variants, e.g.:

	```
	rpmbuild -bb \
		-D "kversion 2.6.32-131.6.1.el6.x86_64" \
		-D "kflavors default debug kdump" \
		rhel/openvswitch-kmod-rhel6.spec
	```

    This produces an "kmod-openvswitch" RPM for each kernel variant,
    in this example: "kmod-openvswitch", "kmod-openvswitch-debug", and
    "kmod-openvswitch-kdump".

Reporting Bugs
--------------

Please report problems to bugs@openvswitch.org.

[INSTALL.md]:INSTALL.md
