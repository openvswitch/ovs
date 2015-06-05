How to Build the Kernel module & userspace daemons for Windows
==============================================================

Autoconf, Automake and Visual C++:
---------------------------------
Open vSwitch on Linux uses autoconf and automake for generating Makefiles.
It will be useful to maintain the same build system while compiling on Windows
too.  One approach is to compile Open vSwitch in a MinGW environment that
contains autoconf and automake utilities and then use Visual C++ as a compiler
and linker.

The following explains the steps in some detail.

* Install Mingw on a Windows machine by following the instructions at:
http://www.mingw.org/wiki/Getting_Started

This should install mingw at C:\Mingw and msys at C:\Mingw\msys.
Add "C:\MinGW\bin" and "C:\Mingw\msys\1.0\bin" to PATH environment variable
of Windows.

You can either use the MinGW installer or the command line utility 'mingw-get'
to install both the base packages and additional packages like automake and
autoconf(version 2.68).

Also make sure that /mingw mount point exists. If its not, please add/create
the following entry in /etc/fstab - 'C:/MinGW /mingw'.

* Install the latest Python 2.x from python.org and verify that its path is
part of Windows' PATH environment variable.

* You will need at least Visual Studio 2013 to compile userspace binaries. In
addition to that, if you want to compile the kernel module you will also need to
install Windows Driver Kit (WDK) 8.1 Update.

It is important to get the Visual Studio related environment variables and to
have the $PATH inside the bash to point to the proper compiler and linker. One
easy way to achieve this is to get into the "Developer Command prompt for visual
studio" and through it enter into the bash shell available from msys by typing
'bash --login'.

If after the above step, a 'which link' inside MSYS's bash says,
"/bin/link.exe", rename /bin/link.exe to something else so that the
Visual studio's linker is used. You should also see a 'which sort' report
"/bin/sort.exe".

* For pthread support, install the library, dll and includes of pthreads-win32
project from
ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-9-1-release to a
directory (e.g.: C:/pthread). You should add the pthread-win32's dll
path (e.g.: C:\pthread\dll\x86) to the Windows' PATH environment variable.

* Get the Open vSwitch sources from either cloning the repo using git
or from a distribution tar ball.

* If you pulled the sources directly from an Open vSwitch Git tree,
  run boot.sh in the top source directory:

    % ./boot.sh

* In the top source directory, configure the package by running the
  configure script.  You should provide some configure options to choose
  the right compiler, linker, libraries, Open vSwitch component installation
  directories, etc. For example,

    % ./configure CC=./build-aux/cccl LD="`which link`" \
      LIBS="-lws2_32 -liphlpapi" --prefix="C:/openvswitch/usr" \
      --localstatedir="C:/openvswitch/var" --sysconfdir="C:/openvswitch/etc" \
       --with-pthread="C:/pthread"

    By default, the above enables compiler optimization for fast code.
    For default compiler optimization, pass the "--with-debug" configure
    option.

* Run make for the ported executables in the top source directory, e.g.:

    % make

  For faster compilation, you can pass the '-j' argument to make.  For
  example, to run 4 jobs simultaneously, run 'make -j4'.

  Note: MSYS 1.0.18 has a bug that causes parallel make to hang. You
  can overcome this by downgrading to MSYS 1.0.17.  A simple way to
  downgrade is to exit all MinGW sessions and then run the command
  'mingw-get upgrade msys-core-bin=1.0.17-1' from MSVC developers command
  prompt.

* To run all the unit tests in Open vSwitch, one at a time:

    % make check

  To run all the unit tests in Open vSwitch, up to 8 in parallel:

    % make check TESTSUITEFLAGS="-j8"

* To install all the compiled executables on the local machine, run:

    % make install

  The above command will install the Open vSwitch executables in
  C:/openvswitch.  You can add 'C:\openvswitch\usr\bin' and
  'C:\openvswitch\usr\sbin' to Windows' PATH environment variable
  for easy access.

OpenSSL, Open vSwitch and Visual C++
------------------------------------
To get SSL support for Open vSwitch on Windows, do the following:

* Install OpenSSL for Windows as suggested at
http://www.openssl.org/related/binaries.html.
The link as of this writing suggests to download it from
http://slproweb.com/products/Win32OpenSSL.html

Note down the directory where OpenSSL is installed (e.g.: C:/OpenSSL-Win32).

* While configuring the package, specify the OpenSSL directory path.
For example,

    % ./configure CC=./build-aux/cccl LD="`which link`"  \
    LIBS="-lws2_32 -liphlpapi" --prefix="C:/openvswitch/usr" \
    --localstatedir="C:/openvswitch/var" --sysconfdir="C:/openvswitch/etc" \
    --with-pthread="C:/pthread" --enable-ssl --with-openssl="C:/OpenSSL-Win32"

* Run make for the ported executables.

Building the Kernel datapath module
-----------------------------------
* We directly use the Visual Studio 2013 IDE to compile the kernel datapath.
You can open the extensions.sln file in the IDE and build the solution.

* The kernel datapath can be compiled from command line as well.  The top
level 'make' will invoke building the kernel datapath, if the
'--with-vstudiotarget' argument is specified while configuring the package.
For example,

    % ./configure CC=./build-aux/cccl LD="`which link`" \
    LIBS="-lws2_32 -liphlpapi" --prefix="C:/openvswitch/usr" \
    --localstatedir="C:/openvswitch/var" --sysconfdir="C:/openvswitch/etc" \
    --with-pthread="C:/pthread" --enable-ssl \
    --with-openssl="C:/OpenSSL-Win32" --with-vstudiotarget="<target type>"

    Possible values for "<target type>" are:
    "Debug" and "Release"

Installing the Kernel module
----------------------------
Once you have built the solution, you can copy the following files to the
target Hyper-V machines.

    ./datapath-windows/x64/Win8.1Debug/package/ovsext.inf
    ./datapath-windows/x64/Win8.1Debug/package/OVSExt.sys
    ./datapath-windows/x64/Win8.1Debug/package/ovsext.cat
    ./datapath-windows/misc/install.cmd
    ./datapath-windows/misc/uninstall.cmd

The above path assumes that the kernel module has been built using Windows
DDK 8.1 in Debug mode. Change the path appropriately, if a different WDK
has been used.

Steps to install the module
---------------------------

01> Run ./uninstall.cmd to remove the old extension.

02> Run ./install.cmd to insert the new one.  For this to work you will have to
turn on TESTSIGNING boot option or 'Disable Driver Signature Enforcement'
during boot.  The following commands can be used:
    % bcdedit /set LOADOPTIONS DISABLE_INTEGRITY_CHECKS
    % bcdedit /set TESTSIGNING ON
    % bcdedit /set nointegritychecks ON

Note: you may have to restart the machine for the settings to take effect.

03> In the Virtual Switch Manager configuration you can enable the Open vSwitch
Extension on an existing switch or create a new switch.  If you are using an
existing switch, make sure to enable the "Allow Management OS" option for VXLAN
to work (covered later).

The command to create a new switch named 'OVS-Extended-Switch' using a physical
NIC named 'Ethernet 1' is:
    % New-VMSwitch "OVS-Extended-Switch" -AllowManagementOS $true \
                   -NetAdapterName "Ethernet 1"

Note: you can obtain the list of physical NICs on the host using
'Get-NetAdapter' command.

04> In the properties of any switch, you should should now see "Open
vSwitch Extension" under 'Extensions'.  Click the check box to enable the
extension.  An alternative way to do the same is to run the following command:
    % Enable-VMSwitchExtension "Open vSwitch Extension" OVS-Extended-Switch

Note: If you enabled the extension using the command line, a delay of a few
seconds has been observed for the change to be reflected in the UI.  This is
not a bug in Open vSwitch.

Steps to run the user processes & configure ports
-------------------------------------------------
The following steps assume that you have installed the Open vSwitch
utilities in the local machine via 'make install'.

01> Create the database.
    % ovsdb-tool create C:\openvswitch\etc\openvswitch\conf.db \
        C:\openvswitch\usr\share\openvswitch\vswitch.ovsschema

02> Start the ovsdb-server and initialize the database.
    % ovsdb-server -vfile:info --remote=punix:db.sock --log-file --pidfile \
        --detach
    % ovs-vsctl --no-wait init

    If you would like to terminate the started ovsdb-server, run:
    % ovs-appctl -t ovsdb-server exit

    (Note that the logfile is created at C:/openvswitch/var/log/openvswitch/)

03> Start ovs-vswitchd.
    % ovs-vswitchd -vfile:info --log-file --pidfile --detach

    If you would like to terminate the started ovs-vswitchd, run:
    % ovs-appctl exit

    (Note that the logfile is created at C:/openvswitch/var/log/openvswitch/)

04> Create integration bridge & pif bridge
    % ovs-vsctl add-br br-int
    % ovs-vsctl add-br br-pif

NOTE: There's a known bug that running the ovs-vsctl command does not
terminate.  This is generally solved by having ovs-vswitchd running.  If
you face the issue despite that, hit Ctrl-C to terminate ovs-vsctl and
check the output to see if your command succeeded.

NOTE: There's a known bug that the ports added to OVSDB via ovs-vsctl don't
get to the kernel datapath immediately, ie. they don't show up in the output of
"ovs-dpctl show" even though they show up in output of "ovs-vsctl show".
In order to workaround this issue, restart ovs-vswitchd. (You can terminate
ovs-vswitchd by running 'ovs-appctl exit'.)

05> Dump the ports in the kernel datapath
    % ovs-dpctl show

* Sample output is as follows:

    % ovs-dpctl show
    system@ovs-system:
            lookups: hit:0 missed:0 lost:0
            flows: 0
            port 2: br-pif (internal)     <<< internal port on 'br-pif' bridge
            port 1: br-int (internal)     <<< internal port on 'br-int' bridge

06> Dump the ports in the OVSDB
    % ovs-vsctl show

* Sample output is as follows:
    % ovs-vsctl show
    a56ec7b5-5b1f-49ec-a795-79f6eb63228b
        Bridge br-pif
            Port br-pif
                Interface br-pif
                    type: internal
        Bridge br-int
            Port br-int
                Interface br-int
                    type: internal

07> Add the physical NIC and the internal port to br-pif.

In OVS for Hyper-V, we use 'external' as a special name to refer to the
physical NICs connected to the Hyper-V switch.  An index is added to this
special name to refer to the particular physical NIC. Eg. 'external.1' refers
to the first physical NIC on the Hyper-V switch.

Note: Currently, we assume that the Hyper-V switch on which OVS extension is
enabled has a single physical NIC connected to it.

Interal port is the virtual adapter created on the Hyper-V switch using the
'AllowManagementOS' setting.  This has already been setup while creating the
switch using the instructions above.  In OVS for Hyper-V, we use a 'internal'
as a special name to refer to that adapter.

    % ovs-vsctl add-port br-pif external.1
    % ovs-vsctl add-port br-pif internal

* Dumping the ports should show the additional ports that were just added.
  Sample output shows up as follows:

    % ovs-dpctl show
    system@ovs-system:
            lookups: hit:0 missed:0 lost:0
            flows: 0
            port 4: internal (internal)   <<< 'AllowManagementOS' adapter on
                                              Hyper-V switch
            port 2: br-pif (internal)
            port 1: br-int (internal
            port 3: external.1            <<< Physical NIC

    % ovs-vsctl show
    a56ec7b5-5b1f-49ec-a795-79f6eb63228b
        Bridge br-pif
            Port internal
                Interface internal
            Port br-pif
                Interface br-pif
                    type: internal
            Port "external.1"
                Interface "external.1"
        Bridge br-int
            Port br-int
                Interface br-int
                    type: internal

08> Add the VIFs to br-int

Adding VIFs to openvswitch is a two step procedure.  The first step is to
assign a 'OVS port name' which is a unique name across all VIFs on this
Hyper-V.  The next step is to add the VIF to the ovsdb using its 'OVS port
name' as key.

08a> Assign a unique 'OVS port name' to the VIF

Note that the VIF needs to have been disconnected from the Hyper-V switch
before assigning a 'OVS port name' to it.  In the example below, we assign a
'OVS port name' called 'ovs-port-a' to a VIF on a VM by name 'VM1'.  By using
index 0 for '$vnic', the first VIF of the VM is being addressed.  After
assigning the name 'ovs-port-a', the VIF is connected back to the Hyper-V
switch with name 'OVS-HV-Switch', which is assumed to be the Hyper-V switch
with OVS extension enabled.

    Eg:
    % import-module .\datapath-windows\misc\OVS.psm1
    % $vnic = Get-VMNetworkAdapter <Name of the VM>
    % Disconnect-VMNetworkAdapter -VMNetworkAdapter $vnic[0]
    % $vnic[0] | Set-VMNetworkAdapterOVSPort -OVSPortName ovs-port-a
    % Connect-VMNetworkAdapter -VMNetworkAdapter $vnic[0] \
                               -SwitchName OVS-Extended-Switch

08b> Add the VIFs to br-int in ovsdb

    Eg:
    % ovs-vsctl add-port br-int ovs-port-a

09> Verify the status
    % ovs-dpctl show
    system@ovs-system:
            lookups: hit:0 missed:0 lost:0
            flows: 0
            port 4: internal (internal)
            port 5: ovs-port-a
            port 2: br-pif (internal)
            port 1: br-int (internal
            port 3: external.1

    % ovs-vsctl show
    4cd86499-74df-48bd-a64d-8d115b12a9f2
        Bridge br-pif
            Port internal
                Interface internal
            Port "external.1"
                Interface "external.1"
            Port br-pif
                Interface br-pif
                    type: internal
        Bridge br-int
            Port br-int
                Interface br-int
                    type: internal
            Port "ovs-port-a"
                Interface "ovs-port-a"

Steps to configure patch ports and switch VLAN tagging
------------------------------------------------------
The Windows Open vSwitch implementation support VLAN tagging in the switch.
Switch VLAN tagging along with patch ports between 'br-int' and 'br-pif' is
used to configure VLAN tagging functionality between two VMs on different
Hyper-Vs.  The following examples demonstrate how it can be done:

01> Add a patch port from br-int to br-pif
    % ovs-vsctl add-port br-int patch-to-pif
    % ovs-vsctl set interface patch-to-pif type=patch \
                                 options:peer=patch-to-int

02> Add a patch port from br-pif to br-int
    % ovs-vsctl add-port br-pif patch-to-int
    % ovs-vsctl set interface patch-to-int type=patch \
                                 options:peer=patch-to-pif

03> Re-Add the VIF ports with the VLAN tag
    % ovs-vsctl add-port br-int ovs-port-a tag=900
    % ovs-vsctl add-port br-int ovs-port-b tag=900

Steps to add VXLAN tunnels
--------------------------
The Windows Open vSwitch implementation support VXLAN tunnels.  To add VXLAN
tunnels, the following steps serve as examples.

Note that, any patch ports created between br-int and br-pif MUST be beleted
prior to adding VXLAN tunnels.

01> Add the vxlan port between 172.168.201.101 <-> 172.168.201.102
    % ovs-vsctl add-port br-int vxlan-1
    % ovs-vsctl set Interface vxlan-1 type=vxlan
    % ovs-vsctl set Interface vxlan-1 options:local_ip=172.168.201.101
    % ovs-vsctl set Interface vxlan-1 options:remote_ip=172.168.201.102
    % ovs-vsctl set Interface vxlan-1 options:in_key=flow
    % ovs-vsctl set Interface vxlan-1 options:out_key=flow

02> Add the vxlan port between 172.168.201.101 <-> 172.168.201.105
    % ovs-vsctl add-port br-int vxlan-2
    % ovs-vsctl set Interface vxlan-2 type=vxlan
    % ovs-vsctl set Interface vxlan-2 options:local_ip=172.168.201.102
    % ovs-vsctl set Interface vxlan-2 options:remote_ip=172.168.201.105
    % ovs-vsctl set Interface vxlan-2 options:in_key=flow
    % ovs-vsctl set Interface vxlan-2 options:out_key=flow


Requirements
------------
* We require that you don't disable the "Allow management operating system to
share this network adapter" under 'Virtual Switch Properties' > 'Connection
type: External network', in the HyperV virtual network switch configuration.

* Checksum Offloads
    While there is some support for checksum/segmentation offloads in software,
this is still a work in progress. Till the support is complete we recommend
disabling TX/RX offloads for both the VM's as well as the HyperV.

Windows Services
----------------
Open vSwitch daemons come with support to run as a Windows service. The
instructions here assume that you have installed the Open vSwitch utilities
and daemons via 'make install'. The commands shown here can be run from
MSYS bash or Windows command prompt.

* Create the database.

  % ovsdb-tool create C:/openvswitch/etc/openvswitch/conf.db \
        "C:/openvswitch/usr/share/openvswitch/vswitch.ovsschema"

* Create the ovsdb-server service and start it.

  % sc create ovsdb-server binpath="C:/openvswitch/usr/sbin/ovsdb-server.exe C:/openvswitch/etc/openvswitch/conf.db -vfile:info --log-file --pidfile --remote=punix:db.sock --service --service-monitor"

  One of the common issues with creating a Windows service is with mungled
  paths. You can make sure that the correct path has been registered with
  the Windows services manager by running:

  % sc qc ovsdb-server

  Start the service.

  % sc start ovsdb-server

  Check that the service is healthy by running:

  % sc query ovsdb-server

* Initialize the database.

  % ovs-vsctl --no-wait init

* Create the ovs-vswitchd service and start it.

  % sc create ovs-vswitchd binpath="C:/openvswitch/usr/sbin/ovs-vswitchd.exe --pidfile -vfile:info --log-file  --service --service-monitor"

  % sc start ovs-vswitchd

  Check that the service is healthy by running:

  % sc query ovs-vswitchd

* To stop and delete the services, run:

  % sc stop ovs-vswitchd
  % sc stop ovsdb-server
  % sc delete ovs-vswitchd
  % sc delete ovsdb-server

Windows autobuild service
-------------------------
AppVeyor (appveyor.com) provides a free Windows autobuild service for
opensource projects.  Open vSwitch has integration with AppVeyor for
continuous build.  A developer can build test his changes for Windows by
logging into appveyor.com using a github account, creating a new project
by linking it to his development repository in github and triggering
a new build.

TODO
----

* Investigate the working of sFlow on Windows and re-enable the unit tests.

* Investigate and add the feature to provide QOS.

* Sign the driver & create an MSI for installing the different OpenvSwitch
components on windows.
