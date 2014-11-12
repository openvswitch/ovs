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
studio" and through it enter into the bash shell available from msys.

If after the above step, a 'which link' inside MSYS's bash says,
"/bin/link.exe", rename /bin/link.exe to something else so that the
Visual studio's linker is used.

* For pthread support, install the library, dll and includes of pthreads-win32
project from
ftp://sourceware.org/pub/pthreads-win32/prebuilt-dll-2-9-1-release to a
directory (e.g.: C:/pthread).

* Get the Open vSwitch sources from either cloning the repo using git
or from a distribution tar ball.

* If you pulled the sources directly from an Open vSwitch Git tree,
  run boot.sh in the top source directory:

    % ./boot.sh

* In the top source directory, configure the package by running the
  configure script.  You should provide some configure options to choose
  the right compiler, linker, libraries, Open vSwitch component installation
  directories, etc. For example,

    % ./configure CC=./build-aux/cccl LD="`which link`" LIBS="-lws2_32" \
      --prefix="C:/openvswitch/usr" --localstatedir="C:/openvswitch/var" \
      --sysconfdir="C:/openvswitch/etc" --with-pthread="C:/pthread"

    By default, the above enables compiler optimization for fast code.
    For default compiler optimization, pass the "--with-debug" configure
    option.

* Run make for the ported executables in the top source directory, e.g.:

    % make

* To run all the unit tests:

    % make check

OpenSSL, Open vSwitch and Visual C++
------------------------------------
To get SSL support for Open vSwitch on Windows, do the following:

* Install OpenSSL for Windows as suggested at
http://www.openssl.org/related/binaries.html.
The link as of this writing suggests to download it from
http://slproweb.com/products/Win32OpenSSL.html and the latest version is
"Win32 OpenSSL v1.0.1j".

Note down the directory where OpenSSL is installed (e.g.: C:/OpenSSL-Win32).

* While configuring the package, specify the OpenSSL directory path.
For example,

    % ./configure CC=./build-aux/cccl LD="`which link`" LIBS="-lws2_32" \
    --prefix="C:/openvswitch/usr" --localstatedir="C:/openvswitch/var" \
    --sysconfdir="C:/openvswitch/etc" --with-pthread="C:/pthread" \
    --enable-ssl --with-openssl="C:/OpenSSL-Win32"

* Run make for the ported executables.

Building the Kernel module
--------------------------
We directly use the Visual Studio 2013 IDE to compile the kernel module. You can
open the extensions.sln file in the IDE and build the solution.

Installing the Kernel module
----------------------------
Once you have built the solution, you can copy the following files to the
target Hyper-V machines:

    ./datapath-windows/x64/Win8.1Debug/package/ovsext.inf
    ./datapath-windows/x64/Win8.1Debug/package/OVSExt.sys
    ./datapath-windows/x64/Win8.1Debug/package/ovsext.cat
    ./datapath-windows/misc/install.cmd
    ./datapath-windows/misc/uninstall.cmd

Steps to install the module
---------------------------

01> Run ./uninstall.cmd to remove the old extension.
02> Run ./install.cmd to insert the new one. For this to work you will have to
turn on TESTSIGNING boot option or 'Disable Driver Signature Enforcement'
during boot.
03> In the Virtual Switch Manager configuration you should now see "VMWare OVS
Extension" under 'Virtual Switch Extensions'. Click the check box to enable the
extension.

Steps to run the user processes & configure VXLAN ports
-------------------------------------------------------

01> Create the conf db file.
ovsdb\ovsdb-tool.exe create conf.db .\vswitchd\vswitch.ovsschema

02> Run ovsdb-server
ovsdb\ovsdb-server.exe -v --remote=ptcp:6632:127.0.0.1 conf.db

03> Create integration bridge & pif bridge
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 add-br br-int
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 add-br br-pif

04> Dump the ports
utilities\ovs-dpctl.exe show

* Sample output shows up like this. Currently it is not possible to figure out
* the mapping between VIF and VM from the output.

$ utilities\ovs-dpctl.exe show
2014-06-27T01:55:32Z|00001|socket_util|ERR|4789:0.0.0.0:
socket: Either the application has not called WSAStartup, or WSAStartup failed.
                                        <<< Ignore this error, it is harmless.
system@ovs-system:
        lookups: hit:0 missed:0 lost:0
        flows: 0
        masks: hit:0 total:0 hit/pkt:0.00
        port 16777216: internal            <<< VTEP created by AllowManagementOS
                                               setting
        port 16777225: external.1          <<< Physical NIC
        port 16777288: vmNICEmu.1000048    <<< VIF #1
        port 16777289: vmNICSyn.1000049    <<< VIF #2


05> Add the physical NIC and the internal port to br-pif
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 add-port br-pif <port name>

Eg:
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 add-port br-pif external.1
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 add-port br-pif internal

06> Add the VIFs to br-int
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 add-port br-int <port name>

Eg:
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 add-port br-int vmNICEmu.1000048
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 add-port br-int vmNICSyn.1000049

07> Verify the status
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 show

Eg:
$ utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 show
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
        Port "vmNICEmu.1000048"
            Interface "vmNICEmu.1000048"
        Port "vmNICSyn.1000049"
            Interface "vmNICSyn.1000049"


09> Run vswitchd
vswitchd\ovs-vswitchd.exe -v tcp:127.0.0.1:6632

10> You can figure out the port name to MAC address mapping now. (optional)
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 list interface

//********** VXLAN PORT CONFIGURATION (Supports Multiple ports) ************//
(Remove all patch ports added to create VLAN networks.)
11> Add the vxlan port between 172.168.201.101 <-> 172.168.201.102
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 add-port br-int vxlan-1
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 set Interface vxlan-1 type=vxlan
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 set Interface vxlan-1 options:local_ip=172.168.201.101
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 set Interface vxlan-1 options:remote_ip=172.168.201.102
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 set Interface vxlan-1 options:in_key=flow
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 set Interface vxlan-1 options:out_key=flow

12> Add the vxlan port between 172.168.201.101 <-> 172.168.201.105
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 add-port br-int vxlan-2
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 set Interface vxlan-2 type=vxlan
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 set Interface vxlan-2 options:local_ip=172.168.201.102
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 set Interface vxlan-2 options:remote_ip=172.168.201.105
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 set Interface vxlan-2 options:in_key=flow
utilities\ovs-vsctl.exe --db=tcp:127.0.0.1:6632 set Interface vxlan-2 options:out_key=flow


//********** VLAN CONFIGURATION (Using patch ports) ************//
(Remove all VXLAN ports from the configuration.)
13> Add a patch port from br-int to br-pif
utilities/ovs-vsctl.exe -- add-port br-int patch-to-pif
utilities/ovs-vsctl.exe -- set interface patch-to-pif type=patch options:peer=patch-to-int

14> Add a patch port from br-pif to br-int
utilities/ovs-vsctl.exe -- add-port br-pif patch-to-int
utilities/ovs-vsctl.exe -- set interface patch-to-int type=patch options:peer=patch-to-pif

15> Re-Add the VIF ports with the VLAN tag
utilities\ovs-vsctl.exe add-port br-int vmNICEmu.1000048 tag=900
utilities\ovs-vsctl.exe add-port br-int vmNICSyn.1000049 tag=900


Requirements
------------

* We require that you don't disable the "Allow management operating system to
share this network adapter" under 'Virtual Switch Properties' > 'Connection
type: External network', in the HyperV virtual network switch configuration.

* Checksum Offloads
    While there is some support for checksum/segmentation offloads in software,
this is still a work in progress. Till the support is complete we recommend
disabling TX/RX offloads for both the VM's as well as the HyperV.


TODO
----

* Investigate the working of sFlow on Windows and re-enable the unit tests.

* Investigate and add the feature to provide QOS.

* Sign the driver & create an MSI for installing the different OpenvSwitch
components on windows.
