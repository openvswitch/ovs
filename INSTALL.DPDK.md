Using Open vSwitch with DPDK
============================

Open vSwitch can use Intel(R) DPDK lib to operate entirely in
userspace. This file explains how to install and use Open vSwitch in
such a mode.

The DPDK support of Open vSwitch is considered experimental.
It has not been thoroughly tested.

This version of Open vSwitch should be built manually with `configure`
and `make`.

OVS needs a system with 1GB hugepages support.

Building and Installing:
------------------------

Required DPDK 2.0, `fuse`, `fuse-devel` (`libfuse-dev` on Debian/Ubuntu)

1. Configure build & install DPDK:
  1. Set `$DPDK_DIR`

     ```
     export DPDK_DIR=/usr/src/dpdk-2.0
     cd $DPDK_DIR
     ```

  2. Update `config/common_linuxapp` so that DPDK generate single lib file.
     (modification also required for IVSHMEM build)

     `CONFIG_RTE_BUILD_COMBINE_LIBS=y`

     Update `config/common_linuxapp` so that DPDK is built with vhost
     libraries; currently, OVS only supports vhost-cuse, so DPDK vhost-user
     libraries should be explicitly turned off (they are enabled by default
     in DPDK 2.0).

     `CONFIG_RTE_LIBRTE_VHOST=y`
     `CONFIG_RTE_LIBRTE_VHOST_USER=n`

     Then run `make install` to build and install the library.
     For default install without IVSHMEM:

     `make install T=x86_64-native-linuxapp-gcc`

     To include IVSHMEM (shared memory):

     `make install T=x86_64-ivshmem-linuxapp-gcc`

     For further details refer to http://dpdk.org/

2. Configure & build the Linux kernel:

   Refer to intel-dpdk-getting-started-guide.pdf for understanding
   DPDK kernel requirement.

3. Configure & build OVS:

   * Non IVSHMEM:

     `export DPDK_BUILD=$DPDK_DIR/x86_64-native-linuxapp-gcc/`

   * IVSHMEM:

     `export DPDK_BUILD=$DPDK_DIR/x86_64-ivshmem-linuxapp-gcc/`

   ```
   cd $(OVS_DIR)/openvswitch
   ./boot.sh
   ./configure --with-dpdk=$DPDK_BUILD [CFLAGS="-g -O2 -Wno-cast-align"]
   make
   ```

   Note: 'clang' users may specify the '-Wno-cast-align' flag to suppress DPDK cast-align warnings.

To have better performance one can enable aggressive compiler optimizations and
use the special instructions(popcnt, crc32) that may not be available on all
machines. Instead of typing `make`, type:

`make CFLAGS='-O3 -march=native'`

Refer to [INSTALL.userspace.md] for general requirements of building userspace OVS.

Using the DPDK with ovs-vswitchd:
---------------------------------

1. Setup system boot
   Add the following options to the kernel bootline:
   
   `default_hugepagesz=1GB hugepagesz=1G hugepages=1`

2. Setup DPDK devices:

   DPDK devices can be setup using either the VFIO (for DPDK 1.7+) or UIO
   modules. UIO requires inserting an out of tree driver igb_uio.ko that is
   available in DPDK. Setup for both methods are described below.

   * UIO:
     1. insert uio.ko: `modprobe uio`
     2. insert igb_uio.ko: `insmod $DPDK_BUILD/kmod/igb_uio.ko`
     3. Bind network device to igb_uio:
         `$DPDK_DIR/tools/dpdk_nic_bind.py --bind=igb_uio eth1`

   * VFIO:

     VFIO needs to be supported in the kernel and the BIOS. More information
     can be found in the [DPDK Linux GSG].

     1. Insert vfio-pci.ko: `modprobe vfio-pci`
     2. Set correct permissions on vfio device: `sudo /usr/bin/chmod a+x /dev/vfio`
        and: `sudo /usr/bin/chmod 0666 /dev/vfio/*`
     3. Bind network device to vfio-pci:
        `$DPDK_DIR/tools/dpdk_nic_bind.py --bind=vfio-pci eth1`

3. Mount the hugetable filsystem

   `mount -t hugetlbfs -o pagesize=1G none /dev/hugepages`

   Ref to http://www.dpdk.org/doc/quick-start for verifying DPDK setup.

4. Follow the instructions in [INSTALL.md] to install only the
   userspace daemons and utilities (via 'make install').
   1. First time only db creation (or clearing):

      ```
      mkdir -p /usr/local/etc/openvswitch
      mkdir -p /usr/local/var/run/openvswitch
      rm /usr/local/etc/openvswitch/conf.db
      ovsdb-tool create /usr/local/etc/openvswitch/conf.db  \
             /usr/local/share/openvswitch/vswitch.ovsschema
      ```

   2. Start ovsdb-server

      ```
      ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
          --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
          --private-key=db:Open_vSwitch,SSL,private_key \
          --certificate=Open_vSwitch,SSL,certificate \
          --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert --pidfile --detach
      ```

    3. First time after db creation, initialize:

       ```
       ovs-vsctl --no-wait init
       ```

5. Start vswitchd:

   DPDK configuration arguments can be passed to vswitchd via `--dpdk`
   argument. This needs to be first argument passed to vswitchd process.
   dpdk arg -c is ignored by ovs-dpdk, but it is a required parameter
   for dpdk initialization.

   ```
   export DB_SOCK=/usr/local/var/run/openvswitch/db.sock
   ovs-vswitchd --dpdk -c 0x1 -n 4 -- unix:$DB_SOCK --pidfile --detach
   ```

   If allocated more than one GB hugepage (as for IVSHMEM), set amount and
   use NUMA node 0 memory:

   ```
   ovs-vswitchd --dpdk -c 0x1 -n 4 --socket-mem 1024,0 \
   -- unix:$DB_SOCK --pidfile --detach
   ```

6. Add bridge & ports

   To use ovs-vswitchd with DPDK, create a bridge with datapath_type
   "netdev" in the configuration database.  For example:

   `ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev`

   Now you can add dpdk devices. OVS expect DPDK device name start with dpdk
   and end with portid. vswitchd should print (in the log file) the number
   of dpdk devices found.

   ```
   ovs-vsctl add-port br0 dpdk0 -- set Interface dpdk0 type=dpdk
   ovs-vsctl add-port br0 dpdk1 -- set Interface dpdk1 type=dpdk
   ```

   Once first DPDK port is added to vswitchd, it creates a Polling thread and
   polls dpdk device in continuous loop. Therefore CPU utilization
   for that thread is always 100%.

   Note: creating bonds of DPDK interfaces is slightly different to creating
   bonds of system interfaces.  For DPDK, the interface type must be explicitly
   set, for example:

   ```
   ovs-vsctl add-bond br0 dpdkbond dpdk0 dpdk1 -- set Interface dpdk0 type=dpdk -- set Interface dpdk1 type=dpdk
   ```

7. Add test flows

   Test flow script across NICs (assuming ovs in /usr/src/ovs):
   Execute script:

   ```
   #! /bin/sh
   # Move to command directory
   cd /usr/src/ovs/utilities/

   # Clear current flows
   ./ovs-ofctl del-flows br0

   # Add flows between port 1 (dpdk0) to port 2 (dpdk1)
   ./ovs-ofctl add-flow br0 in_port=1,action=output:2
   ./ovs-ofctl add-flow br0 in_port=2,action=output:1
   ```

8. Performance tuning

   With pmd multi-threading support, OVS creates one pmd thread for each
   numa node as default.  The pmd thread handles the I/O of all DPDK
   interfaces on the same numa node.  The following two commands can be used
   to configure the multi-threading behavior.

   `ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=<hex string>`

   The command above asks for a CPU mask for setting the affinity of pmd
   threads.  A set bit in the mask means a pmd thread is created and pinned
   to the corresponding CPU core.  For more information, please refer to
   `man ovs-vswitchd.conf.db`

   `ovs-vsctl set Open_vSwitch . other_config:n-dpdk-rxqs=<integer>`

   The command above sets the number of rx queues of each DPDK interface. The
   rx queues are assigned to pmd threads on the same numa node in round-robin
   fashion.  For more information, please refer to `man ovs-vswitchd.conf.db`

   Ideally for maximum throughput, the pmd thread should not be scheduled out
   which temporarily halts its execution. The following affinitization methods
   can help.

   Lets pick core 4,6,8,10 for pmd threads to run on.  Also assume a dual 8 core
   sandy bridge system with hyperthreading enabled where CPU1 has cores 0,...,7
   and 16,...,23 & CPU2 cores 8,...,15 & 24,...,31.  (A different cpu
   configuration could have different core mask requirements).

   To kernel bootline add core isolation list for cores and associated hype cores
   (e.g.  isolcpus=4,20,6,22,8,24,10,26,).  Reboot system for isolation to take
   effect, restart everything.

   Configure pmd threads on core 4,6,8,10 using 'pmd-cpu-mask':

   `ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=00000550`

   You should be able to check that pmd threads are pinned to the correct cores
   via:

   ```
   top -p `pidof ovs-vswitchd` -H -d1
   ```

   Note, the pmd threads on a numa node are only created if there is at least
   one DPDK interface from the numa node that has been added to OVS.

   To understand where most of the time is spent and whether the caches are
   effective, these commands can be used:

   ```
   ovs-appctl dpif-netdev/pmd-stats-clear #To reset statistics
   ovs-appctl dpif-netdev/pmd-stats-show
   ```

DPDK Rings :
------------

Following the steps above to create a bridge, you can now add dpdk rings
as a port to the vswitch.  OVS will expect the DPDK ring device name to
start with dpdkr and end with a portid.

`ovs-vsctl add-port br0 dpdkr0 -- set Interface dpdkr0 type=dpdkr`

DPDK rings client test application

Included in the test directory is a sample DPDK application for testing
the rings.  This is from the base dpdk directory and modified to work
with the ring naming used within ovs.

location tests/ovs_client

To run the client :

```
cd /usr/src/ovs/tests/
ovsclient -c 1 -n 4 --proc-type=secondary -- -n "port id you gave dpdkr"
```

In the case of the dpdkr example above the "port id you gave dpdkr" is 0.

It is essential to have --proc-type=secondary

The application simply receives an mbuf on the receive queue of the
ethernet ring and then places that same mbuf on the transmit ring of
the ethernet ring.  It is a trivial loopback application.

DPDK rings in VM (IVSHMEM shared memory communications)
-------------------------------------------------------

In addition to executing the client in the host, you can execute it within
a guest VM. To do so you will need a patched qemu.  You can download the
patch and getting started guide at :

https://01.org/packet-processing/downloads

A general rule of thumb for better performance is that the client
application should not be assigned the same dpdk core mask "-c" as
the vswitchd.

DPDK vhost:
-----------

vhost-cuse is only supported at present i.e. not using the standard QEMU
vhost-user interface. It is intended that vhost-user support will be added
in future releases when supported in DPDK and that vhost-cuse will eventually
be deprecated. See [DPDK Docs] for more info on vhost.

Prerequisites:
1.  Insert the Cuse module:

      `modprobe cuse`

2.  Build and insert the `eventfd_link` module:

     `cd $DPDK_DIR/lib/librte_vhost/eventfd_link/`
     `make`
     `insmod $DPDK_DIR/lib/librte_vhost/eventfd_link.ko`

Following the steps above to create a bridge, you can now add DPDK vhost
as a port to the vswitch.

`ovs-vsctl add-port br0 dpdkvhost0 -- set Interface dpdkvhost0 type=dpdkvhost`

Unlike DPDK ring ports, DPDK vhost ports can have arbitrary names:

`ovs-vsctl add-port br0 port123ABC -- set Interface port123ABC type=dpdkvhost`

However, please note that when attaching userspace devices to QEMU, the
name provided during the add-port operation must match the ifname parameter
on the QEMU command line.


DPDK vhost VM configuration:
----------------------------

   vhost ports use a Linux* character device to communicate with QEMU.
   By default it is set to `/dev/vhost-net`. It is possible to reuse this
   standard device for DPDK vhost, which makes setup a little simpler but it
   is better practice to specify an alternative character device in order to
   avoid any conflicts if kernel vhost is to be used in parallel.

1. This step is only needed if using an alternative character device.

   The new character device filename must be specified on the vswitchd
   commandline:

        `./vswitchd/ovs-vswitchd --dpdk --cuse_dev_name my-vhost-net -c 0x1 ...`

   Note that the `--cuse_dev_name` argument and associated string must be the first
   arguments after `--dpdk` and come before the EAL arguments. In the example
   above, the character device to be used will be `/dev/my-vhost-net`.

2. This step is only needed if reusing the standard character device. It will
   conflict with the kernel vhost character device so the user must first
   remove it.

       `rm -rf /dev/vhost-net`

3a. Configure virtio-net adaptors:
   The following parameters must be passed to the QEMU binary:

     ```
     -netdev tap,id=<id>,script=no,downscript=no,ifname=<name>,vhost=on
     -device virtio-net-pci,netdev=net1,mac=<mac>
     ```

     Repeat the above parameters for multiple devices.

     The DPDK vhost library will negiotiate its own features, so they
     need not be passed in as command line params. Note that as offloads are
     disabled this is the equivalent of setting:

     `csum=off,gso=off,guest_tso4=off,guest_tso6=off,guest_ecn=off`

3b. If using an alternative character device. It must be also explicitly
    passed to QEMU using the `vhostfd` argument:

     ```
     -netdev tap,id=<id>,script=no,downscript=no,ifname=<name>,vhost=on,
     vhostfd=<open_fd>
     -device virtio-net-pci,netdev=net1,mac=<mac>
     ```

     The open file descriptor must be passed to QEMU running as a child
     process. This could be done with a simple python script.

       ```
       #!/usr/bin/python
       fd = os.open("/dev/usvhost", os.O_RDWR)
       subprocess.call("qemu-system-x86_64 .... -netdev tap,id=vhostnet0,\
                        vhost=on,vhostfd=" + fd +"...", shell=True)

   Alternatively the the `qemu-wrap.py` script can be used to automate the
   requirements specified above and can be used in conjunction with libvirt if
   desired. See the "DPDK vhost VM configuration with QEMU wrapper" section
   below.

4. Configure huge pages:
   QEMU must allocate the VM's memory on hugetlbfs. Vhost ports access a
   virtio-net device's virtual rings and packet buffers mapping the VM's
   physical memory on hugetlbfs. To enable vhost-ports to map the VM's
   memory into their process address space, pass the following paramters
   to QEMU:

     `-object memory-backend-file,id=mem,size=4096M,mem-path=/dev/hugepages,
      share=on -numa node,memdev=mem -mem-prealloc`


DPDK vhost VM configuration with QEMU wrapper:
----------------------------------------------

The QEMU wrapper script automatically detects and calls QEMU with the
necessary parameters. It performs the following actions:

  * Automatically detects the location of the hugetlbfs and inserts this
    into the command line parameters.
  * Automatically open file descriptors for each virtio-net device and
    inserts this into the command line parameters.
  * Calls QEMU passing both the command line parameters passed to the
    script itself and those it has auto-detected.

Before use, you **must** edit the configuration parameters section of the
script to point to the correct emulator location and set additional
settings. Of these settings, `emul_path` and `us_vhost_path` **must** be
set. All other settings are optional.

To use directly from the command line simply pass the wrapper some of the
QEMU parameters: it will configure the rest. For example:

```
qemu-wrap.py -cpu host -boot c -hda <disk image> -m 4096 -smp 4
  --enable-kvm -nographic -vnc none -net none -netdev tap,id=net1,
  script=no,downscript=no,ifname=if1,vhost=on -device virtio-net-pci,
  netdev=net1,mac=00:00:00:00:00:01
```

DPDK vhost VM configuration with libvirt:
-----------------------------------------

If you are using libvirt, you must enable libvirt to access the character
device by adding it to controllers cgroup for libvirtd using the following
steps.

     1. In `/etc/libvirt/qemu.conf` add/edit the following lines:

        ```
        1) clear_emulator_capabilities = 0
        2) user = "root"
        3) group = "root"
        4) cgroup_device_acl = [
               "/dev/null", "/dev/full", "/dev/zero",
               "/dev/random", "/dev/urandom",
               "/dev/ptmx", "/dev/kvm", "/dev/kqemu",
               "/dev/rtc", "/dev/hpet", "/dev/net/tun",
               "/dev/<my-vhost-device>",
               "/dev/hugepages"]
        ```

        <my-vhost-device> refers to "vhost-net" if using the `/dev/vhost-net`
        device. If you have specificed a different name on the ovs-vswitchd
        commandline using the "--cuse_dev_name" parameter, please specify that
        filename instead.

     2. Disable SELinux or set to permissive mode

     3. Restart the libvirtd process
        For example, on Fedora:

          `systemctl restart libvirtd.service`

After successfully editing the configuration, you may launch your
vhost-enabled VM. The XML describing the VM can be configured like so
within the <qemu:commandline> section:

     1. Set up shared hugepages:

     ```
     <qemu:arg value='-object'/>
     <qemu:arg value='memory-backend-file,id=mem,size=4096M,mem-path=/dev/hugepages,share=on'/>
     <qemu:arg value='-numa'/>
     <qemu:arg value='node,memdev=mem'/>
     <qemu:arg value='-mem-prealloc'/>
     ```

     2. Set up your tap devices:

     ```
     <qemu:arg value='-netdev'/>
     <qemu:arg value='type=tap,id=net1,script=no,downscript=no,ifname=vhost0,vhost=on'/>
     <qemu:arg value='-device'/>
     <qemu:arg value='virtio-net-pci,netdev=net1,mac=00:00:00:00:00:01'/>
     ```

     Repeat for as many devices as are desired, modifying the id, ifname
     and mac as necessary.

     Again, if you are using an alternative character device (other than
     `/dev/vhost-net`), please specify the file descriptor like so:

     `<qemu:arg value='type=tap,id=net3,script=no,downscript=no,ifname=vhost0,vhost=on,vhostfd=<open_fd>'/>`

     Where <open_fd> refers to the open file descriptor of the character device.
     Instructions of how to retrieve the file descriptor can be found in the
     "DPDK vhost VM configuration" section.
     Alternatively, the process is automated with the qemu-wrap.py script,
     detailed in the next section.

Now you may launch your VM using virt-manager, or like so:

    `virsh create my_vhost_vm.xml`

DPDK vhost VM configuration with libvirt and QEMU wrapper:
----------------------------------------------------------

To use the qemu-wrapper script in conjuntion with libvirt, follow the
steps in the previous section before proceeding with the following steps:

  1. Place `qemu-wrap.py` in libvirtd's binary search PATH ($PATH)
     Ideally in the same directory that the QEMU binary is located.

  2. Ensure that the script has the same owner/group and file permissions
     as the QEMU binary.

  3. Update the VM xml file using "virsh edit VM.xml"

       1. Set the VM to use the launch script.
          Set the emulator path contained in the `<emulator><emulator/>` tags.
          For example, replace:

            `<emulator>/usr/bin/qemu-kvm<emulator/>`

            with:

            `<emulator>/usr/bin/qemu-wrap.py<emulator/>`

  4. Edit the Configuration Parameters section of the script to point to
  the correct emulator location and set any additional options. If you are
  using a alternative character device name, please set "us_vhost_path" to the
  location of that device. The script will automatically detect and insert
  the correct "vhostfd" value in the QEMU command line arguements.

  5. Use virt-manager to launch the VM

Running ovs-vswitchd with DPDK backend inside a VM
--------------------------------------------------

Please note that additional configuration is required if you want to run
ovs-vswitchd with DPDK backend inside a QEMU virtual machine. Ovs-vswitchd
creates separate DPDK TX queues for each CPU core available. This operation
fails inside QEMU virtual machine because, by default, VirtIO NIC provided
to the guest is configured to support only single TX queue and single RX
queue. To change this behavior, you need to turn on 'mq' (multiqueue)
property of all virtio-net-pci devices emulated by QEMU and used by DPDK.
You may do it manually (by changing QEMU command line) or, if you use Libvirt,
by adding the following string:

`<driver name='vhost' queues='N'/>`

to <interface> sections of all network devices used by DPDK. Parameter 'N'
determines how many queues can be used by the guest.

Restrictions:
-------------

  - Work with 1500 MTU, needs few changes in DPDK lib to fix this issue.
  - Currently DPDK port does not make use any offload functionality.
  - DPDK-vHost support works with 1G huge pages.

  ivshmem:
  - If you run Open vSwitch with smaller page sizes (e.g. 2MB), you may be
    unable to share any rings or mempools with a virtual machine.
    This is because the current implementation of ivshmem works by sharing
    a single 1GB huge page from the host operating system to any guest
    operating system through the Qemu ivshmem device. When using smaller
    page sizes, multiple pages may be required to hold the ring descriptors
    and buffer pools. The Qemu ivshmem device does not allow you to share
    multiple file descriptors to the guest operating system. However, if you
    want to share dpdkr rings with other processes on the host, you can do
    this with smaller page sizes.

Bug Reporting:
--------------

Please report problems to bugs@openvswitch.org.

[INSTALL.userspace.md]:INSTALL.userspace.md
[INSTALL.md]:INSTALL.md
[DPDK Linux GSG]: http://www.dpdk.org/doc/guides/linux_gsg/build_dpdk.html#binding-and-unbinding-network-ports-to-from-the-igb-uioor-vfio-modules
[DPDK Docs]: http://dpdk.org/doc
