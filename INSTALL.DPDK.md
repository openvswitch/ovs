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

Required: DPDK 2.2
Optional (if building with vhost-cuse): `fuse`, `fuse-devel` (`libfuse-dev`
on Debian/Ubuntu)

1. Configure build & install DPDK:
  1. Set `$DPDK_DIR`

     ```
     export DPDK_DIR=/usr/src/dpdk-2.2
     cd $DPDK_DIR
     ```

  2. Update `config/common_linuxapp` so that DPDK generate single lib file.
     (modification also required for IVSHMEM build)

     `CONFIG_RTE_BUILD_COMBINE_LIBS=y`

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
   cd $(OVS_DIR)/
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

3. Mount the hugetable filesystem

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

   Now you can add dpdk devices. OVS expects DPDK device names to start with
   "dpdk" and end with a portid. vswitchd should print (in the log file) the
   number of dpdk devices found.

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

Performance Tuning:
-------------------

  1. PMD affinitization

	A poll mode driver (pmd) thread handles the I/O of all DPDK
	interfaces assigned to it. A pmd thread will busy loop through
	the assigned port/rxq's polling for packets, switch the packets
	and send to a tx port if required. Typically, it is found that
	a pmd thread is CPU bound, meaning that the greater the CPU
	occupancy the pmd thread can get, the better the performance. To
	that end, it is good practice to ensure that a pmd thread has as
	many cycles on a core available to it as possible. This can be
	achieved by affinitizing the pmd thread with a core that has no
	other workload. See section 7 below for a description of how to
	isolate cores for this purpose also.

	The following command can be used to specify the affinity of the
	pmd thread(s).

	`ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=<hex string>`

	By setting a bit in the mask, a pmd thread is created and pinned
	to the corresponding CPU core. e.g. to run a pmd thread on core 1

	`ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=2`

	For more information, please refer to the Open_vSwitch TABLE section in

	`man ovs-vswitchd.conf.db`

	Note, that a pmd thread on a NUMA node is only created if there is
	at least one DPDK interface from that NUMA node added to OVS.

  2. Multiple poll mode driver threads

	With pmd multi-threading support, OVS creates one pmd thread
	for each NUMA node by default. However, it can be seen that in cases
	where there are multiple ports/rxq's producing traffic, performance
	can be improved by creating multiple pmd threads running on separate
	cores. These pmd threads can then share the workload by each being
	responsible for different ports/rxq's. Assignment of ports/rxq's to
	pmd threads is done automatically.

	The following command can be used to specify the affinity of the
	pmd threads.

	`ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=<hex string>`

	A set bit in the mask means a pmd thread is created and pinned
	to the corresponding CPU core. e.g. to run pmd threads on core 1 and 2

	`ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=6`

	For more information, please refer to the Open_vSwitch TABLE section in

	`man ovs-vswitchd.conf.db`

	For example, when using dpdk and dpdkvhostuser ports in a bi-directional
	VM loopback as shown below, spreading the workload over 2 or 4 pmd
	threads shows significant improvements as there will be more total CPU
	occupancy available.

	NIC port0 <-> OVS <-> VM <-> OVS <-> NIC port 1

	The OVS log can be checked to confirm that the port/rxq assignment to
	pmd threads is as required. This can also be checked with the following
	commands:

	```
	top -H
	taskset -p <pid_of_pmd>
	```

	To understand where most of the pmd thread time is spent and whether the
	caches are being utilized, these commands can be used:

	```
	# Clear previous stats
	ovs-appctl dpif-netdev/pmd-stats-clear

	# Check current stats
	ovs-appctl dpif-netdev/pmd-stats-show
	```

  3. DPDK port Rx Queues

	`ovs-vsctl set Open_vSwitch . other_config:n-dpdk-rxqs=<integer>`

	The command above sets the number of rx queues for each DPDK interface.
	The rx queues are assigned to pmd threads on the same NUMA node in a
	round-robin fashion.  For more information, please refer to the
	Open_vSwitch TABLE section in

	`man ovs-vswitchd.conf.db`

  4. Exact Match Cache

	Each pmd thread contains one EMC. After initial flow setup in the
	datapath, the EMC contains a single table and provides the lowest level
	(fastest) switching for DPDK ports. If there is a miss in the EMC then
	the next level where switching will occur is the datapath classifier.
	Missing in the EMC and looking up in the datapath classifier incurs a
	significant performance penalty. If lookup misses occur in the EMC
	because it is too small to handle the number of flows, its size can
	be increased. The EMC size can be modified by editing the define
	EM_FLOW_HASH_SHIFT in lib/dpif-netdev.c.

	As mentioned above an EMC is per pmd thread. So an alternative way of
	increasing the aggregate amount of possible flow entries in EMC and
	avoiding datapath classifier lookups is to have multiple pmd threads
	running. This can be done as described in section 2.

  5. Compiler options

	The default compiler optimization level is '-O2'. Changing this to
	more aggressive compiler optimizations such as '-O3' or
	'-Ofast -march=native' with gcc can produce performance gains.

  6. Simultaneous Multithreading (SMT)

	With SMT enabled, one physical core appears as two logical cores
	which can improve performance.

	SMT can be utilized to add additional pmd threads without consuming
	additional physical cores. Additional pmd threads may be added in the
	same manner as described in section 2. If trying to minimize the use
	of physical cores for pmd threads, care must be taken to set the
	correct bits in the pmd-cpu-mask to ensure that the pmd threads are
	pinned to SMT siblings.

	For example, when using 2x 10 core processors in a dual socket system
	with HT enabled, /proc/cpuinfo will report 40 logical cores. To use
	two logical cores which share the same physical core for pmd threads,
	the following command can be used to identify a pair of logical cores.

	`cat /sys/devices/system/cpu/cpuN/topology/thread_siblings_list`

	where N is the logical core number. In this example, it would show that
	cores 1 and 21 share the same physical core. The pmd-cpu-mask to enable
	two pmd threads running on these two logical cores (one physical core)
	is.

	`ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=100002`

	Note that SMT is enabled by the Hyper-Threading section in the
	BIOS, and as such will apply to the whole system. So the impact of
	enabling/disabling it for the whole system should be considered
	e.g. If workloads on the system can scale across multiple cores,
	SMT may very beneficial. However, if they do not and perform best
	on a single physical core, SMT may not be beneficial.

  7. The isolcpus kernel boot parameter

	isolcpus can be used on the kernel bootline to isolate cores from the
	kernel scheduler and hence dedicate them to OVS or other packet
	forwarding related workloads. For example a Linux kernel boot-line
	could be:

	'GRUB_CMDLINE_LINUX_DEFAULT="quiet hugepagesz=1G hugepages=4 default_hugepagesz=1G 'intel_iommu=off' isolcpus=1-19"'

  8. NUMA/Cluster On Die

	Ideally inter NUMA datapaths should be avoided where possible as packets
	will go across QPI and there may be a slight performance penalty when
	compared with intra NUMA datapaths. On Intel Xeon Processor E5 v3,
	Cluster On Die is introduced on models that have 10 cores or more.
	This makes it possible to logically split a socket into two NUMA regions
	and again it is preferred where possible to keep critical datapaths
	within the one cluster.

	It is good practice to ensure that threads that are in the datapath are
	pinned to cores in the same NUMA area. e.g. pmd threads and QEMU vCPUs
	responsible for forwarding.

  9. Rx Mergeable buffers

	Rx Mergeable buffers is a virtio feature that allows chaining of multiple
	virtio descriptors to handle large packet sizes. As such, large packets
	are handled by reserving and chaining multiple free descriptors
	together. Mergeable buffer support is negotiated between the virtio
	driver and virtio device and is supported by the DPDK vhost library.
	This behavior is typically supported and enabled by default, however
	in the case where the user knows that rx mergeable buffers are not needed
	i.e. jumbo frames are not needed, it can be forced off by adding
	mrg_rxbuf=off to the QEMU command line options. By not reserving multiple
	chains of descriptors it will make more individual virtio descriptors
	available for rx to the guest using dpdkvhost ports and this can improve
	performance.

  10. Packet processing in the guest

	It is good practice whether simply forwarding packets from one
	interface to another or more complex packet processing in the guest,
	to ensure that the thread performing this work has as much CPU
	occupancy as possible. For example when the DPDK sample application
	`testpmd` is used to forward packets in the guest, multiple QEMU vCPU
	threads can be created. Taskset can then be used to affinitize the
	vCPU thread responsible for forwarding to a dedicated core not used
	for other general processing on the host system.

  11. DPDK virtio pmd in the guest

	dpdkvhostcuse or dpdkvhostuser ports can be used to accelerate the path
	to the guest using the DPDK vhost library. This library is compatible with
	virtio-net drivers in the guest but significantly better performance can
	be observed when using the DPDK virtio pmd driver in the guest. The DPDK
	`testpmd` application can be used in the guest as an example application
	that forwards packet from one DPDK vhost port to another. An example of
	running `testpmd` in the guest can be seen here.

	`./testpmd -c 0x3 -n 4 --socket-mem 512 -- --burst=64 -i --txqflags=0xf00 --disable-hw-vlan --forward-mode=io --auto-start`

	See below information on dpdkvhostcuse and dpdkvhostuser ports.
	See [DPDK Docs] for more information on `testpmd`.



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

DPDK 2.2 supports two types of vhost:

1. vhost-user
2. vhost-cuse

Whatever type of vhost is enabled in the DPDK build specified, is the type
that will be enabled in OVS. By default, vhost-user is enabled in DPDK.
Therefore, unless vhost-cuse has been enabled in DPDK, vhost-user ports
will be enabled in OVS.
Please note that support for vhost-cuse is intended to be deprecated in OVS
in a future release.

DPDK vhost-user:
----------------

The following sections describe the use of vhost-user 'dpdkvhostuser' ports
with OVS.

DPDK vhost-user Prerequisites:
-------------------------

1. DPDK 2.2 with vhost support enabled as documented in the "Building and
   Installing section"

2. QEMU version v2.1.0+

   QEMU v2.1.0 will suffice, but it is recommended to use v2.2.0 if providing
   your VM with memory greater than 1GB due to potential issues with memory
   mapping larger areas.

Adding DPDK vhost-user ports to the Switch:
--------------------------------------

Following the steps above to create a bridge, you can now add DPDK vhost-user
as a port to the vswitch. Unlike DPDK ring ports, DPDK vhost-user ports can
have arbitrary names.

  -  For vhost-user, the name of the port type is `dpdkvhostuser`

     ```
     ovs-vsctl add-port br0 vhost-user-1 -- set Interface vhost-user-1
     type=dpdkvhostuser
     ```

     This action creates a socket located at
     `/usr/local/var/run/openvswitch/vhost-user-1`, which you must provide
     to your VM on the QEMU command line. More instructions on this can be
     found in the next section "DPDK vhost-user VM configuration"
     Note: If you wish for the vhost-user sockets to be created in a
     directory other than `/usr/local/var/run/openvswitch`, you may specify
     another location on the ovs-vswitchd command line like so:

      `./vswitchd/ovs-vswitchd --dpdk -vhost_sock_dir /my-dir -c 0x1 ...`

DPDK vhost-user VM configuration:
---------------------------------
Follow the steps below to attach vhost-user port(s) to a VM.

1. Configure sockets.
   Pass the following parameters to QEMU to attach a vhost-user device:

   ```
   -chardev socket,id=char1,path=/usr/local/var/run/openvswitch/vhost-user-1
   -netdev type=vhost-user,id=mynet1,chardev=char1,vhostforce
   -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1
   ```

   ...where vhost-user-1 is the name of the vhost-user port added
   to the switch.
   Repeat the above parameters for multiple devices, changing the
   chardev path and id as necessary. Note that a separate and different
   chardev path needs to be specified for each vhost-user device. For
   example you have a second vhost-user port named 'vhost-user-2', you
   append your QEMU command line with an additional set of parameters:

   ```
   -chardev socket,id=char2,path=/usr/local/var/run/openvswitch/vhost-user-2
   -netdev type=vhost-user,id=mynet2,chardev=char2,vhostforce
   -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2
   ```

2. Configure huge pages.
   QEMU must allocate the VM's memory on hugetlbfs. vhost-user ports access
   a virtio-net device's virtual rings and packet buffers mapping the VM's
   physical memory on hugetlbfs. To enable vhost-user ports to map the VM's
   memory into their process address space, pass the following paramters
   to QEMU:

   ```
   -object memory-backend-file,id=mem,size=4096M,mem-path=/dev/hugepages,
   share=on
   -numa node,memdev=mem -mem-prealloc
   ```

3. Optional: Enable multiqueue support
   QEMU needs to be configured with multiple queues and the number queues
   must be less or equal to Open vSwitch other_config:n-dpdk-rxqs.
   The $q below is the number of queues.
   The $v is the number of vectors, which is '$q x 2 + 2'.

   ```
   -chardev socket,id=char2,path=/usr/local/var/run/openvswitch/vhost-user-2
   -netdev type=vhost-user,id=mynet2,chardev=char2,vhostforce,queues=$q
   -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2,mq=on,vectors=$v
   ```

DPDK vhost-cuse:
----------------

The following sections describe the use of vhost-cuse 'dpdkvhostcuse' ports
with OVS.

DPDK vhost-cuse Prerequisites:
-------------------------

1. DPDK 2.2 with vhost support enabled as documented in the "Building and
   Installing section"
   As an additional step, you must enable vhost-cuse in DPDK by setting the
   following additional flag in `config/common_linuxapp`:

   `CONFIG_RTE_LIBRTE_VHOST_USER=n`

   Following this, rebuild DPDK as per the instructions in the "Building and
   Installing" section. Finally, rebuild OVS as per step 3 in the "Building
   and Installing" section - OVS will detect that DPDK has vhost-cuse libraries
   compiled and in turn will enable support for it in the switch and disable
   vhost-user support.

2. Insert the Cuse module:

     `modprobe cuse`

3. Build and insert the `eventfd_link` module:

     ```
     cd $DPDK_DIR/lib/librte_vhost/eventfd_link/
     make
     insmod $DPDK_DIR/lib/librte_vhost/eventfd_link.ko
     ```

4. QEMU version v2.1.0+

   vhost-cuse will work with QEMU v2.1.0 and above, however it is recommended to
   use v2.2.0 if providing your VM with memory greater than 1GB due to potential
   issues with memory mapping larger areas.
   Note: QEMU v1.6.2 will also work, with slightly different command line parameters,
   which are specified later in this document.

Adding DPDK vhost-cuse ports to the Switch:
--------------------------------------

Following the steps above to create a bridge, you can now add DPDK vhost-cuse
as a port to the vswitch. Unlike DPDK ring ports, DPDK vhost-cuse ports can have
arbitrary names.

  -  For vhost-cuse, the name of the port type is `dpdkvhostcuse`

     ```
     ovs-vsctl add-port br0 vhost-cuse-1 -- set Interface vhost-cuse-1
     type=dpdkvhostcuse
     ```

     When attaching vhost-cuse ports to QEMU, the name provided during the
     add-port operation must match the ifname parameter on the QEMU command
     line. More instructions on this can be found in the next section.

DPDK vhost-cuse VM configuration:
---------------------------------

   vhost-cuse ports use a Linux* character device to communicate with QEMU.
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

   Alternatively the `qemu-wrap.py` script can be used to automate the
   requirements specified above and can be used in conjunction with libvirt if
   desired. See the "DPDK vhost VM configuration with QEMU wrapper" section
   below.

4. Configure huge pages:
   QEMU must allocate the VM's memory on hugetlbfs. Vhost ports access a
   virtio-net device's virtual rings and packet buffers mapping the VM's
   physical memory on hugetlbfs. To enable vhost-ports to map the VM's
   memory into their process address space, pass the following parameters
   to QEMU:

     `-object memory-backend-file,id=mem,size=4096M,mem-path=/dev/hugepages,
      share=on -numa node,memdev=mem -mem-prealloc`

   Note: For use with an earlier QEMU version such as v1.6.2, use the
   following to configure hugepages instead:

     `-mem-path /dev/hugepages -mem-prealloc`

DPDK vhost-cuse VM configuration with QEMU wrapper:
---------------------------------------------------
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

DPDK vhost-cuse VM configuration with libvirt:
----------------------------------------------

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

DPDK vhost-cuse VM configuration with libvirt and QEMU wrapper:
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
  the correct "vhostfd" value in the QEMU command line arguments.

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

  Platform and Network Interface:
  - By default with DPDK 2.2, a maximum of 64 TX queues can be used with an
    Intel XL710 Network Interface on a platform with more than 64 logical
    cores. If a user attempts to add an XL710 interface as a DPDK port type to
    a system as described above, an error will be reported that initialization
    failed for the 65th queue. OVS will then roll back to the previous
    successful queue initialization and use that value as the total number of
    TX queues available with queue locking. If a user wishes to use more than
    64 queues and avoid locking, then the
    `CONFIG_RTE_LIBRTE_I40E_QUEUE_NUM_PER_PF` config parameter in DPDK must be
    increased to the desired number of queues. Both DPDK and OVS must be
    recompiled for this change to take effect.

  vHost and QEMU v2.4.0+:
  - For versions of QEMU v2.4.0 and later, it is currently not possible to
    unbind more than one dpdkvhostuser port from the guest kernel driver
    without causing the ovs-vswitchd process to crash. If this is a requirement
    for your use case, it is recommended either to use a version of QEMU
    between v2.2.0 and v2.3.1 (inclusive), or alternatively, to apply the
    following patch to DPDK and rebuild:
    http://dpdk.org/dev/patchwork/patch/7736/
    This problem will likely be resolved in Open vSwitch at a later date, when
    the next release of DPDK (which includes the above patch) is available and
    integrated into OVS.

Bug Reporting:
--------------

Please report problems to bugs@openvswitch.org.

[INSTALL.userspace.md]:INSTALL.userspace.md
[INSTALL.md]:INSTALL.md
[DPDK Linux GSG]: http://www.dpdk.org/doc/guides/linux_gsg/build_dpdk.html#binding-and-unbinding-network-ports-to-from-the-igb-uioor-vfio-modules
[DPDK Docs]: http://dpdk.org/doc
