OVS DPDK ADVANCED INSTALL GUIDE
=================================

## Contents

1. [Overview](#overview)
2. [Building Shared Library](#build)
3. [System configuration](#sysconf)
4. [Performance Tuning](#perftune)
5. [OVS Testcases](#ovstc)
6. [Vhost Walkthrough](#vhost)
7. [QOS](#qos)
8. [Rate Limiting](#rl)
9. [Flow Control](#fc)
10. [Vsperf](#vsperf)

## <a name="overview"></a> 1. Overview

The Advanced Install Guide explains how to improve OVS performance using
DPDK datapath. This guide also provides information on tuning, system configuration,
troubleshooting, static code analysis and testcases.

## <a name="build"></a> 2. Building Shared Library

DPDK can be built as static or shared library and shall be linked by applications
using DPDK datapath. The section lists steps to build shared library and dynamically
link DPDK against OVS.

Note: Minor performance loss is seen with OVS when using shared DPDK library as
compared to static library.

Check section [INSTALL DPDK], [INSTALL OVS] of INSTALL.DPDK on download instructions
for DPDK and OVS.

  * Configure the DPDK library

  Set `CONFIG_RTE_BUILD_SHARED_LIB=y` in `config/common_base`
  to generate shared DPDK library


  * Build and install DPDK

    For Default install (without IVSHMEM), set `export DPDK_TARGET=x86_64-native-linuxapp-gcc`
    For IVSHMEM case, set `export DPDK_TARGET=x86_64-ivshmem-linuxapp-gcc`

    ```
    export DPDK_DIR=/usr/src/dpdk-16.07
    export DPDK_BUILD=$DPDK_DIR/$DPDK_TARGET
    make install T=$DPDK_TARGET DESTDIR=install
    ```

  * Build, Install and Setup OVS.

  Export the DPDK shared library location and setup OVS as listed in
  section 3.3 of INSTALL.DPDK.

  `export LD_LIBRARY_PATH=$DPDK_DIR/x86_64-native-linuxapp-gcc/lib`

## <a name="sysconf"></a> 3. System Configuration

To achieve optimal OVS performance, the system can be configured and that includes
BIOS tweaks, Grub cmdline additions, better understanding of NUMA nodes and
apt selection of PCIe slots for NIC placement.

### 3.1 Recommended BIOS settings

  ```
  | Settings                  | values    | comments
  |---------------------------|-----------|-----------
  | C3 power state            | Disabled  | -
  | C6 power state            | Disabled  | -
  | MLC Streamer              | Enabled   | -
  | MLC Spacial prefetcher    | Enabled   | -
  | DCU Data prefetcher       | Enabled   | -
  | DCA                       | Enabled   | -
  | CPU power and performance | Performance -
  | Memory RAS and perf       |           | -
    config-> NUMA optimized   | Enabled   | -
  ```

### 3.2 PCIe Slot Selection

The fastpath performance also depends on factors like the NIC placement,
Channel speeds between PCIe slot and CPU, proximity of PCIe slot to the CPU
cores running DPDK application. Listed below are the steps to identify
right PCIe slot.

- Retrieve host details using cmd `dmidecode -t baseboard | grep "Product Name"`
- Download the technical specification for Product listed eg: S2600WT2.
- Check the Product Architecture Overview on the Riser slot placement,
  CPU sharing info and also PCIe channel speeds.

  example: On S2600WT, CPU1 and CPU2 share Riser Slot 1 with Channel speed between
  CPU1 and Riser Slot1 at 32GB/s, CPU2 and Riser Slot1 at 16GB/s. Running DPDK app
  on CPU1 cores and NIC inserted in to Riser card Slots will optimize OVS performance
  in this case.

- Check the Riser Card #1 - Root Port mapping information, on the available slots
  and individual bus speeds. In S2600WT slot 1, slot 2 has high bus speeds and are
  potential slots for NIC placement.

### 3.3 Advanced Hugepage setup

  Allocate and mount 1G Huge pages:

  - For persistent allocation of huge pages, add the following options to the kernel bootline

      Add `default_hugepagesz=1GB hugepagesz=1G hugepages=N`

      For platforms supporting multiple huge page sizes, Add options

      `default_hugepagesz=<size> hugepagesz=<size> hugepages=N`
      where 'N' = Number of huge pages requested, 'size' = huge page size,
      optional suffix [kKmMgG]

  - For run-time allocation of huge pages

      `echo N > /sys/devices/system/node/nodeX/hugepages/hugepages-1048576kB/nr_hugepages`
      where 'N' = Number of huge pages requested, 'X' = NUMA Node

      Note: For run-time allocation of 1G huge pages, Contiguous Memory Allocator(CONFIG_CMA)
      has to be supported by kernel, check your Linux distro.

  - Mount huge pages

      `mount -t hugetlbfs -o pagesize=1G none /dev/hugepages`

      Note: Mount hugepages if not already mounted by default.

### 3.4 Enable Hyperthreading

  Requires BIOS changes

  With HT/SMT enabled, A Physical core appears as two logical cores.
  SMT can be utilized to spawn worker threads on logical cores of the same
  physical core there by saving additional cores.

  With DPDK, When pinning pmd threads to logical cores, care must be taken
  to set the correct bits in the pmd-cpu-mask to ensure that the pmd threads are
  pinned to SMT siblings.

  Example System configuration:
  Dual socket Machine, 2x 10 core processors, HT enabled, 40 logical cores

  To use two logical cores which share the same physical core for pmd threads,
  the following command can be used to identify a pair of logical cores.

  `cat /sys/devices/system/cpu/cpuN/topology/thread_siblings_list`, where N is the
  logical core number.

  In this example, it would show that cores 1 and 21 share the same physical core.
  The pmd-cpu-mask to enable two pmd threads running on these two logical cores
  (one physical core) is.

  `ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=100002`

### 3.5 Isolate cores

  'isolcpus' option can be used to isolate cores from the linux scheduler.
  The isolated cores can then be used to dedicatedly run HPC applications/threads.
  This helps in better application performance due to zero context switching and
  minimal cache thrashing. To run platform logic on core 0 and isolate cores
  between 1 and 19 from scheduler, Add  `isolcpus=1-19` to GRUB cmdline.

  Note: It has been verified that core isolation has minimal advantage due to
  mature Linux scheduler in some circumstances.

### 3.6 NUMA/Cluster on Die

  Ideally inter NUMA datapaths should be avoided where possible as packets
  will go across QPI and there may be a slight performance penalty when
  compared with intra NUMA datapaths. On Intel Xeon Processor E5 v3,
  Cluster On Die is introduced on models that have 10 cores or more.
  This makes it possible to logically split a socket into two NUMA regions
  and again it is preferred where possible to keep critical datapaths
  within the one cluster.

  It is good practice to ensure that threads that are in the datapath are
  pinned to cores in the same NUMA area. e.g. pmd threads and QEMU vCPUs
  responsible for forwarding. If DPDK is built with
  CONFIG_RTE_LIBRTE_VHOST_NUMA=y, vHost User ports automatically
  detect the NUMA socket of the QEMU vCPUs and will be serviced by a PMD
  from the same node provided a core on this node is enabled in the
  pmd-cpu-mask. libnuma packages are required for this feature.

### 3.7 Compiler Optimizations

  The default compiler optimization level is '-O2'. Changing this to
  more aggressive compiler optimization such as '-O3 -march=native'
  with gcc(verified on 5.3.1) can produce performance gains though not
  siginificant. '-march=native' will produce optimized code on local machine
  and should be used when SW compilation is done on Testbed.

## <a name="perftune"></a> 4. Performance Tuning

### 4.1 Affinity

For superior performance, DPDK pmd threads and Qemu vCPU threads
needs to be affinitized accordingly.

  * PMD thread Affinity

    A poll mode driver (pmd) thread handles the I/O of all DPDK
    interfaces assigned to it. A pmd thread shall poll the ports
    for incoming packets, switch the packets and send to tx port.
    pmd thread is CPU bound, and needs to be affinitized to isolated
    cores for optimum performance.

    By setting a bit in the mask, a pmd thread is created and pinned
    to the corresponding CPU core. e.g. to run a pmd thread on core 2

    `ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=4`

    Note: pmd thread on a NUMA node is only created if there is
    at least one DPDK interface from that NUMA node added to OVS.

  * Qemu vCPU thread Affinity

    A VM performing simple packet forwarding or running complex packet
    pipelines has to ensure that the vCPU threads performing the work has
    as much CPU occupancy as possible.

    Example: On a multicore VM, multiple QEMU vCPU threads shall be spawned.
    when the DPDK 'testpmd' application that does packet forwarding
    is invoked, 'taskset' cmd should be used to affinitize the vCPU threads
    to the dedicated isolated cores on the host system.

### 4.2 Multiple poll mode driver threads

  With pmd multi-threading support, OVS creates one pmd thread
  for each NUMA node by default. However, it can be seen that in cases
  where there are multiple ports/rxq's producing traffic, performance
  can be improved by creating multiple pmd threads running on separate
  cores. These pmd threads can then share the workload by each being
  responsible for different ports/rxq's. Assignment of ports/rxq's to
  pmd threads is done automatically.

  A set bit in the mask means a pmd thread is created and pinned
  to the corresponding CPU core. e.g. to run pmd threads on core 1 and 2

  `ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=6`

  For example, when using dpdk and dpdkvhostuser ports in a bi-directional
  VM loopback as shown below, spreading the workload over 2 or 4 pmd
  threads shows significant improvements as there will be more total CPU
  occupancy available.

  NIC port0 <-> OVS <-> VM <-> OVS <-> NIC port 1

### 4.3 DPDK physical port Rx Queues

  `ovs-vsctl set Interface <DPDK interface> options:n_rxq=<integer>`

  The command above sets the number of rx queues for DPDK physical interface.
  The rx queues are assigned to pmd threads on the same NUMA node in a
  round-robin fashion.

### 4.4 Exact Match Cache

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
  running. This can be done as described in section 4.2.

### 4.5 Rx Mergeable buffers

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

## <a name="ovstc"></a> 5. OVS Testcases
### 5.1 PHY-VM-PHY [VHOST LOOPBACK]

The section 5.2 in INSTALL.DPDK guide lists steps for PVP loopback testcase
and packet forwarding using DPDK testpmd application in the Guest VM.
For users wanting to do packet forwarding using kernel stack below are the steps.

  ```
  ifconfig eth1 1.1.1.2/24
  ifconfig eth2 1.1.2.2/24
  systemctl stop firewalld.service
  systemctl stop iptables.service
  sysctl -w net.ipv4.ip_forward=1
  sysctl -w net.ipv4.conf.all.rp_filter=0
  sysctl -w net.ipv4.conf.eth1.rp_filter=0
  sysctl -w net.ipv4.conf.eth2.rp_filter=0
  route add -net 1.1.2.0/24 eth2
  route add -net 1.1.1.0/24 eth1
  arp -s 1.1.2.99 DE:AD:BE:EF:CA:FE
  arp -s 1.1.1.99 DE:AD:BE:EF:CA:EE
  ```

### 5.2 PHY-VM-PHY [IVSHMEM]

  The steps (1-5) in 3.3 section of INSTALL.DPDK guide will create & initialize DB,
  start vswitchd and add dpdk devices to bridge br0.

  1. Add DPDK ring port to the bridge

       ```
       ovs-vsctl add-port br0 dpdkr0 -- set Interface dpdkr0 type=dpdkr
       ```

  2. Build modified Qemu (Qemu-2.2.1 + ivshmem-qemu-2.2.1.patch)

       ```
       cd /usr/src/
       wget http://wiki.qemu.org/download/qemu-2.2.1.tar.bz2
       tar -jxvf qemu-2.2.1.tar.bz2
       cd /usr/src/qemu-2.2.1
       wget https://raw.githubusercontent.com/netgroup-polito/un-orchestrator/master/orchestrator/compute_controller/plugins/kvm-libvirt/patches/ivshmem-qemu-2.2.1.patch
       patch -p1 < ivshmem-qemu-2.2.1.patch
       ./configure --target-list=x86_64-softmmu --enable-debug --extra-cflags='-g'
       make -j 4
       ```

  3. Generate Qemu commandline

       ```
       mkdir -p /usr/src/cmdline_generator
       cd /usr/src/cmdline_generator
       wget https://raw.githubusercontent.com/netgroup-polito/un-orchestrator/master/orchestrator/compute_controller/plugins/kvm-libvirt/cmdline_generator/cmdline_generator.c
       wget https://raw.githubusercontent.com/netgroup-polito/un-orchestrator/master/orchestrator/compute_controller/plugins/kvm-libvirt/cmdline_generator/Makefile
       export RTE_SDK=/usr/src/dpdk-16.07
       export RTE_TARGET=x86_64-ivshmem-linuxapp-gcc
       make
       ./build/cmdline_generator -m -p dpdkr0 XXX
       cmdline=`cat OVSMEMPOOL`
       ```

  4. start Guest VM

       ```
       export VM_NAME=ivshmem-vm
       export QCOW2_IMAGE=/root/CentOS7_x86_64.qcow2
       export QEMU_BIN=/usr/src/qemu-2.2.1/x86_64-softmmu/qemu-system-x86_64

       taskset 0x20 $QEMU_BIN -cpu host -smp 2,cores=2 -hda $QCOW2_IMAGE -m 4096 --enable-kvm -name $VM_NAME -nographic -vnc :2 -pidfile /tmp/vm1.pid $cmdline
       ```

  5. Running sample "dpdk ring" app in VM

       ```
       echo 1024 > /proc/sys/vm/nr_hugepages
       mount -t hugetlbfs nodev /dev/hugepages (if not already mounted)

       # Build the DPDK ring application in the VM
       export RTE_SDK=/root/dpdk-16.07
       export RTE_TARGET=x86_64-ivshmem-linuxapp-gcc
       make

       # Run dpdkring application
       ./build/dpdkr -c 1 -n 4 -- -n 0
       where "-n 0" refers to ring '0' i.e dpdkr0
       ```

### 5.3 PHY-VM-PHY [VHOST MULTIQUEUE]

  The steps (1-5) in 3.3 section of [INSTALL DPDK] guide will create & initialize DB,
  start vswitchd and add dpdk devices to bridge br0.

  1. Configure PMD and RXQs. For example set no. of dpdk port rx queues to atleast 2.
     The number of rx queues at vhost-user interface gets automatically configured after
     virtio device connection and doesn't need manual configuration.

     ```
     ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=c
     ovs-vsctl set Interface dpdk0 options:n_rxq=2
     ovs-vsctl set Interface dpdk1 options:n_rxq=2
     ```

  2. Instantiate Guest VM using Qemu cmdline

       Guest Configuration

       ```
       | configuration        | values | comments
       |----------------------|--------|-----------------
       | qemu version         | 2.5.0  |
       | qemu thread affinity |2 cores | taskset 0x30
       | memory               | 4GB    | -
       | cores                | 2      | -
       | Qcow2 image          |Fedora22| -
       | multiqueue           |   on   | -
       ```

       Instantiate Guest

       ```
       export VM_NAME=vhost-vm
       export GUEST_MEM=4096M
       export QCOW2_IMAGE=/root/Fedora22_x86_64.qcow2
       export VHOST_SOCK_DIR=/usr/local/var/run/openvswitch

       taskset 0x30 qemu-system-x86_64 -cpu host -smp 2,cores=2 -drive file=$QCOW2_IMAGE -m 4096M --enable-kvm -name $VM_NAME -nographic -object memory-backend-file,id=mem,size=$GUEST_MEM,mem-path=/dev/hugepages,share=on -numa node,memdev=mem -mem-prealloc -chardev socket,id=char1,path=$VHOST_SOCK_DIR/dpdkvhostuser0 -netdev type=vhost-user,id=mynet1,chardev=char1,vhostforce,queues=2 -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,mq=on,vectors=6 -chardev socket,id=char2,path=$VHOST_SOCK_DIR/dpdkvhostuser1 -netdev type=vhost-user,id=mynet2,chardev=char2,vhostforce,queues=2 -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2,mq=on,vectors=6
       ```

       Note: Queue value above should match the queues configured in OVS, The vector value
       should be set to 'no. of queues x 2 + 2'.

  3. Guest interface configuration

     Assuming there are 2 interfaces in the guest named eth0, eth1 check the channel
     configuration and set the number of combined channels to 2 for virtio devices.
     More information can be found in [Vhost walkthrough] section.

       ```
       ethtool -l eth0
       ethtool -L eth0 combined 2
       ethtool -L eth1 combined 2
       ```

  4. Kernel Packet forwarding

     Configure IP and enable interfaces

     ```
     ifconfig eth0 5.5.5.1/24 up
     ifconfig eth1 90.90.90.1/24 up
     ```

     Configure IP forwarding and add route entries

     ```
     sysctl -w net.ipv4.ip_forward=1
     sysctl -w net.ipv4.conf.all.rp_filter=0
     sysctl -w net.ipv4.conf.eth0.rp_filter=0
     sysctl -w net.ipv4.conf.eth1.rp_filter=0
     ip route add 2.1.1.0/24 dev eth1
     route add default gw 2.1.1.2 eth1
     route add default gw 90.90.90.90 eth1
     arp -s 90.90.90.90 DE:AD:BE:EF:CA:FE
     arp -s 2.1.1.2 DE:AD:BE:EF:CA:FA
     ```

     Check traffic on multiple queues

     ```
     cat /proc/interrupts | grep virtio
     ```

## <a name="vhost"></a> 6. Vhost Walkthrough

DPDK 16.07 supports two types of vhost:

1. vhost-user - enabled default

2. vhost-cuse - Legacy, disabled by default

### 6.1 vhost-user

  - Prerequisites:

    QEMU version >= 2.2

  - Adding vhost-user ports to Switch

    Unlike DPDK ring ports, DPDK vhost-user ports can have arbitrary names,
    except that forward and backward slashes are prohibited in the names.

    For vhost-user, the name of the port type is `dpdkvhostuser`

    ```
    ovs-vsctl add-port br0 vhost-user-1 -- set Interface vhost-user-1
    type=dpdkvhostuser
    ```

    This action creates a socket located at
    `/usr/local/var/run/openvswitch/vhost-user-1`, which you must provide
    to your VM on the QEMU command line. More instructions on this can be
    found in the next section "Adding vhost-user ports to VM"

    Note: If you wish for the vhost-user sockets to be created in a
    sub-directory of `/usr/local/var/run/openvswitch`, you may specify
    this directory in the ovsdb like so:

    `./utilities/ovs-vsctl --no-wait \
      set Open_vSwitch . other_config:vhost-sock-dir=subdir`

  - Adding vhost-user ports to VM

    1. Configure sockets

       Pass the following parameters to QEMU to attach a vhost-user device:

       ```
       -chardev socket,id=char1,path=/usr/local/var/run/openvswitch/vhost-user-1
       -netdev type=vhost-user,id=mynet1,chardev=char1,vhostforce
       -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1
       ```

       where vhost-user-1 is the name of the vhost-user port added
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
       memory into their process address space, pass the following parameters
       to QEMU:

       ```
       -object memory-backend-file,id=mem,size=4096M,mem-path=/dev/hugepages,
       share=on -numa node,memdev=mem -mem-prealloc
       ```

    3. Enable multiqueue support(OPTIONAL)

       QEMU needs to be configured to use multiqueue.
       The $q below is the number of queues.
       The $v is the number of vectors, which is '$q x 2 + 2'.

       ```
       -chardev socket,id=char2,path=/usr/local/var/run/openvswitch/vhost-user-2
       -netdev type=vhost-user,id=mynet2,chardev=char2,vhostforce,queues=$q
       -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2,mq=on,vectors=$v
       ```

       The vhost-user interface will be automatically reconfigured with required
       number of rx and tx queues after connection of virtio device.
       Manual configuration of `n_rxq` is not supported because OVS will work
       properly only if `n_rxq` will match number of queues configured in QEMU.

       A least 2 PMDs should be configured for the vswitch when using multiqueue.
       Using a single PMD will cause traffic to be enqueued to the same vhost
       queue rather than being distributed among different vhost queues for a
       vhost-user interface.

       If traffic destined for a VM configured with multiqueue arrives to the
       vswitch via a physical DPDK port, then the number of rxqs should also be
       set to at least 2 for that physical DPDK port. This is required to increase
       the probability that a different PMD will handle the multiqueue
       transmission to the guest using a different vhost queue.

       If one wishes to use multiple queues for an interface in the guest, the
       driver in the guest operating system must be configured to do so. It is
       recommended that the number of queues configured be equal to '$q'.

       For example, this can be done for the Linux kernel virtio-net driver with:

       ```
       ethtool -L <DEV> combined <$q>
       ```
       where `-L`: Changes the numbers of channels of the specified network device
       and `combined`: Changes the number of multi-purpose channels.

  - VM Configuration with libvirt

    * change the user/group, access control policty and restart libvirtd.

      - In `/etc/libvirt/qemu.conf` add/edit the following lines

        ```
        user = "root"
        group = "root"
        ```

      - Disable SELinux or set to permissive mode

        `setenforce 0`

      - Restart the libvirtd process, For example, on Fedora

        `systemctl restart libvirtd.service`

    * Instantiate the VM

      - Copy the xml configuration from [Guest VM using libvirt] in to workspace.

      - Start the VM.

         `virsh create demovm.xml`

      - Connect to the guest console

         `virsh console demovm`

    * VM configuration

      The demovm xml configuration is aimed at achieving out of box performance
      on VM.

      - The vcpus are pinned to the cores of the CPU socket 0 using vcpupin.

      - Configure NUMA cell and memory shared using memAccess='shared'.

      - Disable mrg_rxbuf='off'.

      Note: For information on libvirt and further tuning refer [libvirt].

### 6.2 vhost-cuse

  - Prerequisites:

    QEMU version >= 2.2

  - Enable vhost-cuse support

    1. Enable vhost cuse support in DPDK

       Set `CONFIG_RTE_LIBRTE_VHOST_USER=n` in config/common_linuxapp and follow the
       steps in 2.2 section of INSTALL.DPDK guide to build DPDK with cuse support.
       OVS will detect that DPDK has vhost-cuse libraries compiled and in turn will enable
       support for it in the switch and disable vhost-user support.

    2. Insert the Cuse module

       `modprobe cuse`

    3. Build and insert the `eventfd_link` module

       ```
       cd $DPDK_DIR/lib/librte_vhost/eventfd_link/
       make
       insmod $DPDK_DIR/lib/librte_vhost/eventfd_link.ko
       ```

  - Adding vhost-cuse ports to Switch

    Unlike DPDK ring ports, DPDK vhost-cuse ports can have arbitrary names.
    For vhost-cuse, the name of the port type is `dpdkvhostcuse`

    ```
    ovs-vsctl add-port br0 vhost-cuse-1 -- set Interface vhost-cuse-1
    type=dpdkvhostcuse
    ```

    When attaching vhost-cuse ports to QEMU, the name provided during the
    add-port operation must match the ifname parameter on the QEMU cmd line.

  - Adding vhost-cuse ports to VM

    vhost-cuse ports use a Linux* character device to communicate with QEMU.
    By default it is set to `/dev/vhost-net`. It is possible to reuse this
    standard device for DPDK vhost, which makes setup a little simpler but it
    is better practice to specify an alternative character device in order to
    avoid any conflicts if kernel vhost is to be used in parallel.

    1. This step is only needed if using an alternative character device.

       ```
       ./utilities/ovs-vsctl --no-wait set Open_vSwitch . \
            other_config:cuse-dev-name=my-vhost-net
       ```

       In the example above, the character device to be used will be
       `/dev/my-vhost-net`.

    2. In case of reusing kernel vhost character device, there would be conflict
       user should remove it.

       `rm -rf /dev/vhost-net`

    3. Configure virtio-net adapters

       The following parameters must be passed to the QEMU binary, repeat
       the below parameters for multiple devices.

       ```
       -netdev tap,id=<id>,script=no,downscript=no,ifname=<name>,vhost=on
       -device virtio-net-pci,netdev=net1,mac=<mac>
       ```

       The DPDK vhost library will negotiate its own features, so they
       need not be passed in as command line params. Note that as offloads
       are disabled this is the equivalent of setting

       `csum=off,gso=off,guest_tso4=off,guest_tso6=off,guest_ecn=off`

       When using an alternative character device, it must be explicitly
       passed to QEMU using the `vhostfd` argument

       ```
       -netdev tap,id=<id>,script=no,downscript=no,ifname=<name>,vhost=on,
       vhostfd=<open_fd> -device virtio-net-pci,netdev=net1,mac=<mac>
       ```

       The open file descriptor must be passed to QEMU running as a child
       process. This could be done with a simple python script.

       ```
       #!/usr/bin/python
       fd = os.open("/dev/usvhost", os.O_RDWR)
       subprocess.call("qemu-system-x86_64 .... -netdev tap,id=vhostnet0,\
                       vhost=on,vhostfd=" + fd +"...", shell=True)
       ```

    4. Configure huge pages

       QEMU must allocate the VM's memory on hugetlbfs. Vhost ports access a
       virtio-net device's virtual rings and packet buffers mapping the VM's
       physical memory on hugetlbfs. To enable vhost-ports to map the VM's
       memory into their process address space, pass the following parameters
       to QEMU

       `-object memory-backend-file,id=mem,size=4096M,mem-path=/dev/hugepages,
       share=on -numa node,memdev=mem -mem-prealloc`

  - VM Configuration with QEMU wrapper

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

  - VM Configuration with libvirt

    If you are using libvirt, you must enable libvirt to access the character
    device by adding it to controllers cgroup for libvirtd using the following
    steps.

    1. In `/etc/libvirt/qemu.conf` add/edit the following lines:

       ```
       clear_emulator_capabilities = 0
       user = "root"
       group = "root"
       cgroup_device_acl = [
             "/dev/null", "/dev/full", "/dev/zero",
             "/dev/random", "/dev/urandom",
             "/dev/ptmx", "/dev/kvm", "/dev/kqemu",
             "/dev/rtc", "/dev/hpet", "/dev/net/tun",
             "/dev/<my-vhost-device>",
             "/dev/hugepages"]
       ```

       <my-vhost-device> refers to "vhost-net" if using the `/dev/vhost-net`
       device. If you have specificed a different name in the database
       using the "other_config:cuse-dev-name" parameter, please specify that
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

  - VM Configuration with libvirt & QEMU wrapper

    To use the qemu-wrapper script in conjuntion with libvirt, follow the
    steps in the previous section before proceeding with the following steps:

    1. Place `qemu-wrap.py` in libvirtd binary search PATH ($PATH)
       Ideally in the same directory that the QEMU binary is located.

    2. Ensure that the script has the same owner/group and file permissions
       as the QEMU binary.

    3. Update the VM xml file using "virsh edit VM.xml"

       Set the VM to use the launch script.
       Set the emulator path contained in the `<emulator><emulator/>` tags.
       For example, replace `<emulator>/usr/bin/qemu-kvm<emulator/>` with
          `<emulator>/usr/bin/qemu-wrap.py<emulator/>`

    4. Edit the Configuration Parameters section of the script to point to
       the correct emulator location and set any additional options. If you are
       using a alternative character device name, please set "us_vhost_path" to the
       location of that device. The script will automatically detect and insert
       the correct "vhostfd" value in the QEMU command line arguments.

    5. Use virt-manager to launch the VM

### 6.3 DPDK backend inside VM

  Please note that additional configuration is required if you want to run
  ovs-vswitchd with DPDK backend inside a QEMU virtual machine. Ovs-vswitchd
  creates separate DPDK TX queues for each CPU core available. This operation
  fails inside QEMU virtual machine because, by default, VirtIO NIC provided
  to the guest is configured to support only single TX queue and single RX
  queue. To change this behavior, you need to turn on 'mq' (multiqueue)
  property of all virtio-net-pci devices emulated by QEMU and used by DPDK.
  You may do it manually (by changing QEMU command line) or, if you use
  Libvirt, by adding the following string:

  `<driver name='vhost' queues='N'/>`

  to <interface> sections of all network devices used by DPDK. Parameter 'N'
  determines how many queues can be used by the guest.This may not work with
  old versions of QEMU found in some distros and need Qemu version >= 2.2.

## <a name="qos"></a> 7. QOS

Here is an example on QOS usage.
Assuming you have a vhost-user port transmitting traffic consisting of
packets of size 64 bytes, the following command would limit the egress
transmission rate of the port to ~1,000,000 packets per second

`ovs-vsctl set port vhost-user0 qos=@newqos -- --id=@newqos create qos
type=egress-policer other-config:cir=46000000 other-config:cbs=2048`

To examine the QoS configuration of the port:

`ovs-appctl -t ovs-vswitchd qos/show vhost-user0`

To clear the QoS configuration from the port and ovsdb use the following:

`ovs-vsctl destroy QoS vhost-user0 -- clear Port vhost-user0 qos`

For more details regarding egress-policer parameters please refer to the
vswitch.xml.

## <a name="rl"></a> 8. Rate Limiting

Here is an example on Ingress Policing usage.
Assuming you have a vhost-user port receiving traffic consisting of
packets of size 64 bytes, the following command would limit the reception
rate of the port to ~1,000,000 packets per second:

`ovs-vsctl set interface vhost-user0 ingress_policing_rate=368000
 ingress_policing_burst=1000`

To examine the ingress policer configuration of the port:

`ovs-vsctl list interface vhost-user0`

To clear the ingress policer configuration from the port use the following:

`ovs-vsctl set interface vhost-user0 ingress_policing_rate=0`

For more details regarding ingress-policer see the vswitch.xml.

## <a name="fc"></a> 9. Flow control.
Flow control can be enabled only on DPDK physical ports.
To enable flow control support at tx side while adding a port, add the
'tx-flow-ctrl' option to the 'ovs-vsctl add-port' as in the eg: below.

```
ovs-vsctl add-port br0 dpdk0 -- \
set Interface dpdk0 type=dpdk options:tx-flow-ctrl=true
```

Similarly to enable rx flow control,

```
ovs-vsctl add-port br0 dpdk0 -- \
set Interface dpdk0 type=dpdk options:rx-flow-ctrl=true
```

And to enable the flow control auto-negotiation,

```
ovs-vsctl add-port br0 dpdk0 -- \
set Interface dpdk0 type=dpdk options:flow-ctrl-autoneg=true
```

To turn ON the tx flow control at run time(After the port is being added
to OVS), the command-line input will be,

`ovs-vsctl set Interface dpdk0 options:tx-flow-ctrl=true`

The flow control parameters can be turned off by setting 'false' to the
respective parameter. To disable the flow control at tx side,

`ovs-vsctl set Interface dpdk0 options:tx-flow-ctrl=false`

## <a name="vsperf"></a> 10. Vsperf

Vsperf project goal is to develop vSwitch test framework that can be used to
validate the suitability of different vSwitch implementations in a Telco deployment
environment. More information can be found in below link.

https://wiki.opnfv.org/display/vsperf/VSperf+Home


Bug Reporting:
--------------

Please report problems to bugs@openvswitch.org.


[INSTALL.userspace.md]:INSTALL.userspace.md
[INSTALL.md]:INSTALL.md
[DPDK Linux GSG]: http://www.dpdk.org/doc/guides/linux_gsg/build_dpdk.html#binding-and-unbinding-network-ports-to-from-the-igb-uioor-vfio-modules
[DPDK Docs]: http://dpdk.org/doc
[libvirt]: http://libvirt.org/formatdomain.html
[Guest VM using libvirt]: INSTALL.DPDK.md#ovstc
[Vhost walkthrough]: INSTALL.DPDK.md#vhost
[INSTALL DPDK]: INSTALL.DPDK.md#build
[INSTALL OVS]: INSTALL.DPDK.md#build
