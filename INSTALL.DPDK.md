OVS DPDK INSTALL GUIDE
================================

## Contents

1. [Overview](#overview)
2. [Building and Installation](#build)
3. [Setup OVS DPDK datapath](#ovssetup)
4. [DPDK in the VM](#builddpdk)
5. [OVS Testcases](#ovstc)
6. [Limitations ](#ovslimits)

## <a name="overview"></a> 1. Overview

Open vSwitch can use DPDK lib to operate entirely in userspace.
This file provides information on installation and use of Open vSwitch
using DPDK datapath.  This version of Open vSwitch should be built manually
with `configure` and `make`.

The DPDK support of Open vSwitch is considered 'experimental'.

### Prerequisites

* Required: DPDK 16.07.2
* Hardware: [DPDK Supported NICs] when physical ports in use

## <a name="build"></a> 2. Building and Installation

### 2.1 Configure & build the Linux kernel

On Linux Distros running kernel version >= 3.0, kernel rebuild is not required
and only grub cmdline needs to be updated for enabling IOMMU [VFIO support - 3.2].
For older kernels, check if kernel is built with  UIO, HUGETLBFS, PROC_PAGE_MONITOR,
HPET, HPET_MMAP support.

Detailed system requirements can be found at [DPDK requirements] and also refer to
advanced install guide [INSTALL.DPDK-ADVANCED.md]

### 2.2 Install DPDK
  1. [Download DPDK] and extract the file, for example in to /usr/src
     and set DPDK_DIR

     ```
     cd /usr/src/
     wget http://fast.dpdk.org/rel/dpdk-16.07.2.tar.xz
     tar xf dpdk-16.07.2.tar.xz
     export DPDK_DIR=/usr/src/dpdk-stable-16.07.2
     cd $DPDK_DIR
     ```

  2. Configure and Install DPDK

     Build and install the DPDK library.

     ```
     export DPDK_TARGET=x86_64-native-linuxapp-gcc
     export DPDK_BUILD=$DPDK_DIR/$DPDK_TARGET
     make install T=$DPDK_TARGET DESTDIR=install
     ```

     Note: For IVSHMEM, Set `export DPDK_TARGET=x86_64-ivshmem-linuxapp-gcc`

### 2.3 Install OVS
  OVS can be installed using different methods. For OVS to use DPDK datapath,
  it has to be configured with DPDK support and is done by './configure --with-dpdk'.
  This section focus on generic recipe that suits most cases and for distribution
  specific instructions, refer [INSTALL.Fedora.md], [INSTALL.RHEL.md] and
  [INSTALL.Debian.md].

  The OVS sources can be downloaded in different ways and skip this section
  if already having the correct sources. Otherwise download the correct version using
  one of the below suggested methods and follow the documentation of that specific
  version.

  - OVS stable releases can be downloaded in compressed format from [Download OVS]

     ```
     cd /usr/src
     wget http://openvswitch.org/releases/openvswitch-<version>.tar.gz
     tar -zxvf openvswitch-<version>.tar.gz
     export OVS_DIR=/usr/src/openvswitch-<version>
     ```

  - OVS current development can be clone using 'git' tool

     ```
     cd /usr/src/
     git clone https://github.com/openvswitch/ovs.git
     export OVS_DIR=/usr/src/ovs
     ```

  - Install OVS dependencies

     GNU make, GCC 4.x (or) Clang 3.4, libnuma (Mandatory)
     libssl, libcap-ng, Python 2.7 (Optional)
     More information can be found at [Build Requirements]

  - Configure, Install OVS

     ```
     cd $OVS_DIR
     ./boot.sh
     ./configure --with-dpdk=$DPDK_BUILD
     make install
     ```

     Note: Passing DPDK_BUILD can be skipped if DPDK library is installed in
     standard locations i.e `./configure --with-dpdk` should suffice.

  Additional information can be found in [INSTALL.md].

## <a name="ovssetup"></a> 3. Setup OVS with DPDK datapath

### 3.1 Setup Hugepages

  Allocate and mount 2M Huge pages:

  - For persistent allocation of huge pages, write to hugepages.conf file
    in /etc/sysctl.d

    `echo 'vm.nr_hugepages=2048' > /etc/sysctl.d/hugepages.conf`

  - For run-time allocation of huge pages

    `sysctl -w vm.nr_hugepages=N` where N = No. of 2M huge pages allocated

  - To verify hugepage configuration

    `grep HugePages_ /proc/meminfo`

  - Mount hugepages

    `mount -t hugetlbfs none /dev/hugepages`

    Note: Mount hugepages if not already mounted by default.

### 3.2 Setup DPDK devices using VFIO

  - Supported with kernel version >= 3.6
  - VFIO needs support from BIOS and kernel.
  - BIOS changes:

    Enable VT-d, can be verified from `dmesg | grep -e DMAR -e IOMMU` output

  - GRUB bootline:

    Add `iommu=pt intel_iommu=on`, can be verified from `cat /proc/cmdline` output

  - Load modules and bind the NIC to VFIO driver

    ```
    modprobe vfio-pci
    sudo /usr/bin/chmod a+x /dev/vfio
    sudo /usr/bin/chmod 0666 /dev/vfio/*
    $DPDK_DIR/tools/dpdk-devbind.py --bind=vfio-pci eth1
    $DPDK_DIR/tools/dpdk-devbind.py --status
    ```

  Note: If running kernels < 3.6 UIO drivers to be used,
  please check [DPDK in the VM], DPDK devices using UIO section for the steps.

### 3.3 Setup OVS

  1. DB creation (One time step)

     ```
     mkdir -p /usr/local/etc/openvswitch
     mkdir -p /usr/local/var/run/openvswitch
     rm /usr/local/etc/openvswitch/conf.db
     ovsdb-tool create /usr/local/etc/openvswitch/conf.db  \
            /usr/local/share/openvswitch/vswitch.ovsschema
     ```

  2. Start ovsdb-server

     No SSL support

     ```
     ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
         --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
         --pidfile --detach
     ```

     SSL support

     ```
     ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
         --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
         --private-key=db:Open_vSwitch,SSL,private_key \
         --certificate=Open_vSwitch,SSL,certificate \
         --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert --pidfile --detach
     ```

  3. Initialize DB (One time step)

     ```
     ovs-vsctl --no-wait init
     ```

  4. Start vswitchd

     DPDK configuration arguments can be passed to vswitchd via Open_vSwitch
     'other_config' column. The important configuration options are listed below.
     Defaults will be provided for all values not explicitly set. Refer
     ovs-vswitchd.conf.db(5) for additional information on configuration options.

     * dpdk-init
     Specifies whether OVS should initialize and support DPDK ports. This is
     a boolean, and defaults to false.

     * dpdk-lcore-mask
     Specifies the CPU cores on which dpdk lcore threads should be spawned and
     expects hex string (eg '0x123').

     * dpdk-socket-mem
     Comma separated list of memory to pre-allocate from hugepages on specific
     sockets. Please note when using this param for some NUMA nodes, that
     subsequent NUMA nodes will be assigned 0 MB if they are not explicitly
     assigned a value.

     * dpdk-hugepage-dir
     Directory where hugetlbfs is mounted

     * vhost-sock-dir
     Option to set the path to the vhost_user unix socket files.

     NOTE: Changing any of these options requires restarting the ovs-vswitchd
     application.

     Open vSwitch can be started as normal. DPDK will be initialized as long
     as the dpdk-init option has been set to 'true'.

     ```
     export DB_SOCK=/usr/local/var/run/openvswitch/db.sock
     ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-init=true
     ovs-vswitchd unix:$DB_SOCK --pidfile --detach
     ```

     If allocated more than one GB hugepage (as for IVSHMEM), set amount and
     use NUMA node 0 memory. For details on using ivshmem with DPDK, refer to
     [OVS Testcases].

     ```
     ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-socket-mem="1024,0"
     ovs-vswitchd unix:$DB_SOCK --pidfile --detach
     ```

     To better scale the work loads across cores, Multiple pmd threads can be
     created and pinned to CPU cores by explicity specifying pmd-cpu-mask.
     eg: To spawn 2 pmd threads and pin them to cores 1, 2

     ```
     ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=6
     ```

  5. Create bridge & add DPDK devices

     create a bridge with datapath_type "netdev" in the configuration database

     `ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev`

     Now you can add DPDK devices. OVS expects DPDK device names to start with
     "dpdk" and end with a portid. vswitchd should print (in the log file) the
     number of dpdk devices found.

     ```
     ovs-vsctl add-port br0 dpdk0 -- set Interface dpdk0 type=dpdk
     ovs-vsctl add-port br0 dpdk1 -- set Interface dpdk1 type=dpdk
     ```

     After the DPDK ports get added to switch, a polling thread continuously polls
     DPDK devices and consumes 100% of the core as can be checked from 'top' and 'ps' cmds.

     ```
     top -H
     ps -eLo pid,psr,comm | grep pmd
     ```

     Note: creating bonds of DPDK interfaces is slightly different to creating
     bonds of system interfaces.  For DPDK, the interface type must be explicitly
     set, for example:

     ```
     ovs-vsctl add-bond br0 dpdkbond dpdk0 dpdk1 -- set Interface dpdk0 type=dpdk -- set Interface dpdk1 type=dpdk
     ```

  6. PMD thread statistics

     ```
     # Check current stats
       ovs-appctl dpif-netdev/pmd-stats-show

     # Clear previous stats
       ovs-appctl dpif-netdev/pmd-stats-clear
     ```

  7. Port/rxq assigment to PMD threads

     ```
     # Show port/rxq assignment
       ovs-appctl dpif-netdev/pmd-rxq-show
     ```

     To change default rxq assignment to pmd threads rxqs may be manually
     pinned to desired cores using:

     ```
     ovs-vsctl set Interface <iface> \
               other_config:pmd-rxq-affinity=<rxq-affinity-list>
     ```
     where:

     ```
     <rxq-affinity-list> ::= NULL | <non-empty-list>
     <non-empty-list> ::= <affinity-pair> |
                          <affinity-pair> , <non-empty-list>
     <affinity-pair> ::= <queue-id> : <core-id>
     ```

     Example:

     ```
     ovs-vsctl set interface dpdk0 options:n_rxq=4 \
               other_config:pmd-rxq-affinity="0:3,1:7,3:8"

     Queue #0 pinned to core 3;
     Queue #1 pinned to core 7;
     Queue #2 not pinned.
     Queue #3 pinned to core 8;
     ```

     After that PMD threads on cores where RX queues was pinned will become
     `isolated`. This means that this thread will poll only pinned RX queues.

     WARNING: If there are no `non-isolated` PMD threads, `non-pinned` RX queues
     will not be polled. Also, if provided `core_id` is not available (ex. this
     `core_id` not in `pmd-cpu-mask`), RX queue will not be polled by any
     PMD thread.

     Isolation of PMD threads also can be checked using
     `ovs-appctl dpif-netdev/pmd-rxq-show` command.

  8. Stop vswitchd & Delete bridge

     ```
     ovs-appctl -t ovs-vswitchd exit
     ovs-appctl -t ovsdb-server exit
     ovs-vsctl del-br br0
     ```

## <a name="builddpdk"></a> 4. DPDK in the VM

DPDK 'testpmd' application can be run in the Guest VM for high speed
packet forwarding between vhostuser ports. DPDK and testpmd application
has to be compiled on the guest VM. Below are the steps for setting up
the testpmd application in the VM. More information on the vhostuser ports
can be found in [Vhost Walkthrough].

  * Instantiate the Guest

  ```
  Qemu version >= 2.2.0

  export VM_NAME=Centos-vm
  export GUEST_MEM=3072M
  export QCOW2_IMAGE=/root/CentOS7_x86_64.qcow2
  export VHOST_SOCK_DIR=/usr/local/var/run/openvswitch

  qemu-system-x86_64 -name $VM_NAME -cpu host -enable-kvm -m $GUEST_MEM -object memory-backend-file,id=mem,size=$GUEST_MEM,mem-path=/dev/hugepages,share=on -numa node,memdev=mem -mem-prealloc -smp sockets=1,cores=2 -drive file=$QCOW2_IMAGE -chardev socket,id=char0,path=$VHOST_SOCK_DIR/dpdkvhostuser0 -netdev type=vhost-user,id=mynet1,chardev=char0,vhostforce -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,mrg_rxbuf=off -chardev socket,id=char1,path=$VHOST_SOCK_DIR/dpdkvhostuser1 -netdev type=vhost-user,id=mynet2,chardev=char1,vhostforce -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2,mrg_rxbuf=off --nographic -snapshot
  ```

  * Download the DPDK Srcs to VM and build DPDK

  ```
  cd /root/dpdk/
  wget http://fast.dpdk.org/rel/dpdk-16.07.2.tar.xz
  tar xf dpdk-16.07.2.tar.xz
  export DPDK_DIR=/usr/src/dpdk-stable-16.07.2
  export DPDK_TARGET=x86_64-native-linuxapp-gcc
  export DPDK_BUILD=$DPDK_DIR/$DPDK_TARGET
  cd $DPDK_DIR
  make install T=$DPDK_TARGET DESTDIR=install
  ```

  * Build the test-pmd application

  ```
  cd app/test-pmd
  export RTE_SDK=$DPDK_DIR
  export RTE_TARGET=$DPDK_TARGET
  make
  ```

  * Setup Huge pages and DPDK devices using UIO

  ```
  sysctl vm.nr_hugepages=1024
  mkdir -p /dev/hugepages
  mount -t hugetlbfs hugetlbfs /dev/hugepages (only if not already mounted)
  modprobe uio
  insmod $DPDK_BUILD/kmod/igb_uio.ko
  $DPDK_DIR/tools/dpdk-devbind.py --status
  $DPDK_DIR/tools/dpdk-devbind.py -b igb_uio 00:03.0 00:04.0
  ```

  vhost ports pci ids can be retrieved using `lspci | grep Ethernet` cmd.

## <a name="ovstc"></a> 5. OVS Testcases

  Below are few testcases and the list of steps to be followed.

### 5.1 PHY-PHY

  The steps (1-5) in 3.3 section will create & initialize DB, start vswitchd and also
  add DPDK devices to bridge 'br0'.

  1. Add Test flows to forward packets betwen DPDK port 0 and port 1

       ```
       # Clear current flows
       ovs-ofctl del-flows br0

       # Add flows between port 1 (dpdk0) to port 2 (dpdk1)
       ovs-ofctl add-flow br0 in_port=1,action=output:2
       ovs-ofctl add-flow br0 in_port=2,action=output:1
       ```

### 5.2 PHY-VM-PHY [VHOST LOOPBACK]

  The steps (1-5) in 3.3 section will create & initialize DB, start vswitchd and also
  add DPDK devices to bridge 'br0'.

  1. Add dpdkvhostuser ports to bridge 'br0'. More information on the dpdkvhostuser ports
     can be found in [Vhost Walkthrough].

       ```
       ovs-vsctl add-port br0 dpdkvhostuser0 -- set Interface dpdkvhostuser0 type=dpdkvhostuser
       ovs-vsctl add-port br0 dpdkvhostuser1 -- set Interface dpdkvhostuser1 type=dpdkvhostuser
       ```

  2. Add Test flows to forward packets betwen DPDK devices and VM ports

       ```
       # Clear current flows
       ovs-ofctl del-flows br0

       # Add flows
       ovs-ofctl add-flow br0 in_port=1,action=output:3
       ovs-ofctl add-flow br0 in_port=3,action=output:1
       ovs-ofctl add-flow br0 in_port=4,action=output:2
       ovs-ofctl add-flow br0 in_port=2,action=output:4

       # Dump flows
       ovs-ofctl dump-flows br0
       ```

  3. Instantiate Guest VM using Qemu cmdline

       Guest Configuration

       ```
       | configuration        | values | comments
       |----------------------|--------|-----------------
       | qemu version         | 2.2.0  |
       | qemu thread affinity | core 5 | taskset 0x20
       | memory               | 4GB    | -
       | cores                | 2      | -
       | Qcow2 image          | CentOS7| -
       | mrg_rxbuf            | off    | -
       ```

       Instantiate Guest

       ```
       export VM_NAME=vhost-vm
       export GUEST_MEM=3072M
       export QCOW2_IMAGE=/root/CentOS7_x86_64.qcow2
       export VHOST_SOCK_DIR=/usr/local/var/run/openvswitch

       taskset 0x20 qemu-system-x86_64 -name $VM_NAME -cpu host -enable-kvm -m $GUEST_MEM -object memory-backend-file,id=mem,size=$GUEST_MEM,mem-path=/dev/hugepages,share=on -numa node,memdev=mem -mem-prealloc -smp sockets=1,cores=2 -drive file=$QCOW2_IMAGE -chardev socket,id=char0,path=$VHOST_SOCK_DIR/dpdkvhostuser0 -netdev type=vhost-user,id=mynet1,chardev=char0,vhostforce -device virtio-net-pci,mac=00:00:00:00:00:01,netdev=mynet1,mrg_rxbuf=off -chardev socket,id=char1,path=$VHOST_SOCK_DIR/dpdkvhostuser1 -netdev type=vhost-user,id=mynet2,chardev=char1,vhostforce -device virtio-net-pci,mac=00:00:00:00:00:02,netdev=mynet2,mrg_rxbuf=off --nographic -snapshot
       ```

  4. Guest VM using libvirt

     The below is a simple xml configuration of 'demovm' guest that can be instantiated
     using 'virsh'. The guest uses a pair of vhostuser port and boots with 4GB RAM and 2 cores.
     More information can be found in [Vhost Walkthrough].

       ```
       <domain type='kvm'>
         <name>demovm</name>
         <uuid>4a9b3f53-fa2a-47f3-a757-dd87720d9d1d</uuid>
         <memory unit='KiB'>4194304</memory>
         <currentMemory unit='KiB'>4194304</currentMemory>
         <memoryBacking>
           <hugepages>
             <page size='2' unit='M' nodeset='0'/>
           </hugepages>
         </memoryBacking>
         <vcpu placement='static'>2</vcpu>
         <cputune>
           <shares>4096</shares>
           <vcpupin vcpu='0' cpuset='4'/>
           <vcpupin vcpu='1' cpuset='5'/>
           <emulatorpin cpuset='4,5'/>
         </cputune>
         <os>
           <type arch='x86_64' machine='pc'>hvm</type>
           <boot dev='hd'/>
         </os>
         <features>
           <acpi/>
           <apic/>
         </features>
         <cpu mode='host-model'>
           <model fallback='allow'/>
           <topology sockets='2' cores='1' threads='1'/>
           <numa>
             <cell id='0' cpus='0-1' memory='4194304' unit='KiB' memAccess='shared'/>
           </numa>
         </cpu>
         <on_poweroff>destroy</on_poweroff>
         <on_reboot>restart</on_reboot>
         <on_crash>destroy</on_crash>
         <devices>
           <emulator>/usr/bin/qemu-kvm</emulator>
           <disk type='file' device='disk'>
             <driver name='qemu' type='qcow2' cache='none'/>
             <source file='/root/CentOS7_x86_64.qcow2'/>
             <target dev='vda' bus='virtio'/>
           </disk>
           <disk type='dir' device='disk'>
             <driver name='qemu' type='fat'/>
             <source dir='/usr/src/dpdk-stable-16.07.2'/>
             <target dev='vdb' bus='virtio'/>
             <readonly/>
           </disk>
           <interface type='vhostuser'>
             <mac address='00:00:00:00:00:01'/>
             <source type='unix' path='/usr/local/var/run/openvswitch/dpdkvhostuser0' mode='client'/>
              <model type='virtio'/>
             <driver queues='2'>
               <host mrg_rxbuf='off'/>
             </driver>
           </interface>
           <interface type='vhostuser'>
             <mac address='00:00:00:00:00:02'/>
             <source type='unix' path='/usr/local/var/run/openvswitch/dpdkvhostuser1' mode='client'/>
             <model type='virtio'/>
             <driver queues='2'>
               <host mrg_rxbuf='off'/>
             </driver>
           </interface>
           <serial type='pty'>
             <target port='0'/>
           </serial>
           <console type='pty'>
             <target type='serial' port='0'/>
           </console>
         </devices>
       </domain>
       ```

  5. DPDK Packet forwarding in Guest VM

     To accomplish this, DPDK and testpmd application have to be first compiled
     on the VM and the steps are listed in [DPDK in the VM].

       * Run test-pmd application

       ```
       cd $DPDK_DIR/app/test-pmd;
       ./testpmd -c 0x3 -n 4 --socket-mem 1024 -- --burst=64 -i --txqflags=0xf00 --disable-hw-vlan
       set fwd mac retry
       start
       ```

       * Bind vNIC back to kernel once the test is completed.

       ```
       $DPDK_DIR/tools/dpdk-devbind.py --bind=virtio-pci 0000:00:03.0
       $DPDK_DIR/tools/dpdk-devbind.py --bind=virtio-pci 0000:00:04.0
       ```
       Note: Appropriate PCI IDs to be passed in above example. The PCI IDs can be
       retrieved using '$DPDK_DIR/tools/dpdk-devbind.py --status' cmd.

### 5.3 PHY-VM-PHY [IVSHMEM]

  The steps for setup of IVSHMEM are covered in section 5.2(PVP - IVSHMEM)
  of [OVS Testcases] in ADVANCED install guide.

## <a name="ovslimits"></a> 6. Limitations

  - Currently DPDK ports does not use HW offload functionality.
  - Network Interface Firmware requirements:
    Each release of DPDK is validated against a specific firmware version for
    a supported Network Interface. New firmware versions introduce bug fixes,
    performance improvements and new functionality that DPDK leverages. The
    validated firmware versions are available as part of the release notes for
    DPDK. It is recommended that users update Network Interface firmware to
    match what has been validated for the DPDK release.

    For DPDK 16.07.2, the list of validated firmware versions can be found at:

    http://dpdk.org/doc/guides-16.07/rel_notes/release_16_07.html

Bug Reporting:
--------------

Please report problems to bugs@openvswitch.org.


[DPDK requirements]: http://dpdk.org/doc/guides/linux_gsg/sys_reqs.html
[Download DPDK]: http://dpdk.org/browse/dpdk/refs/
[Download OVS]: http://openvswitch.org/releases/
[DPDK Supported NICs]: http://dpdk.org/doc/nics
[Build Requirements]: https://github.com/openvswitch/ovs/blob/master/INSTALL.md#build-requirements
[INSTALL.DPDK-ADVANCED.md]: INSTALL.DPDK-ADVANCED.md
[OVS Testcases]: INSTALL.DPDK-ADVANCED.md#ovstc
[Vhost Walkthrough]: INSTALL.DPDK-ADVANCED.md#vhost
[DPDK in the VM]: INSTALL.DPDK.md#builddpdk
[INSTALL.md]:INSTALL.md
[INSTALL.Fedora.md]:INSTALL.Fedora.md
[INSTALL.RHEL.md]:INSTALL.RHEL.md
[INSTALL.Debian.md]:INSTALL.Debian.md
