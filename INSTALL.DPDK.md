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

Required DPDK 1.7

1. Configure build & install DPDK:
  1. Set `$DPDK_DIR`

     ```
     export DPDK_DIR=/usr/src/dpdk-1.7.1
     cd $DPDK_DIR
     ```

  2. Update `config/common_linuxapp` so that DPDK generate single lib file.
     (modification also required for IVSHMEM build)

     `CONFIG_RTE_BUILD_COMBINE_LIBS=y`

     Then run `make install` to build and isntall the library.
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
   ./configure --with-dpdk=$DPDK_BUILD
   make
   ```

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
   1. insert uio.ko: `modprobe uio`
   2. insert igb_uio.ko: `insmod $DPDK_BUILD/kmod/igb_uio.ko`
   3. Bind network device to igb_uio: `$DPDK_DIR/tools/dpdk_nic_bind.py --bind=igb_uio eth1`

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

   Note, core 0 is always reserved from non-pmd threads and should never be set
   in the cpu mask.

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

Restrictions:
-------------

  - This Support is for Physical NIC. I have tested with Intel NIC only.
  - Work with 1500 MTU, needs few changes in DPDK lib to fix this issue.
  - Currently DPDK port does not make use any offload functionality.

  ivshmem:
  - The shared memory is currently restricted to the use of a 1GB
    huge pages.
  - All huge pages are shared amongst the host, clients, virtual
    machines etc.

Bug Reporting:
--------------

Please report problems to bugs@openvswitch.org.

[INSTALL.userspace.md]:INSTALL.userspace.md
[INSTALL.md]:INSTALL.md
