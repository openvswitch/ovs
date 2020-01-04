..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.


========================
Open vSwitch with AF_XDP
========================

This document describes how to build and install Open vSwitch using
AF_XDP netdev.

.. warning::
  The AF_XDP support of Open vSwitch is considered 'experimental',
  and it is not compiled in by default.


Introduction
------------
AF_XDP, Address Family of the eXpress Data Path, is a new Linux socket type
built upon the eBPF and XDP technology.  It is aims to have comparable
performance to DPDK but cooperate better with existing kernel's networking
stack.  An AF_XDP socket receives and sends packets from an eBPF/XDP program
attached to the netdev, by-passing a couple of Linux kernel's subsystems.
As a result, AF_XDP socket shows much better performance than AF_PACKET.
For more details about AF_XDP, please see linux kernel's
Documentation/networking/af_xdp.rst


AF_XDP Netdev
-------------
OVS has a couple of netdev types, i.e., system, tap, or
dpdk.  The AF_XDP feature adds a new netdev types called
"afxdp", and implement its configuration, packet reception,
and transmit functions.  Since the AF_XDP socket, called xsk,
operates in userspace, once ovs-vswitchd receives packets
from xsk, the afxdp netdev re-uses the existing userspace
dpif-netdev datapath.  As a result, most of the packet processing
happens at the userspace instead of linux kernel.

::

              |   +-------------------+
              |   |    ovs-vswitchd   |<-->ovsdb-server
              |   +-------------------+
              |   |      ofproto      |<-->OpenFlow controllers
              |   +--------+-+--------+
              |   | netdev | |ofproto-|
    userspace |   +--------+ |  dpif  |
              |   | afxdp  | +--------+
              |   | netdev | |  dpif  |
              |   +---||---+ +--------+
              |       ||     |  dpif- |
              |       ||     | netdev |
              |_      ||     +--------+
                      ||
               _  +---||-----+--------+
              |   | AF_XDP prog +     |
       kernel |   |   xsk_map         |
              |_  +--------||---------+
                           ||
                        physical
                           NIC


Build requirements
------------------

In addition to the requirements described in :doc:`general`, building Open
vSwitch with AF_XDP will require the following:

- libbpf from kernel source tree (kernel 5.0.0 or later)

- Linux kernel XDP support, with the following options (required)

  * CONFIG_BPF=y

  * CONFIG_BPF_SYSCALL=y

  * CONFIG_XDP_SOCKETS=y


- The following optional Kconfig options are also recommended, but not
  required:

  * CONFIG_BPF_JIT=y (Performance)

  * CONFIG_HAVE_BPF_JIT=y (Performance)

  * CONFIG_XDP_SOCKETS_DIAG=y (Debugging)

- Once your AF_XDP-enabled kernel is ready, if possible, run
  **./xdpsock -r -N -z -i <your device>** under linux/samples/bpf.
  This is an OVS independent benchmark tools for AF_XDP.
  It makes sure your basic kernel requirements are met for AF_XDP.


Installing
----------
For OVS to use AF_XDP netdev, it has to be configured with LIBBPF support.
First, clone a recent version of Linux bpf-next tree::

  git clone git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git

Second, go into the Linux source directory and build libbpf in the tools
directory::

  cd bpf-next/
  cd tools/lib/bpf/
  make && make install
  make install_headers

.. note::
   Make sure xsk.h and bpf.h are installed in system's library path,
   e.g. /usr/local/include/bpf/ or /usr/include/bpf/

Make sure the libbpf.so is installed correctly::

  ldconfig
  ldconfig -p | grep libbpf

Third, ensure the standard OVS requirements are installed and
bootstrap/configure the package::

  ./boot.sh && ./configure --enable-afxdp

Finally, build and install OVS::

  make && make install

To kick start end-to-end autotesting::

  uname -a # make sure having 5.0+ kernel
  make check-afxdp TESTSUITEFLAGS='1'

.. note::
   Not all test cases pass at this time. Currenly all cvlan tests are skipped
   due to kernel issues.

If a test case fails, check the log at::

  cat \
  tests/system-afxdp-testsuite.dir/<test num>/system-afxdp-testsuite.log


Setup AF_XDP netdev
-------------------
Before running OVS with AF_XDP, make sure the libbpf and libelf are
set-up right::

  ldd vswitchd/ovs-vswitchd

Open vSwitch should be started using userspace datapath as described
in :doc:`general`::

  ovs-vswitchd ...
  ovs-vsctl -- add-br br0 -- set Bridge br0 datapath_type=netdev

Make sure your device driver support AF_XDP, netdev-afxdp supports
the following additional options (see ``man ovs-vswitchd.conf.db`` for
more details):

 * ``xdp-mode``: ``best-effort``, ``native-with-zerocopy``,
   ``native`` or ``generic``.  Defaults to ``best-effort``, i.e. best of
   supported modes, so in most cases you don't need to change it.

 * ``use-need-wakeup``: default ``true`` if libbpf supports it,
   otherwise ``false``.

For example, to use 1 PMD (on core 4) on 1 queue (queue 0) device,
configure these options: ``pmd-cpu-mask``, ``pmd-rxq-affinity``, and
``n_rxq``::

  ethtool -L enp2s0 combined 1
  ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=0x10
  ovs-vsctl add-port br0 enp2s0 -- set interface enp2s0 type="afxdp" \
                                   other_config:pmd-rxq-affinity="0:4"

Or, use 4 pmds/cores and 4 queues by doing::

  ethtool -L enp2s0 combined 4
  ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=0x36
  ovs-vsctl add-port br0 enp2s0 -- set interface enp2s0 type="afxdp" \
    options:n_rxq=4 other_config:pmd-rxq-affinity="0:1,1:2,2:3,3:4"

.. note::
   ``pmd-rxq-affinity`` is optional. If not specified, system will auto-assign.
   ``n_rxq`` equals ``1`` by default.

To validate that the bridge has successfully instantiated, you can use the::

  ovs-vsctl show

Should show something like::

  Port "ens802f0"
   Interface "ens802f0"
      type: afxdp
      options: {n_rxq="1"}

Otherwise, enable debugging by::

  ovs-appctl vlog/set netdev_afxdp::dbg

To check which XDP mode was chosen by ``best-effort``, you can look for
``xdp-mode-in-use`` in the output of ``ovs-appctl dpctl/show``::

  # ovs-appctl dpctl/show
  netdev@ovs-netdev:
    <...>
    port 2: ens802f0 (afxdp: n_rxq=1, use-need-wakeup=true,
                      xdp-mode=best-effort,
                      xdp-mode-in-use=native-with-zerocopy)

References
----------
Most of the design details are described in the paper presented at
Linux Plumber 2018, "Bringing the Power of eBPF to Open vSwitch"[1],
section 4, and slides[2][4].
"The Path to DPDK Speeds for AF XDP"[3] gives a very good introduction
about AF_XDP current and future work.

[1] http://vger.kernel.org/lpc_net2018_talks/ovs-ebpf-afxdp.pdf

[2] http://vger.kernel.org/lpc_net2018_talks/ovs-ebpf-lpc18-presentation.pdf

[3] http://vger.kernel.org/lpc_net2018_talks/lpc18_paper_af_xdp_perf-v2.pdf

[4] https://ovsfall2018.sched.com/event/IO7p/fast-userspace-ovs-with-afxdp


Performance Tuning
------------------
The name of the game is to keep your CPU running in userspace, allowing PMD
to keep polling the AF_XDP queues without any interferences from kernel.

#. Make sure everything is in the same NUMA node (memory used by AF_XDP, pmd
   running cores, device plug-in slot)

#. Isolate your CPU by doing isolcpu at grub configure.

#. IRQ should not set to pmd running core.

#. The Spectre and Meltdown fixes increase the overhead of system calls.


Debugging performance issue
~~~~~~~~~~~~~~~~~~~~~~~~~~~
While running the traffic, use linux perf tool to see where your cpu
spends its cycle::

  cd bpf-next/tools/perf
  make
  ./perf record -p `pidof ovs-vswitchd` sleep 10
  ./perf report

Measure your system call rate by doing::

  pstree -p `pidof ovs-vswitchd`
  strace -c -p <your pmd's PID>

Or, use OVS pmd tool::

  ovs-appctl dpif-netdev/pmd-stats-show


Example Script
--------------

Below is a script using namespaces and veth peer::

  #!/bin/bash
  ovs-vswitchd --no-chdir --pidfile -vvconn -vofproto_dpif -vunixctl \
    --disable-system --detach \
  ovs-vsctl -- add-br br0 -- set Bridge br0 \
    protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13,OpenFlow14 \
    fail-mode=secure datapath_type=netdev
  ovs-vsctl -- add-br br0 -- set Bridge br0 datapath_type=netdev

  ip netns add at_ns0
  ovs-appctl vlog/set netdev_afxdp::dbg

  ip link add p0 type veth peer name afxdp-p0
  ip link set p0 netns at_ns0
  ip link set dev afxdp-p0 up
  ovs-vsctl add-port br0 afxdp-p0 -- \
    set interface afxdp-p0 external-ids:iface-id="p0" type="afxdp"

  ip netns exec at_ns0 sh << NS_EXEC_HEREDOC
  ip addr add "10.1.1.1/24" dev p0
  ip link set dev p0 up
  NS_EXEC_HEREDOC

  ip netns add at_ns1
  ip link add p1 type veth peer name afxdp-p1
  ip link set p1 netns at_ns1
  ip link set dev afxdp-p1 up

  ovs-vsctl add-port br0 afxdp-p1 -- \
    set interface afxdp-p1 external-ids:iface-id="p1" type="afxdp"
  ip netns exec at_ns1 sh << NS_EXEC_HEREDOC
  ip addr add "10.1.1.2/24" dev p1
  ip link set dev p1 up
  NS_EXEC_HEREDOC

  ip netns exec at_ns0 ping -i .2 10.1.1.2


Limitations/Known Issues
------------------------
#. No QoS support because AF_XDP netdev by-pass the Linux TC layer. A possible
   work-around is to use OpenFlow meter action.
#. Most of the tests are done using i40e single port. Multiple ports and
   also ixgbe driver also needs to be tested.
#. No latency test result (TODO items)
#. Due to limitations of current upstream kernel, various offloading
   (vlan, cvlan) is not working over virtual interfaces (i.e. veth pair).
   Also, TCP is not working over virtual interfaces (veth) in generic XDP mode.
   Some more information and possible workaround available `here
   <https://github.com/cilium/cilium/issues/3077#issuecomment-430801467>`__ .
   For TAP interfaces generic mode seems to work fine (TCP works) and even
   could provide better performance than native mode in some cases.


PVP using tap device
--------------------
Assume you have enp2s0 as physical nic, and a tap device connected to VM.
First, start OVS, then add physical port::

  ethtool -L enp2s0 combined 1
  ovs-vsctl set Open_vSwitch . other_config:pmd-cpu-mask=0x10
  ovs-vsctl add-port br0 enp2s0 -- set interface enp2s0 type="afxdp" \
    options:n_rxq=1 other_config:pmd-rxq-affinity="0:4"

Start a VM with virtio and tap device::

  qemu-system-x86_64 -hda ubuntu1810.qcow \
    -m 4096 \
    -cpu host,+x2apic -enable-kvm \
    -device virtio-net-pci,mac=00:02:00:00:00:01,netdev=net0,mq=on,\
      vectors=10,mrg_rxbuf=on,rx_queue_size=1024 \
    -netdev type=tap,id=net0,vhost=on,queues=8 \
    -object memory-backend-file,id=mem,size=4096M,\
      mem-path=/dev/hugepages,share=on \
    -numa node,memdev=mem -mem-prealloc -smp 2

Create OpenFlow rules::

  ovs-vsctl add-port br0 tap0 -- set interface tap0
  ovs-ofctl del-flows br0
  ovs-ofctl add-flow br0 "in_port=enp2s0, actions=output:tap0"
  ovs-ofctl add-flow br0 "in_port=tap0, actions=output:enp2s0"

Inside the VM, use xdp_rxq_info to bounce back the traffic::

  ./xdp_rxq_info --dev ens3 --action XDP_TX


PVP using vhostuser device
--------------------------
First, build OVS with DPDK and AFXDP::

  ./configure  --enable-afxdp --with-dpdk=<dpdk path>
  make -j4 && make install

Create a vhost-user port from OVS::

  ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-init=true
  ovs-vsctl -- add-br br0 -- set Bridge br0 datapath_type=netdev \
    other_config:pmd-cpu-mask=0xfff
  ovs-vsctl add-port br0 vhost-user-1 \
    -- set Interface vhost-user-1 type=dpdkvhostuser

Start VM using vhost-user mode::

  qemu-system-x86_64 -hda ubuntu1810.qcow \
   -m 4096 \
   -cpu host,+x2apic -enable-kvm \
   -chardev socket,id=char1,path=/usr/local/var/run/openvswitch/vhost-user-1 \
   -netdev type=vhost-user,id=mynet1,chardev=char1,vhostforce,queues=4 \
   -device virtio-net-pci,mac=00:00:00:00:00:01,\
      netdev=mynet1,mq=on,vectors=10 \
   -object memory-backend-file,id=mem,size=4096M,\
      mem-path=/dev/hugepages,share=on \
   -numa node,memdev=mem -mem-prealloc -smp 2

Setup the OpenFlow ruls::

  ovs-ofctl del-flows br0
  ovs-ofctl add-flow br0 "in_port=enp2s0, actions=output:vhost-user-1"
  ovs-ofctl add-flow br0 "in_port=vhost-user-1, actions=output:enp2s0"

Inside the VM, use xdp_rxq_info to drop or bounce back the traffic::

  ./xdp_rxq_info --dev ens3 --action XDP_DROP
  ./xdp_rxq_info --dev ens3 --action XDP_TX


PCP container using veth
------------------------
Create namespace and veth peer devices::

  ip netns add at_ns0
  ip link add p0 type veth peer name afxdp-p0
  ip link set p0 netns at_ns0
  ip link set dev afxdp-p0 up
  ip netns exec at_ns0 ip link set dev p0 up

Attach the veth port to br0 (linux kernel mode)::

  ovs-vsctl add-port br0 afxdp-p0 -- set interface afxdp-p0

Or, use AF_XDP::

  ovs-vsctl add-port br0 afxdp-p0 -- set interface afxdp-p0 type="afxdp"

Setup the OpenFlow rules::

  ovs-ofctl del-flows br0
  ovs-ofctl add-flow br0 "in_port=enp2s0, actions=output:afxdp-p0"
  ovs-ofctl add-flow br0 "in_port=afxdp-p0, actions=output:enp2s0"

In the namespace, run drop or bounce back the packet::

  ip netns exec at_ns0 ./xdp_rxq_info --dev p0 --action XDP_DROP
  ip netns exec at_ns0 ./xdp_rxq_info --dev p0 --action XDP_TX


Bug Reporting
-------------

Please report problems to dev@openvswitch.org.
