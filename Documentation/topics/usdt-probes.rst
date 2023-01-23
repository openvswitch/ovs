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

=============================================
User Statically-Defined Tracing (USDT) probes
=============================================

Sometimes it's desired to troubleshoot one of OVS's components in the field.
One of the techniques used is to add dynamic tracepoints, for example using
perf_. However, the desired dynamic tracepoint and/or the desired variable,
might not be available due to compiler optimizations.

In this case, a well-thought-off, static tracepoint could be permanently added,
so it's always available. For OVS we use the DTrace probe macro's, which have
little to no overhead when disabled. Various tools exist to enable them. See
some examples below.


Compiling with USDT probes enabled
----------------------------------

Since USDT probes are compiled out by default, a compile-time option is
available to include them. To add the probes to the generated code, use the
following configure option ::

    $ ./configure --enable-usdt-probes

The following line should be seen in the configure output when the above option
is used ::

    checking whether USDT probes are enabled... yes

As USDT probes internally use the ``DTRACE_PROBExx`` macros, which are part of
the SystemTap framework, you need to install the appropriate package for your
Linux distribution. For example, on Fedora, you need to install the
``systemtap-sdt-devel`` package.


Listing available probes
------------------------

There are various ways to display USDT probes available in a userspace
application. Here we show three examples. All assuming ovs-vswitchd is in the
search path with USDT probes enabled:

You can use the **perf** tool as follows ::

    $ perf buildid-cache --add $(which ovs-vswitchd)
    $ perf list | grep sdt_
      sdt_main:poll_block                                [SDT event]
      sdt_main:run_start                                 [SDT event]

You can use the bpftrace_ tool ::

    # bpftrace -l "usdt:$(which ovs-vswitchd):*"
    usdt:/usr/sbin/ovs-vswitchd:main:poll_block
    usdt:/usr/sbin/ovs-vswitchd:main:run_start

.. note::

   If you execute this on a running process,
   ``bpftrace -lp $(pidof ovs-vswitchd) "usdt:*"`` , it will list all USDT
   events, i.e., also the ones available in the used shared libraries.

Finally, you can use the **tplist** tool which is part of the bcc_ framework ::

    $ /usr/share/bcc/tools/tplist -vv -l $(which ovs-vswitchd)
    b'main':b'poll_block' [sema 0x0]
      location #1 b'/usr/sbin/ovs-vswitchd' 0x407fdc
    b'main':b'run_start' [sema 0x0]
      location #1 b'/usr/sbin/ovs-vswitchd' 0x407ff6


Using probes
------------

We will use the OVS sandbox environment in combination with the probes shown
above to try out some of the available trace tools. To start up the virtual
environment use the ``make sandbox`` command. In addition we have to create
a bridge to kick of the main bridge loop ::

    $ ovs-vsctl add-br test_bridge
    $ ovs-vsctl show
    055acdca-2f0c-4f6e-b542-f4b6d2c44e08
        Bridge test_bridge
            Port test_bridge
                Interface test_bridge
                    type: internal

perf
~~~~

Perf is using Linux uprobe based event tracing to for capturing the events.
To enable the main:\* probes as displayed above and take an actual trace, you
need to execute the following sequence of perf commands ::

    # perf buildid-cache --add $(which ovs-vswitchd)

    # perf list | grep sdt_
      sdt_main:poll_block                                [SDT event]
      sdt_main:run_start                                 [SDT event]

    # perf probe --add=sdt_main:poll_block --add=sdt_main:run_start
    Added new events:
      sdt_main:poll_block  (on %poll_block in /usr/sbin/ovs-vswitchd)
      sdt_main:run_start   (on %run_start in /usr/sbin/ovs-vswitchd)

    You can now use it in all perf tools, such as:

      perf record -e sdt_main:run_start -aR sleep 1

    # perf record -e sdt_main:run_start -e sdt_main:poll_block \
        -p $(pidof ovs-vswitchd) sleep 30
    [ perf record: Woken up 1 times to write data ]
    [ perf record: Captured and wrote 0.039 MB perf.data (132 samples) ]

    # perf script
        ovs-vswitchd  8576 [011] 21031.340433:  sdt_main:run_start: (407ff6)
        ovs-vswitchd  8576 [011] 21031.340516: sdt_main:poll_block: (407fdc)
        ovs-vswitchd  8576 [011] 21031.841726:  sdt_main:run_start: (407ff6)
        ovs-vswitchd  8576 [011] 21031.842088: sdt_main:poll_block: (407fdc)
    ...

Note that the above examples works with the sandbox environment, so make sure
you execute the above command while in the sandbox shell!

There are a lot more options available with perf, for example, the
``--call-graph dwarf`` option, which would give you a call graph in the
``perf script`` output. See the perf documentation for more information.

One other interesting feature is that the perf data can be converted for use
by the trace visualizer `Trace Compass`_. This can be done using the
``--all --to-ctf`` option to the ``perf data convert`` tool.


bpftrace
~~~~~~~~

bpftrace is a high-level tracing language based on eBPF, which can be used to
script USDT probes. Here we will show a simple one-liner to display the
USDT probes being hit. However, the script section below reference some more
advanced bpftrace scripts.

This is a simple bpftrace one-liner to show all ``main:*`` USDT probes ::

    # bpftrace -p $(pidof ovs-vswitchd) -e \
        'usdt::main:* { printf("%s %u [%u] %u %s\n",
          comm, pid, cpu, elapsed, probe); }'
    Attaching 2 probes...
    ovs-vswitchd 8576 [11] 203833199 usdt:main:run_start
    ovs-vswitchd 8576 [11] 204086854 usdt:main:poll_block
    ovs-vswitchd 8576 [11] 221611985 usdt:main:run_start
    ovs-vswitchd 8576 [11] 221892019 usdt:main:poll_block


bcc
~~~

The BPF Compiler Collection (BCC) is a set of tools and scripts that also use
eBPF for tracing. The example below uses the ``trace`` tool to show the events
while they are being generated ::

    # /usr/share/bcc/tools/trace -T -p $(pidof ovs-vswitchd) \
        'u::main:run_start' 'u::main:poll_block'
    TIME     PID     TID     COMM            FUNC
    15:49:06 8576    8576    ovs-vswitchd    main:run_start
    15:49:06 8576    8576    ovs-vswitchd    main:poll_block
    15:49:06 8576    8576    ovs-vswitchd    main:run_start
    15:49:06 8576    8576    ovs-vswitchd    main:poll_block
    ^C


Scripts
-------
To not have to re-invent the wheel when trying to debug complex OVS issues, a
set of scripts are provided in the source repository. They are located in the
``utilities/usdt-scripts/`` directory, and each script contains detailed
information on how they should be used, and what information they provide.


Available probes
----------------
The next sections describes all the available probes, their use case, and if
used in any script, which one. Any new probes being added to OVS should get
their own section. See the below "Adding your own probes" section for the
used naming convention.

Available probes in ``ovs_vswitchd``:

- dpif_netlink_operate\_\_:op_flow_del
- dpif_netlink_operate\_\_:op_flow_execute
- dpif_netlink_operate\_\_:op_flow_get
- dpif_netlink_operate\_\_:op_flow_put
- dpif_recv:recv_upcall
- main:poll_block
- main:run_start
- revalidate_ukey\_\_:entry
- revalidate_ukey\_\_:exit
- udpif_revalidator:start_dump
- udpif_revalidator:sweep_done


dpif_netlink_operate\_\_:op_flow_del
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Description**:

This probe gets triggered when the Netlink datapath is about to execute the
DPIF_OP_FLOW_DEL operation as part of the dpif ``operate()`` callback.

**Arguments**:

- *arg0*: ``(struct dpif_netlink *) dpif``
- *arg1*: ``(struct dpif_flow_del *) del``
- *arg2*: ``(struct dpif_netlink_flow *) flow``
- *arg3*: ``(struct ofpbuf *) aux->request``

**Script references**:

- *None*


dpif_netlink_operate\_\_:op_flow_execute
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Description**:

This probe gets triggered when the Netlink datapath is about to execute the
DPIF_OP_FLOW_EXECUTE operation as part of the dpif ``operate()`` callback.

**Arguments**:

- *arg0*: ``(struct dpif_netlink *) dpif``
- *arg1*: ``(struct dpif_execute *) op->execute``
- *arg2*: ``dp_packet_data(op->execute.packet)``
- *arg3*: ``dp_packet_size(op->execute.packet)``
- *arg4*: ``(struct ofpbuf *) aux->request``

**Script references**:

- ``utilities/usdt-scripts/dpif_nl_exec_monitor.py``
- ``utilities/usdt-scripts/upcall_cost.py``


dpif_netlink_operate\_\_:op_flow_get
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Description**:

This probe gets triggered when the Netlink datapath is about to execute the
DPIF_OP_FLOW_GET operation as part of the dpif ``operate()`` callback.

**Arguments**:

- *arg0*: ``(struct dpif_netlink *) dpif``
- *arg1*: ``(struct dpif_flow_get *) get``
- *arg2*: ``(struct dpif_netlink_flow *) flow``
- *arg3*: ``(struct ofpbuf *) aux->request``

**Script references**:

- *None*


dpif_netlink_operate\_\_:op_flow_put
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Description**:

This probe gets triggered when the Netlink datapath is about to execute the
DPIF_OP_FLOW_PUT operation as part of the dpif ``operate()`` callback.

**Arguments**:

- *arg0*: ``(struct dpif_netlink *) dpif``
- *arg1*: ``(struct dpif_flow_put *) put``
- *arg2*: ``(struct dpif_netlink_flow *) flow``
- *arg3*: ``(struct ofpbuf *) aux->request``

**Script references**:

- ``utilities/usdt-scripts/upcall_cost.py``


probe dpif_recv:recv_upcall
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Description**:

This probe gets triggered when the datapath independent layer gets notified
that a packet needs to be processed by userspace. This allows the probe to
intercept all packets sent by the kernel to ``ovs-vswitchd``. The
``upcall_monitor.py`` script uses this probe to display and capture all packets
sent to ``ovs-vswitchd``.

**Arguments**:

- *arg0*: ``(struct dpif *)->full_name``
- *arg1*: ``(struct dpif_upcall *)->type``
- *arg2*: ``dp_packet_data((struct dpif_upcall *)->packet)``
- *arg3*: ``dp_packet_size((struct dpif_upcall *)->packet)``
- *arg4*: ``(struct dpif_upcall *)->key``
- *arg5*: ``(struct dpif_upcall *)->key_len``

**Script references**:

- ``utilities/usdt-scripts/upcall_cost.py``
- ``utilities/usdt-scripts/upcall_monitor.py``


probe main:run_start
~~~~~~~~~~~~~~~~~~~~

**Description**:

The ovs-vswitchd's main process contains a loop that runs every time some work
needs to be done. This probe gets triggered every time the loop starts from the
beginning. See also the ``main:poll_block`` probe below.

**Arguments**:

*None*

**Script references**:

- ``utilities/usdt-scripts/bridge_loop.bt``


probe main:poll_block
~~~~~~~~~~~~~~~~~~~~~

**Description**:

The ovs-vswitchd's main process contains a loop that runs every time some work
needs to be done. This probe gets triggered every time the loop is done, and
it's about to wait for being re-started by a poll_block() call returning.
See also the ``main:run_start`` probe above.

**Arguments**:

*None*

**Script references**:

- ``utilities/usdt-scripts/bridge_loop.bt``


revalidate_ukey\_\_:entry
~~~~~~~~~~~~~~~~~~~~~~~~~

**Description**:

This probe gets triggered on entry of the revalidate_ukey__() function.

**Arguments**:

- *arg0*: ``(struct udpif *) udpif``
- *arg1*: ``(struct udpif_key *) ukey``
- *arg2*: ``(uint16_t) tcp_flags``
- *arg3*: ``(struct ofpbuf *) odp_actions``
- *arg4*: ``(struct recirc_refs *) recircs``
- *arg5*: ``(struct xlate_cache *) xcache``

**Script references**:

- ``utilities/usdt-scripts/reval_monitor.py``


revalidate_ukey\_\_:exit
~~~~~~~~~~~~~~~~~~~~~~~~

**Description**:

This probe gets triggered right before the revalidate_ukey__() function exits.

**Arguments**:

- *arg0*: ``(struct udpif *) udpif``
- *arg1*: ``(struct udpif_key *) ukey``
- *arg2*: ``(enum reval_result) result``

**Script references**:

*None*


udpif_revalidator:start_dump
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Description**:

The ovs-vswitchd's revalidator process contains a loop that runs every time
revalidation work is needed. This probe gets triggered every time the
dump phase has started.

**Arguments**:

- *arg0*: ``(struct udpif *) udpif``
- *arg1*: ``(size_t) n_flows``

**Script references**:

- ``utilities/usdt-scripts/reval_monitor.py``


udpif_revalidator:sweep_done
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Description**:

The ovs-vswitchd's revalidator process contains a loop that runs every time
revalidation work is needed. This probe gets triggered every time the
sweep phase was completed.

**Arguments**:

- *arg0*: ``(struct udpif *) udpif``
- *arg1*: ``(size_t) n_flows``
- *arg2*: ``(unsigned) MIN(ofproto_max_idle, ofproto_max_revalidator)``

**Script references**:

- ``utilities/usdt-scripts/reval_monitor.py``


Adding your own probes
----------------------

Adding your own probes is as simple as adding the ``OVS_USDT_PROBE()`` macro
to the code. It's similar to the ``DTRACE_PROBExx`` macro's with the difference
that it does automatically determine the number of optional arguments.

The macro requires at least two arguments. The first one being the *provider*,
and the second one being the *name*. To keep some consistency with the probe
naming, please use the following convention. The *provider* should be the
function name, and the *name* should be the name of the tracepoint. If you do
function entry and exit like probes, please use ``entry`` and ``exit``.

If, for some reason, you do not like to use the function name as a *provider*,
please prefix it with ``__``, so we know it's not a function name.

The remaining parameters, up to 10, can be variables, pointers, etc., that
might be of interest to capture at this point in the code. Note that the
provided variables can cause the compiler to be less effective in optimizing.



.. _perf : https://developers.redhat.com/blog/2020/05/29/debugging-vhost-user-tx-contention-in-open-vswitch#
.. _bpftrace : https://github.com/iovisor/bpftrace
.. _bcc : https://github.com/iovisor/bcc
.. _Trace Compass : https://www.eclipse.org/tracecompass/
