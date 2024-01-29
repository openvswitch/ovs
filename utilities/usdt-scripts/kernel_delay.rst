Troubleshooting Open vSwitch: Is the kernel to blame?
=====================================================
Often, when troubleshooting Open vSwitch (OVS) in the field, you might be left
wondering if the issue is really OVS-related, or if it's a problem with the
kernel being overloaded. Messages in the log like
``Unreasonably long XXXXms poll interval`` might suggest it's OVS, but from
experience, these are mostly related to an overloaded Linux Kernel.
The kernel_delay.py tool can help you quickly identify if the focus of your
investigation should be OVS or the Linux kernel.


Introduction
------------
``kernel_delay.py`` consists of a Python script that uses the BCC [#BCC]_
framework to install eBPF probes. The data the eBPF probes collect will be
analyzed and presented to the user by the Python script. Some of the presented
data can also be captured by the individual scripts included in the BBC [#BCC]_
framework.

kernel_delay.py has two modes of operation:

- In **time mode**, the tool runs for a specific time and collects the
  information.
- In **trigger mode**, event collection can be started and/or stopped based on
  a specific eBPF probe. Currently, the following probes are supported:
  - USDT probes
  - Kernel tracepoints
  - kprobe
  - kretprobe
  - uprobe
  - uretprobe


In addition, the option, ``--sample-count``, exists to specify how many
iterations you would like to do. When using triggers, you can also ignore
samples if they are less than a number of nanoseconds with the
``--trigger-delta`` option. The latter might be useful when debugging Linux
syscalls which take a long time to complete. More on this later. Finally, you
can configure the delay between two sample runs with the ``--sample-interval``
option.

Before getting into more details, you can run the tool without any options
to see what the output looks like. Notice that it will try to automatically
get the process ID of the running ``ovs-vswitchd``. You can overwrite this
with the ``--pid`` option.

.. code-block:: console

  $ sudo ./kernel_delay.py
  # Start sampling @2023-06-08T12:17:22.725127 (10:17:22 UTC)
  # Stop sampling @2023-06-08T12:17:23.224781 (10:17:23 UTC)
  # Sample dump @2023-06-08T12:17:23.224855 (10:17:23 UTC)
  TID        THREAD           <RESOURCE SPECIFIC>
  ---------- ---------------- ----------------------------------------------------------------------------
       27090 ovs-vswitchd     [SYSCALL STATISTICS]
                  <EDIT: REMOVED DATA FOR ovs-vswitchd THREAD>

       31741 revalidator122   [SYSCALL STATISTICS]
                  NAME                 NUMBER       COUNT          TOTAL ns            MAX ns
                  poll                      7           5       184,193,176       184,191,520
                  recvmsg                  47         494       125,208,756           310,331
                  futex                   202           8        18,768,758         4,023,039
                  sendto                   44          10           375,861           266,867
                  sendmsg                  46           4            43,294            11,213
                  write                     1           1             5,949             5,949
                  getrusage                98           1             1,424             1,424
                  read                      0           1             1,292             1,292
                  TOTAL( - poll):                     519       144,405,334

                  [THREAD RUN STATISTICS]
                  SCHED_CNT           TOTAL ns            MIN ns            MAX ns
                       6       136,764,071             1,480       115,146,424

                  [THREAD READY STATISTICS]
                  SCHED_CNT           TOTAL ns            MAX ns
                       7            11,334             6,636

                  [THREAD STOPPED STATISTICS]
                  STOP_CNT            TOTAL ns            MAX ns
                       3         3,045,728,323     1,015,739,474

                  [HARD IRQ STATISTICS]
                  NAME                       COUNT          TOTAL ns            MAX ns
                  eno8303-rx-1                   1             3,586             3,586
                  TOTAL:                         1             3,586

                  [SOFT IRQ STATISTICS]
                  NAME                 VECT_NR       COUNT          TOTAL ns            MAX ns
                  net_rx                     3           1            17,699            17,699
                  sched                      7           6            13,820             3,226
                  rcu                        9          16            13,586             1,554
                  timer                      1           3            10,259             3,815
                  TOTAL:                                26            55,364


By default, the tool will run for half a second in `time mode`. To extend this
you can use the ``--sample-time`` option.


What will it report
-------------------
The above sample output separates the captured data on a per-thread basis.
For this, it displays the thread's id (``TID``) and name (``THREAD``),
followed by resource-specific data. Which are:

- ``SYSCALL STATISTICS``
- ``THREAD RUN STATISTICS``
- ``THREAD READY STATISTICS``
- ``THREAD STOPPED STATISTICS``
- ``HARD IRQ STATISTICS``
- ``SOFT IRQ STATISTICS``

The following sections will describe in detail what statistics they report.


``SYSCALL STATISTICS``
~~~~~~~~~~~~~~~~~~~~~~
``SYSCALL STATISTICS`` tell you which Linux system calls got executed during
the measurement interval. This includes the number of times the syscall was
called (``COUNT``), the total time spent in the system calls (``TOTAL ns``),
and the worst-case duration of a single call (``MAX ns``).

It also shows the total of all system calls, but it excludes the poll system
call, as the purpose of this call is to wait for activity on a set of sockets,
and usually, the thread gets swapped out.

Note that it only counts calls that started and stopped during the
measurement interval!


``THREAD RUN STATISTICS``
~~~~~~~~~~~~~~~~~~~~~~~~~
``THREAD RUN STATISTICS`` tell you how long the thread was running on a CPU
during the measurement interval.

Note that these statistics only count events where the thread started and
stopped running on a CPU during the measurement interval. For example, if
this was a PMD thread, you should see zero ``SCHED_CNT`` and ``TOTAL_ns``.
If not, there might be a misconfiguration.


``THREAD READY STATISTICS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~
``THREAD READY STATISTICS`` tell you the time between the thread being ready
to run and it actually running on the CPU.

Note that these statistics only count events where the thread was getting
ready to run and started running during the measurement interval.


``THREAD STOPPED STATISTICS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``THREAD STOPPED STATISTICS`` reveal the number of instances where the thread
has been scheduled out while in the running state due to its transition to
the TASK_STOPPED state.

This behavior can be replicated by manually placing the thread in the stopped
state and subsequently resuming it. For instance:

.. code-block:: console

  # kill -STOP $(pidof ovs-vswitchd); \
    sleep 1; \
    kill -CONT $(pidof ovs-vswitchd);

Note that these statistics only count events where the thread was running at
the time it was put to stopped state.


``HARD IRQ STATISTICS``
~~~~~~~~~~~~~~~~~~~~~~~
``HARD IRQ STATISTICS`` tell you how much time was spent servicing hard
interrupts during the threads run time.

It shows the interrupt name (``NAME``), the number of interrupts (``COUNT``),
the total time spent in the interrupt handler (``TOTAL ns``), and the
worst-case duration (``MAX ns``).


``SOFT IRQ STATISTICS``
~~~~~~~~~~~~~~~~~~~~~~~
``SOFT IRQ STATISTICS`` tell you how much time was spent servicing soft
interrupts during the threads run time.

It shows the interrupt name (``NAME``), vector number (``VECT_NR``), the
number of interrupts (``COUNT``), the total time spent in the interrupt
handler (``TOTAL ns``), and the worst-case duration (``MAX ns``).


The ``--syscall-events`` option
-------------------------------
In addition to reporting global syscall statistics in ``SYSCALL_STATISTICS``,
the tool can also report each individual syscall. This can be a usefull
second step if the ``SYSCALL_STATISTICS`` show high latency numbers.

All you need to do is add the ``--syscall-events`` option, with or without
the additional ``DURATION_NS`` parameter. The ``DUTATION_NS`` parameter
allows you to exclude events that take less than the supplied time.

The ``--skip-syscall-poll-events`` option allows you to exclude poll
syscalls from the report.

Below is an example run, note that the resource-specific data is removed
to highlight the syscall events:

.. code-block:: console

  $ sudo ./kernel_delay.py  --syscall-events 50000 --skip-syscall-poll-events
  # Start sampling @2023-06-13T17:10:46.460874 (15:10:46 UTC)
  # Stop sampling @2023-06-13T17:10:46.960727 (15:10:46 UTC)
  # Sample dump @2023-06-13T17:10:46.961033 (15:10:46 UTC)
  TID        THREAD           <RESOURCE SPECIFIC>
  ---------- ---------------- ----------------------------------------------------------------------------
     3359686 ipf_clean2       [SYSCALL STATISTICS]
     ...
     3359635 ovs-vswitchd     [SYSCALL STATISTICS]
     ...
     3359697 revalidator12    [SYSCALL STATISTICS]
     ...
     3359698 revalidator13    [SYSCALL STATISTICS]
     ...
     3359699 revalidator14    [SYSCALL STATISTICS]
     ...
     3359700 revalidator15    [SYSCALL STATISTICS]
     ...

  # SYSCALL EVENTS:
         ENTRY (ns)           EXIT (ns)        TID COMM             DELTA (us)  SYSCALL
    ------------------- ------------------- ---------- ---------------- ----------  ----------------
       2161821694935486    2161821695031201    3359699 revalidator14            95  futex
        syscall_exit_to_user_mode_prepare+0x161 [kernel]
        syscall_exit_to_user_mode_prepare+0x161 [kernel]
        syscall_exit_to_user_mode+0x9 [kernel]
        do_syscall_64+0x68 [kernel]
        entry_SYSCALL_64_after_hwframe+0x72 [kernel]
        __GI___lll_lock_wait+0x30 [libc.so.6]
        ovs_mutex_lock_at+0x18 [ovs-vswitchd]
        [unknown] 0x696c003936313a63
       2161821695276882    2161821695333687    3359698 revalidator13            56  futex
        syscall_exit_to_user_mode_prepare+0x161 [kernel]
        syscall_exit_to_user_mode_prepare+0x161 [kernel]
        syscall_exit_to_user_mode+0x9 [kernel]
        do_syscall_64+0x68 [kernel]
        entry_SYSCALL_64_after_hwframe+0x72 [kernel]
        __GI___lll_lock_wait+0x30 [libc.so.6]
        ovs_mutex_lock_at+0x18 [ovs-vswitchd]
        [unknown] 0x696c003134313a63
       2161821695275820    2161821695405733    3359700 revalidator15           129  futex
        syscall_exit_to_user_mode_prepare+0x161 [kernel]
        syscall_exit_to_user_mode_prepare+0x161 [kernel]
        syscall_exit_to_user_mode+0x9 [kernel]
        do_syscall_64+0x68 [kernel]
        entry_SYSCALL_64_after_hwframe+0x72 [kernel]
        __GI___lll_lock_wait+0x30 [libc.so.6]
        ovs_mutex_lock_at+0x18 [ovs-vswitchd]
        [unknown] 0x696c003936313a63
       2161821695964969    2161821696052021    3359635 ovs-vswitchd             87  accept
        syscall_exit_to_user_mode_prepare+0x161 [kernel]
        syscall_exit_to_user_mode_prepare+0x161 [kernel]
        syscall_exit_to_user_mode+0x9 [kernel]
        do_syscall_64+0x68 [kernel]
        entry_SYSCALL_64_after_hwframe+0x72 [kernel]
        __GI_accept+0x4d [libc.so.6]
        pfd_accept+0x3a [ovs-vswitchd]
        [unknown] 0x7fff19f2bd00
        [unknown] 0xe4b8001f0f

As you can see above, the output also shows the stackback trace. You can
disable this using the ``--stack-trace-size 0`` option.

As you can see above, the backtrace does not show a lot of useful information
due to the BCC [#BCC]_ toolkit not supporting dwarf decoding. So to further
analyze system call backtraces, you could use perf. The following perf
script can do this for you (refer to the embedded instructions):

https://github.com/chaudron/perf_scripts/blob/master/analyze_perf_pmd_syscall.py


Using triggers
--------------
The tool supports start and, or stop triggers. This will allow you to capture
statistics triggered by a specific event. The following combinations of
stop-and-start triggers can be used.

If you only use ``--start-trigger``, the inspection start when the trigger
happens and runs until the ``--sample-time`` number of seconds has passed.
The example below shows all the supported options in this scenario.

.. code-block:: console

  $ sudo ./kernel_delay.py --start-trigger up:bridge_run --sample-time 4 \
                           --sample-count 4 --sample-interval 1


If you only use ``--stop-trigger``, the inspection starts immediately and
stops when the trigger happens.  The example below shows all the supported
options in this scenario.

.. code-block:: console

  $ sudo ./kernel_delay.py --stop-trigger upr:bridge_run \
                           --sample-count 4 --sample-interval 1


If you use both ``--start-trigger`` and ``--stop-trigger`` triggers, the
statistics are captured between the two first occurrences of these events.
The example below shows all the supported options in this scenario.

.. code-block:: console

  $ sudo ./kernel_delay.py --start-trigger up:bridge_run \
                           --stop-trigger upr:bridge_run \
                           --sample-count 4 --sample-interval 1 \
                           --trigger-delta 50000

What triggers are supported? Note that what ``kernel_delay.py`` calls triggers,
BCC [#BCC]_, calls events; these are eBPF tracepoints you can attach to.
For more details on the supported tracepoints, check out the BCC
documentation [#BCC_EVENT]_.

The list below shows the supported triggers and their argument format:

**USDT probes:**
  [u|usdt]:{provider}:{probe}
**Kernel tracepoint:**
  [t:trace]:{system}:{event}
**kprobe:**
  [k:kprobe]:{kernel_function}
**kretprobe:**
  [kr:kretprobe]:{kernel_function}
**uprobe:**
  [up:uprobe]:{function}
**uretprobe:**
  [upr:uretprobe]:{function}

Here are a couple of trigger examples, more use-case-specific examples can be
found in the *Examples* section.

.. code-block:: console

  --start|stop-trigger u:udpif_revalidator:start_dump
  --start|stop-trigger t:openvswitch:ovs_dp_upcall
  --start|stop-trigger k:ovs_dp_process_packet
  --start|stop-trigger kr:ovs_dp_process_packet
  --start|stop-trigger up:bridge_run
  --start|stop-trigger upr:bridge_run


Examples
--------
This section will give some examples of how to use this tool in real-world
scenarios. Let's start with the issue where Open vSwitch reports
``Unreasonably long XXXXms poll interval`` on your revalidator threads. Note
that there is a blog available explaining how the revalidator process works
in OVS [#REVAL_BLOG]_.

First, let me explain this log message. It gets logged if the time delta
between two ``poll_block()`` calls is more than 1 second. In other words,
the process was spending a lot of time processing stuff that was made
available by the return of the ``poll_block()`` function.

Do a run with the tool using the existing USDT revalidator probes as a start
and stop trigger (Note that the resource-specific data is removed from the none
revalidator threads):

.. code-block:: console

  $ sudo ./kernel_delay.py --start-trigger u:udpif_revalidator:start_dump --stop-trigger u:udpif_revalidator:sweep_done
  # Start sampling (trigger@791777093512008) @2023-06-14T14:52:00.110303 (12:52:00 UTC)
  # Stop sampling (trigger@791778281498462) @2023-06-14T14:52:01.297975 (12:52:01 UTC)
  # Triggered sample dump, stop-start delta 1,187,986,454 ns @2023-06-14T14:52:01.298021 (12:52:01 UTC)
  TID        THREAD           <RESOURCE SPECIFIC>
  ---------- ---------------- ----------------------------------------------------------------------------
     1457761 handler24        [SYSCALL STATISTICS]
                              NAME                 NUMBER       COUNT          TOTAL ns            MAX ns
                              sendmsg                  46        6110       123,274,761            41,776
                              recvmsg                  47      136299        99,397,508            49,896
                              futex                   202          51         7,655,832         7,536,776
                              poll                      7        4068         1,202,883             2,907
                              getrusage                98        2034           586,602             1,398
                              sendto                   44           9           213,682            27,417
                              TOTAL( - poll):                  144503       231,128,385

                              [THREAD RUN STATISTICS]
                              SCHED_CNT           TOTAL ns            MIN ns            MAX ns

                              [THREAD READY STATISTICS]
                              SCHED_CNT           TOTAL ns            MAX ns
                                       1             1,438             1,438

                              [SOFT IRQ STATISTICS]
                              NAME                 VECT_NR       COUNT          TOTAL ns            MAX ns
                              sched                      7          21            59,145             3,769
                              rcu                        9          50            42,917             2,234
                              TOTAL:                                71           102,062
     1457733 ovs-vswitchd     [SYSCALL STATISTICS]
     ...
     1457792 revalidator55    [SYSCALL STATISTICS]
                              NAME                 NUMBER       COUNT          TOTAL ns            MAX ns
                              futex                   202          73       572,576,329        19,621,600
                              recvmsg                  47         815       296,697,618           405,338
                              sendto                   44           3            78,302            26,837
                              sendmsg                  46           3            38,712            13,250
                              write                     1           1             5,073             5,073
                              TOTAL( - poll):                     895       869,396,034

                              [THREAD RUN STATISTICS]
                              SCHED_CNT           TOTAL ns            MIN ns            MAX ns
                                      48       394,350,393             1,729       140,455,796

                              [THREAD READY STATISTICS]
                              SCHED_CNT           TOTAL ns            MAX ns
                                      49            23,650             1,559

                              [SOFT IRQ STATISTICS]
                              NAME                 VECT_NR       COUNT          TOTAL ns            MAX ns
                              sched                      7          14            26,889             3,041
                              rcu                        9          28            23,024             1,600
                              TOTAL:                                42            49,913


Above you see from the start of the output that the trigger took more than a
second (1,187,986,454 ns), which is already know, by looking at the output of
the ``ovs-vsctl upcall/show`` command.

From the *revalidator55*'s ``SYSCALL STATISTICS`` statistics you can see it
spent almost 870ms handling syscalls, and there were no poll() calls being
executed. The ``THREAD RUN STATISTICS`` statistics here are a bit misleading,
as it looks like OVS only spent 394ms on the CPU. But earlier, it was mentioned
that this time does not include the time being on the CPU at the start or stop
of an event. What is exactly the case here, because USDT probes were used.

From the above data and maybe some ``top`` output, it can be determined that
the *revalidator55* thread is taking a lot of CPU time, probably because it
has to do a lot of revalidator work by itself. The solution here is to increase
the number of revalidator threads, so more work could be done in parallel.

Here is another run of the same command in another scenario:

.. code-block:: console

  $ sudo ./kernel_delay.py --start-trigger u:udpif_revalidator:start_dump --stop-trigger u:udpif_revalidator:sweep_done
  # Start sampling (trigger@795160501758971) @2023-06-14T15:48:23.518512 (13:48:23 UTC)
  # Stop sampling (trigger@795160764940201) @2023-06-14T15:48:23.781381 (13:48:23 UTC)
  # Triggered sample dump, stop-start delta 263,181,230 ns @2023-06-14T15:48:23.781414 (13:48:23 UTC)
  TID        THREAD           <RESOURCE SPECIFIC>
  ---------- ---------------- ----------------------------------------------------------------------------
     1457733 ovs-vswitchd     [SYSCALL STATISTICS]
                              ...
     1457792 revalidator55    [SYSCALL STATISTICS]
                              NAME                 NUMBER       COUNT          TOTAL ns            MAX ns
                              recvmsg                  47         284       193,422,110        46,248,418
                              sendto                   44           2            46,685            23,665
                              sendmsg                  46           2            24,916            12,703
                              write                     1           1             6,534             6,534
                              TOTAL( - poll):                     289       193,500,245

                              [THREAD RUN STATISTICS]
                              SCHED_CNT           TOTAL ns            MIN ns            MAX ns
                                       2        47,333,558           331,516        47,002,042

                              [THREAD READY STATISTICS]
                              SCHED_CNT           TOTAL ns            MAX ns
                                       3        87,000,403        45,999,712

                              [SOFT IRQ STATISTICS]
                              NAME                 VECT_NR       COUNT          TOTAL ns            MAX ns
                              sched                      7           2             9,504             5,109
                              TOTAL:                                 2             9,504


Here you can see the revalidator run took about 263ms, which does not look
odd, however, the ``THREAD READY STATISTICS`` information shows that OVS was
waiting 87ms for a CPU to be run on. This means the revalidator process could
have finished 87ms faster. Looking at the ``MAX ns`` value, a worst-case delay
of almost 46ms can be seen, which hints at an overloaded system.

One final example that uses a ``uprobe`` to get some statistics on a
``bridge_run()`` execution that takes more than 1ms.

.. code-block:: console

  $ sudo ./kernel_delay.py --start-trigger up:bridge_run --stop-trigger ur:bridge_run --trigger-delta 1000000
  # Start sampling (trigger@2245245432101270) @2023-06-14T16:21:10.467919 (14:21:10 UTC)
  # Stop sampling (trigger@2245245432414656) @2023-06-14T16:21:10.468296 (14:21:10 UTC)
  # Sample dump skipped, delta 313,386 ns @2023-06-14T16:21:10.468419 (14:21:10 UTC)
  # Start sampling (trigger@2245245505301745) @2023-06-14T16:21:10.540970 (14:21:10 UTC)
  # Stop sampling (trigger@2245245506911119) @2023-06-14T16:21:10.542499 (14:21:10 UTC)
  # Triggered sample dump, stop-start delta 1,609,374 ns @2023-06-14T16:21:10.542565 (14:21:10 UTC)
  TID        THREAD           <RESOURCE SPECIFIC>
  ---------- ---------------- ----------------------------------------------------------------------------
     3371035 <unknown:3366258/3371035> [SYSCALL STATISTICS]
     ... <REMOVED 7 MORE unknown THREADS>
     3371102 handler66        [SYSCALL STATISTICS]
     ... <REMOVED 7 MORE HANDLER THREADS>
     3366258 ovs-vswitchd     [SYSCALL STATISTICS]
                              NAME                 NUMBER       COUNT          TOTAL ns            MAX ns
                              futex                   202          43           403,469           199,312
                              clone3                  435          13           174,394            30,731
                              munmap                   11           8           115,774            21,861
                              poll                      7           5            92,969            38,307
                              unlink                   87           2            49,918            35,741
                              mprotect                 10           8            47,618            13,201
                              accept                   43          10            31,360             6,976
                              mmap                      9           8            30,279             5,776
                              write                     1           6            27,720            11,774
                              rt_sigprocmask           14          28            12,281               970
                              read                      0           6             9,478             2,318
                              recvfrom                 45           3             7,024             4,024
                              sendto                   44           1             4,684             4,684
                              getrusage                98           5             4,594             1,342
                              close                     3           2             2,918             1,627
                              recvmsg                  47           1             2,722             2,722
                              TOTAL( - poll):                     144           924,233

                              [THREAD RUN STATISTICS]
                              SCHED_CNT           TOTAL ns            MIN ns            MAX ns
                                      13           817,605             5,433           524,376

                              [THREAD READY STATISTICS]
                              SCHED_CNT           TOTAL ns            MAX ns
                                      14            28,646            11,566

                              [SOFT IRQ STATISTICS]
                              NAME                 VECT_NR       COUNT          TOTAL ns            MAX ns
                              rcu                        9           1             2,838             2,838
                              TOTAL:                                 1             2,838

     3371110 revalidator74    [SYSCALL STATISTICS]
     ... <REMOVED 7 MORE NEW revalidator THREADS>
     3366311 urcu3            [SYSCALL STATISTICS]
     ...


OVS removed some of the threads and their resource-specific data, but based
on the ``<unknown:3366258/3371035>`` thread name, you can determine that some
threads no longer exist. In the ``ovs-vswitchd`` thread, you can see some
``clone3`` syscalls, indicating threads were created. In this example, it was
due to the deletion of a bridge, which resulted in the recreation of the
revalidator and handler threads.


Use with Openshift
------------------
This section describes how you would use the tool on a node in an OpenShift
cluster. It assumes you have console access to the node, either directly or
through a debug container.

A base fedora38 container will be used through podman, as this will allow the
use of some additional tools and packages needed.

First the containers need to be started:

.. code-block:: console

  [core@sno-master ~]$ sudo podman run -it --rm \
     -e PS1='[(DEBUG)\u@\h \W]\$ ' \
     --privileged --network=host --pid=host \
     -v /lib/modules:/lib/modules:ro \
     -v /sys/kernel/debug:/sys/kernel/debug \
     -v /proc:/proc \
     -v /:/mnt/rootdir \
     quay.io/fedora/fedora:38-x86_64

  [(DEBUG)root@sno-master /]#


Next add the ``linux_delay.py`` dependencies:

.. code-block:: console

  [(DEBUG)root@sno-master /]# dnf install -y bcc-tools perl-interpreter \
       python3-pytz  python3-psutil


You need to install the devel, debug and source RPMs for your OVS and kernel
version:

.. code-block:: console

  [(DEBUG)root@sno-master home]# rpm -i \
      openvswitch2.17-debuginfo-2.17.0-67.el8fdp.x86_64.rpm \
      openvswitch2.17-debugsource-2.17.0-67.el8fdp.x86_64.rpm \
      kernel-devel-4.18.0-372.41.1.el8_6.x86_64.rpm


Now the tool can be started. Here the above ``bridge_run()`` example is used:

.. code-block:: console

  [(DEBUG)root@sno-master home]# ./kernel_delay.py --start-trigger up:bridge_run --stop-trigger ur:bridge_run
  # Start sampling (trigger@75279117343513) @2023-06-15T11:44:07.628372 (11:44:07 UTC)
  # Stop sampling (trigger@75279117443980) @2023-06-15T11:44:07.628529 (11:44:07 UTC)
  # Triggered sample dump, stop-start delta 100,467 ns @2023-06-15T11:44:07.628569 (11:44:07 UTC)
  TID        THREAD           <RESOURCE SPECIFIC>
  ---------- ---------------- ----------------------------------------------------------------------------
        1246 ovs-vswitchd     [SYSCALL STATISTICS]
                              NAME                 NUMBER       COUNT          TOTAL ns            MAX ns
                              getdents64              217           2             8,560             8,162
                              openat                  257           1             6,951             6,951
                              accept                   43           4             6,942             3,763
                              recvfrom                 45           1             3,726             3,726
                              recvmsg                  47           2             2,880             2,188
                              stat                      4           2             1,946             1,384
                              close                     3           1             1,393             1,393
                              fstat                     5           1             1,324             1,324
                              TOTAL( - poll):                      14            33,722

                              [THREAD RUN STATISTICS]
                              SCHED_CNT           TOTAL ns            MIN ns            MAX ns

                              [THREAD READY STATISTICS]
                              SCHED_CNT           TOTAL ns            MAX ns


.. rubric:: Footnotes

.. [#BCC] https://github.com/iovisor/bcc
.. [#BCC_EVENT] https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#events--arguments
.. [#REVAL_BLOG] https://developers.redhat.com/articles/2022/10/19/open-vswitch-revalidator-process-explained
