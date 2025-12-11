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

========
Releases
========

Q: What does it mean for an Open vSwitch release to be LTS (long-term support)?

    A: All official releases have been through a comprehensive testing process
    and are suitable for production use.  Planned releases occur twice a year.
    If a significant bug is identified in an LTS release, we will provide an
    updated release that includes the fix.  Releases that are not LTS may not
    be fixed and may just be supplanted by the next major release.  The current
    LTS release is 3.3.x.

    For more information on the Open vSwitch release process, refer to
    :doc:`/internals/release-process`.

Q: What Linux kernel versions does each Open vSwitch release work with?

    A: Open vSwitch userspace works with the kernel module shipped with
    Linux upstream 3.3 and later.

    Building the Linux kernel module from the Open vSwitch source tree was
    deprecated starting with Open vSwitch 2.15.  And the kernel module
    source code was completely removed from the Open vSwitch source tree in
    3.0 release.

Q: Are all features available with all datapaths?

    A: Open vSwitch supports different datapaths on different platforms.  Each
    datapath has a different feature set: the following tables try to summarize
    the status.

    Supported datapaths:

    Linux upstream
      The datapath implemented by the kernel module shipped with Linux
      upstream.  Since features have been gradually introduced into the kernel,
      the table mentions the first Linux release whose OVS module supports the
      feature.

    Userspace
      This datapath supports conventional system devices as well as
      DPDK and AF_XDP devices when support for those is built.  This
      is the only datapath that works on NetBSD, FreeBSD and Mac OSX.

    Hyper-V
      Also known as the Windows datapath.

    The following table lists the datapath supported features from an
    Open vSwitch user's perspective.  The "Linux upstream" column
    lists the Linux kernel version that introduced a given feature
    into its kernel module.  The "Linux OVS tree" and "Userspace"
    columns list the Open vSwitch release versions that introduced a
    given feature into the included kernel module or the userspace
    datapath, respectively.

    ========================== ============== ========= =======
    Feature                    Linux upstream Userspace Hyper-V
    ========================== ============== ========= =======
    Connection tracking             4.3          2.6      YES
    Connection tracking-IPv6        YES          YES      3.0
    Conntrack Fragment Reass.       4.3          2.12     YES
    Conntrack IPv6 Fragment         4.3          2.12     3.1
    Conntrack Timeout Policies      5.2          2.14     NO
    Conntrack Zone Limit            4.18         2.13     YES
    Conntrack NAT                   4.6          2.8      YES
    Conntrack NAT6                  4.6          2.8      3.0
    Conntrack Helper Persist.       YES          3.3      NO
    Tunnel - GRE                    3.11         2.4      YES
    Tunnel - VXLAN                  3.12         2.4      YES
    Tunnel - Geneve                 3.18         2.4      YES
    Tunnel - GRE-IPv6               4.18         2.6      NO
    Tunnel - VXLAN-IPv6             4.3          2.6      NO
    Tunnel - Geneve-IPv6            4.4          2.6      3.0
    Tunnel - ERSPAN                 4.18         2.10     NO
    Tunnel - ERSPAN-IPv6            4.18         2.10     NO
    Tunnel - GTP-U                  NO           2.14     NO
    Tunnel - SRv6                   NO           3.2      NO
    Tunnel - Bareudp                5.7          NO       NO
    QoS - Policing                  YES          2.6      NO
    QoS - Shaping                   YES          NO       NO
    sFlow                           YES          1.0      NO
    IPFIX                           3.10         1.11     YES
    Set action                      YES          1.0    PARTIAL
    NIC Bonding                     YES          1.0      YES
    Multiple VTEPs                  YES          1.10     YES
    Meter action                    4.15         2.7      NO
    check_pkt_len action            5.2          2.12     NO
    ========================== ============== ========= =======

    Do note, however:

    * Only a limited set of flow fields is modifiable via the set action by the
      Hyper-V datapath.

    * Userspace datapath support, in some cases, is dependent on the associated
      interface types.  For example, DPDK interfaces support ingress and egress
      policing, but not shaping.

    The following table lists features that do not *directly* impact an Open
    vSwitch user, e.g. because their absence can be hidden by the ofproto layer
    (usually this comes with a performance penalty).

    ===================== ============== ============== ========= =======
    Feature               Linux upstream Linux OVS tree Userspace Hyper-V
    ===================== ============== ============== ========= =======
    SCTP flows            3.12           YES            YES       YES
    MPLS                  3.19           YES            YES       YES
    UFID                  4.0            YES            YES       NO
    Megaflows             3.12           YES            YES       NO
    Masked set action     4.0            YES            YES       NO
    Recirculation         3.19           YES            YES       YES
    TCP flags matching    3.13           YES            YES       NO
    Validate flow actions YES            YES            N/A       NO
    Multiple datapaths    YES            YES            YES       NO
    ===================== ============== ============== ========= =======

Q: What DPDK version does each Open vSwitch release work with?

    A: The following table lists the DPDK version against which the given
    versions of Open vSwitch will successfully build.

    ============ ========
    Open vSwitch DPDK
    ============ ========
    2.2.x        1.6
    2.3.x        1.6
    2.4.x        2.0
    2.5.x        2.2
    2.6.x        16.07.2
    2.7.x        16.11.9
    2.8.x        17.05.2
    2.9.x        17.11.10
    2.10.x       17.11.10
    2.11.x       18.11.9
    2.12.x       18.11.9
    2.13.x       19.11.13
    2.14.x       19.11.13
    2.15.x       20.11.6
    2.16.x       20.11.6
    2.17.x       21.11.9
    3.0.x        21.11.9
    3.1.x        22.11.7
    3.2.x        22.11.7
    3.3.x        23.11.5
    3.4.x        23.11.5
    3.5.x        24.11.3
    3.6.x        24.11.3
    ============ ========

Q: Are all the DPDK releases that OVS versions work with maintained?

    No. DPDK follows YY.MM.n (Year.Month.Number) versioning.

    Typically, all DPDK releases get a stable YY.MM.1 update with bugfixes 3
    months after the YY.MM.0 release. In some cases there may also be a
    YY.MM.2 release.

    DPDK LTS releases start once a year at YY.11.0 and are maintained for
    two years, with YY.MM.n+1 releases around every 3 months.

    The latest information about DPDK stable and LTS releases can be found
    at `DPDK stable`_.

.. _DPDK stable: https://doc.dpdk.org/guides-25.11/contributing/stable.html

Q: What features are not available in the Open vSwitch kernel datapath that
ships as part of the upstream Linux kernel?

    A: Certain features require kernel support to function or to have
    reasonable performance.  If the ovs-vswitchd log file indicates that a
    feature is not supported, consider upgrading to a newer upstream Linux
    release.

Q: Why do tunnels not work when using a kernel module other than the one
packaged with Open vSwitch?

    A: Support for tunnels was added to the upstream Linux kernel module after
    the rest of Open vSwitch. As a result, some kernels may contain support for
    Open vSwitch but not tunnels. The minimum kernel version that supports each
    tunnel protocol is:

    ======== ============
    Protocol Linux Kernel
    ======== ============
    GRE      3.11
    VXLAN    3.12
    Geneve   3.18
    ERSPAN   4.18
    ======== ============

Q: Why are UDP tunnel checksums not computed for VXLAN or Geneve?

    A: Generating outer UDP checksums requires kernel support that was not part
    of the initial implementation of these protocols. The kernel modules
    shipped with upstream Linux 4.0 and later support UDP checksums.

Q: What features are not available when using the userspace datapath?

    A: Tunnel virtual ports are not supported, as described in the previous
    answer.  It is also not possible to use queue-related actions.  On Linux
    kernels before 2.6.39, maximum-sized VLAN packets may not be transmitted.

Q: Should userspace or kernel be upgraded first to minimize downtime?

    A. In general, the Open vSwitch userspace should be used with the kernel
    version included in the same release or with the version from upstream
    Linux.  However, when upgrading between two releases of Open vSwitch it is
    best to migrate userspace first to reduce the possibility of
    incompatibilities.

Q: What happened to the bridge compatibility feature?

    A: Bridge compatibility was a feature of Open vSwitch 1.9 and earlier.
    When it was enabled, Open vSwitch imitated the interface of the Linux
    kernel "bridge" module.  This allowed users to drop Open vSwitch into
    environments designed to use the Linux kernel bridge module without
    adapting the environment to use Open vSwitch.

    Open vSwitch 1.10 and later do not support bridge compatibility.  The
    feature was dropped because version 1.10 adopted a new internal
    architecture that made bridge compatibility difficult to maintain.  Now
    that many environments use OVS directly, it would be rarely useful in any
    case.

    To use bridge compatibility, install OVS 1.9 or earlier, including the
    accompanying kernel modules (both the main and bridge compatibility
    modules), following the instructions that come with the release.  Be sure
    to start the ovs-brcompatd daemon.
