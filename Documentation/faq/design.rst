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

======================
Implementation Details
======================

Q: I hear OVS has a couple of kinds of flows.  Can you tell me about them?

    A: Open vSwitch uses different kinds of flows for different purposes:

    - OpenFlow flows are the most important kind of flow.  OpenFlow controllers
      use these flows to define a switch's policy.  OpenFlow flows support
      wildcards, priorities, and multiple tables.

      When in-band control is in use, Open vSwitch sets up a few "hidden"
      flows, with priority higher than a controller or the user can configure,
      that are not visible via OpenFlow.  (See the "Controller" section of the
      FAQ for more information about hidden flows.)

    - The Open vSwitch software switch implementation uses a second kind of
      flow internally.  These flows, called "datapath" or "kernel" flows, do
      not support priorities and comprise only a single table, which makes them
      suitable for caching.  (Like OpenFlow flows, datapath flows do support
      wildcarding, in Open vSwitch 1.11 and later.)  OpenFlow flows and
      datapath flows also support different actions and number ports
      differently.

      Datapath flows are an implementation detail that is subject to change in
      future versions of Open vSwitch.  Even with the current version of Open
      vSwitch, hardware switch implementations do not necessarily use this
      architecture.

Users and controllers directly control only the OpenFlow flow table.  Open
vSwitch manages the datapath flow table itself, so users should not normally be
concerned with it.

Q: Why are there so many different ways to dump flows?

    A: Open vSwitch has two kinds of flows (see the previous question), so it
    has commands with different purposes for dumping each kind of flow:

    - ``ovs-ofctl dump-flows <br>`` dumps OpenFlow flows, excluding hidden
      flows.  This is the most commonly useful form of flow dump.  (Unlike the
      other commands, this should work with any OpenFlow switch, not just Open
      vSwitch.)

    - ``ovs-appctl bridge/dump-flows <br>`` dumps OpenFlow flows, including
      hidden flows.  This is occasionally useful for troubleshooting suspected
      issues with in-band control.

    - ``ovs-dpctl dump-flows [dp]`` dumps the datapath flow table entries for a
      Linux kernel-based datapath.  In Open vSwitch 1.10 and later,
      ovs-vswitchd merges multiple switches into a single datapath, so it will
      show all the flows on all your kernel-based switches.  This command can
      occasionally be useful for debugging.

    - ``ovs-appctl dpif/dump-flows <br>``, new in Open vSwitch 1.10, dumps
      datapath flows for only the specified bridge, regardless of the type.

Q: How does multicast snooping works with VLANs?

    A: Open vSwitch maintains snooping tables for each VLAN.

Q: Can OVS populate the kernel flow table in advance instead of in reaction to
packets?

    A: No.  There are several reasons:

    - Kernel flows are not as sophisticated as OpenFlow flows, which means that
      some OpenFlow policies could require a large number of kernel flows.  The
      "conjunctive match" feature is an extreme example: the number of kernel
      flows it requires is the product of the number of flows in each
      dimension.

    - With multiple OpenFlow flow tables and simple sets of actions, the number
      of kernel flows required can be as large as the product of the number of
      flows in each dimension.  With more sophisticated actions, the number of
      kernel flows could be even larger.

    - Open vSwitch is designed so that any version of OVS userspace
      interoperates with any version of the OVS kernel module.  This forward
      and backward compatibility requires that userspace observe how the kernel
      module parses received packets.  This is only possible in a
      straightforward way when userspace adds kernel flows in reaction to
      received packets.

    For more relevant information on the architecture of Open vSwitch, please
    read "The Design and Implementation of Open vSwitch", published in USENIX
    NSDI 2015.
