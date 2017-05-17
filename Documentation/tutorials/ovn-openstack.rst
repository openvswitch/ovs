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
OVN OpenStack Tutorial
======================

This tutorial demonstrates how OVN works in an OpenStack "DevStack"
environment.  It was tested with the "master" branches of DevStack and
Open vSwitch near the beginning of May 2017.  Anyone using an earlier
version is likely to encounter some differences.  In particular, we
noticed some shortcomings in OVN utilities while writing the tutorial
and pushed out some improvements, so it's best to use recent Open
vSwitch at least from that point of view.

The goal of this tutorial is to demonstrate OVN in an end-to-end way,
that is, to show how it works from the cloud management system at the
top (in this case, OpenStack and specifically its Neutron networking
subsystem), through the OVN northbound and southbound databases, to
the bottom at the OVN local controller and Open vSwitch data plane.
We hope that this demonstration makes it easier for users and
potential users to understand how OVN works and how to debug and
troubleshoot it.

In addition to new material, this tutorial incorporates content from
``testing.rst`` in OpenStack networking-ovn, by Russell Bryant and
others.  Without that example, this tutorial could not have been
written.

We provide enough details in the tutorial that you should be able to
fully follow along, by creating a DevStack VM and cloning DevStack and
so on.  If you want to do this, start out from `Setting Up DevStack`_
below.

Setting Up DevStack
-------------------

This section explains how to install DevStack, a kind of OpenStack
packaging for developers, in a way that allows you to follow along
with the tutorial in full.

Unless you have a spare computer laying about, it's easiest to install
DevStacck in a virtual machine.  This tutorial was built using a VM
implemented by KVM and managed by virt-manager.  I recommend
configuring the VM configured for the x86-64 architecture, 4 GB RAM, 2
VCPUs, and a 20 GB virtual disk.

.. note::

   If you happen to run your Linux-based host with 32-bit userspace,
   then you will have some special issues, even if you use a 64-bit
   kernel:

   * You may find that you can get 32-bit DevStack VMs to work to some
     extent, but I personally got tired of finding workarounds.  I
     recommend running your VMs in 64-bit mode.  To get this to work,
     I had to go to the CPUs tab for the VM configuration in
     virt-manager and change the CPU model from the one originally
     listed to "Hypervisor Default' (it is curious that this is not
     the default!).

   * On a host with 32-bit userspace, KVM supports VMs with at most
     2047 MB RAM.  This is adequate, barely, to start DevStack, but it
     is not enough to run multiple (nested) VMs.  To prevent
     out-of-memory failures, set up extra swap space in the guest.
     For example, to add 2 GB swap::

       $ sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
       $ sudo mkswap /swapfile
       $ sudo swapon /swapfile

     and then add a line like this to ``/etc/fstab`` to add the new
     swap automatically upon reboot::

       /swapfile swap swap defaults 0 0

Here are step-by-step instructions to get started:

1. Install a VM.

   I tested these instructions with Centos 7.3.  Download the "minimal
   install" ISO and booted it.  The install is straightforward.  Be
   sure to enable networking, and set a host name, such as
   "ovn-devstack-1".  Add a regular (non-root) user, and check the box
   "Make this user administrator".  Also, set your time zone.

2. You can SSH into the DevStack VM, instead of running from a
   console.  I recommend it because it's easier to cut and paste
   commands into a terminal than a VM console.  You might also
   consider using a very wide terminal, perhaps 160 columns, to keep
   tables from wrapping.

   To improve convenience further, you can make it easier to log in
   with the following steps, which are optional:

   a. On your host, edit your ``~/.ssh/config``, adding lines like
      the following::

        Host ovn-devstack-1
              Hostname VMIP
              User VMUSER

      where VMIP is the VM's IP address and VMUSER is your username
      inside the VM.  (You can omit the ``User`` line if your
      username is the same in the host and the VM.)  After you do
      this, you can SSH to the VM by name, e.g. ``ssh
      ovn-devstack-1``, and if command-line completion is set up in
      your host shell, you can shorten that to something like ``ssh
      ovn`` followed by hitting the Tab key.

   b. If you have SSH public key authentication set up, with an SSH
      agent, run on your host::

        $ ssh-copy-id ovn-devstack-1

      and type your password once.  Afterward, you can log in without
      typing your password again.

      (If you don't already use SSH public key authentication and an
      agent, consider looking into it--it will save you time in the
      long run.)

   c. Optionally, inside the VM, append the following to your
      ``~/.bash_profile``::

        . $HOME/devstack/openrc admin

      It will save you running it by hand each time you log in.  But
      it also prints garbage to the console, which can screw up
      services like ``ssh-copy-id``, so be careful.

2. Boot into the installed system and log in as the regular user, then
   install Git::

     $ sudo yum install git

   .. note::

      If you installed a 32-bit i386 guest (against the advice above),
      install a non-PAE kernel and reboot into it at this point::

           $ sudo yum install kernel-core kernel-devel
           $ sudo reboot

      Be sure to select the non-PAE kernel from the list at boot.
      Without this step, DevStack will fail to install properly later.

3. Get copies of DevStack and OVN and set them up::

     $ git clone http://git.openstack.org/openstack-dev/devstack.git
     $ git clone http://git.openstack.org/openstack/networking-ovn.git
     $ cd devstack
     $ cp ../networking-ovn/devstack/local.conf.sample local.conf

   .. note::

      If you installed a 32-bit i386 guest (against the advice above),
      at this point edit ``local.conf`` to add the following line::

        CIRROS_ARCH=i386

4. Initialize DevStack::

     $ ./stack.sh

   This will spew many screenfuls of text, and the first time you run
   it, it will download lots of software from the Internet.  The
   output should eventually end with something like this::

     This is your host IP address: 172.16.189.6
     This is your host IPv6 address: ::1
     Horizon is now available at http://172.16.189.6/dashboard
     Keystone is serving at http://172.16.189.6/identity/
     The default users are: admin and demo
     The password: password
     2017-03-09 15:10:54.117 | stack.sh completed in 2110 seconds.

   If there's some kind of failure, you can restart by running
   ``./stack.sh`` again.  It won't restart exactly where it left off,
   but steps up to the one where it failed will skip the download
   steps.  (Sometimes blindly restarting after a failure will allow it
   to succeed.)  If you reboot your VM, you need to rerun this
   command.  (If you run into trouble with ``stack.sh`` after
   rebooting your VM, try running ``./unstack.sh``.)

   At this point you can navigate a web browser on your host to the
   Horizon dashboard URL.  Many OpenStack operations can be initiated
   from this UI.  Feel free to explore, but this tutorial focuses on
   the alternative command-line interfaces because they are easier to
   explain and to cut and paste.

5. As of this writing, you need to run the following to fix a problem
   with using VM consoles from the OpenStack web instance::

     $ (cd /opt/stack/noVNC && git checkout v0.6.0)

   See
   https://serenity-networks.com/how-to-fix-setkeycodes-00-and-unknown-key-pressed-console-errors-on-openstack/
   for more details.

6. The firewall in the VM by default allows SSH access but not HTTP.
   You will probably want HTTP access to use the OpenStack web
   interface.  The following command enables that.  (It also enables
   every other kind of network access, so if you're concerned about
   security then you might want to find a more targeted approach.)

   ::

      $ sudo iptables -F

   (You need to re-run this if you reboot the VM.)

7. To use OpenStack command line utilities in the tutorial, run::

     $ . ~/devstack/openrc admin

   This needs to be re-run each time you log in (but see the following
   section).

DevStack preliminaries
----------------------

Before we really jump in, let's set up a couple of things in DevStack.
This is the first real test that DevStack is working, so if you get
errors from any of these commands, it's a sign that ``stack.sh``
didn't finish properly, or perhaps that you didn't run the ``openrc
admin`` command at the end of the previous instructions.

If you stop and restart DevStack via ``unstack.sh`` followed by
``stack.sh``, you have to rerun these steps.

1. For SSH access to the VMs we're going to create, we'll need a SSH
   keypair.  Later on, we'll get OpenStack to install this keypair
   into VMs.  Create one with::

     $ openstack keypair create demo > ~/id_rsa_demo
     $ chmod 600 ~/id_rsa_demo

2. By default, DevStack security groups drop incoming traffic, but to
   test networking in a reasonable way we need to enable it.  You only
   need to actually edit one particular security group, but DevStack
   creates multiple and it's somewhat difficult to figure out which
   one is important because all of them are named "default".  So, the
   following adds rules to allow SSH and ICMP traffic into **every**
   security group::

     $ for group in $(openstack security group list -f value -c ID); do \
     openstack security group rule create --ingress --ethertype IPv4 --dst-port 22 --protocol tcp $group; \
     openstack security group rule create --ingress --ethertype IPv4 --protocol ICMP $group; \
     done

3. Later on, we're going to create some VMs and we'll need an
   operating system image to install.  DevStack comes with a very
   simple image built-in, called "cirros", which works fine.  We need
   to get the UUID for this image.  Our later commands assume shell
   variable ``IMAGE_ID`` holds this UUID.  You can set this by hand,
   e.g.::

     $ openstack image list
     +--------------------------------------+--------------------------+--------+
     | ID                                   | Name                     | Status |
     +--------------------------------------+--------------------------+--------+
     | 77f37d2c-3d6b-4e99-a01b-1fa5d78d1fa1 | cirros-0.3.5-x86_64-disk | active |
     +--------------------------------------+--------------------------+--------+
     $ IMAGE_ID=73ca34f3-63c4-4c10-a62f-4540afc24eaa

   or by parsing CLI output::

     $ IMAGE_ID=$(openstack image list -f value -c ID)

   .. note::

      Your image ID will differ from the one above, as will every UUID
      in this tutorial.  They will also change every time you run
      ``stack.sh``.  The UUIDs are generated randomly.

Shortening UUIDs
----------------

OpenStack, OVN, and Open vSwitch all really like UUIDs.  These are
great for uniqueness, but 36-character strings are terrible for
readability.  Statistically, just the first few characters are enough
for uniqueness in small environments, so let's define a helper to make
things more readable::

  $ abbrev() { a='[0-9a-fA-F]' b=$a$a c=$b$b; sed "s/$b-$c-$c-$c-$c$c$c//g"; }

You can use this as a filter to abbreviate UUIDs.  For example, use it
to abbreviate the above image list::

  $ openstack image list -f yaml | abbrev
  - ID: 77f37d
    Name: cirros-0.3.5-x86_64-disk
    Status: active

The command above also adds ``-f yaml`` to switch to YAML output
format, because abbreviating UUIDs screws up the default table-based
formatting and because YAML output doesn't produce wrap columns across
lines and therefore is easier to cut and paste.

Overview
--------

Now that DevStack is ready, with OVN set up as the networking
back-end, here's an overview of what we're going to do in the
remainder of the demo, all via OpenStack:

1. Switching: Create an OpenStack network ``n1`` and VMs ``a`` and
   ``b`` attached to it.

   An OpenStack network is a virtual switch; it corresponds to an OVN
   logical switch.

2. Routing: Create a second OpenStack network ``n2`` and VM ``c``
   attached to it, then connect it to network ``n1`` by creating an
   OpenStack router and attaching ``n1`` and ``n2`` to it.

3. Gateways: Make VMs ``a`` and ``b`` available via an external network.

4. IPv6: Add IPv6 addresses to our VMs to demonstrate OVN support for
   IPv6 routing.

5. ACLs: Add and modify OpenStack stateless and stateful rules in
   security groups.

6. DHCP: How it works in OVN.

7. Further directions: Adding more compute nodes.

At each step, we will take a look at how the features in question work
from OpenStack's Neutron networking layer at the top to the data plane
layer at the bottom.  From the highest to lowest level, these layers
and the software components that connect them are:

* OpenStack Neutron, which as the top level in the system is the
  authoritative source of the virtual network configuration.

  We will use OpenStack's ``openstack`` utility to observe and modify
  Neutron and other OpenStack configuration.

* networking-ovn, the Neutron driver that interfaces with OVN and
  translates the internal Neutron representation of the virtual
  network into OVN's representation and pushes that representation
  down the OVN northbound database.

  In this tutorial it's rarely worth distinguishing Neutron from
  networking-ovn, so we usually don't break out this layer separately.

* The OVN Northbound database, aka NB DB.  This is an instance of
  OVSDB, a simple general-purpose database that is used for multiple
  purposes in Open vSwitch and OVN.  The NB DB's schema is in terms of
  networking concepts such as switches and routers.  The NB DB serves
  the purpose that in other systems might be filled by some kind of
  API; for example, in place of calling an API to create or delete a
  logical switch, networking-ovn performs these operations by
  inserting or deleting a row in the NB DB's Logical_Switch table.

  We will use OVN's ``ovn-nbctl`` utility to observe the NB DB.  (We
  won't directly modify data at this layer or below.  Because
  configuration trickles down from Neutron through the stack, the
  right way to make changes is to use the ``openstack`` utility or
  another OpenStack interface and then wait for them to percolate
  through to lower layers.)

* The ovn-northd daemon, a program that runs centrally and translates
  the NB DB's network representation into the lower-level
  representation used by the OVN Southbound database in the next
  layer.  The details of this daemon are usually not of interest,
  although without it OVN will not work, so this tutorial does not
  often mention it.

* The OVN Southbound database, aka SB DB, which is also an OVSDB
  database.  Its schema is very different from the NB DB.  Instead of
  familiar networking concepts, the SB DB defines the network in terms
  of collections of match-action rules called "logical flows", which
  while similar in concept to OpenFlow flows use logical concepts, such
  as virtual machine instances, in place of physical concepts like
  physical Ethernet ports.

  We will use OVN's ``ovn-sbctl`` utility to observe the SB DB.

* The ovn-controller daemon.  A copy of ovn-controller runs on each
  hypervisor.  It reads logical flows from the SB DB, translates them
  into OpenFlow flows, and sends them to Open vSwitch's ovs-vswitchd
  daemon.  Like ovn-northd, usually the details of what this daemon
  are not of interest, even though it's important to the operation of
  the system.

* ovs-vswitchd.  This program runs on each hypervisor.  It is the core
  of Open vSwitch, which processes packets according to the OpenFlow
  flows set up by ovn-controller.

* Open vSwitch datapath.  This is essentially a cache designed to
  accelerate packet processing.  Open vSwitch includes a few different
  datapaths but OVN installations typically use one based on the Open
  vSwitch Linux kernel module.

Switching
---------

Switching is the basis of networking in the real world and in virtual
networking as well.  OpenStack calls its concept of a virtual switch a
"network", and OVN calls its corresponding concept a "logical switch".

In this step, we'll create an OpenStack network ``n1``, then create
VMs ``a`` and ``b`` and attach them to ``n1``.

Creating network ``n1``
~~~~~~~~~~~~~~~~~~~~~~~

Let's start by creating the network::

  $ openstack network create --project admin --provider-network-type geneve n1

OpenStack needs to know the subnets that a network serves.  We inform
it by creating subnet objects.  To keep it simple, let's give our
network a single subnet for the 10.1.1.0/24 network.  We have to give
it a name, in this case ``n1subnet``::

  $ openstack subnet create --subnet-range 10.1.1.0/24 --network n1 n1subnet

If you ask Neutron to show us the available networks, we see ``n1`` as
well as the two networks that DevStack creates by default::

  $ openstack network list -f yaml | abbrev
  - ID: 5b6baf
    Name: n1
    Subnets: 5e67e7
  - ID: c02c4d
    Name: private
    Subnets: d88a34, fd87f9
  - ID: d1ac28
    Name: public
    Subnets: 0b1e79, c87dc1

Neutron pushes this network setup down to the OVN northbound
database.  We can use ``ovn-nbctl show`` to see an overview of what's
in the NB DB::

  $ ovn-nbctl show | abbrev
  switch 5b3d5f (neutron-c02c4d) (aka private)
      port b256dd
          type: router
          router-port: lrp-b256dd
      port f264e7
          type: router
          router-port: lrp-f264e7
  switch 2579f4 (neutron-d1ac28) (aka public)
      port provnet-d1ac28
          type: localnet
          addresses: ["unknown"]
      port ae9b52
          type: router
          router-port: lrp-ae9b52
  switch 3eb263 (neutron-5b6baf) (aka n1)
  router c59ad2 (neutron-9b057f) (aka router1)
      port lrp-ae9b52
          mac: "fa:16:3e:b2:d2:67"
          networks: ["172.24.4.9/24", "2001:db8::b/64"]
      port lrp-b256dd
          mac: "fa:16:3e:35:33:db"
          networks: ["fdb0:5860:4ba8::1/64"]
      port lrp-f264e7
          mac: "fa:16:3e:fc:c8:da"
          networks: ["10.0.0.1/26"]
      nat 80914c
          external ip: "172.24.4.9"
          logical ip: "10.0.0.0/26"
          type: "snat"

This output shows that OVN has three logical switches, each of which
corresponds to a Neutron network, and a logical router that
corresponds to the Neutron router that DevStack creates by default.
The logical switch that corresponds to our new network ``n1`` has no
ports yet, because we haven't added any.  The ``public`` and
``private`` networks that DevStack creates by default have router
ports that connect to the logical router.

Using ovn-northd, OVN translates the NB DB's high-level switch and
router concepts into lower-level concepts of "logical datapaths" and
logical flows.  There's one logical datapath for each logical switch
or router::

  $ ovn-sbctl list datapath_binding | abbrev
  _uuid               : 0ad69d
  external_ids        : {logical-switch="5b3d5f", name="neutron-c02c4d", "name2"=private}
  tunnel_key          : 1

  _uuid               : a8a758
  external_ids        : {logical-switch="3eb263", name="neutron-5b6baf", "name2"="n1"}
  tunnel_key          : 4

  _uuid               : 191256
  external_ids        : {logical-switch="2579f4", name="neutron-d1ac28", "name2"=public}
  tunnel_key          : 3

  _uuid               : b87bec
  external_ids        : {logical-router="c59ad2", name="neutron-9b057f", "name2"="router1"}
  tunnel_key          : 2

This output lists the NB DB UUIDs in external_ids:logical-switch and
Neutron UUIDs in externals_ids:uuid.  We can dive in deeper by viewing
the OVN logical flows that implement a logical switch.  Our new
logical switch is a simple and almost pathological example given that
it doesn't yet have any ports attached to it.  We'll look at the
details a bit later::

  $ ovn-sbctl lflow-list n1 | abbrev
  Datapath: "neutron-5b6baf" aka "n1" (a8a758)  Pipeline: ingress
    table=0 (ls_in_port_sec_l2  ), priority=100  , match=(eth.src[40]), action=(drop;)
    table=0 (ls_in_port_sec_l2  ), priority=100  , match=(vlan.present), action=(drop;)
  ...
  Datapath: "neutron-5b6baf" aka "n1" (a8a758)  Pipeline: egress
    table=0 (ls_out_pre_lb      ), priority=0    , match=(1), action=(next;)
    table=1 (ls_out_pre_acl     ), priority=0    , match=(1), action=(next;)
  ...

We have one hypervisor (aka "compute node", in OpenStack parlance),
which is the one where we're running all these commands.  On this
hypervisor, ovn-controller is translating OVN logical flows into
OpenFlow flows ("physical flows").  It makes sense to go deeper, to
see the OpenFlow flows that get generated from this datapath.  By
adding ``--ovs`` to the ``ovn-sbctl`` command, we can see OpenFlow
flows listed just below their logical flows.  We also need to use
``sudo`` because connecting to Open vSwitch is privileged.  Go ahead
and try it::

  $ sudo ovn-sbctl --ovs lflow-list n1 | abbrev
  Datapath: "neutron-5b6baf" aka "n1" (a8a758)  Pipeline: ingress
    table=0 (ls_in_port_sec_l2  ), priority=100  , match=(eth.src[40]), action=(drop;)
    table=0 (ls_in_port_sec_l2  ), priority=100  , match=(vlan.present), action=(drop;)
  ...
  Datapath: "neutron-5b6baf" aka "n1" (a8a758)  Pipeline: egress
    table=0 (ls_out_pre_lb      ), priority=0    , match=(1), action=(next;)
    table=1 (ls_out_pre_acl     ), priority=0    , match=(1), action=(next;)
  ...

You were probably disappointed: the output didn't change, and no
OpenFlow flows were printed.  That's because no OpenFlow flows are
installed for this logical datapath, which in turn is because there
are no VIFs for this logical datapath on the local hypervisor.  For a
better example, you can try ``ovn-sbctl --ovs`` on one of the other
logical datapaths.

Attaching VMs
~~~~~~~~~~~~~

A switch without any ports is not very interesting.  Let's create a
couple of VMs and attach them to the switch.  Run the following
commands, which create VMs named ``a`` and ``b`` and attaches them to
our network ``n1`` with IP addresses 10.1.1.5 and 10.1.1.6,
respectively.  It is not actually necessary to manually assign IP
address assignments, since OpenStack is perfectly happy to assign them
itself from the subnet's IP address range, but predictable addresses
are useful for our discussion::

  $ openstack server create --nic net-id=n1,v4-fixed-ip=10.1.1.5 --flavor m1.nano --image $IMAGE_ID --key-name demo a
  $ openstack server create --nic net-id=n1,v4-fixed-ip=10.1.1.6 --flavor m1.nano --image $IMAGE_ID --key-name demo b

These commands return before the VMs are really finished being built.
You can run ``openstack server list`` a few times until each of them
is shown in the state ACTIVE, which means that they're not just built
but already running on the local hypervisor.

These operations had the side effect of creating separate "port"
objects, but without giving those ports any easy-to-read names.  It'll
be easier to deal with them later if we can refer to them by name, so
let's name ``a``'s port ``ap`` and ``b``'s port ``bp``::

  $ openstack port set --name ap $(openstack port list --server a -f value -c ID)
  $ openstack port set --name bp $(openstack port list --server b -f value -c ID)

We'll need to refer to these ports' MAC addresses a few times, so
let's put them in variables::

  $ AP_MAC=$(openstack port show -f value -c mac_address ap)
  $ BP_MAC=$(openstack port show -f value -c mac_address bp)

At this point you can log into the consoles of the VMs if you like.
You can do that from the OpenStack web interface or get a direct URL
to paste into a web browser using a command like::

  $ openstack console url show -f yaml a

(The option ``-f yaml`` keeps the URL in the output from being broken
into noncontiguous pieces on a 80-column console.)

The VMs don't have many tools in them but ``ping`` and ``ssh`` from
one to the other should work fine.  The VMs do not have any external
network access or DNS configuration.

Let's chase down what's changed in OVN.  Start with the NB DB at the
top of the system.  It's clear that our logical switch now has the two
logical ports attached to it::

  $ ovn-nbctl show | abbrev
  ...
  switch 3eb263 (neutron-5b6baf) (aka n1)
      port c29d41 (aka bp)
          addresses: ["fa:16:3e:99:7a:17 10.1.1.6"]
      port 820c08 (aka ap)
          addresses: ["fa:16:3e:a9:4c:c7 10.1.1.5"]
  ...

We can get some more details on each of these by looking at their NB
DB records in the Logical_Switch_Port table.  Each port has addressing
information, port security enabled, and a pointer to DHCP
configuration (which we'll look at much later in `DHCP`_)::

  $ ovn-nbctl list logical_switch_port ap bp | abbrev
  _uuid               : ef17e5
  addresses           : ["fa:16:3e:a9:4c:c7 10.1.1.5"]
  dhcpv4_options      : 165974
  dhcpv6_options      : []
  dynamic_addresses   : []
  enabled             : true
  external_ids        : {"neutron:port_name"=ap}
  name                : "820c08"
  options             : {}
  parent_name         : []
  port_security       : ["fa:16:3e:a9:4c:c7 10.1.1.5"]
  tag                 : []
  tag_request         : []
  type                : ""
  up                  : true

  _uuid               : e8af12
  addresses           : ["fa:16:3e:99:7a:17 10.1.1.6"]
  dhcpv4_options      : 165974
  dhcpv6_options      : []
  dynamic_addresses   : []
  enabled             : true
  external_ids        : {"neutron:port_name"=bp}
  name                : "c29d41"
  options             : {}
  parent_name         : []
  port_security       : ["fa:16:3e:99:7a:17 10.1.1.6"]
  tag                 : []
  tag_request         : []
  type                : ""
  up                  : true

Now that the logical switch is less pathological, it's worth taking
another look at the SB DB logical flow table.  Try a command like
this::

  $ ovn-sbctl lflow-list n1 | abbrev | less -S

and then glance through the flows.  Packets that egress a VM into the
logical switch travel through the flow table's ingress pipeline
starting from table 0.  At each table, the switch finds the
highest-priority logical flow that matches and executes its actions,
or if there's no matching flow then the packet is dropped.  The
``ovn-sb``\(5) manpage gives all the details, but with a little
thought it's possible to guess a lot without reading the manpage.  For
example, consider the flows in ingress pipeline table 0, which are the
first flows encountered by a packet traversing the switch::

  table=0 (ls_in_port_sec_l2  ), priority=100  , match=(eth.src[40]), action=(drop;)
  table=0 (ls_in_port_sec_l2  ), priority=100  , match=(vlan.present), action=(drop;)
  table=0 (ls_in_port_sec_l2  ), priority=50   , match=(inport == "820c08" && eth.src == {fa:16:3e:a9:4c:c7}), action=(next;)
  table=0 (ls_in_port_sec_l2  ), priority=50   , match=(inport == "c29d41" && eth.src == {fa:16:3e:99:7a:17}), action=(next;)

The first two flows, with priority 100, immediately drop two kinds of
invalid packets: those with a multicast or broadcast Ethernet source
address (since multicast is only for packet destinations) and those
with a VLAN tag (because OVN doesn't yet support VLAN tags inside
logical networks).  The next two flows implement L2 port security:
they advance to the next table for packets with the correct Ethernet
source addresses for their ingress ports.  A packet that does not
match any flow is implicitly dropped, so there's no need for flows to
deal with mismatches.

The logical flow table includes many other flows, some of which we
will look at later.  For now, it's most worth looking at ingress table
13::

  table=13(ls_in_l2_lkup      ), priority=100  , match=(eth.mcast), action=(outport = "_MC_flood"; output;)
  table=13(ls_in_l2_lkup      ), priority=50   , match=(eth.dst == fa:16:3e:99:7a:17), action=(outport = "c29d41"; output;)
  table=13(ls_in_l2_lkup      ), priority=50   , match=(eth.dst == fa:16:3e:a9:4c:c7), action=(outport = "820c08"; output;)

The first flow in table 13 checks whether the packet is an Ethernet
multicast or broadcast and, if so, outputs it to a special port that
egresses to every logical port (other than the ingress port).
Otherwise the packet is output to the port corresponding to its
Ethernet destination address.  Packets addressed to any other Ethernet
destination are implicitly dropped.

(It's common for an OVN logical switch to know all the MAC addresses
supported by its logical ports, like this one.  That's why there's no
logic here for MAC learning or flooding packets to unknown MAC
addresses.  OVN does support unknown MAC handling but that's not in
play in our example.)

.. note::

  If you're interested in the details for the multicast group, you can
  run a command like the following and then look at the row for the
  correct datapath::

    $ ovn-sbctl find multicast_group name=_MC_flood | abbrev

Now if you want to look at the OpenFlow flows, you can actually see
them.  For example, here's the beginning of the output that lists the
first four logical flows, which we already looked at above, and their
corresponding OpenFlow flows.  If you want to know more about the
syntax, the ``ovs-fields``\(7) manpage explains OpenFlow matches and
``ovs-ofctl``\(8) explains OpenFlow actions::

  $ sudo ovn-sbctl --ovs lflow-list n1 | abbrev
  Datapath: "neutron-5b6baf" aka "n1" (a8a758)  Pipeline: ingress
    table=0 (ls_in_port_sec_l2  ), priority=100  , match=(eth.src[40]), action=(drop;)
      table=8 metadata=0x4,dl_src=01:00:00:00:00:00/01:00:00:00:00:00 actions=drop
    table=0 (ls_in_port_sec_l2  ), priority=100  , match=(vlan.present), action=(drop;)
      table=8 metadata=0x4,vlan_tci=0x1000/0x1000 actions=drop
    table=0 (ls_in_port_sec_l2  ), priority=50   , match=(inport == "820c08" && eth.src == {fa:16:3e:a9:4c:c7}), action=(next;)
      table=8 reg14=0x1,metadata=0x4,dl_src=fa:16:3e:a9:4c:c7 actions=resubmit(,9)
    table=0 (ls_in_port_sec_l2  ), priority=50   , match=(inport == "c29d41" && eth.src == {fa:16:3e:99:7a:17}), action=(next;)
      table=8 reg14=0x2,metadata=0x4,dl_src=fa:16:3e:99:7a:17 actions=resubmit(,9)
  ...

Logical Tracing
+++++++++++++++

Let's go a level deeper.  So far, everything we've done has been
fairly general.  We can also look at something more specific: the path
that a particular packet would take through OVN, logically, and Open
vSwitch, physically.

Let's use OVN's ovn-trace utility to see what happens to packets from
a logical point of view.  The ``ovn-trace``\(8) manpage has a lot of
detail on how to do that, but let's just start by building up from a
simple example.  You can start with a command that just specifies the
logical datapath, an input port, and nothing else; unspecified fields
default to all-zeros.  This doesn't do much::

  $ ovn-trace n1 'inport == "ap"'
  ...
  ingress(dp="n1", inport="ap")
  -----------------------------
   0. ls_in_port_sec_l2: no match (implicit drop)

We see that the packet was dropped in logical table 0,
"ls_in_port_sec_l2", the L2 port security stage (as we discussed
earlier).  That's because we didn't use the right Ethernet source
address for ``a``.  Let's see what happens if we do::

  $ ovn-trace n1 'inport == "ap" && eth.src == '$AP_MAC
  ...
  ingress(dp="n1", inport="ap")
  -----------------------------
   0. ls_in_port_sec_l2 (ovn-northd.c:3234): inport == "ap" && eth.src == {fa:16:3e:a9:4c:c7}, priority 50, uuid 6dcc418a
      next;
  13. ls_in_l2_lkup: no match (implicit drop)

Now the packet passes through L2 port security and skips through
several other tables until it gets dropped in the L2 lookup stage
(because the destination is unknown).  Let's add the Ethernet
destination for ``b``::

  $ ovn-trace n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == '$BP_MAC
  ...
  ingress(dp="n1", inport="ap")
  -----------------------------
   0. ls_in_port_sec_l2 (ovn-northd.c:3234): inport == "ap" && eth.src == {fa:16:3e:a9:4c:c7}, priority 50, uuid 6dcc418a
      next;
  13. ls_in_l2_lkup (ovn-northd.c:3529): eth.dst == fa:16:3e:99:7a:17, priority 50, uuid 57a4c46f
      outport = "bp";
      output;

  egress(dp="n1", inport="ap", outport="bp")
  ------------------------------------------
   8. ls_out_port_sec_l2 (ovn-northd.c:3654): outport == "bp" && eth.dst == {fa:16:3e:99:7a:17}, priority 50, uuid 8aa6426d
      output;
      /* output to "bp", type "" */

You can see that in this case the packet gets properly switched from
``a`` to ``b``.

Physical Tracing for Hypothetical Packets
+++++++++++++++++++++++++++++++++++++++++

ovn-trace showed us how a hypothetical packet would travel through the
system in a logical fashion, that is, without regard to how VMs are
distributed across the physical network.  This is a convenient
representation for understanding how OVN is **supposed** to work
abstractly, but sometimes we might want to know more about how it
actually works in the real systems where it is running.  For this, we
can use the tracing tool that Open vSwitch provides, which traces
a hypothetical packet through the OpenFlow tables.

We can actually get two levels of detail.  Let's start with the
version that's easier to interpret, by physically tracing a packet
that looks like the one we logically traced before.  One obstacle is
that we need to know the OpenFlow port number of the input port.  One
way to do that is to look for a port whose "attached-mac" is the one
we expect and print its ofport number::

  $ AP_PORT=$(ovs-vsctl --bare --columns=ofport find  interface external-ids:attached-mac=\"$AP_MAC\")
  $ echo $AP_PORT
  3

(You could also just do a plain ``ovs-vsctl list interface`` and then
look through for the right row and pick its ``ofport`` value.)

Now we can feed this input port number into ``ovs-appctl
ofproto/trace`` along with the correct Ethernet source and
destination addresses and get a physical trace::

  $ sudo ovs-appctl ofproto/trace br-int in_port=$AP_PORT,dl_src=$AP_MAC,dl_dst=$BP_MAC
  Flow: in_port=3,vlan_tci=0x0000,dl_src=fa:16:3e:a9:4c:c7,dl_dst=fa:16:3e:99:7a:17,dl_type=0x0000

  bridge("br-int")
  ----------------
   0. in_port=3, priority 100
      set_field:0x8->reg13
      set_field:0x9->reg11
      set_field:0xa->reg12
      set_field:0x4->metadata
      set_field:0x1->reg14
      resubmit(,8)
   8. reg14=0x1,metadata=0x4,dl_src=fa:16:3e:a9:4c:c7, priority 50, cookie 0x6dcc418a
      resubmit(,9)
   9. metadata=0x4, priority 0, cookie 0x8fe8689e
      resubmit(,10)
  10. metadata=0x4, priority 0, cookie 0x719549d1
      resubmit(,11)
  11. metadata=0x4, priority 0, cookie 0x39c99e6f
      resubmit(,12)
  12. metadata=0x4, priority 0, cookie 0x838152a3
      resubmit(,13)
  13. metadata=0x4, priority 0, cookie 0x918259e3
      resubmit(,14)
  14. metadata=0x4, priority 0, cookie 0xcad14db2
      resubmit(,15)
  15. metadata=0x4, priority 0, cookie 0x7834d912
      resubmit(,16)
  16. metadata=0x4, priority 0, cookie 0x87745210
      resubmit(,17)
  17. metadata=0x4, priority 0, cookie 0x34951929
      resubmit(,18)
  18. metadata=0x4, priority 0, cookie 0xd7a8c9fb
      resubmit(,19)
  19. metadata=0x4, priority 0, cookie 0xd02e9578
      resubmit(,20)
  20. metadata=0x4, priority 0, cookie 0x42d35507
      resubmit(,21)
  21. metadata=0x4,dl_dst=fa:16:3e:99:7a:17, priority 50, cookie 0x57a4c46f
      set_field:0x2->reg15
      resubmit(,32)
  32. priority 0
      resubmit(,33)
  33. reg15=0x2,metadata=0x4, priority 100
      set_field:0xb->reg13
      set_field:0x9->reg11
      set_field:0xa->reg12
      resubmit(,34)
  34. priority 0
      set_field:0->reg0
      set_field:0->reg1
      set_field:0->reg2
      set_field:0->reg3
      set_field:0->reg4
      set_field:0->reg5
      set_field:0->reg6
      set_field:0->reg7
      set_field:0->reg8
      set_field:0->reg9
      resubmit(,40)
  40. metadata=0x4, priority 0, cookie 0xde9f3899
      resubmit(,41)
  41. metadata=0x4, priority 0, cookie 0x74074eff
      resubmit(,42)
  42. metadata=0x4, priority 0, cookie 0x7789c8b1
      resubmit(,43)
  43. metadata=0x4, priority 0, cookie 0xa6b002c0
      resubmit(,44)
  44. metadata=0x4, priority 0, cookie 0xaeab2b45
      resubmit(,45)
  45. metadata=0x4, priority 0, cookie 0x290cc4d4
      resubmit(,46)
  46. metadata=0x4, priority 0, cookie 0xa3223b88
      resubmit(,47)
  47. metadata=0x4, priority 0, cookie 0x7ac2132e
      resubmit(,48)
  48. reg15=0x2,metadata=0x4,dl_dst=fa:16:3e:99:7a:17, priority 50, cookie 0x8aa6426d
      resubmit(,64)
  64. priority 0
      resubmit(,65)
  65. reg15=0x2,metadata=0x4, priority 100
      output:4

  Final flow: reg11=0x9,reg12=0xa,reg13=0xb,reg14=0x1,reg15=0x2,metadata=0x4,in_port=3,vlan_tci=0x0000,dl_src=fa:16:3e:a9:4c:c7,dl_dst=fa:16:3e:99:7a:17,dl_type=0x0000
  Megaflow: recirc_id=0,ct_state=-new-est-rel-rpl-inv-trk,ct_label=0/0x1,in_port=3,vlan_tci=0x0000/0x1000,dl_src=fa:16:3e:a9:4c:c7,dl_dst=fa:16:3e:99:7a:17,dl_type=0x0000
  Datapath actions: 4

There's a lot there, which you can read through if you like, but the
important part is::

  65. reg15=0x2,metadata=0x4, priority 100
      output:4

which means that the packet is ultimately being output to OpenFlow
port 4.  That's port ``b``, which you can confirm with::

  $ sudo ovs-vsctl find interface ofport=4
  _uuid               : 840a5aca-ea8d-4c16-a11b-a94e0f408091
  admin_state         : up
  bfd                 : {}
  bfd_status          : {}
  cfm_fault           : []
  cfm_fault_status    : []
  cfm_flap_count      : []
  cfm_health          : []
  cfm_mpid            : []
  cfm_remote_mpids    : []
  cfm_remote_opstate  : []
  duplex              : full
  error               : []
  external_ids        : {attached-mac="fa:16:3e:99:7a:17", iface-id="c29d4120-20a4-4c44-bd83-8d91f5f447fd", iface-status=active, vm-id="2db969ca-ca2a-4d9a-b49e-f287d39c5645"}
  ifindex             : 9
  ingress_policing_burst: 0
  ingress_policing_rate: 0
  lacp_current        : []
  link_resets         : 1
  link_speed          : 10000000
  link_state          : up
  lldp                : {}
  mac                 : []
  mac_in_use          : "fe:16:3e:99:7a:17"
  mtu                 : 1500
  mtu_request         : []
  name                : "tapc29d4120-20"
  ofport              : 4
  ofport_request      : []
  options             : {}
  other_config        : {}
  statistics          : {collisions=0, rx_bytes=4254, rx_crc_err=0, rx_dropped=0, rx_errors=0, rx_frame_err=0, rx_over_err=0, rx_packets=39, tx_bytes=4188, tx_dropped=0, tx_errors=0, tx_packets=39}
  status              : {driver_name=tun, driver_version="1.6", firmware_version=""}
  type                : ""

or::

  $ BP_PORT=$(ovs-vsctl --bare --columns=ofport find  interface external-ids:attached-mac=\"$BP_MAC\")
  $ echo $BP_PORT
  4

Physical Tracing for Real Packets
+++++++++++++++++++++++++++++++++

In the previous sections we traced a hypothetical L2 packet, one
that's honestly not very realistic: we didn't even supply an Ethernet
type, so it defaulted to zero, which isn't anything one would see on a
real network.  We could refine our packet so that it becomes a more
realistic TCP or UDP or ICMP, etc. packet, but let's try a different
approach: working from a real packet.

Pull up a console for VM ``a`` and start ``ping 10.1.1.6``, then leave
it running for the rest of our experiment.

Now go back to your DevStack session and run::

  $ sudo watch ovs-dpctl dump-flows

We're working with a new program.  ovn-dpctl is an interface to Open
vSwitch datapaths, in this case to the Linux kernel datapath.  Its
``dump-flows`` command displays the contents of the in-kernel flow
cache, and by running it under the ``watch`` program we see a new
snapshot of the flow table every 2 seconds.

Look through the output for a flow that begins with ``recirc_id(0)``
and matches the Ethernet source address for ``a``.  There is one flow
per line, but the lines are very long, so it's easier to read if you
make the window very wide.  This flow's packet counter should be
increasing at a rate of 1 packet per second.  It looks something like
this::

  recirc_id(0),in_port(3),eth(src=fa:16:3e:f5:2a:90),eth_type(0x0800),ipv4(src=10.1.1.5,frag=no), packets:388, bytes:38024, used:0.977s, actions:ct(zone=8),recirc(0x18)

We can hand the first part of this (everything up to the first space)
to ``ofproto/trace``, and it will tell us what happens::

  $ sudo ovs-appctl ofproto/trace 'recirc_id(0),in_port(3),eth(src=fa:16:3e:a9:4c:c7),eth_type(0x0800),ipv4(src=10.1.1.5,dst=10.1.0.0/255.255.0.0,frag=no)'
  Flow: ip,in_port=3,vlan_tci=0x0000,dl_src=fa:16:3e:a9:4c:c7,dl_dst=00:00:00:00:00:00,nw_src=10.1.1.5,nw_dst=10.1.0.0,nw_proto=0,nw_tos=0,nw_ecn=0,nw_ttl=0

  bridge("br-int")
  ----------------
   0. in_port=3, priority 100
      set_field:0x8->reg13
      set_field:0x9->reg11
      set_field:0xa->reg12
      set_field:0x4->metadata
      set_field:0x1->reg14
      resubmit(,8)
   8. reg14=0x1,metadata=0x4,dl_src=fa:16:3e:a9:4c:c7, priority 50, cookie 0x6dcc418a
      resubmit(,9)
   9. ip,reg14=0x1,metadata=0x4,dl_src=fa:16:3e:a9:4c:c7,nw_src=10.1.1.5, priority 90, cookie 0x343af48c
      resubmit(,10)
  10. metadata=0x4, priority 0, cookie 0x719549d1
      resubmit(,11)
  11. ip,metadata=0x4, priority 100, cookie 0x46c089e6
      load:0x1->NXM_NX_XXREG0[96]
      resubmit(,12)
  12. metadata=0x4, priority 0, cookie 0x838152a3
      resubmit(,13)
  13. ip,reg0=0x1/0x1,metadata=0x4, priority 100, cookie 0xd1941634
      ct(table=22,zone=NXM_NX_REG13[0..15])
      drop

  Final flow: ip,reg0=0x1,reg11=0x9,reg12=0xa,reg13=0x8,reg14=0x1,metadata=0x4,in_port=3,vlan_tci=0x0000,dl_src=fa:16:3e:a9:4c:c7,dl_dst=00:00:00:00:00:00,nw_src=10.1.1.5,nw_dst=10.1.0.0,nw_proto=0,nw_tos=0,nw_ecn=0,nw_ttl=0
  Megaflow: recirc_id=0,ip,in_port=3,vlan_tci=0x0000/0x1000,dl_src=fa:16:3e:a9:4c:c7,nw_src=10.1.1.5,nw_dst=10.1.0.0/16,nw_frag=no
  Datapath actions: ct(zone=8),recirc(0xb)

.. note::
   Be careful cutting and pasting ``ovs-dpctl dump-flows`` output into
   ``ofproto/trace`` because the latter has terrible error reporting.
   If you add an extra line break, etc., it will likely give you a
   useless error message.

There's no ``output`` action in the output, but there are ``ct`` and
``recirc`` actions (which you can see in the ``Datapath actions`` at
the end).  The ``ct`` action tells the kernel to pass the packet
through the kernel connection tracking for firewalling purposes and
the ``recirc`` says to go back to the flow cache for another pass
based on the firewall results.  The ``0xb`` value inside the
``recirc`` gives us a hint to look at the kernel flows for a cached
flow with ``recirc_id(0xb)``.  Indeed, there is one::

  recirc_id(0xb),in_port(3),ct_state(-new+est-rel-rpl-inv+trk),ct_label(0/0x1),eth(src=fa:16:3e:a9:4c:c7,dst=fa:16:3e:99:7a:17),eth_type(0x0800),ipv4(dst=10.1.1.4/255.255.255.252,frag=no), packets:171, bytes:16758, used:0.271s, actions:ct(zone=11),recirc(0xc)

We can then repeat our command with the match part of this kernel
flow::

  $ sudo ovs-appctl ofproto/trace 'recirc_id(0xb),in_port(3),ct_state(-new+est-rel-rpl-inv+trk),ct_label(0/0x1),eth(src=fa:16:3e:a9:4c:c7,dst=fa:16:3e:99:7a:17),eth_type(0x0800),ipv4(dst=10.1.1.4/255.255.255.252,frag=no)'
  ...
  Datapath actions: ct(zone=11),recirc(0xc)

In other words, the flow passes through the connection tracker a
second time.  The first time was for ``a``'s outgoing firewall; this
second time is for ``b``'s incoming firewall.  Again, we continue
tracing with ``recirc_id(0xc)``::

  $ sudo ovs-appctl ofproto/trace 'recirc_id(0xc),in_port(3),ct_state(-new+est-rel-rpl-inv+trk),ct_label(0/0x1),eth(src=fa:16:3e:a9:4c:c7,dst=fa:16:3e:99:7a:17),eth_type(0x0800),ipv4(dst=10.1.1.6,proto=1,frag=no)'
  ...
  Datapath actions: 4

It was took multiple hops, but we finally came to the end of the line
where the packet was output to ``b`` after passing through both
firewalls.  The port number here is a datapath port number, which is
usually different from an OpenFlow port number.  To check that it is
``b``'s port, we first list the datapath ports to get the name
corresponding to the port number::

  $ sudo ovs-dpctl show
  system@ovs-system:
          lookups: hit:1994 missed:56 lost:0
          flows: 6
          masks: hit:2340 total:4 hit/pkt:1.14
          port 0: ovs-system (internal)
          port 1: br-int (internal)
          port 2: br-ex (internal)
          port 3: tap820c0888-13
          port 4: tapc29d4120-20

and then confirm that this is the port we think it is with a command
like this::

  $ ovs-vsctl --columns=external-ids list interface tapc29d4120-20
  external_ids        : {attached-mac="fa:16:3e:99:7a:17", iface-id="c29d4120-20a4-4c44-bd83-8d91f5f447fd", iface-status=active, vm-id="2db969ca-ca2a-4d9a-b49e-f287d39c5645"}

Finally, we can relate the OpenFlow flows from our traces back to OVN
logical flows.  For individual flows, cut and paste a "cookie" value
from ``ofproto/trace`` output into ``ovn-sbctl lflow-list``, e.g.::

  $ ovn-sbctl lflow-list 0x6dcc418a|abbrev
  Datapath: "neutron-5b6baf" aka "n1" (a8a758)  Pipeline: ingress
    table=0 (ls_in_port_sec_l2  ), priority=50   , match=(inport == "820c08" && eth.src == {fa:16:3e:a9:4c:c7}), action=(next;)

Or, you can pipe ``ofproto/trace`` output through ``ovn-detrace`` to
annotate every flow::

  $ sudo ovs-appctl ofproto/trace 'recirc_id(0xc),in_port(3),ct_state(-new+est-rel-rpl-inv+trk),ct_label(0/0x1),eth(src=fa:16:3e:a9:4c:c7,dst=fa:16:3e:99:7a:17),eth_type(0x0800),ipv4(dst=10.1.1.6,proto=1,frag=no)' | ovn-detrace
  ...

Routing
-------

Previously we set up a pair of VMs ``a`` and ``b`` on a network ``n1``
and demonstrated how packets make their way between them.  In this
step, we'll set up a second network ``n2`` with a new VM ``c``,
connect a router ``r`` to both networks, and demonstrate how routing
works in OVN.

There's nothing really new for the network and the VM so let's just go
ahead and create them::

  $ openstack network create --project admin --provider-network-type geneve n2
  $ openstack subnet create --subnet-range 10.1.2.0/24 --network n2 n2subnet
  $ openstack server create --nic net-id=n2,v4-fixed-ip=10.1.2.7 --flavor m1.nano --image $IMAGE_ID --key-name demo c
  $ openstack port set --name cp $(openstack port list --server c -f value -c ID)
  $ CP_MAC=$(openstack port show -f value -c mac_address cp)

The new network ``n2`` is not yet connected to ``n1`` in any way.  You
can try tracing a broadcast packet from ``a`` to see, for example,
that it doesn't make it to ``c``::

  $ ovn-trace n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == '$CP_MAC
  ...

Now create an OpenStack router and connect it to ``n1`` and ``n2``::

  $ openstack router create r
  $ openstack router add subnet r n1subnet
  $ openstack router add subnet r n2subnet

Now ``a``, ``b``, and ``c`` should all be able to reach other.  You
can get some verification that routing is taking place by running you
``ping`` between ``c`` and one of the other VMs: the reported TTL
should be one less than between ``a`` and ``b`` (63 instead of 64).

Observe via ``ovn-nbctl`` the new OVN logical switch and router and
then ports that connect them together::

  $ ovn-nbctl show|abbrev
  ...
  switch f51234 (neutron-332346) (aka n2)
      port 82b983
          type: router
          router-port: lrp-82b983
      port 2e585f (aka cp)
          addresses: ["fa:16:3e:89:f2:36 10.1.2.7"]
  switch 3eb263 (neutron-5b6baf) (aka n1)
      port c29d41 (aka bp)
          addresses: ["fa:16:3e:99:7a:17 10.1.1.6"]
      port 820c08 (aka ap)
          addresses: ["fa:16:3e:a9:4c:c7 10.1.1.5"]
      port 17d870
          type: router
          router-port: lrp-17d870
  ...
  router dde06c (neutron-f88ebc) (aka r)
      port lrp-82b983
          mac: "fa:16:3e:19:9f:46"
          networks: ["10.1.2.1/24"]
      port lrp-17d870
          mac: "fa:16:3e:f6:e2:8f"
          networks: ["10.1.1.1/24"]

We have not yet looked at the logical flows for an OVN logical router.
You might find it of interest to look at them on your own::

  $ ovn-sbctl lflow-list r | abbrev | less -S
  ...

Let's grab the ``n1subnet`` router porter MAC address to simplify
later commands::

  $ N1SUBNET_MAC=$(ovn-nbctl --bare --columns=mac find logical_router_port networks=10.1.1.1/24)

Let's see what happens at the logical flow level for an ICMP packet
from ``a`` to ``c``.  This generates a long trace but an interesting
one, so we'll look at it bit by bit.  The first three stanzas in the
output show the packet's ingress into ``n1`` and processing through
the firewall on that side (via the "ct_next" connection-tracking
action), and then the selection of the port that leads to router ``r``
as the output port::

  $ ovn-trace n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == '$N1SUBNET_MAC' && ip4.src == 10.1.1.5 && ip4.dst == 10.1.2.7 && ip.ttl == 64 && icmp4.type == 8'
  ...
  ingress(dp="n1", inport="ap")
  -----------------------------
   0. ls_in_port_sec_l2 (ovn-northd.c:3234): inport == "ap" && eth.src == {fa:16:3e:a9:4c:c7}, priority 50, uuid 6dcc418a
      next;
   1. ls_in_port_sec_ip (ovn-northd.c:2364): inport == "ap" && eth.src == fa:16:3e:a9:4c:c7 && ip4.src == {10.1.1.5}, priority 90, uuid 343af48c
      next;
   3. ls_in_pre_acl (ovn-northd.c:2646): ip, priority 100, uuid 46c089e6
      reg0[0] = 1;
      next;
   5. ls_in_pre_stateful (ovn-northd.c:2764): reg0[0] == 1, priority 100, uuid d1941634
      ct_next;

  ct_next(ct_state=est|trk /* default (use --ct to customize) */)
  ---------------------------------------------------------------
   6. ls_in_acl (ovn-northd.c:2925): !ct.new && ct.est && !ct.rpl && ct_label.blocked == 0 && (inport == "ap" && ip4), priority 2002, uuid a12b39f0
      next;
  13. ls_in_l2_lkup (ovn-northd.c:3529): eth.dst == fa:16:3e:f6:e2:8f, priority 50, uuid c43ead31
      outport = "17d870";
      output;

  egress(dp="n1", inport="ap", outport="17d870")
  ----------------------------------------------
   1. ls_out_pre_acl (ovn-northd.c:2626): ip && outport == "17d870", priority 110, uuid 60395450
      next;
   8. ls_out_port_sec_l2 (ovn-northd.c:3654): outport == "17d870", priority 50, uuid 91b5cab0
      output;
      /* output to "17d870", type "patch" */

The next two stanzas represent processing through logical router
``r``.  The processing in table 5 is the core of the routing
implementation: it recognizes that the packet is destined for an
attached subnet, decrements the TTL and updates the Ethernet source
address.  Table 6 then selects the Ethernet destination address based
on the IP destination.  The packet then passes to switch ``n2`` via an
OVN "logical patch port"::

  ingress(dp="r", inport="lrp-17d870")
  ------------------------------------
   0. lr_in_admission (ovn-northd.c:4071): eth.dst == fa:16:3e:f6:e2:8f && inport == "lrp-17d870", priority 50, uuid fa5270b0
      next;
   5. lr_in_ip_routing (ovn-northd.c:3782): ip4.dst == 10.1.2.0/24, priority 49, uuid 5f9d469f
      ip.ttl--;
      reg0 = ip4.dst;
      reg1 = 10.1.2.1;
      eth.src = fa:16:3e:19:9f:46;
      outport = "lrp-82b983";
      flags.loopback = 1;
      next;
   6. lr_in_arp_resolve (ovn-northd.c:5088): outport == "lrp-82b983" && reg0 == 10.1.2.7, priority 100, uuid 03d506d3
      eth.dst = fa:16:3e:89:f2:36;
      next;
   8. lr_in_arp_request (ovn-northd.c:5260): 1, priority 0, uuid 6dacdd82
      output;

  egress(dp="r", inport="lrp-17d870", outport="lrp-82b983")
  ---------------------------------------------------------
   3. lr_out_delivery (ovn-northd.c:5288): outport == "lrp-82b983", priority 100, uuid 00bea4f2
      output;
      /* output to "lrp-82b983", type "patch" */

Finally the logical switch for ``n2`` runs through the same logic as
``n1`` and the packet is delivered to VM ``c``::

  ingress(dp="n2", inport="82b983")
  ---------------------------------
   0. ls_in_port_sec_l2 (ovn-northd.c:3234): inport == "82b983", priority 50, uuid 9a789e06
      next;
   3. ls_in_pre_acl (ovn-northd.c:2624): ip && inport == "82b983", priority 110, uuid ab52f21a
      next;
  13. ls_in_l2_lkup (ovn-northd.c:3529): eth.dst == fa:16:3e:89:f2:36, priority 50, uuid dcafb3e9
      outport = "cp";
      output;

  egress(dp="n2", inport="82b983", outport="cp")
  ----------------------------------------------
   1. ls_out_pre_acl (ovn-northd.c:2648): ip, priority 100, uuid cd9cfa74
      reg0[0] = 1;
      next;
   2. ls_out_pre_stateful (ovn-northd.c:2766): reg0[0] == 1, priority 100, uuid 9e8e22c5
      ct_next;

  ct_next(ct_state=est|trk /* default (use --ct to customize) */)
  ---------------------------------------------------------------
   4. ls_out_acl (ovn-northd.c:2925): !ct.new && ct.est && !ct.rpl && ct_label.blocked == 0 && (outport == "cp" && ip4 && ip4.src == $as_ip4_0fc1b6cf_f925_49e6_8f00_6dd13beca9dc), priority 2002, uuid a746fa0d
      next;
   7. ls_out_port_sec_ip (ovn-northd.c:2364): outport == "cp" && eth.dst == fa:16:3e:89:f2:36 && ip4.dst == {255.255.255.255, 224.0.0.0/4, 10.1.2.7}, priority 90, uuid 4d9862b5
      next;
   8. ls_out_port_sec_l2 (ovn-northd.c:3654): outport == "cp" && eth.dst == {fa:16:3e:89:f2:36}, priority 50, uuid 0242cdc3
      output;
      /* output to "cp", type "" */

Physical Tracing
~~~~~~~~~~~~~~~~

It's possible to use ``ofproto/trace``, just as before, to trace a
packet through OpenFlow tables, either for a hypothetical packet or
one that you get from a real test case using ``ovs-dpctl``.  The
process is just the same as before and the output is almost the same,
too.  Using a router doesn't actually introduce any interesting new
wrinkles, so we'll skip over this for this case and for the remainder
of the tutorial, but you can follow the steps on your own if you like.

Adding a Gateway
----------------

The VMs that we've created can access each other but they are isolated
from the physical world.  In OpenStack, the dominant way to connect a
VM to external networks is by creating what is called a "floating IP
address", which uses network address translation to connect an
external address to an internal one.

DevStack created a pair of networks named "private" and "public".  To
use a floating IP address from a VM, we first add a port to the VM
with an IP address from the "private" network, then we create a
floating IP address on the "public" network, then we associate the
port with the floating IP address.

Let's add a new VM ``d`` with a floating IP::

  $ openstack server create --nic net-id=private --flavor m1.nano --image $IMAGE_ID --key-name demo d
  $ openstack port set --name dp $(openstack port list --server d -f value -c ID)
  $ DP_MAC=$(openstack port show -f value -c mac_address dp)
  $ openstack floating ip create --floating-ip-address 172.24.4.8 public
  $ openstack server add floating ip d 172.24.4.8

(We specified a particular floating IP address to make the examples
easier to follow, but without that OpenStack will automatically
allocate one.)

It's also necessary to configure the "public" network because DevStack
does not do it automatically::

  $ sudo ip link set br-ex up
  $ sudo ip route add 172.24.4.0/24 dev br-ex
  $ sudo ip addr add 172.24.4.1/24 dev br-ex

Now you should be able to "ping" VM ``d`` from the OpenStack host::

  $ ping 172.24.4.8
  PING 172.24.4.8 (172.24.4.8) 56(84) bytes of data.
  64 bytes from 172.24.4.8: icmp_seq=1 ttl=63 time=56.0 ms
  64 bytes from 172.24.4.8: icmp_seq=2 ttl=63 time=1.44 ms
  64 bytes from 172.24.4.8: icmp_seq=3 ttl=63 time=1.04 ms
  64 bytes from 172.24.4.8: icmp_seq=4 ttl=63 time=0.403 ms
  ^C
  --- 172.24.4.8 ping statistics ---
  4 packets transmitted, 4 received, 0% packet loss, time 3003ms
  rtt min/avg/max/mdev = 0.403/14.731/56.028/23.845 ms

You can also SSH in with the key that we created during setup::

  $ ssh -i ~/id_rsa_demo cirros@172.24.4.8

Let's dive in and see how this gets implemented in OVN.  First, the
relevant parts of the NB DB for the "public" and "private" networks
and the router between them::

  $ ovn-nbctl show | abbrev
  switch 2579f4 (neutron-d1ac28) (aka public)
      port provnet-d1ac28
          type: localnet
          addresses: ["unknown"]
      port ae9b52
          type: router
          router-port: lrp-ae9b52
  switch 5b3d5f (neutron-c02c4d) (aka private)
      port b256dd
          type: router
          router-port: lrp-b256dd
      port f264e7
          type: router
          router-port: lrp-f264e7
      port cae25b (aka dp)
          addresses: ["fa:16:3e:c1:f5:a2 10.0.0.6 fdb0:5860:4ba8:0:f816:3eff:fec1:f5a2"]
  ...
  router c59ad2 (neutron-9b057f) (aka router1)
      port lrp-ae9b52
          mac: "fa:16:3e:b2:d2:67"
          networks: ["172.24.4.9/24", "2001:db8::b/64"]
      port lrp-b256dd
          mac: "fa:16:3e:35:33:db"
          networks: ["fdb0:5860:4ba8::1/64"]
      port lrp-f264e7
          mac: "fa:16:3e:fc:c8:da"
          networks: ["10.0.0.1/26"]
      nat 788c6d
          external ip: "172.24.4.8"
          logical ip: "10.0.0.6"
          type: "dnat_and_snat"
      nat 80914c
          external ip: "172.24.4.9"
          logical ip: "10.0.0.0/26"
          type: "snat"
  ...

What we see is:

* VM ``d`` is on the "private" switch under its private IP address
  10.0.0.8.  The "private" switch is connected to "router1" via two
  router ports (one for IPv4, one for IPv6).

* The "public" switch is connected to "router1" and to the physical
  network via a "localnet" port.

* "router1" is in the middle between "private" and "public".  In
  addition to the router ports that connect to these switches, it has
  "nat" entries that direct network address translation.  The
  translation between floating IP address 172.24.4.8 and private
  address 10.0.0.8 makes perfect sense.

When the NB DB gets translated into logical flows at the southbound
layer, the "nat" entries get translated into IP matches that then
invoke "ct_snat" and "ct_dnat" actions.  The details are intricate,
but you can get some of the idea by just looking for relevant flows::

  $ ovn-sbctl lflow-list router1 | abbrev | grep nat | grep -E '172.24.4.8|10.0.0.8'
    table=3 (lr_in_unsnat       ), priority=100  , match=(ip && ip4.dst == 172.24.4.8 && inport == "lrp-ae9b52" && is_chassis_resident("cr-lrp-ae9b52")), action=(ct_snat;)
    table=3 (lr_in_unsnat       ), priority=50   , match=(ip && ip4.dst == 172.24.4.8), action=(reg9[0] = 1; next;)
    table=4 (lr_in_dnat         ), priority=100  , match=(ip && ip4.dst == 172.24.4.8 && inport == "lrp-ae9b52" && is_chassis_resident("cr-lrp-ae9b52")), action=(ct_dnat(10.0.0.6);)
    table=4 (lr_in_dnat         ), priority=50   , match=(ip && ip4.dst == 172.24.4.8), action=(reg9[0] = 1; next;)
    table=1 (lr_out_snat        ), priority=33   , match=(ip && ip4.src == 10.0.0.6 && outport == "lrp-ae9b52" && is_chassis_resident("cr-lrp-ae9b52")), action=(ct_snat(172.24.4.8);)

Let's take a look at how a packet passes through this whole gauntlet.
The first two stanzas just show the packet traveling through the
"public" network and being forwarded to the "router1" network::

  $ ovn-trace public 'inport == "provnet-d1ac2896-18a7-4bca-8f46-b21e2370e5b1" && eth.src == 00:01:02:03:04:05 && eth.dst == fa:16:3e:b2:d2:67 && ip4.src == 172.24.4.1 && ip4.dst == 172.24.4.8 && ip.ttl == 64 && icmp4.type==8'
  ...
  ingress(dp="public", inport="provnet-d1ac28")
  ---------------------------------------------
   0. ls_in_port_sec_l2 (ovn-northd.c:3234): inport == "provnet-d1ac28", priority 50, uuid 8d86fb06
      next;
  10. ls_in_arp_rsp (ovn-northd.c:3266): inport == "provnet-d1ac28", priority 100, uuid 21313eff
      next;
  13. ls_in_l2_lkup (ovn-northd.c:3571): eth.dst == fa:16:3e:b2:d2:67 && is_chassis_resident("cr-lrp-ae9b52"), priority 50, uuid 7f28f51f
      outport = "ae9b52";
      output;

  egress(dp="public", inport="provnet-d1ac28", outport="ae9b52")
  --------------------------------------------------------------
   8. ls_out_port_sec_l2 (ovn-northd.c:3654): outport == "ae9b52", priority 50, uuid 72fea396
      output;
      /* output to "ae9b52", type "patch" */

In "router1", first the ``ct_snat`` action without an argument
attempts to "un-SNAT" the packet.  ovn-trace treats this as a no-op,
because it doesn't have any state for tracking connections.  As an
alternative, it invokes ``ct_dnat(10.0.0.8)`` to NAT the destination
IP::

  ingress(dp="router1", inport="lrp-ae9b52")
  ------------------------------------------
   0. lr_in_admission (ovn-northd.c:4071): eth.dst == fa:16:3e:b2:d2:67 && inport == "lrp-ae9b52" && is_chassis_resident("cr-lrp-ae9b52"), priority 50, uuid 8c6945c2
      next;
   3. lr_in_unsnat (ovn-northd.c:4591): ip && ip4.dst == 172.24.4.8 && inport == "lrp-ae9b52" && is_chassis_resident("cr-lrp-ae9b52"), priority 100, uuid e922f541
      ct_snat;

  ct_snat /* assuming no un-snat entry, so no change */
  -----------------------------------------------------
   4. lr_in_dnat (ovn-northd.c:4649): ip && ip4.dst == 172.24.4.8 && inport == "lrp-ae9b52" && is_chassis_resident("cr-lrp-ae9b52"), priority 100, uuid 02f41b79
      ct_dnat(10.0.0.6);

Still in "router1", the routing and output steps transmit the packet
to the "private" network::

  ct_dnat(ip4.dst=10.0.0.6)
  -------------------------
   5. lr_in_ip_routing (ovn-northd.c:3782): ip4.dst == 10.0.0.0/26, priority 53, uuid 86e005b0
      ip.ttl--;
      reg0 = ip4.dst;
      reg1 = 10.0.0.1;
      eth.src = fa:16:3e:fc:c8:da;
      outport = "lrp-f264e7";
      flags.loopback = 1;
      next;
   6. lr_in_arp_resolve (ovn-northd.c:5088): outport == "lrp-f264e7" && reg0 == 10.0.0.6, priority 100, uuid 2963d67c
      eth.dst = fa:16:3e:c1:f5:a2;
      next;
   8. lr_in_arp_request (ovn-northd.c:5260): 1, priority 0, uuid eea419b7
      output;

  egress(dp="router1", inport="lrp-ae9b52", outport="lrp-f264e7")
  ---------------------------------------------------------------
   3. lr_out_delivery (ovn-northd.c:5288): outport == "lrp-f264e7", priority 100, uuid 42dadc23
      output;
      /* output to "lrp-f264e7", type "patch" */

In the "private" network, the packet passes through VM ``d``'s
firewall and is output to ``d``::

  ingress(dp="private", inport="f264e7")
  --------------------------------------
   0. ls_in_port_sec_l2 (ovn-northd.c:3234): inport == "f264e7", priority 50, uuid 5b721214
      next;
   3. ls_in_pre_acl (ovn-northd.c:2624): ip && inport == "f264e7", priority 110, uuid 5bdc3209
      next;
  13. ls_in_l2_lkup (ovn-northd.c:3529): eth.dst == fa:16:3e:c1:f5:a2, priority 50, uuid 7957f80f
      outport = "dp";
      output;

  egress(dp="private", inport="f264e7", outport="dp")
  ---------------------------------------------------
   1. ls_out_pre_acl (ovn-northd.c:2648): ip, priority 100, uuid 4981c79d
      reg0[0] = 1;
      next;
   2. ls_out_pre_stateful (ovn-northd.c:2766): reg0[0] == 1, priority 100, uuid 247e02eb
      ct_next;

  ct_next(ct_state=est|trk /* default (use --ct to customize) */)
  ---------------------------------------------------------------
   4. ls_out_acl (ovn-northd.c:2925): !ct.new && ct.est && !ct.rpl && ct_label.blocked == 0 && (outport == "dp" && ip4 && ip4.src == 0.0.0.0/0 && icmp4), priority 2002, uuid b860fc9f
      next;
   7. ls_out_port_sec_ip (ovn-northd.c:2364): outport == "dp" && eth.dst == fa:16:3e:c1:f5:a2 && ip4.dst == {255.255.255.255, 224.0.0.0/4, 10.0.0.6}, priority 90, uuid 15655a98
      next;
   8. ls_out_port_sec_l2 (ovn-northd.c:3654): outport == "dp" && eth.dst == {fa:16:3e:c1:f5:a2}, priority 50, uuid 5916f94b
      output;
      /* output to "dp", type "" */

IPv6
----

OVN supports IPv6 logical routing.  Let's try it out.

The first step is to add an IPv6 subnet to networks ``n1`` and ``n2``,
then attach those subnets to our router ``r``.  As usual, though
OpenStack can assign addresses itself, we use fixed ones to make the
discussion easier::

  $ openstack subnet create --ip-version 6 --subnet-range fc11::/64 --network n1 n1subnet6
  $ openstack subnet create --ip-version 6 --subnet-range fc22::/64 --network n2 n2subnet6
  $ openstack router add subnet r n1subnet6
  $ openstack router add subnet r n2subnet6

Then we add an IPv6 address to each of our VMs::

  $ A_PORT_ID=$(openstack port list --server a -f value -c ID)
  $ openstack port set --fixed-ip subnet=n1subnet6,ip-address=fc11::5 $A_PORT_ID
  $ B_PORT_ID=$(openstack port list --server b -f value -c ID)
  $ openstack port set --fixed-ip subnet=n1subnet6,ip-address=fc11::6 $B_PORT_ID
  $ C_PORT_ID=$(openstack port list --server c -f value -c ID)
  $ openstack port set --fixed-ip subnet=n2subnet6,ip-address=fc22::7 $C_PORT_ID

At least for me, the new IPv6 addresses didn't automatically get
propagated into the VMs.  To do it by hand, pull up the console for
``a`` and run::

  $ sudo ip addr add fc11::5/64 dev eth0
  $ sudo ip route add via fc11::1

Then in ``b``::

  $ sudo ip addr add fc11::6/64 dev eth0
  $ sudo ip route add via fc11::1

Finally in ``c``::

  $ sudo ip addr add fc22::7/64 dev eth0
  $ sudo ip route add via fc22::1

Now you should have working IPv6 routing through router ``r``.  The
relevant parts of the NB DB look like the following.  The interesting
parts are the new ``fc11::`` and ``fc22::`` addresses on the ports in
``n1`` and ``n2`` and the new IPv6 router ports in ``r``::

  $ ovn-nbctl show | abbrev
  ...
  switch f51234 (neutron-332346) (aka n2)
      port 1a8162
          type: router
          router-port: lrp-1a8162
      port 82b983
          type: router
          router-port: lrp-82b983
      port 2e585f (aka cp)
          addresses: ["fa:16:3e:89:f2:36 10.1.2.7 fc22::7"]
  switch 3eb263 (neutron-5b6baf) (aka n1)
      port ad952e
          type: router
          router-port: lrp-ad952e
      port c29d41 (aka bp)
          addresses: ["fa:16:3e:99:7a:17 10.1.1.6 fc11::6"]
      port 820c08 (aka ap)
          addresses: ["fa:16:3e:a9:4c:c7 10.1.1.5 fc11::5"]
      port 17d870
          type: router
          router-port: lrp-17d870
  ...
  router dde06c (neutron-f88ebc) (aka r)
      port lrp-1a8162
          mac: "fa:16:3e:06:de:ad"
          networks: ["fc22::1/64"]
      port lrp-82b983
          mac: "fa:16:3e:19:9f:46"
          networks: ["10.1.2.1/24"]
      port lrp-ad952e
          mac: "fa:16:3e:ef:2f:8b"
          networks: ["fc11::1/64"]
      port lrp-17d870
          mac: "fa:16:3e:f6:e2:8f"
          networks: ["10.1.1.1/24"]

Try tracing a packet from ``a`` to ``c``.  The results correspond
closely to those for IPv4 which we already discussed back under
`Routing`_::

  $ N1SUBNET6_MAC=$(ovn-nbctl --bare --columns=mac find logical_router_port networks=\"fc11::1/64\")
  $ ovn-trace n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == '$N1SUBNET6_MAC' && ip6.src == fc11::5 && ip6.dst == fc22::7 && ip.ttl == 64 && icmp6.type == 8'
  ...
  ingress(dp="n1", inport="ap")
  -----------------------------
   0. ls_in_port_sec_l2 (ovn-northd.c:3234): inport == "ap" && eth.src == {fa:16:3e:a9:4c:c7}, priority 50, uuid 6dcc418a
      next;
   1. ls_in_port_sec_ip (ovn-northd.c:2390): inport == "ap" && eth.src == fa:16:3e:a9:4c:c7 && ip6.src == {fe80::f816:3eff:fea9:4cc7, fc11::5}, priority 90, uuid 604810ea
      next;
   3. ls_in_pre_acl (ovn-northd.c:2646): ip, priority 100, uuid 46c089e6
      reg0[0] = 1;
      next;
   5. ls_in_pre_stateful (ovn-northd.c:2764): reg0[0] == 1, priority 100, uuid d1941634
      ct_next;

  ct_next(ct_state=est|trk /* default (use --ct to customize) */)
  ---------------------------------------------------------------
   6. ls_in_acl (ovn-northd.c:2925): !ct.new && ct.est && !ct.rpl && ct_label.blocked == 0 && (inport == "ap" && ip6), priority 2002, uuid 7fdd607e
      next;
  13. ls_in_l2_lkup (ovn-northd.c:3529): eth.dst == fa:16:3e:ef:2f:8b, priority 50, uuid e1d87fc5
      outport = "ad952e";
      output;

  egress(dp="n1", inport="ap", outport="ad952e")
  ----------------------------------------------
   1. ls_out_pre_acl (ovn-northd.c:2626): ip && outport == "ad952e", priority 110, uuid 88f68988
      next;
   8. ls_out_port_sec_l2 (ovn-northd.c:3654): outport == "ad952e", priority 50, uuid 5935755e
      output;
      /* output to "ad952e", type "patch" */

  ingress(dp="r", inport="lrp-ad952e")
  ------------------------------------
   0. lr_in_admission (ovn-northd.c:4071): eth.dst == fa:16:3e:ef:2f:8b && inport == "lrp-ad952e", priority 50, uuid ddfeb712
      next;
   5. lr_in_ip_routing (ovn-northd.c:3782): ip6.dst == fc22::/64, priority 129, uuid cc2130ec
      ip.ttl--;
      xxreg0 = ip6.dst;
      xxreg1 = fc22::1;
      eth.src = fa:16:3e:06:de:ad;
      outport = "lrp-1a8162";
      flags.loopback = 1;
      next;
   6. lr_in_arp_resolve (ovn-northd.c:5122): outport == "lrp-1a8162" && xxreg0 == fc22::7, priority 100, uuid bcf75288
      eth.dst = fa:16:3e:89:f2:36;
      next;
   8. lr_in_arp_request (ovn-northd.c:5260): 1, priority 0, uuid 6dacdd82
      output;

  egress(dp="r", inport="lrp-ad952e", outport="lrp-1a8162")
  ---------------------------------------------------------
   3. lr_out_delivery (ovn-northd.c:5288): outport == "lrp-1a8162", priority 100, uuid 5260dfc5
      output;
      /* output to "lrp-1a8162", type "patch" */

  ingress(dp="n2", inport="1a8162")
  ---------------------------------
   0. ls_in_port_sec_l2 (ovn-northd.c:3234): inport == "1a8162", priority 50, uuid 10957d1b
      next;
   3. ls_in_pre_acl (ovn-northd.c:2624): ip && inport == "1a8162", priority 110, uuid a27ebd00
      next;
  13. ls_in_l2_lkup (ovn-northd.c:3529): eth.dst == fa:16:3e:89:f2:36, priority 50, uuid dcafb3e9
      outport = "cp";
      output;

  egress(dp="n2", inport="1a8162", outport="cp")
  ----------------------------------------------
   1. ls_out_pre_acl (ovn-northd.c:2648): ip, priority 100, uuid cd9cfa74
      reg0[0] = 1;
      next;
   2. ls_out_pre_stateful (ovn-northd.c:2766): reg0[0] == 1, priority 100, uuid 9e8e22c5
      ct_next;

  ct_next(ct_state=est|trk /* default (use --ct to customize) */)
  ---------------------------------------------------------------
   4. ls_out_acl (ovn-northd.c:2925): !ct.new && ct.est && !ct.rpl && ct_label.blocked == 0 && (outport == "cp" && ip6 && ip6.src == $as_ip6_0fc1b6cf_f925_49e6_8f00_6dd13beca9dc), priority 2002, uuid 12fc96f9
      next;
   7. ls_out_port_sec_ip (ovn-northd.c:2390): outport == "cp" && eth.dst == fa:16:3e:89:f2:36 && ip6.dst == {fe80::f816:3eff:fe89:f236, ff00::/8, fc22::7}, priority 90, uuid c622596a
      next;
   8. ls_out_port_sec_l2 (ovn-northd.c:3654): outport == "cp" && eth.dst == {fa:16:3e:89:f2:36}, priority 50, uuid 0242cdc3
      output;
      /* output to "cp", type "" */

ACLs
----

Let's explore how ACLs work in OpenStack and OVN.  In OpenStack, ACL
rules are part of "security groups", which are "default deny", that
is, packets are not allowed by default and the rules added to security
groups serve to allow different classes of packets.  The default group
(named "default") that is assigned to each of our VMs so far allows
all traffic from our other VMs, which isn't very interesting for
testing.  So, let's create a new security group, which we'll name
"custom", add rules to it that allow incoming SSH and ICMP traffic,
and apply this security group to VM ``c``::

  $ openstack security group create custom
  $ openstack security group rule create --dst-port 22 custom
  $ openstack security group rule create --protocol icmp custom
  $ openstack server remove security group c default
  $ openstack server add security group c custom

Now we can do some experiments to test security groups.  From the
console on ``a`` or ``b``, it should now be possible to "ping" ``c``
or to SSH to it, but attempts to initiate connections on other ports
should be blocked.  (You can try to connect on another port with
``ssh -p PORT IP`` or ``nc PORT IP``.)  Connection attempts should
time out rather than receive the "connection refused" or "connection
reset" error that you would see between ``a`` and ``b``.

It's also possible to test ACLs via ovn-trace, with one new wrinkle.
ovn-trace can't simulate connection tracking state in the network, so
by default it assumes that every packet represents an established
connection.  That's good enough for what we've been doing so far, but
for checking properties of security groups we want to look at more
detail.

If you look back at the VM-to-VM traces we've done until now, you can
see that they execute two ``ct_next`` actions:

* The first of these is for the packet passing outward through the
  source VM's firewall.  We can tell ovn-trace to treat the packet as
  starting a new connection or adding to an established connection by
  adding a ``--ct`` option: ``--ct new`` or ``--ct est``,
  respectively.  The latter is the default and therefore what we've
  been using so far.  We can also use ``--ct est,rpl``, which in
  addition to ``--ct est`` means that the connection was initiated by
  the destination VM rather than by the VM sending this packet.

* The second is for the packet passing inward through the destination
  VM's firewall.  For this one, it makes sense to tell ovn-trace that
  the packet is starting a new connection, with ``--ct new``, or that
  it is a packet sent in reply to a connection established by the
  destination VM, with ``--ct est,rpl``.

ovn-trace uses the ``--ct`` options in order, so if we want to
override the second ``ct_next`` behavior we have to specify two
options.

Another useful ovn-trace option for this testing is ``--minimal``,
which reduces the amount of output.  In this case we're really just
interested in finding out whether the packet reaches the destination
VM, that is, whether there's an eventual ``output`` action to ``c``,
so ``--minimal`` works fine and the output is easier to read.

Try a few traces.  For example:

* VM ``a`` initiates a new SSH connection to ``c``::

    $ ovn-trace --ct new --ct new --minimal n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == '$N1SUBNET6_MAC' && ip4.src == 10.1.1.5 && ip4.dst == 10.1.2.7 && ip.ttl == 64 && tcp.dst == 22'
    ...
    ct_next(ct_state=new|trk) {
        ip.ttl--;
        eth.src = fa:16:3e:19:9f:46;
        eth.dst = fa:16:3e:89:f2:36;
        ct_next(ct_state=new|trk) {
            output("cp");
        };
    };

  This succeeds, as you can see since there is an ``output`` action.

* VM ``a`` initiates a new Telnet connection to ``c``::

    $ ovn-trace --ct new --ct new --minimal n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == '$N1SUBNET6_MAC' && ip4.src == 10.1.1.5 && ip4.dst == 10.1.2.7 && ip.ttl == 64 && tcp.dst == 23'
    ct_next(ct_state=new|trk) {
        ip.ttl--;
        eth.src = fa:16:3e:19:9f:46;
        eth.dst = fa:16:3e:89:f2:36;
        ct_next(ct_state=new|trk);
    };

  This fails, as you can see from the lack of an ``output`` action.

* VM ``a`` replies to a packet that is part of a Telnet connection
  originally initiated by ``c``::

    $ ovn-trace --ct est,rpl --ct est,rpl --minimal n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == '$N1SUBNET6_MAC' && ip4.src == 10.1.1.5 && ip4.dst == 10.1.2.7 && ip.ttl == 64 && tcp.dst == 23'
    ...
    ct_next(ct_state=est|rpl|trk) {
        ip.ttl--;
        eth.src = fa:16:3e:19:9f:46;
        eth.dst = fa:16:3e:89:f2:36;
        ct_next(ct_state=est|rpl|trk) {
            output("cp");
        };
    };

  This succeeds, as you can see from the ``output`` action, since
  traffic received in reply to an outgoing connection is always
  allowed.

DHCP
----

As a final demonstration of the OVN architecture, let's examine the
DHCP implementation.  Like switching, routing, and NAT, the OVN
implementation of DHCP involves configuration in the NB DB and logical
flows in the SB DB.

Let's look at the DHCP support for ``a``'s port ``ap``.  The port's
Logical_Switch_Port record shows that ``ap`` has DHCPv4 options::

  $ ovn-nbctl list logical_switch_port ap | abbrev
  _uuid               : ef17e5
  addresses           : ["fa:16:3e:a9:4c:c7 10.1.1.5 fc11::5"]
  dhcpv4_options      : 165974
  dhcpv6_options      : 26f7cd
  dynamic_addresses   : []
  enabled             : true
  external_ids        : {"neutron:port_name"=ap}
  name                : "820c08"
  options             : {}
  parent_name         : []
  port_security       : ["fa:16:3e:a9:4c:c7 10.1.1.5 fc11::5"]
  tag                 : []
  tag_request         : []
  type                : ""
  up                  : true

We can then list them either by UUID or, more easily, by port name::

  $ ovn-nbctl list dhcp_options ap | abbrev
  _uuid               : 165974
  cidr                : "10.1.1.0/24"
  external_ids        : {subnet_id="5e67e7"}
  options             : {lease_time="43200", mtu="1442", router="10.1.1.1", server_id="10.1.1.1", server_mac="fa:16:3e:bb:94:72"}

These options show the basic DHCP configuration for the subnet.  They
do not include the IP address itself, which comes from the
Logical_Switch_Port record.  This allows a whole Neutron subnet to
share a single DHCP_Options record.  You can see this sharing in
action, if you like, by listing the record for port ``bp``, which is
on the same subnet as ``ap``, and see that it is the same record as before::

  $ ovn-nbctl list dhcp_options bp | abbrev
  _uuid               : 165974
  cidr                : "10.1.1.0/24"
  external_ids        : {subnet_id="5e67e7"}
  options             : {lease_time="43200", mtu="1442", router="10.1.1.1", server_id="10.1.1.1", server_mac="fa:16:3e:bb:94:72"}

You can take another look at the southbound flow table if you like,
but the best demonstration is to trace a DHCP packet.  The following
is a trace of a DHCP request inbound from ``ap``.  The first part is
just the usual travel through the firewall::

  $ ovn-trace n1 'inport == "ap" && eth.src == '$AP_MAC' && eth.dst == ff:ff:ff:ff:ff:ff && ip4.dst == 255.255.255.255 && udp.src == 68 && udp.dst == 67 && ip.ttl == 1'
  ...
  ingress(dp="n1", inport="ap")
  -----------------------------
   0. ls_in_port_sec_l2 (ovn-northd.c:3234): inport == "ap" && eth.src == {fa:16:3e:a9:4c:c7}, priority 50, uuid 6dcc418a
      next;
   1. ls_in_port_sec_ip (ovn-northd.c:2325): inport == "ap" && eth.src == fa:16:3e:a9:4c:c7 && ip4.src == 0.0.0.0 && ip4.dst == 255.255.255.255 && udp.src == 68 && udp.dst == 67, priority 90, uuid e46bed6f
      next;
   3. ls_in_pre_acl (ovn-northd.c:2646): ip, priority 100, uuid 46c089e6
      reg0[0] = 1;
      next;
   5. ls_in_pre_stateful (ovn-northd.c:2764): reg0[0] == 1, priority 100, uuid d1941634
      ct_next;

The next part is the new part.  First, an ACL in table 6 allows a DHCP
request to pass through.  In table 11, the special ``put_dhcp_opts``
action replaces a DHCPDISCOVER or DHCPREQUEST packet by a
reply.  Table 12 flips the packet's source and destination and sends
it back the way it came in::

   6. ls_in_acl (ovn-northd.c:2925): !ct.new && ct.est && !ct.rpl && ct_label.blocked == 0 && (inport == "ap" && ip4 && ip4.dst == {255.255.255.255, 10.1.1.0/24} && udp && udp.src == 68 && udp.dst == 67), priority 2002, uuid 9c90245d
      next;
  11. ls_in_dhcp_options (ovn-northd.c:3409): inport == "ap" && eth.src == fa:16:3e:a9:4c:c7 && ip4.src == 0.0.0.0 && ip4.dst == 255.255.255.255 && udp.src == 68 && udp.dst == 67, priority 100, uuid 8d63f29c
      reg0[3] = put_dhcp_opts(offerip = 10.1.1.5, lease_time = 43200, mtu = 1442, netmask = 255.255.255.0, router = 10.1.1.1, server_id = 10.1.1.1);
      /* We assume that this packet is DHCPDISCOVER or DHCPREQUEST. */
      next;
  12. ls_in_dhcp_response (ovn-northd.c:3438): inport == "ap" && eth.src == fa:16:3e:a9:4c:c7 && ip4 && udp.src == 68 && udp.dst == 67 && reg0[3], priority 100, uuid 995eeaa9
      eth.dst = eth.src;
      eth.src = fa:16:3e:bb:94:72;
      ip4.dst = 10.1.1.5;
      ip4.src = 10.1.1.1;
      udp.src = 67;
      udp.dst = 68;
      outport = inport;
      flags.loopback = 1;
      output;

Then the last part is just traveling back through the firewall to VM
``a``::

  egress(dp="n1", inport="ap", outport="ap")
  ------------------------------------------
   1. ls_out_pre_acl (ovn-northd.c:2648): ip, priority 100, uuid 3752b746
      reg0[0] = 1;
      next;
   2. ls_out_pre_stateful (ovn-northd.c:2766): reg0[0] == 1, priority 100, uuid 0c066ea1
      ct_next;

  ct_next(ct_state=est|trk /* default (use --ct to customize) */)
  ---------------------------------------------------------------
   4. ls_out_acl (ovn-northd.c:3008): outport == "ap" && eth.src == fa:16:3e:bb:94:72 && ip4.src == 10.1.1.1 && udp && udp.src == 67 && udp.dst == 68, priority 34000, uuid 0b383e77
      ct_commit;
      next;
   7. ls_out_port_sec_ip (ovn-northd.c:2364): outport == "ap" && eth.dst == fa:16:3e:a9:4c:c7 && ip4.dst == {255.255.255.255, 224.0.0.0/4, 10.1.1.5}, priority 90, uuid 7b8cbcd5
      next;
   8. ls_out_port_sec_l2 (ovn-northd.c:3654): outport == "ap" && eth.dst == {fa:16:3e:a9:4c:c7}, priority 50, uuid b874ece8
      output;
      /* output to "ap", type "" */

Further Directions
------------------

We've looked at a fair bit of how OVN works and how it interacts with
OpenStack.  If you still have some interest, then you might want to
explore some of these directions:

* Adding more than one hypervisor ("compute node", in OpenStack
  parlance).  OVN connects compute nodes by tunneling packets with the
  STT or Geneve protocols.  OVN scales to 1000 compute nodes or more,
  but two compute nodes demonstrate the principle.  All of the tools
  and techniques we demonstrated also work with multiple compute
  nodes.

* Container support.  OVN supports seamlessly connecting VMs to
  containers, whether the containers are hosted on "bare metal" or
  nested inside VMs.  OpenStack support for containers, however, is
  still evolving, and too difficult to incorporate into the tutorial
  at this point.

* Other kinds of gateways.  In addition to floating IPs with NAT, OVN
  supports directly attaching VMs to a physical network and connecting
  logical switches to VTEP hardware.
