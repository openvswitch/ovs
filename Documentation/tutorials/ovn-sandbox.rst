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

===========
OVN Sandbox
===========

This tutorial shows you how to explore features using ``ovs-sandbox`` as a
simulated test environment.  It's assumed that you have an understanding of OVS
before going through this tutorial. Detail about OVN is covered in
ovn-architecture_, but this tutorial lets you quickly see it in action.

Getting Started
---------------

For some general information about ``ovs-sandbox``, see the "Getting Started"
section of the tutorial_.

``ovs-sandbox`` does not include OVN support by default.  To enable OVN, you
must pass the ``--ovn`` flag.  For example, if running it straight from the OVS
git tree you would run::

    $ make sandbox SANDBOXFLAGS="--ovn"

Running the sandbox with OVN enabled does the following additional steps to the
environment:

1. Creates the ``OVN_Northbound`` and ``OVN_Southbound`` databases as described in
   `ovn-nb(5)`_ and `ovn-sb(5)`_.

2. Creates a backup server for ``OVN_Southbond`` database. Sandbox launch
   screen provides the instructions on accessing the backup database.  However
   access to the backup server is not required to go through the tutorial.

3. Creates the ``hardware_vtep`` database as described in `vtep(5)`_.

4. Runs the `ovn-northd(8)`_, `ovn-controller(8)`_, and
   `ovn-controller-vtep(8)`_ daemons.

5. Makes OVN and VTEP utilities available for use in the environment, including
   `vtep-ctl(8)`_, `ovn-nbctl(8)`_, and `ovn-sbctl(8)`_.

Using GDB
---------

GDB support is not required to go through the tutorial. See the "Using GDB"
section of the `tutorial`_ for more info. Additional flags exist for launching
the debugger for the OVN programs::

    --gdb-ovn-northd
    --gdb-ovn-controller
    --gdb-ovn-controller-vtep

Creating OVN Resources
----------------------

Once you have ``ovs-sandbox`` running with OVN enabled, you can start using OVN
utilities to create resources in OVN.  As an example, we will create an
environment that has two logical switches connected by a logical router.

Create the first logical switch with one port::

    $ ovn-nbctl ls-add sw0
    $ ovn-nbctl lsp-add sw0 sw0-port1
    $ ovn-nbctl lsp-set-addresses sw0-port1 "50:54:00:00:00:01 192.168.0.2"

Create the second logical switch with one port::

    $ ovn-nbctl ls-add sw1
    $ ovn-nbctl lsp-add sw1 sw1-port1
    $ ovn-nbctl lsp-set-addresses sw1-port1 "50:54:00:00:00:03 11.0.0.2"

Create the logical router and attach both logical switches::

    $ ovn-nbctl lr-add lr0
    $ ovn-nbctl lrp-add lr0 lrp0 00:00:00:00:ff:01 192.168.0.1/24
    $ ovn-nbctl lsp-add sw0 lrp0-attachment
    $ ovn-nbctl lsp-set-type lrp0-attachment router
    $ ovn-nbctl lsp-set-addresses lrp0-attachment 00:00:00:00:ff:01
    $ ovn-nbctl lsp-set-options lrp0-attachment router-port=lrp0
    $ ovn-nbctl lrp-add lr0 lrp1 00:00:00:00:ff:02 11.0.0.1/24
    $ ovn-nbctl lsp-add sw1 lrp1-attachment
    $ ovn-nbctl lsp-set-type lrp1-attachment router
    $ ovn-nbctl lsp-set-addresses lrp1-attachment 00:00:00:00:ff:02
    $ ovn-nbctl lsp-set-options lrp1-attachment router-port=lrp1

View a summary of OVN's current logical configuration::

    $ ovn-nbctl show
        switch 1396cf55-d176-4082-9a55-1c06cef626e4 (sw1)
            port lrp1-attachment
                addresses: ["00:00:00:00:ff:02"]
            port sw1-port1
                addresses: ["50:54:00:00:00:03 11.0.0.2"]
        switch 2c9d6d03-09fc-4e32-8da6-305f129b0d53 (sw0)
            port lrp0-attachment
                addresses: ["00:00:00:00:ff:01"]
            port sw0-port1
                addresses: ["50:54:00:00:00:01 192.168.0.2"]
        router f8377e8c-f75e-4fc8-8751-f3ea03c6dd98 (lr0)
            port lrp0
                mac: "00:00:00:00:ff:01"
                networks: ["192.168.0.1/24"]
            port lrp1
                mac: "00:00:00:00:ff:02"
                networks: ["11.0.0.1/24"]

The ``tutorial`` directory of the OVS source tree includes a script
that runs all of the commands for you::

    $ ./ovn-setup.sh

Using ovn-trace
---------------

Once you have configured resources in OVN, try using ``ovn-trace`` to see
how OVN would process a sample packet through its logical pipeline.

For example, we can trace an IP packet from ``sw0-port1`` to ``sw1-port1``.
The ``--minimal`` output shows each visible action performed on the packet,
which includes:

#. The logical router will decrement the IP TTL field.
#. The logical router will change the source and destination
   MAC addresses to reflect the next hop.
#. The packet will be output to ``sw1-port1``.

::

    $ ovn-trace --minimal sw0 'inport == "sw0-port1" \
    > && eth.src == 50:54:00:00:00:01 && ip4.src == 192.168.0.2 \
    > && eth.dst == 00:00:00:00:ff:01 && ip4.dst == 11.0.0.2 \
    > && ip.ttl == 64'

    # ip,reg14=0x1,vlan_tci=0x0000,dl_src=50:54:00:00:00:01,dl_dst=00:00:00:00:ff:01,nw_src=192.168.0.2,nw_dst=11.0.0.2,nw_proto=0,nw_tos=0,nw_ecn=0,nw_ttl=64
    ip.ttl--;
    eth.src = 00:00:00:00:ff:02;
    eth.dst = 50:54:00:00:00:03;
    output("sw1-port1");

The ``ovn-trace`` utility can also provide much more detail on how the packet
would be processed through OVN's logical pipeline, as well as correlate that
to OpenFlow flows programmed by ``ovn-controller``.  See the `ovn-trace(8)`_
man page for more detail.


.. _ovn-architecture: http://openvswitch.org/support/dist-docs/ovn-architecture.7.html
.. _Tutorial: :ref:`ovs-advanced`
.. _ovn-nb(5): http://openvswitch.org/support/dist-docs/ovn-nb.5.html
.. _ovn-sb(5): http://openvswitch.org/support/dist-docs/ovn-sb.5.html
.. _vtep(5): http://openvswitch.org/support/dist-docs/vtep.5.html
.. _ovn-northd(8): http://openvswitch.org/support/dist-docs/ovn-northd.8.html
.. _ovn-controller(8): http://openvswitch.org/support/dist-docs/ovn-controller.8.html
.. _ovn-controller-vtep(8): http://openvswitch.org/support/dist-docs/ovn-controller-vtep.8.html
.. _vtep-ctl(8): http://openvswitch.org/support/dist-docs/vtep-ctl.8.html
.. _ovn-nbctl(8): http://openvswitch.org/support/dist-docs/ovn-nbctl.8.html
.. _ovn-sbctl(8): http://openvswitch.org/support/dist-docs/ovn-sbctl.8.html
.. _ovn-trace(8): http://openvswitch.org/support/dist-docs/ovn-trace.8.html
