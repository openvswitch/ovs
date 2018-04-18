..
      Copyright (c) 2016, Stephen Finucane <stephen@that.guru>

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

===============
Reference Guide
===============

Man Pages
---------

.. TODO(stephenfin): Remove the below notice once everything is converted to
   rST

The following man pages are written in rST and converted to roff at compile
time:

.. toctree::
   :maxdepth: 3

   ovs-test.8
   ovs-vlan-test.8
   ovsdb-server.7
   ovsdb.5
   ovsdb.7

The remainder are still in roff format can be found below:

.. list-table::

   * - ovn-architecture(7)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovn-architecture.7.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovn-architecture.7.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovn-architecture.7.txt>`__
   * - ovn-controller(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovn-controller.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovn-controller.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovn-controller.8.txt>`__
   * - ovn-controller-vtep(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovn-controller-vtep.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovn-controller-vtep.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovn-controller-vtep.8.txt>`__
   * - ovn-ctl(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovn-ctl.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovn-ctl.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovn-ctl.8.txt>`__
   * - ovn-nb(5)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovn-nb.5.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovn-nb.5.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovn-nb.5.txt>`__
   * - ovn-nbctl(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovn-nbctl.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovn-nbctl.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovn-nbctl.8.txt>`__
   * - ovn-northd(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovn-northd.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovn-northd.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovn-northd.8.txt>`__
   * - ovn-sb(5)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovn-sb.5.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovn-sb.5.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovn-sb.5.txt>`__
   * - ovn-sbctl(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovn-sbctl.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovn-sbctl.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovn-sbctl.8.txt>`__
   * - ovn-trace(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovn-trace.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovn-trace.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovn-trace.8.txt>`__
   * - ovs-appctl(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-appctl.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-appctl.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-appctl.8.txt>`__
   * - ovs-bugtool(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-bugtool.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-bugtool.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-bugtool.8.txt>`__
   * - ovs-ctl(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-ctl.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-ctl.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-ctl.8.txt>`__
   * - ovsdb-client(1)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovsdb-client.1.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovsdb-client.1.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovsdb-client.1.txt>`__
   * - ovsdb-server(1)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovsdb-server.1.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovsdb-server.1.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovsdb-server.1.txt>`__
   * - ovsdb-tool(1)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovsdb-tool.1.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovsdb-tool.1.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovsdb-tool.1.txt>`__
   * - ovs-dpctl(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-dpctl.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-dpctl.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-dpctl.8.txt>`__
   * - ovs-dpctl-top(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-dpctl-top.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-dpctl-top.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-dpctl-top.8.txt>`__
   * - ovs-fields(7)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-fields.7.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-fields.7.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-fields.7.txt>`__
   * - ovs-l3ping(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-l3ping.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-l3ping.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-l3ping.8.txt>`__
   * - ovs-ofctl(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-ofctl.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-ofctl.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-ofctl.8.txt>`__
   * - ovs-parse-backtrace(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-parse-backtrace.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-parse-backtrace.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-parse-backtrace.8.txt>`__
   * - ovs-pcap(1)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-pcap.1.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-pcap.1.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-pcap.1.txt>`__
   * - ovs-pki(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-pki.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-pki.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-pki.8.txt>`__
   * - ovs-tcpdump(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-tcpdump.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-tcpdump.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-tcpdump.8.txt>`__
   * - ovs-tcpundump(1)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-tcpundump.1.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-tcpundump.1.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-tcpundump.1.txt>`__
   * - ovs-test(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-test.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-test.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-test.8.txt>`__
   * - ovs-testcontroller(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-testcontroller.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-testcontroller.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-testcontroller.8.txt>`__
   * - ovs-vlan-bug-workaround(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-vlan-bug-workaround.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-vlan-bug-workaround.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-vlan-bug-workaround.8.txt>`__
   * - ovs-vlan-test(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-vlan-test.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-vlan-test.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-vlan-test.8.txt>`__
   * - ovs-vsctl(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-vsctl.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-vsctl.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-vsctl.8.txt>`__
   * - ovs-vswitchd(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-vswitchd.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-vswitchd.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-vswitchd.8.txt>`__
   * - ovs-vswitchd.conf.db(5)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/ovs-vswitchd.conf.db.5.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/ovs-vswitchd.conf.db.5.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/ovs-vswitchd.conf.db.5.txt>`__
   * - vtep(5)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/vtep.5.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/vtep.5.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/vtep.5.txt>`__
   * - vtep-ctl(8)
     - `(pdf) <http://www.openvswitch.org/support/dist-docs/vtep-ctl.8.pdf>`__
     - `(html) <http://www.openvswitch.org/support/dist-docs/vtep-ctl.8.html>`__
     - `(plain text) <http://www.openvswitch.org/support/dist-docs/vtep-ctl.8.html>`__
