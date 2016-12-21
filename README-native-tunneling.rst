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

==========================================
Native Tunneling in Open vSwitch Userspace
==========================================

Open vSwitch supports tunneling in userspace. Tunneling is implemented in
a platform-independent way.

Setup
-----

Setup physical bridges for all physical interfaces. Create integration bridge.
Add VXLAN port to int-bridge. Assign IP address to physical bridge where
VXLAN traffic is expected.

Example
-------

Connect to VXLAN tunnel endpoint logical IP: ``192.168.1.2`` and
``192.168.1.1``.

Configure OVS bridges as follows.

1. Let's assume ``172.168.1.2/24`` network is reachable via ``eth1``. Create
   physical bridge ``br-eth1``. Assign IP address (``172.168.1.1/24``) to
   ``br-eth1``. Add ``eth1`` to ``br-eth1``.

2. Check ovs cached routes using appctl command.

   ::

       $ ovs-appctl ovs/route/show

   Add tunnel route if not present in OVS route table.

   ::

       $ ovs-appctl ovs/route/add 172.168.1.1/24 br-eth1

3. Add integration bridge ``int-br`` and add tunnel port using standard syntax.

   ::

       $ ovs-vsctl add-port int-br vxlan0 \
         -- set interface vxlan0 type=vxlan options:remote_ip=172.168.1.2

4. Assign IP address to ``int-br``.

The final topology should looks like so:

::

    Diagram

     192.168.1.1/24
    +--------------+
    |    int-br    |                                    192.168.1.2/24
    +--------------+                                   +--------------+
    |    vxlan0    |                                   |    vxlan0    |
    +--------------+                                   +--------------+
           |                                                  |
           |                                                  |
           |                                                  |
     172.168.1.1/24                                           |
    +--------------+                                          |
    |    br-eth1   |                                   172.168.1.2/24
    +--------------+                                  +---------------+
    |    eth1      |----------------------------------|      eth1     |
    +--------------+                                  +---------------+

    Host A with OVS.                                      Remote host.

With this setup, ping to VXLAN target device (``192.168.1.2``) should work.

Tunneling-related Commands
--------------------------

Tunnel routing table
~~~~~~~~~~~~~~~~~~~~

To add route:

::

    $ ovs-appctl ovs/route/add <IP address>/<prefix length> <output-bridge-name> <gw>

To see all routes configured:

::

    $ ovs-appctl ovs/route/show

To delete route:

::

    $ ovs-appctl ovs/route/del <IP address>/<prefix length>

To look up and display the route for a destination:

::

    $ ovs-appctl ovs/route/lookup <IP address>

ARP
~~~

To see arp cache content:

::

    $ ovs-appctl tnl/arp/show

To flush arp cache:

::

    $ ovs-appctl tnl/arp/flush

Ports
~~~~~

To check tunnel ports listening in ovs-vswitchd:

::

    $ ovs-appctl tnl/ports/show

To set range for VxLan UDP source port:

::

    $ ovs-appctl tnl/egress_port_range <num1> <num2>

To show current range:

::

    $ ovs-appctl tnl/egress_port_range

Datapath
~~~~~~~~

To check datapath ports:

::

    $ ovs-appctl dpif/show

To check datapath flows:

::

    $ ovs-appctl dpif/dump-flows
