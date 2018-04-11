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

===========================================
Open vSwitch Networking Namespaces on Linux
===========================================

The Open vSwitch has networking namespaces basic support on Linux. That allows
ovs-vswitchd daemon to continue tracking status and statistics after moving a
port to another networking namespace.


How It Works
------------

The daemon ovs-vswitchd runs on what is called parent network namespace. It
listens to netlink event messages from all networking namespaces (netns)
with an identifier on the parent. Each netlink message contains the network
namespace identifier (netnsid) as ancillary data which is used to match the
event to the corresponding port.

The ovs-vswitchd uses an extended openvswitch kernel API [1]_ to get the
current netnsid (stored in struct netdev_linux) and statistics from a specific
port.  The netnsid remains cached in userspace until a changing event is
received, for example, when the port is moved to another network namespace.

Using another extended kernel API [2]_, the daemon gets port's information
such as flags, MTU, MAC address and ifindex from a port already in another
namespace.

The upstream kernel 4.15 includes the necessary changes for the basic support.
In case of the running kernel doesn't provide the APIs, the daemon falls back
to the previous behavior.

.. [1] Request cmd: OVS_VPORT_CMD_GET, attribute: OVS_VPORT_ATTR_NETNSID
.. [2] Request cmd: RTM_GETLINK passing IFLA_IF_NETNSID attribute.


Limitations
-----------

Currently it is only possible to retrieve the information listed in the
above section.  Most of other operations, for example querying MII or
setting MTU, lacks the proper API in the kernel, so they remain unsupported.

In most use cases that needs to move ports to another networking namespaces
should use veth pairs instead because it offers a cleaner and more robust
solution with no noticeable performance penalty.
