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

===============================
RHEL Packaging for Open vSwitch
===============================

For RHEL 7.x (or derivatives, such as CentOS 7.x) and newer, you should follow
the instructions in the :doc:`fedora`.  The Fedora spec files are used for RHEL
7.x and above.

If you want to install Open vSwitch on a generic Linux host or on an older
RHEL, refer to :doc:`general` instead.

Red Hat Network Scripts Integration
-----------------------------------

A RHEL host has default firewall rules that prevent any Open vSwitch tunnel
traffic from passing through. If a user configures Open vSwitch tunnels like
Geneve, GRE, VXLAN, etc., they will either have to manually add iptables
firewall rules to allow the tunnel traffic or add it through a startup script
Refer to the "enable-protocol" command in the ovs-ctl(8) manpage for more
information.

In addition, simple integration with Red Hat network scripts has been
implemented.  Refer to `README.RHEL.rst`__ in the source tree or
/usr/share/doc/openvswitch/README.RHEL.rst in the installed openvswitch package
for details.

__ https://github.com/openvswitch/ovs/blob/main/rhel/README.RHEL.rst

Reporting Bugs
--------------

Report problems to bugs@openvswitch.org.
