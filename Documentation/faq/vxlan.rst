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

======
VXLANs
======

Q: What's a VXLAN?

    A: VXLAN stands for Virtual eXtensible Local Area Network, and is a means
    to solve the scaling challenges of VLAN networks in a multi-tenant
    environment. VXLAN is an overlay network which transports an L2 network
    over an existing L3 network. For more information on VXLAN, please see `RFC
    7348 <https://tools.ietf.org/html/rfc7348>`__.

Q: How much of the VXLAN protocol does Open vSwitch currently support?

    A: Open vSwitch currently supports the framing format for packets on the
    wire. There is currently no support for the multicast aspects of VXLAN.  To
    get around the lack of multicast support, it is possible to pre-provision
    MAC to IP address mappings either manually or from a controller.

Q: What destination UDP port does the VXLAN implementation in Open vSwitch
use?

    A: By default, Open vSwitch will use the assigned IANA port for VXLAN,
    which is 4789. However, it is possible to configure the destination UDP
    port manually on a per-VXLAN tunnel basis. An example of this configuration
    is provided below.::

        $ ovs-vsctl add-br br0
        $ ovs-vsctl add-port br0 vxlan1 -- set interface vxlan1 type=vxlan \
            options:remote_ip=192.168.1.2 options:key=flow options:dst_port=8472
