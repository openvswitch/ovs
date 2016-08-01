#!/bin/bash
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# This script simulates 2 chassis connected to a physical switch,
# which we call "physnet1". We have two logical ports, one on each hypervisor,
# that OVN will connect to physnet1.
#
# The way to accomplish this in OVN is to create a logical switch for each
# logical port.  In addition to the normal logical port, each logical switch
# has a special "localnet" port, which represents the connection to physnet1.
#
# In this setup we see the view of this environment from one of the hypervisors.

set -o xtrace

ovn-nbctl ls-add sw0

ovn-nbctl lsp-add sw0 sw0-port1
ovn-nbctl lsp-set-addresses sw0-port1 00:00:00:00:00:01
ovn-nbctl lsp-set-port-security sw0-port1 00:00:00:00:00:01
ovs-vsctl add-port br-int lport1 -- set Interface lport1 external_ids:iface-id=sw0-port1

ovn-nbctl lsp-add sw0 sw0-port2
ovn-nbctl lsp-set-addresses sw0-port2 00:00:00:00:00:02
ovn-nbctl lsp-set-port-security sw0-port2 00:00:00:00:00:02
ovs-vsctl add-port br-int lport2 -- set Interface lport2 external_ids:iface-id=sw0-port2

ovn-nbctl lsp-add sw0 sw0-port3
ovn-nbctl lsp-set-addresses sw0-port3 unknown
ovn-nbctl lsp-set-type sw0-port3 l2gateway
# The chassis UUID is hard-coded in tutorial/ovs-sandbox.
ovn-nbctl lsp-set-options sw0-port3 l2gateway-chassis=56b18105-5706-46ef-80c4-ff20979ab068 network_name=physnet1

ovs-vsctl --may-exist add-br br-eth1
ovs-vsctl set open .  external-ids:ovn-bridge-mappings=physnet1:br-eth1
