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

ovs-vsctl add-br br-eth1
ovs-vsctl set open .  external-ids:ovn-bridge-mappings=physnet1:br-eth1

ovn-sbctl chassis-add fakechassis geneve 127.0.0.1

for n in 1 2 3 4; do
    ovn-nbctl ls-add provnet1-$n

    ovn-nbctl lsp-add provnet1-$n provnet1-$n-port1
    ovn-nbctl lsp-set-addresses provnet1-$n-port1 00:00:00:00:00:0$n
    ovn-nbctl lsp-set-port-security provnet1-$n-port1 00:00:00:00:00:0$n

    ovn-nbctl lsp-add provnet1-$n provnet1-$n-physnet1
    ovn-nbctl lsp-set-addresses provnet1-$n-physnet1 unknown
    ovn-nbctl lsp-set-type provnet1-$n-physnet1 localnet
    ovn-nbctl lsp-set-options provnet1-$n-physnet1 network_name=physnet1
done

ovs-vsctl add-port br-int lport1 -- set Interface lport1 external_ids:iface-id=provnet1-1-port1
ovs-vsctl add-port br-int lport2 -- set Interface lport2 external_ids:iface-id=provnet1-2-port1

ovn-sbctl lsp-bind provnet1-3-port1 fakechassis
ovn-sbctl lsp-bind provnet1-4-port1 fakechassis
