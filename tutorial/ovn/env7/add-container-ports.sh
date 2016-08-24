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

set -o xtrace

# create a logical switch
ovn-nbctl ls-add csw0

# create a container port with parent set to sw0-port1
ovn-nbctl lsp-add csw0 csw0-cport1 sw0-port1 42
ovn-nbctl lsp-set-addresses csw0-cport1 00:00:00:00:01:01
ovn-nbctl lsp-set-port-security csw0-cport1 00:00:00:00:01:01

# create another container port with parent set to sw0-port1
ovn-nbctl lsp-add csw0 csw0-cport2 sw0-port2 43
ovn-nbctl lsp-set-addresses csw0-cport2 00:00:00:00:01:02
ovn-nbctl lsp-set-port-security csw0-cport2 00:00:00:00:01:02


# Make lport1 as a patch port, other end connected to br-vmport1
ovs-vsctl set interface lport1 type=patch
ovs-vsctl set interface lport1 options:peer=patch-lport1

ovs-vsctl set interface lport2 type=patch
ovs-vsctl set interface lport2 options:peer=patch-lport2


# This represents ovs bridge inside a VM attached to lport1
ovs-vsctl add-br br-vmport1

# create a patch port with peer set to lport1.
ovs-vsctl add-port br-vmport1 patch-lport1
ovs-vsctl set interface patch-lport1 type=patch
ovs-vsctl set interface patch-lport1 options:peer=lport1

# create a container port on br-vmport1. Any traffic sent on this
# port will reach to the br-int of the host via the patch port
ovs-vsctl add-port br-vmport1 cport1
ovs-vsctl set port cport1 tag=42

# This represents ovs bridge inside a VM attached to lport2
ovs-vsctl add-br br-vmport2
ovs-vsctl add-port br-vmport2 patch-lport2
ovs-vsctl set interface patch-lport2 type=patch
ovs-vsctl set interface patch-lport2 options:peer=lport2

ovs-vsctl add-port br-vmport2 cport2
ovs-vsctl set port cport2 tag=43
