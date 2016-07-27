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

ovn-nbctl ls-add sw0

ovn-nbctl lsp-add sw0 sw0-port1
ovn-nbctl lsp-add sw0 sw0-port2
ovn-nbctl lsp-add sw0 sw0-port3
ovn-nbctl lsp-add sw0 sw0-port4

ovn-nbctl lsp-set-addresses sw0-port1 00:00:00:00:00:01
ovn-nbctl lsp-set-addresses sw0-port2 00:00:00:00:00:02
ovn-nbctl lsp-set-addresses sw0-port3 00:00:00:00:00:03
ovn-nbctl lsp-set-addresses sw0-port4 00:00:00:00:00:04

ovn-nbctl lsp-set-port-security sw0-port1 00:00:00:00:00:01
ovn-nbctl lsp-set-port-security sw0-port2 00:00:00:00:00:02
ovn-nbctl lsp-set-port-security sw0-port3 00:00:00:00:00:03
ovn-nbctl lsp-set-port-security sw0-port4 00:00:00:00:00:04

# Bind sw0-port1 and sw0-port2 to the local chassis
ovs-vsctl add-port br-int lport1 -- set Interface lport1 external_ids:iface-id=sw0-port1
ovs-vsctl add-port br-int lport2 -- set Interface lport2 external_ids:iface-id=sw0-port2

# Create a fake remote chassis.
ovn-sbctl chassis-add fakechassis geneve 127.0.0.1

# Bind sw0-port3 and sw0-port4 to the fake remote chassis.
ovn-sbctl lsp-bind sw0-port3 fakechassis
ovn-sbctl lsp-bind sw0-port4 fakechassis
