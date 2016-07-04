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

ovn-nbctl lsp-add sw0 sw0-port4
ovn-nbctl lsp-add sw0 sw0-port5
ovn-nbctl lsp-set-addresses sw0-port4 unknown
ovn-nbctl lsp-set-addresses sw0-port5 unknown
ovn-nbctl lsp-set-port-security sw0-port4 00:00:00:00:00:04 00:00:00:00:00:05
ovn-nbctl lsp-set-port-security sw0-port5 00:00:00:00:00:04 00:00:00:00:00:05
ovs-vsctl add-port br-int lport4 -- set Interface lport4 external_ids:iface-id=sw0-port4
ovs-vsctl add-port br-int lport5 -- set Interface lport5 external_ids:iface-id=sw0-port5
