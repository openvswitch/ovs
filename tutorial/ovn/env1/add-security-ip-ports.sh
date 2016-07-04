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

ovn-nbctl lsp-add sw0 sw0-port6
ovn-nbctl lsp-add sw0 sw0-port7
ovn-nbctl lsp-set-addresses sw0-port6 "00:00:00:00:00:06"
ovn-nbctl lsp-set-addresses sw0-port7 "00:00:00:00:00:07"
ovn-nbctl lsp-set-port-security sw0-port6 00:00:00:00:00:06 192.168.1.10/24
ovn-nbctl lsp-set-port-security sw0-port7 00:00:00:00:00:07 192.168.1.20/24
ovs-vsctl add-port br-int lport6 -- set Interface lport6 external_ids:iface-id=sw0-port6
ovs-vsctl add-port br-int lport7 -- set Interface lport7 external_ids:iface-id=sw0-port7
