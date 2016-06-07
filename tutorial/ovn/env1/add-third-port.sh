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

ovn-nbctl lsp-add sw0 sw0-port3
ovn-nbctl lsp-set-addresses sw0-port3 00:00:00:00:00:03
ovn-nbctl lsp-set-port-security sw0-port3 00:00:00:00:00:03
ovs-vsctl add-port br-int lport3 -- set Interface lport3 external_ids:iface-id=sw0-port3
