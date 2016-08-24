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

# input from local vif, lport5 (ofport 6)
# destination MAC is lport6
# expect to go out via localnet port (ofport 7) and lport6 (ofport 8)
ovs-appctl ofproto/trace br-int in_port=6,dl_src=00:00:00:00:00:05,dl_dst=00:00:00:00:00:06 -generate
