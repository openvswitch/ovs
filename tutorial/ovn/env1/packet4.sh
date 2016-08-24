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

# Trace a packet from sw0-port6 to sw0-port7.
ovs-appctl ofproto/trace br-int in_port=6,dl_type=0x0800,dl_src=00:00:00:00:00:06,dl_dst=00:00:00:00:00:07,nw_src=192.168.1.10,nw_dst=192.168.1.20  -generate
