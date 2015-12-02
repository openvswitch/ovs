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

#
# This trace simulates a packet arriving over a Geneve tunnel from a remote OVN
# chassis.  The fields are as follows:
#
# tun_id -
#    The logical datapath (or logical switch) ID.  In this case, we only
#    have a single logical switch and its ID is 1.
#
# tun_metadata0 -
#     This field holds 2 pieces of metadata.  The low 16 bits hold the logical
#     destination port (1 in this case).  The upper 16 bits hold the logical
#     source port (3 in this case.
#
ovs-appctl ofproto/trace br-int in_port=3,dl_src=00:00:00:00:00:03,dl_dst=00:00:00:00:00:01,tun_id=1,tun_metadata0=$[1 + $[3 << 16]] -generate
