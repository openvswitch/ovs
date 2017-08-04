# Copyright (c) 2017 Red Hat, Inc.
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

use strict;
use warnings;
use Getopt::Long;

my ($check_dpdk) = 0;
my ($disabled_print) = 0;

Getopt::Long::Configure ("bundling");
GetOptions("dpdk!" => \$check_dpdk) or exit(1);

OUTER: while (<STDIN>) {
    if (/@(begin|end)_dpdk@/) {
        if (!$check_dpdk) {
            $disabled_print = ! $disabled_print;
        }
        next;
    }

    print $_ unless $disabled_print;
}
exit 0;
