#! /bin/sh -e

# Copyright (c) 2009 Nicira Networks.
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

srcdir=`cd $srcdir && pwd`
trap 'rm -f flows$$ pcap$$ out$$' 0 1 2 13 15
cd tests
"$srcdir"/tests/flowgen.pl >/dev/null 3>flows$$ 4>pcap$$
./test-flows <flows$$ 3<pcap$$ >out$$ || true
diff -u - out$$ <<EOF
checked 247 packets, 0 errors
EOF
