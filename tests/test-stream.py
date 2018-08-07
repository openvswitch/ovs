# Copyright (c) 2018, Red Hat Inc.
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

import sys

import ovs.stream


def main(argv):
    remote = argv[1]
    err, stream = ovs.stream.Stream.open_block(
            ovs.stream.Stream.open(remote))

    if err or stream is None:
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main(sys.argv)
