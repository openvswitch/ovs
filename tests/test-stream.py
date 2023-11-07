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
import ovs.util


def main(argv):
    if len(argv) < 2:
        ovs.util.ovs_fatal(0,
                           "usage: %s REMOTE [SSL_KEY] [SSL_CERT] [SSL_CA]",
                           argv[0],
                           )
    remote = argv[1]

    if remote.startswith("ssl:"):
        if len(argv) < 5:
            ovs.util.ovs_fatal(
                0,
                "usage with ssl: %s REMOTE [SSL_KEY] [SSL_CERT] [SSL_CA]",
                argv[0],
            )
        ovs.stream.SSLStream.ssl_set_ca_cert_file(argv[4])
        ovs.stream.SSLStream.ssl_set_certificate_file(argv[3])
        ovs.stream.SSLStream.ssl_set_private_key_file(argv[2])

    err, stream = ovs.stream.Stream.open_block(
            ovs.stream.Stream.open(remote), 10000)

    if err or stream is None:
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main(sys.argv)
