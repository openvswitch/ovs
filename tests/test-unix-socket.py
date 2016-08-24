#
# Copyright (c) 2010, 2012, 2013 Nicira, Inc.
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

import os
import signal
import socket
import sys

import ovs.socket_util
from ovs.fatal_signal import signal_alarm


def main(argv):
    if len(argv) not in (2, 3):
        sys.stderr.write("usage: %s SOCKETNAME1 [SOCKETNAME2]", argv[0])
        sys.exit(1)

    sockname1 = argv[1]
    if len(argv) > 2:
        sockname2 = argv[2]
    else:
        sockname2 = sockname1

    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal_alarm(5)

    # Create a listening socket under name 'sockname1'.
    error, sock1 = ovs.socket_util.make_unix_socket(socket.SOCK_STREAM, False,
                                                    sockname1, None)
    if error:
        sys.stderr.write("%s: bind failed (%s)" % (sockname1,
                                                   os.strerror(error)))
        sys.exit(1)
    sock1.listen(1)

    # Connect to 'sockname2' (which should be the same file, perhaps under a
    # different name).
    error, sock2 = ovs.socket_util.make_unix_socket(socket.SOCK_STREAM, False,
                                                    None, sockname2)
    if error:
        sys.stderr.write("%s: connect failed (%s)" % (sockname2,
                                                      os.strerror(error)))
        sys.exit(1)


if __name__ == '__main__':
    main(sys.argv)
