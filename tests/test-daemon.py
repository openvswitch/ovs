# Copyright (c) 2010, 2011 Nicira, Inc.
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

import argparse
import signal
import sys
import time

import ovs.daemon
import ovs.util


def handler(signum, _):
    raise Exception("Signal handler called with %d" % signum)


def main():

    if sys.platform != 'win32':
        # signal.SIGHUP does not exist on Windows
        signal.signal(signal.SIGHUP, handler)

    parser = argparse.ArgumentParser(
            description="Open vSwitch daemonization test program for Python.")
    parser.add_argument("-b", "--bail", action="store_true",
            help="Exit with an error after daemonize_start().")

    ovs.daemon.add_args(parser)
    args = parser.parse_args()
    ovs.daemon.handle_args(args)

    ovs.daemon.daemonize_start()
    if args.bail:
        sys.stderr.write("%s: exiting after daemonize_start() as requested\n"
                         % ovs.util.PROGRAM_NAME)
        sys.exit(1)
    ovs.daemon.daemonize_complete()

    while True:
        time.sleep(1)


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        # Let system.exit() calls complete normally
        raise
    except:
        sys.exit(ovs.daemon.RESTART_EXIT_CODE)
