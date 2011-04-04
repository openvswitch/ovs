# Copyright (c) 2010, 2011 Nicira Networks.
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

import getopt
import logging
import signal
import sys
import time

import ovs.daemon
import ovs.util

def handler(signum, frame):
    raise Exception("Signal handler called with %d" % signum)

def main(argv):
    logging.basicConfig(level=logging.DEBUG)

    signal.signal(signal.SIGHUP, handler)

    try:
        options, args = getopt.gnu_getopt(
            argv[1:], 'b', ["bail", "help"] + ovs.daemon.LONG_OPTIONS)
    except getopt.GetoptError, geo:
        sys.stderr.write("%s: %s\n" % (ovs.util.PROGRAM_NAME, geo.msg))
        sys.exit(1)

    bail = False
    for key, value in options:
        if key == '--help':
            usage()
        elif key in ['-b', '--bail']:
            bail = True
        elif not ovs.daemon.parse_opt(key, value):
            sys.stderr.write("%s: unhandled option %s\n"
                             % (ovs.util.PROGRAM_NAME, key))
            sys.exit(1)

    ovs.daemon.daemonize_start()
    if bail:
        sys.stderr.write("%s: exiting after daemonize_start() as requested\n"
                         % ovs.util.PROGRAM_NAME)
        sys.exit(1)
    ovs.daemon.daemonize_complete()

    while True:
        time.sleep(1)

def usage():
    sys.stdout.write("""\
%s: Open vSwitch daemonization test program for Python
usage: %s [OPTIONS]
""" % ovs.util.PROGRAM_NAME)
    ovs.daemon.usage()
    sys.stdout.write("""
Other options:
  -h, --help              display this help message
  -b, --bail              exit with an error after daemonize_start()
""")
    sys.exit(0)

if __name__ == '__main__':
    try:
        main(sys.argv)
    except SystemExit:
        # Let system.exit() calls complete normally
        raise
    except:
        sys.exit(ovs.daemon.RESTART_EXIT_CODE)
