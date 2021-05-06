# Copyright (c) 2009, 2010 Nicira, Inc.
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
import sys

import ovs.json


def print_json(json):
    if isinstance(json, str):
        print("error: %s" % json)
        return False
    else:
        ovs.json.to_stream(json, sys.stdout)
        sys.stdout.write("\n")
        return True


def parse_multiple(stream):
    buf = stream.read(4096)
    ok = True
    parser = None
    while len(buf):
        if parser is None and buf[0] in " \t\r\n":
            buf = buf[1:]
        else:
            if parser is None:
                parser = ovs.json.Parser()
            n = parser.feed(buf)
            buf = buf[n:]
            if len(buf):
                if not print_json(parser.finish()):
                    ok = False
                parser = None
        if len(buf) == 0:
            buf = stream.read(4096)
    if parser and not print_json(parser.finish()):
        ok = False
    return ok


def main(argv):
    argv0 = argv[0]

    try:
        options, args = getopt.gnu_getopt(argv[1:], '', ['multiple'])
    except getopt.GetoptError as geo:
        sys.stderr.write("%s: %s\n" % (argv0, geo.msg))
        sys.exit(1)

    multiple = False
    for key, value in options:
        if key == '--multiple':
            multiple = True
        else:
            sys.stderr.write("%s: unhandled option %s\n" % (argv0, key))
            sys.exit(1)

    if len(args) != 1:
        sys.stderr.write("usage: %s [--multiple] INPUT.json\n" % argv0)
        sys.exit(1)

    input_file = args[0]
    if input_file == "-":
        stream = sys.stdin
    else:
        stream = open(input_file, "r")

    if multiple:
        ok = parse_multiple(stream)
    else:
        ok = print_json(ovs.json.from_stream(stream))

    if not ok:
        sys.exit(1)


if __name__ == '__main__':
    main(sys.argv)
