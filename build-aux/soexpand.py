#! /usr/bin/env python3

# Copyright (c) 2008, 2017 Nicira, Inc.
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

from build import soutil
import sys


def soexpand(include_dirs, src, dst):
    ok = True
    while True:
        line = src.readline()
        if not line:
            break

        name = soutil.extract_include_directive(line)
        if name:
            fn = soutil.find_file(include_dirs, name)
            if fn:
                try:
                    f = open(fn)
                    while True:
                        inner = f.readline()
                        if not inner:
                            break
                        dst.write(inner)
                except IOError as e:
                    sys.stderr.write("%s: open: %s\n" % (fn, e.strerror))
                    ok = False
                continue
            else:
                ok = False

        dst.write(line)
    return ok


if __name__ == '__main__':
    include_dirs, args = soutil.parse_include_dirs()
    if args:
        error = False
        for arg in args:
            if not soexpand(include_dirs, open(arg), sys.stdout):
                error = True
    else:
        error = not soexpand(include_dirs, sys.stdin, sys.stdout)
    sys.exit(1 if error else 0)
