#! /usr/bin/env python3

# Copyright (c) 2008, 2011, 2017 Nicira, Inc.
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


def sodepends(include_dirs, filenames, dst):
    ok = True
    print("# Generated automatically -- do not modify!    "
          "-*- buffer-read-only: t -*-")
    for toplevel in sorted(filenames):
        # Skip names that don't end in .in.
        if not toplevel.endswith('.in'):
            continue

        # Open file.
        fn = soutil.find_file(include_dirs, toplevel)
        if not fn:
            ok = False
            continue
        try:
            outer = open(fn)
        except IOError as e:
            sys.stderr.write("%s: open: %s\n" % (fn, e.strerror))
            ok = False
            continue

        dependencies = []
        while True:
            line = outer.readline()
            if not line:
                break

            name = soutil.extract_include_directive(line)
            if name:
                if soutil.find_file(include_dirs, name):
                    dependencies.append(name)
                else:
                    ok = False

        dst.write("\n%s:" % toplevel[:-3])
        for s in [toplevel] + sorted(dependencies):
            dst.write(' \\\n\t%s' % s)
        dst.write('\n')
        for s in [toplevel] + sorted(dependencies):
            dst.write('%s:\n' % s)
    return ok


if __name__ == '__main__':
    include_dirs, args = soutil.parse_include_dirs()
    error = not sodepends(include_dirs, args, sys.stdout)
    sys.exit(1 if error else 0)
