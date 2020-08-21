#!/usr/bin/env python3
# Copyright (c) 2020 VMware, Inc.
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

# Breaks lines read from stdin into groups using blank lines as
# group separators, then sorts lines within the groups for
# reproducibility.

import re
import sys


# This is copied out of the Python Sorting HOWTO at
# https://docs.python.org/3/howto/sorting.html#sortinghowto
def cmp_to_key(mycmp):
    'Convert a cmp= function into a key= function'
    class K(object):

        def __init__(self, obj, *args):
            self.obj = obj

        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0

        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0

        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0

        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0

        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0

        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0

    return K


u = '[0-9a-fA-F]'
uuid_re = re.compile(r'%s{8}-%s{4}-%s{4}-%s{4}-%s{12}' % ((u,) * 5))


def cmp(a, b):
    return (a > b) - (a < b)


def compare_lines(a, b):
    if uuid_re.match(a):
        if uuid_re.match(b):
            return cmp(a[36:], b[36:])
        else:
            return 1
    elif uuid_re.match(b):
        return -1
    else:
        return cmp(a, b)


def output_group(group, dst):
    for x in sorted(group, key=cmp_to_key(compare_lines)):
        dst.write(x)


def ovsdb_monitor_sort(src, dst):
    group = []
    while True:
        line = src.readline()
        if not line:
            break
        if line.rstrip() == '':
            output_group(group, dst)
            group = []
            dst.write(line)
        elif line.startswith(',') and group:
            group[len(group) - 1] += line
        else:
            group.append(line)
    if group:
        output_group(group, dst)


if __name__ == '__main__':
    ovsdb_monitor_sort(sys.stdin, sys.stdout)
