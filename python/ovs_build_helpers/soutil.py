#!/usr/bin/env python3

# Copyright (c) 2008, 2017, 2020 Nicira, Inc.
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
import os
import re
import sys


def parse_include_dirs():
    include_dirs = []
    options, args = getopt.gnu_getopt(sys.argv[1:], 'I:', ['include='])
    for key, value in options:
        if key in ['-I', '--include']:
            include_dirs.append(value)
        else:
            assert False

    include_dirs.append('.')
    return include_dirs, args


def find_file(include_dirs, name):
    for dir in include_dirs:
        file = "%s/%s" % (dir, name)
        try:
            os.stat(file)
            return file
        except OSError:
            pass
    sys.stderr.write("%s not found in: %s\n" % (name, ' '.join(include_dirs)))
    return None


so_re = re.compile(r'^\.so (\S+)$')


def extract_include_directive(line):
    m = so_re.match(line)
    if m:
        return m.group(1)
    else:
        return None
