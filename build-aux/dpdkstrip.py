#! /usr/bin/env python3
# Copyright (c) 2017 Red Hat, Inc.
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


def strip_dpdk(check_dpdk, src, dst):
    disabled_print = False
    while True:
        line = src.readline()
        if not line:
            break
        if '@begin_dpdk@' in line or '@end_dpdk@' in line:
            if not check_dpdk:
                disabled_print = not disabled_print
            continue
        if not disabled_print:
            dst.write(line)


if __name__ == '__main__':
    check_dpdk = False
    options, args = getopt.gnu_getopt(sys.argv[1:], '', ['dpdk', 'nodpdk'])
    for key, value in options:
        if key == '--dpdk':
            check_dpdk = True
        elif key == '--nodpdk':
            check_dpdk = False
        else:
            assert False
    if args:
        for arg in args:
            strip_dpdk(check_dpdk, open(arg), sys.stdout)
    else:
        strip_dpdk(check_dpdk, sys.stdin, sys.stdout)
