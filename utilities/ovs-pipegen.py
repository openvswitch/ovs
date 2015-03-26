#!/usr/bin/python
# Copyright (c) 2013, 2014, 2015 Nicira, Inc.
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
import random
import sys
import textwrap

def flow_str(stage, match, action, priority=32768):
    mtd_match = "metadata=%d" % stage
    if match:
        mtd_match += "," + match

    return "priority=%d %s,actions=%s" % (priority, mtd_match, action)


def resubmit(nxt):
    return "load:%d->OXM_OF_METADATA[],resubmit(,0)" % nxt


def rand_ip_mask():
    return ("%d.%d.%d.%d" % (random.randint(0, 255), random.randint(0, 255),
                             random.randint(0, 255), random.randint(0, 255)),
            random.choice([8, 16, 24, 32]))


def rand_bool():
    return bool(random.randint(0, 1))


def l2(stage, action):
    mac = ["%x" % random.randint(0, 2 ** 8 - 1) for x in range(6)]
    mac = [x.zfill(2) for x in mac]
    mac = ":".join(mac)
    return flow_str(stage, "dl_dst=%s" % mac, action)


def l3(stage, action):
    ip, mask = rand_ip_mask()
    return flow_str(stage, "ip,ip_dst=%s/%d" % (ip, mask), action,
                    priority=mask)


def l4(stage, action):
    match = "tcp"

    if rand_bool():
        match += ",ip_src=%s/%d" % rand_ip_mask()

    if rand_bool():
        match += ",ip_dst=%s/%d" % rand_ip_mask()

    src_dst = "tp_src" if rand_bool() else "tp_dst"
    match += ",%s=%d" % (src_dst, random.randint(1024, 2**16 - 1))
    return flow_str(stage, match, action)


def pipeline(size):
    pipeline = [l2, l3, l4, l2]

    flows = []
    for stage in xrange(len(pipeline)):
        action = resubmit(stage + 1)
        flows += [pipeline[stage](stage, action) for _ in xrange(size)]
        flows.append(flow_str(stage, "", action, priority=1))

    flows.append(flow_str(len(pipeline), "", "in_port"))

    for f in flows:
        print f


def main():
    description = textwrap.dedent(
        """
        Generate a test OpenFlow pipeline.

        Open vSwitch relies heavily on flow caching to get good performance for
        packet processing.  While on average, this produces good results,
        performance is heavily depedent on the slow path OpenFlow tables, and
        how they're translated into datapath megaflows.  For this reason, when
        doing performance testing it's important to run with "realistic"
        OpenFlow tables to ensure results will stand up in the real world.

        This script generates a simple OpenFlow pipeline intended to simulate
        realistic network virtualization workloads.  All traffic received is
        run through a series of OpenFlow tables designed to simulate a logical
        switch, router, and firewall, before forwarded back on the in_port.
        """)

    epilog = textwrap.dedent(
        """
        typical usage:
          ovs-ofctl del-flows bridge \\
          && %s | ovs-ofctl add-flows bridge - \\
          && ovs-ofctl dump-flows bridge
        """ % sys.argv[0])

    parser = argparse.ArgumentParser(description=description, epilog=epilog,
                                     formatter_class=\
                                     argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--size", dest="size", default=1000,
                        help="Size (rules) of each OpenFlow table.")
    args=parser.parse_args()

    pipeline(int(args.size))


if __name__ == "__main__":
    main()
