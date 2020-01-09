#!/usr/bin/env python

import re
import sys


def lookup_uuid(uuids, match):
    return "<%s>" % uuids.setdefault(match.group(0), len(uuids))


int_re = re.compile(r'\d+')


def sort_set(match):
    s = match.group(0)
    uuids = sorted([int(x) for x in int_re.findall(s)])
    return '["set",[' + ','.join('["uuid","<%s>"]' % x for x in uuids) + ']]'


u = '[0-9a-fA-F]'
uuid_re = re.compile(r'%s{8}(?<!ffffffff)-%s{4}-%s{4}-%s{4}-%s{12}'
                     % ((u,) * 5))
set_re = re.compile(r'(\["set",\[(,?\["uuid","<\d+>"\])+\]\])')


def filter_uuids(src, dst):
    uuids = {}

    def lf(match):
        return lookup_uuid(uuids, match)

    while True:
        line = src.readline()
        if not line:
            break
        line = uuid_re.sub(lf, line)

        # Sort sets like this:
        #    [["uuid","<1>"],["uuid","<0>"]]
        # to look like this:
        #    [["uuid","<0>"],["uuid","<1>"]]
        line = set_re.sub(sort_set, line)
        dst.write(line)


if __name__ == '__main__':
    if '--help' in sys.argv:
        print("""\
uuidfilt, for filtering UUIDs into numbered markers
usage: %s [INPUT..] > OUTPUT
    or %s < INPUT > OUTPUT

Reads each INPUT, locates UUIDs in the standard textual form, and
converts them into numbered markers <0>, <1>, ..., <n>, where <0>
stands in for each instance of the first unique UUID found, <1> for
each instance of the second, and so on.

UUIDs that begin with ffffffff are not converted to markers.
""")
    elif len(sys.argv) > 1:
        for src in sys.argv[1:]:
            filter_uuids(open(src), sys.stdout)
    else:
        filter_uuids(sys.stdin, sys.stdout)
