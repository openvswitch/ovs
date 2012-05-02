# Copyright (c) 2011 Nicira, Inc.
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

import ovs.vlog


def main():
    modules = [ovs.vlog.Vlog("module_%d" % i) for i in xrange(3)]

    parser = argparse.ArgumentParser(description="Vlog Module Tester")
    ovs.vlog.add_args(parser)
    args = parser.parse_args()
    ovs.vlog.handle_args(args)

    for m in modules:
        m.emer("emergency")
        m.err("error")
        m.warn("warning")
        m.info("information")
        m.dbg("debug")

        try:
            fail = False  # Silence pychecker warning.
            assert fail
        except AssertionError:
            m.emer("emergency exception", exc_info=True)
            m.err("error exception", exc_info=True)
            m.warn("warn exception", exc_info=True)
            m.info("information exception", exc_info=True)
            m.dbg("debug exception", exc_info=True)
            m.exception("exception")


if __name__ == '__main__':
    main()
