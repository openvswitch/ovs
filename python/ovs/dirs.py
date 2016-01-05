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

# The @variables@ in this file are replaced by default directories for
# use in python/ovs/dirs.py in the source directory and replaced by the
# configured directories for use in the installed python/ovs/dirs.py.
#
import os

# Note that the use of """ is to aid in dealing with paths with quotes in them.
PKGDATADIR = os.environ.get("OVS_PKGDATADIR", """/usr/local/share/openvswitch""")
RUNDIR = os.environ.get("OVS_RUNDIR", """/var/run""")
LOGDIR = os.environ.get("OVS_LOGDIR", """/usr/local/var/log""")
BINDIR = os.environ.get("OVS_BINDIR", """/usr/local/bin""")

DBDIR = os.environ.get("OVS_DBDIR")
if not DBDIR:
    sysconfdir = os.environ.get("OVS_SYSCONFDIR")
    if sysconfdir:
        DBDIR = "%s/openvswitch" % sysconfdir
    else:
        DBDIR = """/usr/local/etc/openvswitch"""
