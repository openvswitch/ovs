# Copyright (c) 2010, 2011 Nicira, Inc.
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

import os
import signal


def _signal_status_msg(type_, signr):
    s = "%s by signal %d" % (type_, signr)
    for name in signal.__dict__:
        if name.startswith("SIG") and getattr(signal, name) == signr:
            return "%s (%s)" % (s, name)
    return s


def status_msg(status):
    """Given 'status', which is a process status in the form reported by
    waitpid(2) and returned by process_status(), returns a string describing
    how the process terminated."""
    if os.WIFEXITED(status):
        s = "exit status %d" % os.WEXITSTATUS(status)
    elif os.WIFSIGNALED(status):
        s = _signal_status_msg("killed", os.WTERMSIG(status))
    elif os.WIFSTOPPED(status):
        s = _signal_status_msg("stopped", os.WSTOPSIG(status))
    else:
        s = "terminated abnormally (%x)" % status
    if os.WCOREDUMP(status):
        s += ", core dumped"
    return s
