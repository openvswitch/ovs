# Copyright (c) 2010, 2011, 2012 Nicira, Inc.
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
import os.path
import sys

PROGRAM_NAME = os.path.basename(sys.argv[0])
EOF = -1


def abs_file_name(dir_, file_name):
    """If 'file_name' starts with '/', returns a copy of 'file_name'.
    Otherwise, returns an absolute path to 'file_name' considering it relative
    to 'dir_', which itself must be absolute.  'dir_' may be None or the empty
    string, in which case the current working directory is used.

    Returns None if 'dir_' is None and getcwd() fails.

    This differs from os.path.abspath() in that it will never change the
    meaning of a file name.

    On Windows an absolute path contains ':' ( i.e: C:\ ) """
    if file_name.startswith('/') or file_name.find(':') > -1:
        return file_name
    else:
        if dir_ is None or dir_ == "":
            try:
                dir_ = os.getcwd()
            except OSError:
                return None

        if dir_.endswith('/'):
            return dir_ + file_name
        else:
            return "%s/%s" % (dir_, file_name)


def ovs_retval_to_string(retval):
    """Many OVS functions return an int which is one of:
    - 0: no error yet
    - >0: errno value
    - EOF: end of file (not necessarily an error; depends on the function
      called)

    Returns the appropriate human-readable string."""

    if not retval:
        return ""
    if retval > 0:
        return os.strerror(retval)
    if retval == EOF:
        return "End of file"
    return "***unknown return value: %s***" % retval


def ovs_error(err_no, message, vlog=None):
    """Prints 'message' on stderr and emits an ERROR level log message to
    'vlog' if supplied.  If 'err_no' is nonzero, then it is formatted with
    ovs_retval_to_string() and appended to the message inside parentheses.

    'message' should not end with a new-line, because this function will add
    one itself."""

    err_msg = "%s: %s" % (PROGRAM_NAME, message)
    if err_no:
        err_msg += " (%s)" % ovs_retval_to_string(err_no)

    sys.stderr.write("%s\n" % err_msg)
    if vlog:
        vlog.err(err_msg)


def ovs_fatal(*args, **kwargs):
    """Prints 'message' on stderr and emits an ERROR level log message to
    'vlog' if supplied.  If 'err_no' is nonzero, then it is formatted with
    ovs_retval_to_string() and appended to the message inside parentheses.
    Then, terminates with exit code 1 (indicating a failure).

    'message' should not end with a new-line, because this function will add
    one itself."""

    ovs_error(*args, **kwargs)
    sys.exit(1)
