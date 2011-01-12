# Copyright (c) 2010, 2011 Nicira Networks
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

def abs_file_name(dir, file_name):
    """If 'file_name' starts with '/', returns a copy of 'file_name'.
    Otherwise, returns an absolute path to 'file_name' considering it relative
    to 'dir', which itself must be absolute.  'dir' may be None or the empty
    string, in which case the current working directory is used.

    Returns None if 'dir' is null and getcwd() fails.

    This differs from os.path.abspath() in that it will never change the
    meaning of a file name."""
    if file_name.startswith('/'):
        return file_name
    else:
        if dir is None or dir == "":
            try:
                dir = os.getcwd()
            except OSError:
                return None

        if dir.endswith('/'):
            return dir + file_name
        else:
            return "%s/%s" % (dir, file_name)
