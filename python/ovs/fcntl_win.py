# Copyright (c) 2016 Cloudbase Solutions Srl
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

import errno

import msvcrt

import pywintypes

import win32con

import win32file

LOCK_EX = win32con.LOCKFILE_EXCLUSIVE_LOCK
LOCK_SH = 0  # the default
LOCK_NB = win32con.LOCKFILE_FAIL_IMMEDIATELY
LOCK_UN = 0x80000000  # unlock - non-standard


def lockf(fd, flags, length=0xFFFF0000, start=0, whence=0):
    overlapped = pywintypes.OVERLAPPED()
    hfile = msvcrt.get_osfhandle(fd.fileno())
    if LOCK_UN & flags:
        ret = win32file.UnlockFileEx(hfile, 0, start, length, overlapped)
    else:
        try:
            ret = win32file.LockFileEx(hfile, flags, start, length, overlapped)
        except:
            raise IOError(errno.EAGAIN, "", "")

    return ret


def flock(fd, flags):
    lockf(fd, flags, 0xFFFF0000, 0, 0)
