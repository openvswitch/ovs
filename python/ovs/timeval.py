# Copyright (c) 2009, 2010 Nicira, Inc.
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

import sys
import time

try:
    import ctypes

    LIBRT = 'librt.so.1'
    clock_gettime_name = 'clock_gettime'

    if sys.platform.startswith("linux"):
        CLOCK_MONOTONIC = 1
        time_t = ctypes.c_long
    elif sys.platform.startswith("netbsd"):
        # NetBSD uses function renaming for ABI versioning.  While the proper
        # way to get the appropriate version is of course "#include <time.h>",
        # it is difficult with ctypes.  The following is appropriate for
        # recent versions of NetBSD, including NetBSD-6.
        LIBRT = 'libc.so.12'
        clock_gettime_name = '__clock_gettime50'
        CLOCK_MONOTONIC = 3
        time_t = ctypes.c_int64
    elif sys.platform.startswith("freebsd"):
        CLOCK_MONOTONIC = 4
        time_t = ctypes.c_int64
    else:
        raise Exception

    class timespec(ctypes.Structure):
        _fields_ = [
            ('tv_sec', time_t),
            ('tv_nsec', ctypes.c_long),
        ]

    librt = ctypes.CDLL(LIBRT)
    clock_gettime = getattr(librt, clock_gettime_name)
    clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(timespec)]
except:
    # Librt shared library could not be loaded
    librt = None


def monotonic():
    if not librt:
        return time.time()

    t = timespec()
    if clock_gettime(CLOCK_MONOTONIC, ctypes.pointer(t)) == 0:
        return t.tv_sec + t.tv_nsec * 1e-9
    # Kernel does not support CLOCK_MONOTONIC
    return time.time()


# Use time.monotonic() if Python version >= 3.3
if not hasattr(time, 'monotonic'):
    time.monotonic = monotonic


def msec():
    """ Returns the system's monotonic time if possible, otherwise returns the
    current time as the amount of time since the epoch, in milliseconds, as a
    float."""
    return time.monotonic() * 1000.0


def postfork():
    # Just a stub for now
    pass
