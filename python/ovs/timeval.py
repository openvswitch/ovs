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

import time

LIBRT = 'librt.so.1'
CLOCK_MONOTONIC = 1

try:
    import ctypes

    class timespec(ctypes.Structure):
        _fields_ = [
            ('tv_sec', ctypes.c_long),
            ('tv_nsec', ctypes.c_long),
        ]

    librt = ctypes.CDLL(LIBRT)
    clock_gettime = librt.clock_gettime
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
    """Returns the current time, as the amount of time since the epoch, in
    milliseconds, as a float."""
    return time.monotonic() * 1000.0


def postfork():
    # Just a stub for now
    pass
