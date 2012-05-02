# Copyright (c) 2011 Nicira, Inc.
# Copyright (c) 2010 Citrix Systems, Inc.
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

import os, re, struct, sys, time, types, uuid
from copy import deepcopy
from pprint import pprint

# Set globalForcePySide to True to use PySide instead of PyQt if both are installed
globalForcePySide = False

try:
    import ovs.json
except Exception, e:
    print('+++ OVS JSON module is required\n')
    raise

try:
    if globalForcePySide:
        print('Forcing use of PySide')
        raise Exception()
    from PyQt4.QtCore import Qt, QVariant
    from PyQt4 import QtCore, QtGui
except:
    try:
        from PySide.QtCore import Qt, QVariant
        from PySide import QtCore, QtGui
    except Exception, e:
        print('+++ This application requires either PyQt4 or PySide\n')
        raise

