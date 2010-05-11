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

from OVEStandard import *

class OVELogger(QtCore.QObject):
    instance = None
    def __init__(self):
        QtCore.QObject.__init__(self)
        self.contents = []
        self.loggers = []
        
    @classmethod
    def Inst(cls):
        if cls.instance is None:
            cls.instance = OVELogger()
        return cls.instance
    
    def reset(self):
        self.contents = []
        self.update()
    
    def logString(self, message):
        self.contents += [str(message)]
        if len(self.contents) > 500:
            self.contents = ['+++ Log truncated', ''] + self.contents[50:]
        self.update()

    def update(self):
        self.emit(QtCore.SIGNAL("logUpdated()"))
        
def OVELog(message):
    OVELogger.Inst().logString(message)
    
