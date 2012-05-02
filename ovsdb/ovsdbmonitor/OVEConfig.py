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

from OVEStandard import *
from OVELogger import *
import ovs.json

def str_recursive(x):
    t = type(x)
    if t == unicode:
        return str(x)
    elif t == list:
        return [str_recursive(_) for _ in x]
    elif t == dict:
        out = {}
        for k,v in x.iteritems():
            out[str_recursive(k)] = str_recursive(v)
        return out
    else:
        return x

class OVEConfig(QtCore.QObject):
    instance = None
    def __init__(self):
        QtCore.QObject.__init__(self)
        self.hosts = []
        self.logTraffic = True
        self.truncateUuids = True
        self.ssgList = []
        
    @classmethod
    def Inst(cls):
        if cls.instance is None:
            cls.instance = OVEConfig()
            cls.instance.loadConfig()
        return cls.instance

    def hostFromUuid(self, uuid):
        for host in self.hosts:
            if host['uuid'] == uuid:
                return host
        OVELog("+++ Couldn't find host '"+str(uuid)+"' in "+str([x['uuid'] for x in self.hosts]))
        return None

    def saveConfig(self):
        settings = QtCore.QSettings()
        settings.setValue('config/hosts', QVariant(ovs.json.to_string((self.hosts))))
        settings.setValue('config/logTraffic', QVariant(self.logTraffic))
        settings.setValue('config/truncateUuids', QVariant(self.truncateUuids))
        settings.setValue('config/ssgList', QVariant(ovs.json.to_string(self.ssgList)))
        settings.sync()
        self.emitUpdated()

    def loadConfig(self):
        settings = QtCore.QSettings()
        jsonText = unicode(settings.value('config/hosts', QVariant('[]')).toString())
        self.hosts = str_recursive(ovs.json.from_string(str(jsonText)))
        self.logTraffic = settings.value('config/logTraffic', QVariant(False)).toBool()
        self.truncateUuids = settings.value('config/truncateUuids', QVariant(False)).toBool()
        jsonText = unicode(settings.value('config/ssgList', QVariant('[]')).toString())
        self.ssgList = ovs.json.from_string(str(jsonText))
        if len(self.ssgList) == 0:
            self.ssgList = [
                r'in_port0000',
                r'in_port0001',
                r'in_port0002',
                r'in_port0003',
                r'vlan65535',
                r'type0800',
                r'type0806',
                r'proto0',
                r'proto6',
                r'proto17',
                r'ff:ff:ff:ff:ff:ff',
                r'!ff:ff:ff:ff:ff:ff',
                r'0\.0\.0\.0',
                r'!0\.0\.0\.0',
                r'255\.255\.255\.255',
                r'!255\.255\.255\.255',
                r'never',
                r'drop',
                r'!never',
                r'!drop',
                r'(never|drop)',
                r'!(never|drop)'
            ]
        
    def emitUpdated(self):
        self.emit(QtCore.SIGNAL("configUpdated()"))
