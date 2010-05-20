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

from OVEConfig import *

class OVEUtil:
    UUID_RE = re.compile(r'([a-f0-9]{8}-[a-f0-9]{2})[a-f0-9]{2}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}')
    
    @classmethod
    def paramToLongString(cls, param):
        if isinstance(param, (types.ListType, types.TupleType)) and len(param) > 1:
            text = str(param[1])
        else:
            text = str(param)

        return text.replace(', ', ',\n')
        
    @classmethod
    def paramToString(cls, param):
        if isinstance(param, (types.ListType, types.TupleType)) and len(param) > 1:
            text = str(param[1])
        else:
            text = str(param)
        if OVEConfig.Inst().truncateUuids:
            text = cls.UUID_RE.sub('\\1...', text)
            
        return text.replace(', ', ',\n')

    @classmethod
    def flowDecodeHeadings(self):
        return [
                'Type',
                'Proto',
                'Inport',
                'VLAN',
                'Source MAC',
                'Destination MAC',
                'Source IP',
                'Destination IP',
                'Src port',
                'Dest port',
                'Packet count',
                'Bytes',
                'Used',
                'Tos',
                'PCP',
                'Tunnel',
                'Actions',
                ]

    @classmethod
    def getFlowColumn(cls, name):
        lowerName = name.lower()
        for i, columnName in enumerate(cls.flowDecodeHeadings()):
            if lowerName == columnName.lower():
                return i
        return None

    ETHERTYPE_TRANS = {
        '05ff':'ESX probe',
        '0800':'IP',
        '0806':'ARP',
        '86dd':'IPv6',
        '88cc':'LLDP'
    }
                  
    ETHERPROTO_TRANS = {
        '1':'ICMP',
        '6':'TCP',
        '17':'UDP'
    }
    
    # Parsing of ovs-dpctl dump-flows output should be localised in this method and flowDecodeHeadings
    @classmethod
    def decodeFlows(cls, srcLines):
        retVal = []
        flowRe = re.compile(
            # To fix this regexp:
            #  Comment out lines, starting from the bottom, until it works, then fix the one you stopped at
            '^' +
            r'tunnel([^:]*):'+ # Tunnel: tunnel00000000
            r'in_port([^:]+):' + # in_port: in_port0002
            r'vlan([^:]+):' + #VLAN: vlan65535
            r'([^ ]*) ' + # PCP: pcp0
            r'mac(.{17})->' + # Source MAC: mac00:16:76:c8:1f:c9->
            r'(.{17}) ' + # Dest MAC: mac00:16:76:c8:1f:c9
            r'type([^ ]+) ' + #Type: type05ff
            r'proto([^ ]+) ' + #Proto: proto0
            r'(tos[^ ]+) ' + #Tos: tos0
            r'ip(\d+\.\d+\.\d+\.\d+)->' + # Source IP: ip1.2.3.4->
            r'(\d+\.\d+\.\d+\.\d+) ' + # Dest IP: 1.2.3.4
            r'port(\d+)->' + # Source port: port0->
            r'(\d+),\s*' + # Dest port: 0
            r'packets:(\d*),\s*' + # Packets: packets:3423,
            r'bytes:(\d*),\s*' + # Bytes: bytes:272024,
            r'used:([^,]+),\s*' + # Used: used:0.870s,
            r'actions:(\w+)\s*' + # Actions: actions:drop
            ''
            )
        for line in srcLines.split('\n'):
            if line != '':
                match = flowRe.match(line)
                if not match:
                    OVELog("Could not decode flow record '"+line+"'.  Abandoning")
                    return retVal
                else:
                    tunnel, inport, vlan, pcp, srcmac, destmac, type, proto, tos, srcip, destip, srcport, destport, packets, bytes, used, actions = match.groups()
                    tunnel = int(tunnel)
                    inport = int(inport)
                    vlan = int(vlan)
                    type = cls.ETHERTYPE_TRANS.get(type, type)
                    proto = cls.ETHERPROTO_TRANS.get(proto, proto)
                    srcport = int(srcport)
                    destport = int(destport)
                    packets = long(packets)
                    bytes = long(bytes)
                    # Order below needs to match that in flowDecodeHeadings
                    retVal.append((type, proto, inport, vlan, srcmac, destmac, srcip, destip, srcport, destport, packets, bytes, used, tos, pcp, tunnel, actions))
                    
        return retVal
        
    COLOURS = [Qt.black, Qt.darkBlue,  Qt.darkRed, Qt.darkGreen, Qt.darkMagenta, Qt.darkCyan, Qt.darkGray, Qt.darkYellow, Qt.blue, Qt.gray, Qt.magenta, Qt.red]
        
    @classmethod
    def intToColour(cls, value):
        return cls.COLOURS[value % len(cls.COLOURS)]
