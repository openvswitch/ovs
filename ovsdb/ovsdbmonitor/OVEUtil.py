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

from OVEConfig import *
import re

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
        for line in srcLines.split('\n'):
            if line != '':
                fields = {}
                for name, val in re.findall(r'([a-zA-Z0-9_+]+)\(([^)]+)\)', line):
                    if '=' in val:
                        for setting in val.split(','):
                            k,v = setting.split('=')
                            fields['%s.%s' % (name, k)] = v
                    else:
                        fields[name] = val
                for setting in re.split(', ', line)[1:]:
                    if ':' in setting:
                        k,v = setting.split(':')
                        fields[k] = v

                tun_id = fields.get('tun_id', '')
                in_port = int(fields.get('in_port', 0))
                eth_src = fields.get('eth.src', '')
                eth_dst = fields.get('eth.dst', '')
                vlan_vid = int(fields.get('vlan.vid', 0))
                vlan_pcp = int(fields.get('vlan.pcp', 0))
                eth_type = fields.get('eth_type', '')
                ip_src = fields.get('ipv4.src', fields.get('ipv6.src', ''))
                ip_dst = fields.get('ipv4.dst', fields.get('ipv6.dst', ''))
                ip_proto = fields.get('ipv4.proto', fields.get('ipv6.proto', ''))
                ip_tos = fields.get('ipv4.tos', fields.get('ipv6.tos', ''))
                tp_src = fields.get('tcp.src', fields.get('udp.src', fields.get('arp.sip', fields.get('icmp.type', fields.get('icmpv6.type', '')))))
                tp_dst = fields.get('tcp.dst', fields.get('udp.dst', fields.get('arp.tip', fields.get('icmp.code', fields.get('icmpv6.code', '')))))

                packets = fields.get('packets', '')
                bytes = fields.get('bytes', '')
                actions = fields.get('actions', '')
                used = fields.get('used', '')

                # Order below needs to match that in flowDecodeHeadings
                retVal.append((eth_type, ip_proto, in_port, vlan_vid, eth_src, eth_dst, ip_src, ip_dst, tp_src, tp_dst, packets, bytes, used, ip_tos, vlan_pcp, tun_id, actions))
                    
        return retVal
        
    COLOURS = [Qt.black, Qt.darkBlue,  Qt.darkRed, Qt.darkGreen, Qt.darkMagenta, Qt.darkCyan, Qt.darkGray, Qt.darkYellow, Qt.blue, Qt.gray, Qt.magenta, Qt.red]
        
    @classmethod
    def intToColour(cls, value):
        return cls.COLOURS[value % len(cls.COLOURS)]
