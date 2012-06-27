# Copyright (c) 2011, 2012 Nicira, Inc.
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

import re

def xapi_local():
    return Session()


class Session(object):
    def __init__(self):
        self.xenapi = XenAPI()


class Failure(Exception):
    pass


class XenAPI(object):
    def __init__(self):
        self.network = Network()
        self.pool = Pool()
        self.VIF = VIF()
        self.VM = VM()

    def login_with_password(self, unused_username, unused_password):
        pass


class RecordRef(object):
    def __init__(self, attrs):
        self.attrs = attrs


class Table(object):
    def __init__(self, records):
        self.records = records

    def get_all(self):
        return [RecordRef(rec) for rec in self.records]

    def get_all_records_where(self, condition):
        k, v = re.match(r'field "([^"]*)"="([^"]*)"$', condition).groups()
        d = {}

        # I'm sure that the keys used in the dictionary below are wrong
        # but I can't find any documentation on get_all_records_where
        # and this satisfies the current test case.
        i = 0
        for rec in self.records:
            if rec[k] == v:
                d[i] = rec
                i += 1
        return d

    def get_by_uuid(self, uuid):
        recs = [rec for rec in self.records if rec["uuid"] == uuid]
        if len(recs) != 1:
            raise Failure("No record with UUID %s" % uuid)
        return RecordRef(recs[0])

    def get_record(self, record_ref):
        return record_ref.attrs


class Network(Table):
    __records = ({"uuid": "9b66c68b-a74e-4d34-89a5-20a8ab352d1e",
                  "bridge": "xenbr0",
                  "other_config":
                      {"vswitch-controller-fail-mode": "secure",
                       "nicira-bridge-id": "custom bridge ID"}},
                 {"uuid": "e1c9019d-375b-45ac-a441-0255dd2247de",
                  "bridge": "xenbr1",
                  "other_config":
                      {"vswitch-disable-in-band": "true"}})

    def __init__(self):
        Table.__init__(self, Network.__records)


class Pool(Table):
    __records = ({"uuid": "7a793edf-e5f4-4994-a0f9-cee784c0cda3",
                  "other_config":
                      {"vswitch-controller-fail-mode": "secure"}},)

    def __init__(self):
        Table.__init__(self, Pool.__records)

class VIF(Table):
    __records = ({"uuid": "6ab1b260-398e-49ba-827b-c7696108964c",
                  "other_config":
                      {"nicira-iface-id": "custom iface ID"}},)

    def __init__(self):
        Table.__init__(self, VIF.__records)

class VM(Table):
    __records = ({"uuid": "fcb8a3f6-dc04-41d2-8b8a-55afd2b755b8",
                  "other_config":
                      {"nicira-vm-id": "custom vm ID"}},)

    def __init__(self):
        Table.__init__(self, VM.__records)
