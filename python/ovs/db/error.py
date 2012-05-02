# Copyright (c) 2009, 2010, 2011 Nicira, Inc.
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

import ovs.json


class Error(Exception):
    def __init__(self, msg, json=None, tag=None):
        self.msg = msg
        self.json = json
        if tag is None:
            if json is None:
                self.tag = "ovsdb error"
            else:
                self.tag = "syntax error"
        else:
            self.tag = tag

        # Compose message.
        syntax = ""
        if self.json is not None:
                syntax = 'syntax "%s": ' % ovs.json.to_string(self.json)
        Exception.__init__(self, "%s%s: %s" % (syntax, self.tag, self.msg))
