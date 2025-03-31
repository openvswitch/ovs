# Copyright (c) 2021 Red Hat, Inc.
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
import subprocess


class DpPortMapping:
    """Class used to retrieve and cache datapath port numbers to port names."""

    def __init__(self):
        self.cache_map = None

    def get_map(self):
        """Get the cache map."""
        if not self.cache_map:
            self._get_mapping()

        return self.cache_map

    def set_map(self, cache_map):
        """Override the internal cache map."""
        self.cache_map = cache_map

    def get_port_name(self, dp, port_no):
        """Get the port name from a port number."""
        if self.cache_map is None:
            self._get_mapping()

        if not self.cache_map.get(dp):
            return None

        for name, num in self.cache_map[dp].items():
            if num == port_no:
                return name

        return None

    def get_port_number(self, dp, port):
        """Get the port number from a port name."""
        if self.cache_map is None:
            self._get_mapping()

        return self.cache_map.get(dp, {}).get(port, None)

    def _get_mapping(self):
        """Get the datapath port mapping from the running OVS."""
        try:
            output = subprocess.check_output(
                ["ovs-appctl", "dpctl/show"], encoding="utf8"
            ).split("\n")
        except subprocess.CalledProcessError:
            output = ""
            return

        current_dp = None
        self.cache_map = {}

        for line in output:
            match = re.match("^system@(.*):$", line)
            if match:
                current_dp = match.group(1)

            match = re.match("^  port ([0-9]+): ([^ /]*)", line)
            if match and current_dp:
                try:
                    self.cache_map[current_dp][match.group(2)] = int(
                        match.group(1)
                    )
                except KeyError:
                    self.cache_map[current_dp] = {
                        match.group(2): int(match.group(1))
                    }
