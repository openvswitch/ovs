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

from __future__ import print_function
import sys

import setuptools

VERSION = "unknown"

try:
    # Try to set the version from the generated ovs/version.py
    execfile("ovs/version.py")
except IOError:
    print("Ensure version.py is created by running make python/ovs/version.py",
          file=sys.stderr)
    sys.exit(-1)


setuptools.setup(
    name='ovs',
    description='Open vSwitch library',
    version=VERSION,
    url='http://www.openvswitch.org/',
    author='Open vSwitch',
    author_email='dev@openvswitch.org',
    packages=['ovs', 'ovs.db', 'ovs.unixctl'],
    keywords=['openvswitch', 'ovs', 'OVSDB'],
    license='Apache 2.0',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Topic :: Database :: Front-Ends',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: Apache Software License'
    ]
)
