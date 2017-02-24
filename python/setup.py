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

from distutils.command.build_ext import build_ext
from distutils.errors import CCompilerError, DistutilsExecError, \
    DistutilsPlatformError

import setuptools

VERSION = "unknown"

try:
    # Try to set the version from the generated ovs/version.py
    exec(open("ovs/version.py").read())
except IOError:
    print("Ensure version.py is created by running make python/ovs/version.py",
          file=sys.stderr)
    sys.exit(-1)

ext_errors = (CCompilerError, DistutilsExecError, DistutilsPlatformError)
if sys.platform == 'win32':
    ext_errors += (IOError, ValueError)


class BuildFailed(Exception):
    pass


class try_build_ext(build_ext):
    # This class allows C extension building to fail
    # NOTE: build_ext is not a new-style class

    def run(self):
        try:
            build_ext.run(self)
        except DistutilsPlatformError:
            raise BuildFailed()

    def build_extension(self, ext):
        try:
            build_ext.build_extension(self, ext)
        except ext_errors:
            raise BuildFailed()


setup_args = dict(
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
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    ext_modules=[setuptools.Extension("ovs._json", sources=["ovs/_json.c"],
                                      libraries=['openvswitch'])],
    cmdclass={'build_ext': try_build_ext},
)

try:
    setuptools.setup(**setup_args)
except BuildFailed:
    BUILD_EXT_WARNING = ("WARNING: The C extension could not be compiled, "
                         "speedups are not enabled.")
    print("*" * 75)
    print(BUILD_EXT_WARNING)
    print("Failure information, if any, is above.")
    print("Retrying the build without the C extension.")
    print("*" * 75)

    del(setup_args['cmdclass'])
    del(setup_args['ext_modules'])
    setuptools.setup(**setup_args)
