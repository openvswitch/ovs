# Copyright (c) 2021 Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#! /bin/bash
set -e

source os_ver_details.sh

if [ -z "$1" ]
then
    echo "- Missing mandatory argument:"
    echo " - Usage: source p4ovs_env_setup.sh <SDE_INSTALL> [P4OVS_DEPS_INSTALL]"
    return 0
fi

export SDE_INSTALL=$1
export P4OVS_DEPS_INSTALL=$2

#Get the OS and Version details
get_os_ver_details
echo "OS and Version details..."
echo "$OS : $VER"

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SDE_INSTALL/lib

#Dependencies needed for building netlink library
if [[ $OS =~ "Fedora" ]]; then
    export PKG_CONFIG_PATH=${SDE_INSTALL}/lib64/pkgconfig
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SDE_INSTALL/lib64
else
    export PKG_CONFIG_PATH=${SDE_INSTALL}/lib/x86_64-linux-gnu/pkgconfig
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SDE_INSTALL/lib/x86_64-linux-gnu
fi

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib64

#...P4-OVS Dependencies Path...#
if [ ! -z "$P4OVS_DEPS_INSTALL" ]
then
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$P4OVS_DEPS_INSTALL/lib
    export PATH=$PATH:$P4OVS_DEPS_INSTALL/bin:$P4OVS_DEPS_INSTALL/sbin
    export LIBRARY_PATH=$P4OVS_DEPS_INSTALL/lib
    export C_INCLUDE_PATH=$P4OVS_DEPS_INSTALL/include
    export CPLUS_INCLUDE_PATH=$P4OVS_DEPS_INSTALL/include
fi

echo ""
echo ""
echo "Updated Environment Variables ..."
echo "SDE_INSTALL: $SDE_INSTALL"
echo "PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
echo "LIBRARY_PATH: $LIBRARY_PATH"
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo "PATH: $PATH"
echo "C_INCLUDE_PATH: $C_INCLUDE_PATH"
echo "CPLUS_INCLUDE_PATH: $CPLUS_INCLUDE_PATH"
echo ""

set +e
