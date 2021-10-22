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

if [ -z "$1" ]
then
    echo "- Missing mandatory argument:"
    echo " - Usage: ./build_p4ovs.sh <SDE_INSTALL_PATH> [P4OVS_DEPS_INSTALL_PATH]"
    exit 1
fi

SDE_INSTALL_PATH=$1
DEPS_INSTALL_PATH=$2

echo $SDE_INSTALL_PATH
echo $DEPS_INSTALL_PATH

if [ ! -z "$DEPS_INSTALL_PATH" ]
then
    source p4ovs_env_setup.sh $SDE_INSTALL_PATH $DEPS_INSTALL_PATH
else
    source p4ovs_env_setup.sh $SDE_INSTALL_PATH
fi

./apply_stratum_artifacts.sh $SDE_INSTALL_PATH
./fix_sde_libs.sh $SDE_INSTALL_PATH

# P4-OVS build process starts here
./boot.sh
if [ ! -z "$DEPS_INSTALL_PATH" ]
then
    ./configure --prefix=$DEPS_INSTALL_PATH --with-p4tdi=$SDE_INSTALL_PATH CFLAGS='-O0 -g'
else
    ./configure --with-p4tdi=$SDE_INSTALL_PATH CFLAGS='-O0 -g'
fi

#Read the number of CPUs in a system and derive the NUM threads
get_num_cores
echo ""
echo "Number of Parallel threads used: $NUM_THREADS ..."
echo ""
make clean
make $NUM_THREADS
make $NUM_THREADS install

set +e
