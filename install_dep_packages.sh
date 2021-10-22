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
WS_DIR=$PWD
echo "WS_DIR: $WS_DIR"

if [ -z "$1" ];
then
    echo "- Missing mandatory arguments:"
    echo " - Usage: ./install_dep_packages.sh <SRC_FOLDER> [INSTALL_FOLDER]"
    exit 1
fi

echo "#### \
THIS SCRIPT INSTALLS THE DEPENDENCY MODULES \
NEEDED FOR P4-OVS COMPILATION/RUNNING \
####"

#First argument is taken as the directory path \
#for the source code and installables scratch area.
SRC_DIR=$1/P4OVS_DEPS_SRC_CODE

echo "Removing  and Creating SOURCE directory, $SRC_DIR"
if [ -d "$SRC_DIR" ]; then rm -rf $SRC_DIR; fi
mkdir -p $SRC_DIR

if [ -z "$2" ];
then
    CMAKE_PREFIX=""
    CONFIG_PREFIX=""
    MAKE_PREFIX=""
else
    INSTALL_DIR=$2/P4OVS_DEPS_INSTALL
    CMAKE_PREFIX="-DCMAKE_INSTALL_PREFIX=$INSTALL_DIR"
    MAKE_PREFIX="prefix=$INSTALL_DIR"
    CONFIG_PREFIX="--prefix=$INSTALL_DIR"
    echo "Removing  and Creating INSTALL scratch directory, $INSTALL_DIR"
    if [ -d "$INSTALL_DIR" ]; then rm -rf $INSTALL_DIR; fi
    mkdir -p $INSTALL_DIR
fi

#Get the OS and Version details
get_os_ver_details
echo "OS and Version details..."
echo "$OS : $VER"
echo ""
#Read the number of CPUs in a system and derive the NUM threads
get_num_cores
echo "Number of Parallel threads used: $NUM_THREADS ..."
echo ""

# Dependencies needed for building netlink library
if [[ $OS =~ "Fedora" ]]; then
    sudo dnf install -y pkgconfig
    sudo dnf install -y libnl3-devel
elif [[ $OS =~ "Ubuntu" ]]; then
    sudo apt-get install -y pkg-config
    sudo apt-get install -y libnl-route-3-dev
else
    sudo yum install -y pkgconfig
    sudo yum install -y libnl3-devel
fi

#gflags source code Repo checkout, Build and Install
MODULE="gflags"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${SRC_DIR}/$MODULE
git clone https://github.com/gflags/gflags.git  ${SRC_DIR}/$MODULE
mkdir -p $SRC_DIR/$MODULE/build
cd $SRC_DIR/$MODULE/build
cmake -DBUILD_SHARED_LIBS=ON $CMAKE_PREFIX ..
make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

#glog source code Repo checkout, Build and Install
MODULE="glog"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${SRC_DIR}/$MODULE
git clone https://github.com/google/glog.git  ${SRC_DIR}/$MODULE
mkdir -p $SRC_DIR/$MODULE/build
cd $SRC_DIR/$MODULE/build
cmake $CMAKE_PREFIX ..
make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

#abseil-cpp source code Repo checkout, Build and Install
MODULE="abseil-cpp"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${SRC_DIR}/$MODULE
git clone https://github.com/abseil/abseil-cpp.git  ${SRC_DIR}/$MODULE
mkdir -p $SRC_DIR/$MODULE/build
cd $SRC_DIR/$MODULE/build
cmake -DBUILD_TESTING=OFF $CMAKE_PREFIX ..
make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

#cctz source code Repo checkout, Build and Install
MODULE="cctz"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${SRC_DIR}/$MODULE
git clone https://github.com/google/cctz.git  ${SRC_DIR}/$MODULE
mkdir -p $SRC_DIR/$MODULE/build
cd $SRC_DIR/$MODULE/build
cmake -DBUILD_TESTING=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON $CMAKE_PREFIX ..
make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

#Protobuf source code Repo checkout, Build and Install
MODULE="protobuf"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${SRC_DIR}/$MODULE
git clone https://github.com/google/protobuf.git  ${SRC_DIR}/$MODULE
cd ${SRC_DIR}/$MODULE
git checkout tags/v3.6.1
./autogen.sh
./configure $CONFIG_PREFIX
make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

#grpc source code Repo checkout, Build and Install
MODULE="grpc"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${SRC_DIR}/$MODULE
git clone https://github.com/google/grpc.git  ${SRC_DIR}/$MODULE
cd ${SRC_DIR}/$MODULE
git checkout tags/v1.17.2
git submodule update --init --recursive
if [[ $OS =~ "Fedora" ]];
then
   git apply $WS_DIR/external/PATCH-01-GRPC
fi
make $NUM_THREADS $MAKE_PREFIX
sudo make $NUM_THREADS $MAKE_PREFIX install
sudo ldconfig

#nlohmann source code Repo checkout, Build and Install
MODULE="json"
echo "####  Cloning, Building and Installing the '$MODULE' module ####"
mkdir -p ${SRC_DIR}/$MODULE
git clone https://github.com/nlohmann/json.git  ${SRC_DIR}/$MODULE
mkdir -p $SRC_DIR/$MODULE/build
cd $SRC_DIR/$MODULE/build
cmake $CMAKE_PREFIX ..
make $NUM_THREADS
sudo make $NUM_THREADS install
sudo ldconfig

set +e
