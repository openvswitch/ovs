#!/bin/sh
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

KERNEL_VERSION=$1
OVS_BRANCH=$2
GITHUB_SRC=$3

# Install deps
build_deps="apt-utils libelf-dev build-essential libssl-dev python3 \
wget gdb autoconf libtool git automake bzip2 debhelper dh-autoreconf openssl"

apt-get update
if [ $KERNEL_VERSION != "host" ]; then
    linux="linux-image-$KERNEL_VERSION linux-headers-$KERNEL_VERSION"
    apt-get install -y ${linux}
fi

apt-get install -y ${build_deps}

# get the source
mkdir /build; cd /build
git clone --depth 1 -b $OVS_BRANCH $GITHUB_SRC
cd ovs

# build and install
./boot.sh

config="./configure --localstatedir="/var" --sysconfdir="/etc" --prefix="/usr"
--enable-ssl"

if [ $KERNEL_VERSION = "host" ]; then
   eval $config
else
    withlinux=" --with-linux=/lib/modules/$KERNEL_VERSION/build"
    eval $config$withlinux
fi

make -j8; make install; make modules_install

# remove deps to make the container light weight.
apt-get remove --purge -y ${build_deps}
apt-get autoremove -y --purge
cd ..; rm -rf ovs
basic_utils="vim kmod net-tools uuid-runtime iproute2"
apt-get install -y ${basic_utils}