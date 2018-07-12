#!/bin/sh

# Copyright (c) 2018 Nicira/VMware, Inc.
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

# This version of the script is intended to be used on kernel version
# 3.10.0 major revision 693 only. It is packaged in the openvswitch kmod RPM
# built using the rhel6 spec file, and run in the post-install for minor 
# revision 693 kernels.
#
# Due to some backward incompatible changes introduced in minor revision 17.1,
# kernel modules built against kernels newer than 17.1 cannot be loaded on
# system running kernels older than 17.1, vice versa.
#
# This script checks the current running kernel version, and update symlinks
# for the openvswitch kernel modules in the appropriate kernel directory,
# provided the kmod RPM has installed kernel modules files built from both
# 1.1 and 17.1 minor revisions.
# 
# In case of a kernel minor revision change after the openvswitch kmod package
# is installed, this script shall be run manually after system reboots and
# switches to a different kernel
script_name=$(basename -- "$0")
current_kernel=$(uname -r)
echo current kernel is $current_kernel

IFS=. read installed_major installed_minor installed_micro \
    installed_arch installed_build <<<"${current_kernel##*-}"
# echo installed_major=$installed_major installed_minor=$installed_minor \
# installed_micro=$installed_micro installed_arch=$installed_arch \
# installed_build=$installed_build

expected_base_minor="el7"
expected_minor=11

found_match=false
for kname in `ls -d /lib/modules/*`
do
    IFS=. read major minor micro arch build <<<"${kname##*-}"
#   echo major=$major minor=$minor micro=$micro arch=$arch build=$build
    if [ "$installed_minor" = "$expected_base_minor" ] ||
       [ "$installed_minor" -le "$expected_minor" ]; then
        if [ "$minor" = "1" ]; then
            requested_kernel=$kname
            found_match="true"
            echo "Installing Openvswitch KMOD from kernel $kname"
            break
        fi
    else
        if [ "$minor" = "17" ]; then
            requested_kernel=$kname
            found_match="true"
            echo "Installing Openvswitch KMOD from kernel $kname"
            break
        fi
    fi
done

if [ "$found_match" = "false" ]; then
    echo $script_name: Failed
    exit 1
fi

if [ "$requested_kernel" != "/lib/modules/$current_kernel" ]; then
    if [ -x "/sbin/weak-modules" ]; then
        if [ ! -d /lib/modules/$current_kernel/weak-updates/openvswitch ]; then
            mkdir -p /lib/modules/$current_kernel/weak-updates
            mkdir -p /lib/modules/$current_kernel/weak-updates/openvswitch
        fi
        for m in openvswitch vport-gre vport-stt vport-geneve \
            vport-lisp vport-vxlan; do
            ln -f -s $requested_kernel/extra/openvswitch/$m.ko \
                /lib/modules/$current_kernel/weak-updates/openvswitch/$m.ko
        done
    fi
else
    echo Proper OVS kernel modules already configured
fi
# Always run depmod
/sbin/depmod -a
