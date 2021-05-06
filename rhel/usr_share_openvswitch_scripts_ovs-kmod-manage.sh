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

# This script is intended to be used on the following kernels.
#   - 3.10.0 major revision 327  (RHEL 7.2)
#   - 3.10.0 major revision 693  (RHEL 7.4)
#   - 3.10.0 major revision 957  (RHEL 7.6)
#   - 3.10.0 major revision 1062 (RHEL 7.7)
#   - 3.10.0 major revision 1101 (RHEL 7.8 Beta)
#   - 3.10.0 major revision 1127 (RHEL 7.8 GA)
#   - 3.10.0 major revision 1160 (RHEL 7.9)
#   - 4.4.x,  x >= 73           (SLES 12 SP3)
#   - 4.12.x, x >= 14           (SLES 12 SP4).
# It is packaged in the openvswitch kmod RPM and run in the post-install
# scripts.
#
# For kernel 3.10.0-957,
# due to some backward incompatible changes introduced in minor revision 12.1,
# kernel modules built against kernels newer than 12.1 cannot be loaded on
# system running kernels older than 12.1, vice versa.
#
# For kernel 3.10.0-693,
# due to some backward incompatible changes introduced in minor revision 17.1,
# kernel modules built against kernels newer than 17.1 cannot be loaded on
# system running kernels older than 17.1, vice versa.
#
# For kernel 3.10.0-327,
# due to some backward incompatible changes introduced in minor revision 41.3,
# kernel modules built against kernels newer than 41.3 cannot be loaded on
# system running kernels older than 41.3, vice versa.
#
# For kernel >= 4.4.73,
# kernel modules built with 4.4.73 can run on systems with kernel versions from
# 4.4.73 to 4.4.114; modules built against 4.4.120 can run on systems from
# 4.4.120 onwards.
#
# For kernel 4.12.x, x>=14,
# kernel modules built with the oldest compatible kernel 4.12.14-94.41.1 can
# run on all versions onwards.
#
# This script checks the current running kernel version, and update symlinks
# for the openvswitch kernel modules in the appropriate kernel directory,
# provided the kmod RPM has installed kernel modules files built from both
# minor revisions.
#
# In case of a kernel minor revision change after the openvswitch kmod package
# is installed, this script shall be run manually after system reboots and
# switches to a different kernel
if [ -n "$(rpm -qa kmod-openvswitch)" ]; then
    rpmname="kmod-openvswitch"
elif [ -n "$(rpm -qa openvswitch-kmod)" ]; then
    rpmname="openvswitch-kmod"
else
    echo "openvswitch kmod package not installed, existing"
    exit 1
fi
#echo $rpmname
script_name=$(basename -- "$0")
current_kernel=$(uname -r)
echo current kernel is $current_kernel

IFS='.\|-' read mainline_major mainline_minor mainline_patch major_rev \
    minor_rev _extra <<<"${current_kernel}"
# echo mainline_major=$mainline_major mainline_minor=$mainline_minor \
# mainline_patch=$mainline_patch major_rev=$major_rev minor_rev=$minor_rev

expected_rhel_base_minor="el7"
if [ "$mainline_major" = "3" ] && [ "$mainline_minor" = "10" ]; then
    if [ "$major_rev" = "327" ]; then
#        echo "rhel72"
        comp_ver=36
        ver_offset=4
        installed_ver="$minor_rev"
    elif [ "$major_rev" = "514" ]; then
#        echo "rhel73"
        comp_ver=26
        ver_offset=4
        installed_ver="$minor_rev"
    elif [ "$major_rev" = "693" ]; then
#        echo "rhel74"
        comp_ver=11
        ver_offset=4
        installed_ver="$minor_rev"
    elif [ "$major_rev" = "862" ]; then
#        echo "rhel75"
        comp_ver=20
        ver_offset=4
        installed_ver="$minor_rev"
    elif [ "$major_rev" = "957" ]; then
#        echo "rhel76"
        comp_ver=10
        ver_offset=4
        installed_ver="$minor_rev"
    elif [ "$major_rev" = "1062" ]; then
#        echo "rhel77"
        comp_ver=10
        ver_offset=4
        installed_ver="$minor_rev"
    elif [ "$major_rev" = "1101" ]; then
#        echo "rhel78"
        comp_ver=10
        ver_offset=4
        installed_ver="$minor_rev"
    elif [ "$major_rev" = "1127" ]; then
#        echo "rhel78"
        comp_ver=10
        ver_offset=4
        installed_ver="$minor_rev"
    elif [ "$major_rev" = "1160" ]; then
#        echo "rhel79"
        comp_ver=10
        ver_offset=4
        installed_ver="$minor_rev"
    fi
elif [ "$mainline_major" = "4" ] && [ "$mainline_minor" = "4" ]; then
    if [ "$mainline_patch" -ge "73" ]; then
#        echo "sles12sp3"
        comp_ver=114
        ver_offset=2
        installed_ver="$mainline_patch"
    fi
elif [ "$mainline_major" = "4" ] && [ "$mainline_minor" = "12" ]; then
    if [ "$mainline_patch" -ge "14" ]; then
#        echo "sles12sp4"
        comp_ver=1
        ver_offset=2
        installed_ver="$mainline_patch"
    fi
fi

if [ X"$ver_offset" = X ]; then
#    echo "This script is not intended to run on kernel $(uname -r)"
    exit 0
fi

#IFS='.\|-' read -r -a version_nums <<<"${current_kernel}"
#echo ver_offset=$ver_offset
#echo installed_ver="$installed_ver"
#echo installed_ver="${version_nums[$ver_offset]}"

kmod_versions=()
kversion=$(rpm -ql ${rpmname} | grep '\.ko$' | \
           sed -n -e 's/^\/lib\/modules\/\(.*\)\/extra\/.*$/\1/p' | \
           sort | uniq)

IFS='.\|-' read installed_major installed_minor installed_patch \
    installed_major_rev installed_minor_rev installed_extra <<<"${kversion}"

if [ "$installed_major_rev" -lt "$major_rev" ]; then
    echo "Not installing RPM with major revision $installed_major_rev" \
         "to kernel with greater major revision $major_rev.  Exiting"
    exit 1
fi

for kv in $kversion; do
    IFS='.\|-' read -r -a kv_nums <<<"${kv}"
    kmod_versions+=(${kv_nums[$ver_offset]})
done
sorted_kmod_vers=$(printf "%s\n" "${kmod_versions[@]}" | \
                       sort -n)
#echo "$sorted_kmod_vers"

if [ ! -n "$sorted_kmod_vers" ]; then
    echo "No kernel modules found from package $rpmname, exiting"
    exit 1
else
    # first line for kmod_low_ver, last for kmod_high_ver
    kmod_low_ver=$(echo "$sorted_kmod_vers" | head -1)
    kmod_high_ver=$(echo "$sorted_kmod_vers" | tail -1)
fi
#echo "Installing KMOD with minor revisions $kmod_low_ver and \
#$kmod_high_ver"

found_match=false
for kname in $kversion;
do
    IFS='.\|-' read -r -a pkg_ver_nums <<<"${kname}"
    pkg_ver=${pkg_ver_nums[$ver_offset]}
    if [ "$installed_ver" = "$expected_rhel_base_minor" ] ||
       [ "$installed_ver" -le "$comp_ver" ]; then
        if [ "$pkg_ver" = "$kmod_low_ver" ]; then
            requested_kernel=$kname
            found_match="true"
            echo "Installing Openvswitch KMOD from kernel $kname"
            break
        fi
    else
        if [ "$pkg_ver" = "$kmod_high_ver" ]; then
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

if [ "$requested_kernel" != "$current_kernel" ]; then
    if [ ! -d /lib/modules/$current_kernel/weak-updates/openvswitch ]; then
        mkdir -p /lib/modules/$current_kernel/weak-updates
        mkdir -p /lib/modules/$current_kernel/weak-updates/openvswitch
    fi
    for m in openvswitch vport-gre vport-stt vport-geneve \
        vport-lisp vport-vxlan; do
        ln -f -s /lib/modules/$requested_kernel/extra/openvswitch/$m.ko \
            /lib/modules/$current_kernel/weak-updates/openvswitch/$m.ko
    done
else
    echo Proper OVS kernel modules already configured
fi
# Always run depmod
/sbin/depmod -a
