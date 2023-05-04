#!/bin/bash

set -o errexit
set -x

CFLAGS_FOR_OVS="-g -O2"
SPARSE_FLAGS=""
EXTRA_OPTS="--enable-Werror"

function install_dpdk()
{
    local VERSION_FILE="dpdk-dir/cached-version"
    local DPDK_LIB=$(pwd)/dpdk-dir/build/lib/x86_64-linux-gnu

    if [ "$DPDK_SHARED" ]; then
        EXTRA_OPTS="$EXTRA_OPTS --with-dpdk=shared"
        export LD_LIBRARY_PATH=$DPDK_LIB/:$LD_LIBRARY_PATH
    else
        EXTRA_OPTS="$EXTRA_OPTS --with-dpdk=static"
    fi

    # Export the following path for pkg-config to find the .pc file.
    export PKG_CONFIG_PATH=$DPDK_LIB/pkgconfig/:$PKG_CONFIG_PATH

    if [ ! -f "${VERSION_FILE}" ]; then
        echo "Could not find DPDK in $(pwd)/dpdk-dir"
        return 1
    fi

    # Update the library paths.
    sudo ldconfig
    echo "Found cached DPDK $(cat ${VERSION_FILE}) build in $(pwd)/dpdk-dir"
}

function configure_ovs()
{
    ./boot.sh
    ./configure CFLAGS="${CFLAGS_FOR_OVS}" $*
}

function build_ovs()
{
    configure_ovs $OPTS
    make selinux-policy

    make -j4
}

if [ "$DEB_PACKAGE" ]; then
    ./boot.sh && ./configure --with-dpdk=$DPDK && make debian
    mk-build-deps --install --root-cmd sudo --remove debian/control
    dpkg-checkbuilddeps
    make debian-deb
    packages=$(ls $(pwd)/../*.deb)
    deps=""
    for pkg in $packages; do
        _ifs=$IFS
        IFS=","
        for dep in $(dpkg-deb -f $pkg Depends); do
            dep_name=$(echo "$dep"|awk '{print$1}')
            # Don't install internal package inter-dependencies from apt
            echo $dep_name | grep -q openvswitch && continue
            deps+=" $dep_name"
        done
        IFS=$_ifs
    done
    # install package dependencies from apt
    echo $deps | xargs sudo apt -y install
    # install the locally built openvswitch packages
    sudo dpkg -i $packages

    # Check that python C extension is built correctly.
    python3 -c "
from ovs import _json
import ovs.json
assert ovs.json.from_string('{\"a\": 42}') == {'a': 42}"

    exit 0
fi

if [ "$DPDK" ] || [ "$DPDK_SHARED" ]; then
    install_dpdk
fi

if [ "$CC" = "clang" ]; then
    CFLAGS_FOR_OVS="${CFLAGS_FOR_OVS} -Wno-error=unused-command-line-argument"
elif [ "$M32" ]; then
    # Not using sparse for 32bit builds on 64bit machine.
    # Adding m32 flag directly to CC to avoid any posiible issues with API/ABI
    # difference on 'configure' and 'make' stages.
    export CC="$CC -m32"
else
    EXTRA_OPTS="$EXTRA_OPTS --enable-sparse"
    CFLAGS_FOR_OVS="${CFLAGS_FOR_OVS} ${SPARSE_FLAGS}"
fi

if [ "$ASAN" ]; then
    # This will override default option configured in tests/atlocal.in.
    export ASAN_OPTIONS='detect_leaks=1'
    CFLAGS_ASAN="-fno-omit-frame-pointer -fno-common -fsanitize=address"
    CFLAGS_FOR_OVS="${CFLAGS_FOR_OVS} ${CFLAGS_ASAN}"
fi

if [ "$UBSAN" ]; then
    # Use the default options configured in tests/atlocal.in, in UBSAN_OPTIONS.
    CFLAGS_UBSAN="-fno-omit-frame-pointer -fno-common -fsanitize=undefined"
    CFLAGS_FOR_OVS="${CFLAGS_FOR_OVS} ${CFLAGS_UBSAN}"
fi

OPTS="${EXTRA_OPTS} ${OPTS} $*"

if [ "$TESTSUITE" ]; then
    # 'distcheck' will reconfigure with required options.
    # Now we only need to prepare the Makefile without sparse-wrapped CC.
    configure_ovs

    export DISTCHECK_CONFIGURE_FLAGS="$OPTS"
    make distcheck -j4 CFLAGS="${CFLAGS_FOR_OVS}" \
        TESTSUITEFLAGS=-j4 RECHECK=yes
else
    build_ovs
fi

exit 0
