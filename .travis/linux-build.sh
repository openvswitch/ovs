#!/bin/bash

set -o errexit
set -x

CFLAGS=""
SPARSE_FLAGS=""
EXTRA_OPTS="--enable-Werror"
TARGET="x86_64-native-linuxapp-gcc"

function install_kernel()
{
    if [[ "$1" =~ ^5.* ]]; then
        PREFIX="v5.x"
    elif [[ "$1" =~ ^4.* ]]; then
        PREFIX="v4.x"
    elif [[ "$1" =~ ^3.* ]]; then
        PREFIX="v3.x"
    else
        PREFIX="v2.6/longterm/v2.6.32"
    fi

    base_url="https://cdn.kernel.org/pub/linux/kernel/${PREFIX}"
    # Download page with list of all available kernel versions.
    wget ${base_url}/
    # Uncompress in case server returned gzipped page.
    (file index* | grep ASCII) || (mv index* index.new.gz && gunzip index*)
    # Get version of the latest stable release.
    hi_ver=$(echo ${1} | sed 's/\./\\\./')
    lo_ver=$(cat ./index* | grep -P -o "${hi_ver}\.[0-9]+" | \
             sed 's/.*\..*\.\(.*\)/\1/' | sort -h | tail -1)
    version="${1}.${lo_ver}"

    url="${base_url}/linux-${version}.tar.xz"
    # Download kernel sources. Try direct link on CDN failure.
    wget ${url} || wget ${url} || wget ${url/cdn/www}

    tar xvf linux-${version}.tar.xz > /dev/null
    cd linux-${version}
    make allmodconfig

    # Cannot use CONFIG_KCOV: -fsanitize-coverage=trace-pc is not supported by compiler
    sed -i 's/CONFIG_KCOV=y/CONFIG_KCOV=n/' .config

    # stack validation depends on tools/objtool, but objtool does not compile on travis.
    # It is giving following error.
    #  >>> GEN      arch/x86/insn/inat-tables.c
    #  >>> Semantic error at 40: Unknown imm opnd: AL
    # So for now disable stack-validation for the build.

    sed -i 's/CONFIG_STACK_VALIDATION=y/CONFIG_STACK_VALIDATION=n/' .config
    make oldconfig

    # Older kernels do not include openvswitch
    if [ -d "net/openvswitch" ]; then
        make net/openvswitch/
    else
        make net/bridge/
    fi

    EXTRA_OPTS="${EXTRA_OPTS} --with-linux=$(pwd)"
    echo "Installed kernel source in $(pwd)"
    cd ..
}

function install_dpdk()
{
    if [ -n "$DPDK_GIT" ]; then
        git clone $DPDK_GIT dpdk-$1
        cd dpdk-$1
        git checkout tags/v$1
    else
        wget https://fast.dpdk.org/rel/dpdk-$1.tar.xz
        tar xvf dpdk-$1.tar.xz > /dev/null
        DIR_NAME=$(tar -tf dpdk-$1.tar.xz | head -1 | cut -f1 -d"/")
        if [ $DIR_NAME != "dpdk-$1"  ]; then mv $DIR_NAME dpdk-$1; fi
        cd dpdk-$1
    fi
    echo 'CONFIG_RTE_BUILD_FPIC=y' >>config/common_linuxapp
    sed -ri '/EXECENV_CFLAGS  = -pthread -fPIC/{s/$/\nelse ifeq ($(CONFIG_RTE_BUILD_FPIC),y)/;s/$/\nEXECENV_CFLAGS  = -pthread -fPIC/}' mk/exec-env/linuxapp/rte.vars.mk

    make config CC=gcc T=$TARGET

    if [ "$DPDK_SHARED" ]; then
        sed -i '/CONFIG_RTE_BUILD_SHARED_LIB=n/s/=n/=y/' build/.config
        export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(pwd)/$TARGET/lib
    fi

    # Disable building DPDK kernel modules. Not needed for OVS build or tests.
    sed -i '/CONFIG_RTE_EAL_IGB_UIO=y/s/=y/=n/' build/.config
    sed -i '/CONFIG_RTE_KNI_KMOD=y/s/=y/=n/' build/.config

    make -j4 CC=gcc
    echo "Installed DPDK source in $(pwd)"
    cd ..
}

function configure_ovs()
{
    ./boot.sh && ./configure $* || { cat config.log; exit 1; }
}

if [ "$KERNEL" ]; then
    install_kernel $KERNEL
fi

if [ "$DPDK" ] || [ "$DPDK_SHARED" ]; then
    if [ -z "$DPDK_VER" ]; then
        DPDK_VER="18.11.1"
    fi
    install_dpdk $DPDK_VER
    if [ "$CC" = "clang" ]; then
        # Disregard cast alignment errors until DPDK is fixed
        CFLAGS="$CFLAGS -Wno-cast-align"
    fi
    EXTRA_OPTS="$EXTRA_OPTS --with-dpdk=$(pwd)/dpdk-$DPDK_VER/build"
fi

OPTS="$EXTRA_OPTS $*"

if [ "$CC" = "clang" ]; then
    export OVS_CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument"
elif [[ $BUILD_ENV =~ "-m32" ]]; then
    # Disable sparse for 32bit builds on 64bit machine
    export OVS_CFLAGS="$CFLAGS $BUILD_ENV"
else
    OPTS="$OPTS --enable-sparse"
    export OVS_CFLAGS="$CFLAGS $BUILD_ENV $SPARSE_FLAGS"
fi

if [ "$TESTSUITE" ]; then
    # 'distcheck' will reconfigure with required options.
    # Now we only need to prepare the Makefile without sparse-wrapped CC.
    configure_ovs

    export DISTCHECK_CONFIGURE_FLAGS="$OPTS"
    if ! make distcheck TESTSUITEFLAGS=-j4 RECHECK=yes; then
        # testsuite.log is necessary for debugging.
        cat */_build/tests/testsuite.log
        exit 1
    fi
else
    configure_ovs $OPTS
    make selinux-policy

    # Only build datapath if we are testing kernel w/o running testsuite
    if [ "$KERNEL" ]; then
        cd datapath
    fi
    make -j4
fi

exit 0
