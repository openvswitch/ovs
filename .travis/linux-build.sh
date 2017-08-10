#!/bin/bash

set -o errexit

KERNELSRC=""
CFLAGS="-Werror"
SPARSE_FLAGS=""
EXTRA_OPTS=""

function install_kernel()
{
    if [[ "$1" =~ ^4.* ]]; then
        PREFIX="v4.x"
    elif [[ "$1" =~ ^3.* ]]; then
        PREFIX="v3.x"
    else
        PREFIX="v2.6/longterm/v2.6.32"
    fi

    wget https://www.kernel.org/pub/linux/kernel/${PREFIX}/linux-${1}.tar.gz
    tar xzvf linux-${1}.tar.gz > /dev/null
    cd linux-${1}
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

    KERNELSRC=$(pwd)
    if [ ! "$DPDK" ]; then
        EXTRA_OPTS="--with-linux=$(pwd)"
    fi
    echo "Installed kernel source in $(pwd)"
    cd ..
}

function install_dpdk()
{
    if [ -n "$DPDK_GIT" ]; then
        git clone $DPDK_GIT dpdk-stable-$1
        cd dpdk-stable-$1
        git checkout tags/v$1
    else
        wget http://fast.dpdk.org/rel/dpdk-$1.tar.gz
        tar xzvf dpdk-$1.tar.gz > /dev/null
        cd dpdk-stable-$1
    fi
    find ./ -type f | xargs sed -i 's/max-inline-insns-single=100/max-inline-insns-single=400/'
    find ./ -type f | xargs sed -i 's/-Werror/-Werror -Wno-error=inline/'
    echo 'CONFIG_RTE_BUILD_FPIC=y' >>config/common_linuxapp
    sed -ri '/EXECENV_CFLAGS  = -pthread -fPIC/{s/$/\nelse ifeq ($(CONFIG_RTE_BUILD_FPIC),y)/;s/$/\nEXECENV_CFLAGS  = -pthread -fPIC/}' mk/exec-env/linuxapp/rte.vars.mk
    make config CC=gcc T=x86_64-native-linuxapp-gcc
    make CC=gcc RTE_KERNELDIR=$KERNELSRC
    echo "Installed DPDK source in $(pwd)"
    cd ..
}

function configure_ovs()
{
    ./boot.sh && ./configure $*
}

if [ "$KERNEL" ] || [ "$DPDK" ]; then
    install_kernel $KERNEL
fi

if [ "$DPDK" ]; then
    if [ -z "$DPDK_VER" ]; then
        DPDK_VER="17.05.1"
    fi
    install_dpdk $DPDK_VER
    if [ "$CC" = "clang" ]; then
        # Disregard cast alignment errors until DPDK is fixed
        CFLAGS="$CFLAGS -Wno-cast-align"
    fi
    EXTRA_OPTS="$EXTRA_OPTS --with-dpdk=./dpdk-stable-$DPDK_VER/build"
elif [ "$CC" != "clang" ]; then
    # DPDK headers currently trigger sparse errors
    SPARSE_FLAGS="$SPARSE_FLAGS -Wsparse-error"
fi

configure_ovs $EXTRA_OPTS $*

# Only build datapath if we are testing kernel w/o running testsuite
if [ "$KERNEL" ] && [ ! "$TESTSUITE" ] && [ ! "$DPDK" ]; then
    cd datapath
fi

if [ "$CC" = "clang" ]; then
    make -j2 CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument"
elif [[ $BUILD_ENV =~ "-m32" ]]; then
    # Disable sparse for 32bit builds on 64bit machine
    make -j2 CFLAGS="$CFLAGS $BUILD_ENV"
else
    make -j2 CFLAGS="$CFLAGS $BUILD_ENV $SPARSE_FLAGS" C=1
fi

if [ "$TESTSUITE" ] && [ "$CC" != "clang" ]; then
    if ! make distcheck TESTSUITEFLAGS=-j4 RECHECK=yes; then
        # testsuite.log is necessary for debugging.
        cat */_build/tests/testsuite.log
        exit 1
    fi
fi

exit 0
