#!/bin/bash

set -o errexit

KERNELSRC=""

function install_kernel()
{
    wget https://www.kernel.org/pub/linux/kernel/v3.x/linux-3.14.7.tar.gz
    tar xzvf linux-3.14.7.tar.gz > /dev/null
    cd linux-3.14.7
    make allmodconfig
    make net/openvswitch/
    KERNELSRC=$(pwd)
    echo "Installed kernel source in $(pwd)"
    cd ..
}

function install_dpdk()
{
    wget http://www.dpdk.org/browse/dpdk/snapshot/dpdk-1.7.0.tar.gz
    tar xzvf dpdk-1.7.0.tar.gz > /dev/null
    cd dpdk-1.7.0
    find ./ -type f | xargs sed -i 's/max-inline-insns-single=100/max-inline-insns-single=400/'
    make config CC=gcc T=x86_64-native-linuxapp-gcc
    make CC=gcc RTE_KERNELDIR=$KERNELSRC
    sudo make install CC=gcc T=x86_64-native-linuxapp-gcc RTE_KERNELDIR=$KERNELSRC
    echo "Installed DPDK source in $(pwd)"
    cd ..
}

function configure_ovs()
{
    ./boot.sh && ./configure $*
}

if [ "$KERNEL" ] || [ "$DPDK" ]; then
    install_kernel
fi

[ "$DPDK" ] && install_dpdk

configure_ovs $*

if [ $CC = "clang" ]; then
    make CFLAGS="-Werror -Wno-error=unused-command-line-argument"
else
    make CFLAGS="-Werror" C=1
    [ "$TESTSUITE" ] && make check
fi

exit 0
