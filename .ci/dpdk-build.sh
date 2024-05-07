#!/bin/bash

set -o errexit
set -x

function build_dpdk()
{
    local DPDK_VER=$1
    local DPDK_OPTS=""
    local DPDK_INSTALL_DIR="$(pwd)/dpdk-dir"
    local VERSION_FILE="$DPDK_INSTALL_DIR/cached-version"

    rm -rf dpdk-src
    rm -rf $DPDK_INSTALL_DIR

    if [ "${DPDK_VER##refs/*/}" != "${DPDK_VER}" ]; then
        git clone --single-branch $DPDK_GIT dpdk-src -b "${DPDK_VER##refs/*/}"
        pushd dpdk-src
        git log -1 --oneline
    else
        wget https://fast.dpdk.org/rel/dpdk-$1.tar.xz
        tar xvf dpdk-$1.tar.xz > /dev/null
        DIR_NAME=$(tar -tf dpdk-$1.tar.xz | head -1 | cut -f1 -d"/")
        mv ${DIR_NAME} dpdk-src
        pushd dpdk-src
    fi

    # Switching to 'generic' platform to make the dpdk cache usable on
    # different CPUs. We can't be sure that all CI machines are exactly same.
    DPDK_OPTS="$DPDK_OPTS -Dplatform=generic"

    # Disable building DPDK unit tests. Not needed for OVS build or tests.
    DPDK_OPTS="$DPDK_OPTS -Dtests=false"

    # Disable DPDK developer mode, this results in less build checks and less
    # meson verbose outputs.
    DPDK_OPTS="$DPDK_OPTS -Ddeveloper_mode=disabled"

    # OVS compilation and "normal" unit tests (run in the CI) do not depend on
    # any DPDK driver.
    # check-dpdk unit tests requires testpmd and some net/ driver.
    DPDK_OPTS="$DPDK_OPTS -Denable_apps=test-pmd"
    enable_drivers="net/null,net/af_xdp,net/tap,net/virtio,net/pcap"
    DPDK_OPTS="$DPDK_OPTS -Denable_drivers=$enable_drivers"
    # OVS depends on the vhost library (and its dependencies).
    # net/tap depends on the gso library.
    DPDK_OPTS="$DPDK_OPTS -Denable_libs=cryptodev,dmadev,gso,vhost"

    # Install DPDK using prefix.
    DPDK_OPTS="$DPDK_OPTS --prefix=$DPDK_INSTALL_DIR"

    meson setup $DPDK_OPTS build
    ninja -C build
    ninja -C build install
    popd

    # Remove examples sources.
    rm -rf $DPDK_INSTALL_DIR/share/dpdk/examples

    echo "Installed DPDK in $DPDK_INSTALL_DIR"
    echo "${DPDK_VER}" > ${VERSION_FILE}
}

build_dpdk $DPDK_VER
