#!/bin/bash

set -o errexit
set -x

CFLAGS_FOR_OVS="-g -O2"
SPARSE_FLAGS=""
EXTRA_OPTS="--enable-Werror"

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

    rm -rf index* linux-*

    url="${base_url}/linux-${version}.tar.xz"
    # Download kernel sources. Try direct link on CDN failure.
    wget ${url} ||
    (rm -f linux-${version}.tar.xz && wget ${url}) ||
    (rm -f linux-${version}.tar.xz && wget ${url/cdn/www})

    tar xvf linux-${version}.tar.xz > /dev/null
    pushd linux-${version}
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

    if [ "$AFXDP" ]; then
        sudo make headers_install INSTALL_HDR_PATH=/usr
        pushd tools/lib/bpf/
        # Bulding with gcc because there are some issues in make files
        # that breaks building libbpf with clang on Travis.
        CC=gcc sudo make install
        CC=gcc sudo make install_headers
        sudo ldconfig
        popd
        # The Linux kernel defines __always_inline in stddef.h (283d7573), and
        # sys/cdefs.h tries to re-define it.  Older libc-dev package in xenial
        # doesn't have a fix for this issue.  Applying it manually.
        sudo sed -i '/^# define __always_inline .*/i # undef __always_inline' \
                    /usr/include/x86_64-linux-gnu/sys/cdefs.h || true
        EXTRA_OPTS="${EXTRA_OPTS} --enable-afxdp"
    else
        EXTRA_OPTS="${EXTRA_OPTS} --with-linux=$(pwd)"
        echo "Installed kernel source in $(pwd)"
    fi
    popd
}

function install_dpdk()
{
    local DPDK_VER=$1
    local VERSION_FILE="dpdk-dir/travis-dpdk-cache-version"
    local DPDK_OPTS=""
    local DPDK_LIB=""

    if [ -z "$TRAVIS_ARCH" ] ||
       [ "$TRAVIS_ARCH" == "amd64" ]; then
        DPDK_LIB=$(pwd)/dpdk-dir/build/lib/x86_64-linux-gnu
    elif [ "$TRAVIS_ARCH" == "aarch64" ]; then
        DPDK_LIB=$(pwd)/dpdk-dir/build/lib/aarch64-linux-gnu
    else
        echo "Target is unknown"
        exit 1
    fi

    if [ "$DPDK_SHARED" ]; then
        EXTRA_OPTS="$EXTRA_OPTS --with-dpdk=shared"
        export LD_LIBRARY_PATH=$DPDK_LIB/:$LD_LIBRARY_PATH
    else
        EXTRA_OPTS="$EXTRA_OPTS --with-dpdk=static"
    fi

    # Export the following path for pkg-config to find the .pc file.
    export PKG_CONFIG_PATH=$DPDK_LIB/pkgconfig/:$PKG_CONFIG_PATH

    if [ "${DPDK_VER##refs/*/}" != "${DPDK_VER}" ]; then
        # Avoid using cache for git tree build.
        rm -rf dpdk-dir

        DPDK_GIT=${DPDK_GIT:-https://dpdk.org/git/dpdk}
        git clone --single-branch $DPDK_GIT dpdk-dir -b "${DPDK_VER##refs/*/}"
        pushd dpdk-dir
        git log -1 --oneline
    else
        if [ -f "${VERSION_FILE}" ]; then
            VER=$(cat ${VERSION_FILE})
            if [ "${VER}" = "${DPDK_VER}" ]; then
                # Update the library paths.
                sudo ldconfig
                echo "Found cached DPDK ${VER} build in $(pwd)/dpdk-dir"
                return
            fi
        fi
        # No cache or version mismatch.
        rm -rf dpdk-dir
        wget https://fast.dpdk.org/rel/dpdk-$1.tar.xz
        tar xvf dpdk-$1.tar.xz > /dev/null
        DIR_NAME=$(tar -tf dpdk-$1.tar.xz | head -1 | cut -f1 -d"/")
        mv ${DIR_NAME} dpdk-dir
        pushd dpdk-dir
    fi

    # Switching to 'default' machine to make dpdk-dir cache usable on
    # different CPUs. We can't be sure that all CI machines are exactly same.
    DPDK_OPTS="$DPDK_OPTS -Dmachine=default"

    # Disable building DPDK unit tests. Not needed for OVS build or tests.
    DPDK_OPTS="$DPDK_OPTS -Dtests=false"

    # Install DPDK using prefix.
    DPDK_OPTS="$DPDK_OPTS --prefix=$(pwd)/build"

    CC=gcc meson $DPDK_OPTS build
    ninja -C build
    ninja -C build install

    # Update the library paths.
    sudo ldconfig


    echo "Installed DPDK source in $(pwd)"
    popd
    echo "${DPDK_VER}" > ${VERSION_FILE}
}

function configure_ovs()
{
    ./boot.sh
    ./configure CFLAGS="${CFLAGS_FOR_OVS}" $* || { cat config.log; exit 1; }
}

function build_ovs()
{
    local KERNEL=$1

    configure_ovs $OPTS
    make selinux-policy

    # Only build datapath if we are testing kernel w/o running testsuite and
    # AF_XDP support.
    if [ "${KERNEL}" ] && ! [ "$AFXDP" ]; then
        pushd datapath
        make -j4
        popd
    else
        make -j4 || { cat config.log; exit 1; }
    fi
}

if [ "$DEB_PACKAGE" ]; then
    mk-build-deps --install --root-cmd sudo --remove debian/control
    dpkg-checkbuilddeps
    DEB_BUILD_OPTIONS='parallel=4 nocheck' fakeroot debian/rules binary
    # Not trying to install ipsec package as there are issues with system-wide
    # installed python3-openvswitch package and the pyenv used by Travis.
    packages=$(ls $(pwd)/../*.deb | grep -v ipsec)
    sudo apt install ${packages}
    exit 0
fi

if [ "$KERNEL" ]; then
    install_kernel $KERNEL
fi

if [ "$DPDK" ] || [ "$DPDK_SHARED" ]; then
    if [ -z "$DPDK_VER" ]; then
        DPDK_VER="20.11.1"
    fi
    install_dpdk $DPDK_VER
    if [ "$CC" = "clang" ]; then
        # Disregard cast alignment errors until DPDK is fixed
        CFLAGS_FOR_OVS="${CFLAGS_FOR_OVS} -Wno-cast-align"
    fi
fi

if [ "$CC" = "clang" ]; then
    CFLAGS_FOR_OVS="${CFLAGS_FOR_OVS} -Wno-error=unused-command-line-argument"
elif [ "$M32" ]; then
    # Not using sparse for 32bit builds on 64bit machine.
    # Adding m32 flag directly to CC to avoid any posiible issues with API/ABI
    # difference on 'configure' and 'make' stages.
    export CC="$CC -m32"
elif [ "$TRAVIS_ARCH" != "aarch64" ]; then
    OPTS="--enable-sparse"
    if [ "$AFXDP" ]; then
        # netdev-afxdp uses memset for 64M for umem initialization.
        SPARSE_FLAGS="${SPARSE_FLAGS} -Wno-memcpy-max-count"
    fi
    CFLAGS_FOR_OVS="${CFLAGS_FOR_OVS} ${SPARSE_FLAGS}"
fi

if [ "$ASAN" ]; then
    # This will override default option configured in tests/atlocal.in.
    export ASAN_OPTIONS='detect_leaks=1'
    # -O2 generates few false-positive memory leak reports in test-ovsdb
    # application, so lowering optimizations to -O1 here.
    CLFAGS_ASAN="-O1 -fno-omit-frame-pointer -fno-common -fsanitize=address"
    CFLAGS_FOR_OVS="${CFLAGS_FOR_OVS} ${CLFAGS_ASAN}"
fi

save_OPTS="${OPTS} $*"
OPTS="${EXTRA_OPTS} ${save_OPTS}"

if [ "$TESTSUITE" ]; then
    # 'distcheck' will reconfigure with required options.
    # Now we only need to prepare the Makefile without sparse-wrapped CC.
    configure_ovs

    export DISTCHECK_CONFIGURE_FLAGS="$OPTS"
    if ! make distcheck -j4 CFLAGS="${CFLAGS_FOR_OVS}" \
         TESTSUITEFLAGS=-j4 RECHECK=yes; then
        # testsuite.log is necessary for debugging.
        cat */_build/sub/tests/testsuite.log
        exit 1
    fi
else
    if [ -z "${KERNEL_LIST}" ]; then build_ovs ${KERNEL};
    else
        save_EXTRA_OPTS="${EXTRA_OPTS}"
        for KERNEL in ${KERNEL_LIST}; do
            echo "=============================="
            echo "Building with kernel ${KERNEL}"
            echo "=============================="
            EXTRA_OPTS="${save_EXTRA_OPTS}"
            install_kernel ${KERNEL}
            OPTS="${EXTRA_OPTS} ${save_OPTS}"
            build_ovs ${KERNEL}
            make distclean
        done
    fi
fi

exit 0
