#!/bin/bash

set -o errexit
set -x

CFLAGS_FOR_OVS="-g -O2"
EXTRA_OPTS=""


function configure_ovs()
{
    ./boot.sh
    ./configure CC=./build-aux/cccl LD="`which link`" \
    --with-pthread="./PTHREADS-BUILT" \
    LIBS="-lws2_32 -lShlwapi -liphlpapi -lwbemuuid -lole32 -loleaut32" \
    CFLAGS="${CFLAGS_FOR_OVS}" $* || { cat config.log; exit 1; }
}

function build_ovs()
{
    configure_ovs $OPTS
    make -j4 || { cat config.log; exit 1; }

}

save_OPTS="${OPTS} $*"
OPTS="${EXTRA_OPTS} ${save_OPTS}"

if [ "$TESTSUITE" ]; then
    # 'distcheck' will reconfigure with required options.
    configure_ovs

    export DISTCHECK_CONFIGURE_FLAGS="$OPTS"
    if ! make distcheck -j4 CFLAGS="${CFLAGS_FOR_OVS}" \
         TESTSUITEFLAGS=-j4 RECHECK=yes; then
        # testsuite.log is necessary for debugging.
        cat */_build/sub/tests/testsuite.log
        exit 1
    fi
else
    EXTRA_OPTS="${save_EXTRA_OPTS}"
    OPTS="${EXTRA_OPTS} ${save_OPTS}"
    build_ovs
    make distclean
fi

exit 0
