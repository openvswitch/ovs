#!/bin/bash

set -o errexit
set -x

CFLAGS_FOR_OVS="-g -O2"
EXTRA_OPTS="--with-pthread=`realpath ./PTHREADS-BUILT | xargs cygpath -m`"

function configure_ovs()
{
    ./boot.sh
    ./configure CC="./build-aux/cccl" LD="`which link`" \
    LIBS="-lws2_32 -lShlwapi -liphlpapi -lwbemuuid -lole32 -loleaut32" \
    CFLAGS="${CFLAGS_FOR_OVS}" $* || { cat config.log; exit 1; }
}


OPTS="${EXTRA_OPTS} ${OPTS} $*"
configure_ovs $OPTS
make -j || { cat config.log; exit 1; }

if [ "$TESTSUITE" ]; then
    if ! make check RECHECK=yes; then
        # testsuite.log is necessary for debugging.
        cat ./tests/testsuite.log
        exit 1
    fi
fi

exit 0