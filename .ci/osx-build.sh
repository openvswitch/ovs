#!/bin/bash

set -o errexit

CFLAGS="-Werror $CFLAGS"
EXTRA_OPTS=""

function configure_ovs()
{
    ./boot.sh && ./configure $*
}

configure_ovs $EXTRA_OPTS $OPTS $*

if [ "$CC" = "clang" ]; then
    make CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument"
else
    make CFLAGS="$CFLAGS $BUILD_ENV"
fi

if [ "$TESTSUITE" ] && [ "$CC" != "clang" ]; then
    make distcheck RECHECK=yes
fi

exit 0
