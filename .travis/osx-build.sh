#!/bin/bash

set -o errexit

CFLAGS="-Werror $CFLAGS"
EXTRA_OPTS=""

function configure_ovs()
{
    ./boot.sh && ./configure $*
}

configure_ovs $EXTRA_OPTS $*

if [ "$CC" = "clang" ]; then
    set make CFLAGS="$CFLAGS -Wno-error=unused-command-line-argument"
else
    set make CFLAGS="$CFLAGS $BUILD_ENV"
fi
if ! "$@"; then
    cat config.log
    exit 1
fi
if [ "$TESTSUITE" ] && [ "$CC" != "clang" ]; then
    if ! make distcheck RECHECK=yes; then
        # testsuite.log is necessary for debugging.
        cat */_build/sub/tests/testsuite.log
        exit 1
    fi
fi

exit 0
