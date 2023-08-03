#!/bin/bash

set -o errexit

CFLAGS="-Werror $CFLAGS"
EXTRA_OPTS=""

on_exit() {
    if [ $? = 0 ]; then
        exit
    fi
    FILES_TO_PRINT="config.log"
    FILES_TO_PRINT="$FILES_TO_PRINT */_build/sub/tests/testsuite.log"

    for pr_file in $FILES_TO_PRINT; do
        cat "$pr_file" 2>/dev/null
    done
}
# We capture the error logs as artifacts in Github Actions, no need to dump
# them via a EXIT handler.
[ -n "$GITHUB_WORKFLOW" ] || trap on_exit EXIT

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
