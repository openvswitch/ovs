#! /bin/sh
set -e
progress=
for d in ${stp_files}; do
    echo "Testing $d..."
    $SUPERVISOR ./test-stp ${srcdir}/$d
done
