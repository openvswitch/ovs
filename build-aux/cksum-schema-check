#!/bin/sh

schema=$1
stamp=$2

cksumcheckpath=`dirname $0`
sum=`$cksumcheckpath/calculate-schema-cksum $schema`
expected=`sed -n 's/.*"cksum": "\(.*\)".*/\1/p' $schema`
if test "X$sum" = "X$expected"; then
    touch $stamp
else
    ln=`sed -n '/"cksum":/=' $schema`
    echo >&2 "$schema:$ln: The checksum \"$sum\" was calculated from the schema file and does not match cksum field in the schema file - you should probably update the version number and the checksum in the schema file with the value listed here."
    exit 1
fi
