#! /bin/bash
set -e
if [ -z "$1" ]
then
    echo "- Missing mandatory argument:"
    echo " - Usage: ./component.sh <SDE_INSTALL_PATH>"
    echo " - Usage: Run from the parent directory of source"
    exit 1
fi
SDE_INSTALL_PATH=$1
export OVS=$PWD/p4-ovs
tar -C $PWD -czf $PWD/p4-ovs.tar.gz p4-ovs
cd $OVS
tar -xvf install.tar.gz
./build-p4ovs.sh $SDE_INSTALL_PATH
