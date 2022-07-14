#!/bin/sh

set -e

case "$1" in
    remove)
        update-alternatives --remove ovs-vswitchd /usr/lib/openvswitch-switch-dpdk/ovs-vswitchd-dpdk
        ;;

    deconfigure|upgrade|failed-upgrade)
        ;;

    *)
        echo "postinst called with unknown argument \`$1'" >&2
        exit 1
        ;;
esac

#DEBHELPER#

exit 0

