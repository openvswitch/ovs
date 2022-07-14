#!/bin/sh

set -e

case "$1" in
    remove)
        update-alternatives --remove ovs-vswitchd /usr/lib/openvswitch-switch/ovs-vswitchd

        if [ -x /usr/lib/openvswitch-switch/ovs-vswitchd-dpdk ]; then
            update-alternatives --remove ovs-vswitchd /usr/lib/openvswitch-switch/ovs-vswitchd-dpdk
        fi
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

