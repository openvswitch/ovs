#!/bin/sh

set -e

case "$1" in
    configure)
        update-alternatives --install /usr/sbin/ovs-vswitchd ovs-vswitchd \
            /usr/lib/openvswitch-switch-dpdk/ovs-vswitchd-dpdk 50
        ;;

    abort-upgrade|abort-remove|abort-deconfigure)
        ;;

    *)
        echo "postinst called with unknown argument \`$1'" >&2
        exit 1
        ;;
esac

#DEBHELPER#

exit 0
