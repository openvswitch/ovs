#!/bin/sh
# postinst script for openvswitch-switch
#
# see: dh_installdeb(1)

set -e

# summary of how this script can be called:
#        * <postinst> `configure' <most-recently-configured-version>
#        * <old-postinst> `abort-upgrade' <new version>
#        * <conflictor's-postinst> `abort-remove' `in-favour' <package>
#          <new-version>
#        * <postinst> `abort-remove'
#        * <deconfigured's-postinst> `abort-deconfigure' `in-favour'
#          <failed-install-package> <version> `removing'
#          <conflicting-package> <version>
# for details, see http://www.debian.org/doc/debian-policy/ or
# the debian-policy package


case "$1" in
    configure)
        update-alternatives --install /usr/sbin/ovs-vswitchd ovs-vswitchd \
            /usr/lib/openvswitch-switch/ovs-vswitchd 100
        mkdir -p /var/lib/openvswitch

        conffile="/etc/default/openvswitch-switch"
        if [ -f "${conffile}.dpkg-bak" ]; then
            # Old conffile was modified, retain old content
            mv "${conffile}.dpkg-bak" "${conffile}"
        fi

        # Ensure that /etc/openvswitch/conf.db links to /var/lib/openvswitch,
        # moving an existing file if there is one.
        #
        # Ditto for .conf.db.~lock~.
        for base in conf.db .conf.db.~lock~; do
            new=/var/lib/openvswitch/$base
            old=/etc/openvswitch/$base
            if test -f $old && test ! -e $new; then
                mv $old $new
            fi
            if test ! -e $old && test ! -h $old; then
                ln -s $new $old
            fi
        done
        ;;

    abort-upgrade|abort-remove|abort-deconfigure)
        ;;

    *)
        echo "postinst called with unknown argument \`$1'" >&2
        exit 1
        ;;
esac

# Do not fail package installation just because the kernel module
# is not available.
OVS_MISSING_KMOD_OK=yes
export OVS_MISSING_KMOD_OK

# force-reload-kmod during upgrade. If a user wants to override this,
# they can set the variable OVS_FORCE_RELOAD_KMOD=no while installing.
[ -z "${OVS_FORCE_RELOAD_KMOD}" ] && OVS_FORCE_RELOAD_KMOD=yes || true
export OVS_FORCE_RELOAD_KMOD

#DEBHELPER#

exit 0
