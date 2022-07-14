#!/bin/sh
# postinst script for openvswitch-testcontroller
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
        cd /etc/openvswitch-testcontroller
        if ! test -e cacert.pem; then
            ln -s /var/lib/openvswitch/pki/switchca/cacert.pem cacert.pem
        fi
        if ! test -e privkey.pem || ! test -e cert.pem; then
            oldumask=$(umask)
            umask 077
            ovs-pki req+sign tmp controller >/dev/null
            mv tmp-privkey.pem privkey.pem
            mv tmp-cert.pem cert.pem
            mv tmp-req.pem req.pem
            chmod go+r cert.pem req.pem
            umask $oldumask
        fi
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


