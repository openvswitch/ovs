#!/bin/sh
# preinst script for openvswitch-switch
#
# see: dh_installdeb(1)

set -e

# summary of how this script can be called:
#        * <new-preinst> `install'
#        * <new-preinst> `install' <old-version>
#        * <new-preinst> `upgrade' <old-version>
#        * <old-preinst> `abort-upgrade' <new-version>
# for details, see http://www.debian.org/doc/debian-policy/ or
# the debian-policy package

case "$1" in
    install|upgrade)
       if dpkg --compare-versions "$2" lt-nl "2.17.2-1"; then
           # the conffile was not owned by the pkg before if it had any
           # custom content, retain as is to avoid an upgrade error or
           # conffile prompt we back it up in that case and restore it
           # in the postinst
           # Since it wasn#t owned we can't query the old checksum via
           # dpkg-query -W -f='${Conffiles}' as one usually would
           conffile="/etc/default/openvswitch-switch"
           md5olddebian="167668db26d5b29ec1469413b12d9bbe"
           md5oldubuntu="ae4d44b501cfb1eb362d87644a1bae0d"
           md5new="$(md5sum ${conffile} | sed -e 's/ .*//')"
           if [ "${md5olddebian}" = "${md5new}" ]; then
               # was unmodified, remove - will drop the new at unpack
               rm -f "${conffile}"
           else
               if [ ! "${md5oldubuntu}" = "${md5new}" ]; then
                   # neither matches old default Debian, nor Ubuntu.
                   # move to restore in postinst after taking conffile ownership
                   mv "${conffile}" "${conffile}.dpkg-bak"
               fi
           fi
       fi
    ;;

    *)
        echo "preinst called with unknown argument \`$1'" >&2
        exit 1
    ;;
esac

#DEBHELPER#

exit 0
