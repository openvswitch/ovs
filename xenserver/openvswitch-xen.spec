# Spec file for Open vSwitch.

# Copyright (C) 2009, 2010 Nicira Networks, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

# When building, the rpmbuild command line should define
# openvswitch_version, xen_version, and build_number using -D arguments.
# for example:
#
#    rpmbuild -D "openvswitch_version 0.8.9~1+build123" -D "xen_version 2.6.18-128.1.1.el5.xs5.1.0.483.1000xen" -D "build_number --with-build-number=123" -bb /usr/src/redhat/SPECS/openvswitch-xen.spec
#
%define version %{openvswitch_version}-%{xen_version}

Name: openvswitch
Summary: Virtual switch
Group: System Environment/Daemons
URL: http://www.openvswitch.org/
Vendor: Nicira Networks, Inc.
Version: %{openvswitch_version}

# The entire source code is ASL 2.0 except datapath/ which is GPLv2
License: ASL 2.0 and GPLv2
Release: 1
Source: openvswitch-%{openvswitch_version}.tar.gz
Buildroot: /tmp/openvswitch-xen-rpm
Requires: kernel-xen = %(echo '%{xen_version}' | sed 's/xen$//')

%description
Open vSwitch provides standard network bridging functions augmented with
support for the OpenFlow protocol for remote per-flow control of
traffic.

%prep
%setup -q -n openvswitch-%{openvswitch_version}

%build
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=%{_localstatedir} --with-l26=/lib/modules/%{xen_version}/build --enable-ssl %{build_number}
make %{_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
install -d -m 755 $RPM_BUILD_ROOT/etc
install -d -m 755 $RPM_BUILD_ROOT/etc/init.d
install -m 755 xenserver/etc_init.d_openvswitch \
         $RPM_BUILD_ROOT/etc/init.d/openvswitch
install -m 755 xenserver/etc_init.d_openvswitch-xapi-update \
         $RPM_BUILD_ROOT/etc/init.d/openvswitch-xapi-update
install -d -m 755 $RPM_BUILD_ROOT/etc/sysconfig
install -d -m 755 $RPM_BUILD_ROOT/etc/logrotate.d
install -m 755 xenserver/etc_logrotate.d_openvswitch \
         $RPM_BUILD_ROOT/etc/logrotate.d/openvswitch
install -d -m 755 $RPM_BUILD_ROOT/etc/profile.d
install -m 755 xenserver/etc_profile.d_openvswitch.sh \
         $RPM_BUILD_ROOT/etc/profile.d/openvswitch.sh
install -d -m 755 $RPM_BUILD_ROOT/etc/xapi.d/plugins
install -m 755 xenserver/etc_xapi.d_plugins_openvswitch-cfg-update \
         $RPM_BUILD_ROOT/etc/xapi.d/plugins/openvswitch-cfg-update
install -d -m 755 $RPM_BUILD_ROOT/usr/share/openvswitch/scripts
install -m 644 vswitchd/vswitch.ovsschema \
         $RPM_BUILD_ROOT/usr/share/openvswitch/vswitch.ovsschema
install -m 755 xenserver/opt_xensource_libexec_interface-reconfigure \
             $RPM_BUILD_ROOT/usr/share/openvswitch/scripts/interface-reconfigure
install -m 644 xenserver/opt_xensource_libexec_InterfaceReconfigure.py \
             $RPM_BUILD_ROOT/usr/share/openvswitch/scripts/InterfaceReconfigure.py
install -m 644 xenserver/opt_xensource_libexec_InterfaceReconfigureBridge.py \
             $RPM_BUILD_ROOT/usr/share/openvswitch/scripts/InterfaceReconfigureBridge.py
install -m 644 xenserver/opt_xensource_libexec_InterfaceReconfigureVswitch.py \
             $RPM_BUILD_ROOT/usr/share/openvswitch/scripts/InterfaceReconfigureVswitch.py
install -m 755 xenserver/etc_xensource_scripts_vif \
             $RPM_BUILD_ROOT/usr/share/openvswitch/scripts/vif
install -m 755 xenserver/usr_share_openvswitch_scripts_monitor-external-ids \
               $RPM_BUILD_ROOT/usr/share/openvswitch/scripts/monitor-external-ids
install -m 755 xenserver/usr_share_openvswitch_scripts_refresh-xs-network-uuids \
               $RPM_BUILD_ROOT/usr/share/openvswitch/scripts/refresh-xs-network-uuids
install -m 755 xenserver/usr_sbin_xen-bugtool \
             $RPM_BUILD_ROOT/usr/share/openvswitch/scripts/xen-bugtool
install -m 755 xenserver/usr_sbin_brctl \
             $RPM_BUILD_ROOT/usr/share/openvswitch/scripts/brctl
install -m 755 xenserver/usr_share_openvswitch_scripts_sysconfig.template \
         $RPM_BUILD_ROOT/usr/share/openvswitch/scripts/sysconfig.template
install -d -m 755 $RPM_BUILD_ROOT/usr/lib/xsconsole/plugins-base
install -m 644 \
        xenserver/usr_lib_xsconsole_plugins-base_XSFeatureVSwitch.py \
               $RPM_BUILD_ROOT/usr/lib/xsconsole/plugins-base/XSFeatureVSwitch.py

install -d -m 755 $RPM_BUILD_ROOT/lib/modules/%{xen_version}/kernel/extra/openvswitch
find datapath/linux-2.6 -name *.ko -exec install -m 755  \{\} $RPM_BUILD_ROOT/lib/modules/%{xen_version}/kernel/extra/openvswitch \;
install xenserver/uuid.py $RPM_BUILD_ROOT/usr/share/openvswitch/python

# Get rid of stuff we don't want to make RPM happy.
rm \
    $RPM_BUILD_ROOT/usr/bin/ovs-controller \
    $RPM_BUILD_ROOT/usr/bin/ovs-discover \
    $RPM_BUILD_ROOT/usr/bin/ovs-kill \
    $RPM_BUILD_ROOT/usr/bin/ovs-openflowd \
    $RPM_BUILD_ROOT/usr/bin/ovs-pki \
    $RPM_BUILD_ROOT/usr/share/man/man8/ovs-controller.8 \
    $RPM_BUILD_ROOT/usr/share/man/man8/ovs-discover.8 \
    $RPM_BUILD_ROOT/usr/share/man/man8/ovs-kill.8 \
    $RPM_BUILD_ROOT/usr/share/man/man8/ovs-openflowd.8 \
    $RPM_BUILD_ROOT/usr/share/man/man8/ovs-pki.8

install -d -m 755 $RPM_BUILD_ROOT/var/lib/openvswitch

%clean
rm -rf $RPM_BUILD_ROOT

%post
if [ ! -f /etc/xensource-inventory ]; then
    printf "XenSource inventory not present in /etc/xensource-inventory"
    exit 1
fi
. /etc/xensource-inventory

if [ "$1" = "1" ]; then
    if md5sum -c --status <<EOF
ca141d60061dcfdade73e75abc6529b5  /usr/sbin/brctl
b8e9835862ef1a9cec2a3f477d26c989  /etc/xensource/scripts/vif
51970ad613a3996d5997e18e44db47da  /opt/xensource/libexec/interface-reconfigure
5654c8c36699fcc8744ca9cd5b855414  /usr/sbin/xen-bugtool
EOF
    then
        printf "\nVerified host scripts from XenServer 5.5.0.\n\n"
    elif md5sum -c --status <<EOF
ca141d60061dcfdade73e75abc6529b5  /usr/sbin/brctl
b8e9835862ef1a9cec2a3f477d26c989  /etc/xensource/scripts/vif
51970ad613a3996d5997e18e44db47da  /opt/xensource/libexec/interface-reconfigure
f6519085c2fc5f7bc4eccc294ed62000  /usr/sbin/xen-bugtool
EOF
    then
        printf "\nVerified host scripts from XenServer 5.5.0-24648p (Update 1)\n"
        printf "or 5.5.0-25727p (Update 2).\n\n"
    elif md5sum -c --status <<EOF
ca141d60061dcfdade73e75abc6529b5  /usr/sbin/brctl
02cf136237ed85fcbcc1efc15ce0591c  /opt/xensource/libexec/interface-reconfigure
3a192ee70ebf2153c90051b3af95f331  /opt/xensource/libexec/InterfaceReconfigureBridge.py
f71cadf1464caefa7943de0ab47fdd8a  /opt/xensource/libexec/InterfaceReconfigure.py
d70f08f235fb1bfd49a0580e440f15a0  /opt/xensource/libexec/InterfaceReconfigureVswitch.py
f5c85ca825b1e6f5a0845530981cd836  /etc/xensource/scripts/vif
facb851606f82ca2bcc760a4d91bbe33  /usr/sbin/xen-bugtool
EOF
    then
        printf "\nVerified host scripts from XenServer 5.5.900-29381p.\n\n"
    else
cat <<EOF

The original XenServer scripts replaced by this package are not those
of any supported version of XenServer.  This could lead to unexpected
behavior of your server.  Unless you are sure you know what you are
doing, it is highly recommended that you remove this package
immediately after the install completes, which will restore the
XenServer scripts that you were previously using.

EOF
    fi
fi

# On XenServer 5.5.0, we need refresh-xs-network-uuids to run whenever
# XAPI starts or restarts.  (On XenServer 5.6.0, XAPI calls the
# "update" method of the vswitch-cfg-update plugin whenever it starts
# or restarts, so this is no longer necessary.)
if test "$PRODUCT_VERSION" = "5.5.0"; then
    RNU=/usr/share/openvswitch/scripts/refresh-xs-network-uuids
    XSS=/opt/xensource/libexec/xapi-startup-script
    if test -e $XSS && (test ! -L $XSS || test "`readlink $XSS`" != $RNU); then
        echo "$XSS is already in use, refusing to overwrite"
        exit 1
    fi
    rm -f $XSS
    ln -s $RNU $XSS

    # If /etc/xensource/network.conf doesn't exist (it was added in 5.6.0),
    # then interface-reconfigure will be unhappy when we run it below.
    if test ! -e /etc/xensource/network.conf; then
        echo bridge > /etc/xensource/network.conf
    fi
fi


if test ! -e /var/xapi/network.dbcache; then
    if test "$1" = 1; then
        printf "Creating xapi database cache...  "
    else
        printf "warning: Open vSwitch is being re-installed or upgraded,\n"
        printf "         but the xapi database cache is missing.\n"
        printf "Re-creating xapi database cache...  "
    fi

    if /usr/share/openvswitch/scripts/interface-reconfigure rewrite; then
        printf "done.\n"
    else
        printf "FAILED\n"
        printf "Open vSwitch can only be installed on a XenServer that\n"
        printf "has connectivity to xapi on the pool master.  Please\n"
        printf "fix connectivity to the pool master, then try again.\n"
        exit 1
    fi
fi

# Ensure that modprobe will find our modules.
depmod %{xen_version}

if grep -F net.ipv4.conf.all.arp_filter /etc/sysctl.conf >/dev/null 2>&1; then :; else
    cat >>/etc/sysctl.conf <<EOF
# This works around an issue in xhad, which binds to a particular
# Ethernet device, which in turn causes ICMP port unreachable messages
# if packets are received are on the wrong interface, which in turn
# can happen if we send out ARP replies on every interface (as Linux
# does by default) instead of just on the interface that has the IP
# address being ARPed for, which this sysctl setting in turn works
# around.
#
# Bug #1378.
net.ipv4.conf.all.arp_filter = 1
EOF
fi

if test ! -e /etc/openvswitch/conf.db; then
    install -d -m 755 -o root -g root /etc/openvswitch

    # Create ovs-vswitchd config database
    ovsdb-tool -vANY:console:emer create /etc/openvswitch/conf.db \
            /usr/share/openvswitch/vswitch.ovsschema

    # Create initial table in config database
    ovsdb-tool -vANY:console:emer transact /etc/openvswitch/conf.db \
            '[{"op": "insert", "table": "Open_vSwitch", "row": {}}]' \
            > /dev/null
fi

# Create default or update existing /etc/sysconfig/openvswitch.
SYSCONFIG=/etc/sysconfig/openvswitch
TEMPLATE=/usr/share/openvswitch/scripts/sysconfig.template
if [ ! -e $SYSCONFIG ]; then
    cp $TEMPLATE $SYSCONFIG
else
    for var in $(awk -F'[ :]' '/^# [_A-Z0-9]+:/{print $2}' $TEMPLATE)
    do
        if ! grep $var $SYSCONFIG >/dev/null 2>&1; then
            echo >> $SYSCONFIG
            sed -n "/$var:/,/$var=/p" $TEMPLATE >> $SYSCONFIG
        fi
    done
fi

# Replace XenServer files by our versions.
mkdir -p /usr/lib/openvswitch/xs-original \
    || printf "Could not create script backup directory.\n"
for f in \
    /opt/xensource/libexec/interface-reconfigure \
    /opt/xensource/libexec/InterfaceReconfigure.py \
    /opt/xensource/libexec/InterfaceReconfigureBridge.py \
    /opt/xensource/libexec/InterfaceReconfigureVswitch.py \
    /etc/xensource/scripts/vif \
    /usr/sbin/xen-bugtool \
    /usr/sbin/brctl
do
    s=$(basename "$f")
    t=$(readlink "$f")
    if [ -f "$f" ] && [ "$t" != "/usr/share/openvswitch/scripts/$s" ]; then
        mv "$f" /usr/lib/openvswitch/xs-original/ \
            || printf "Could not save original XenServer $s script\n"
        ln -s "/usr/share/openvswitch/scripts/$s" "$f" \
            || printf "Could not link to Open vSwitch $s script\n"
    fi
done

# Ensure all required services are set to run
for s in openvswitch openvswitch-xapi-update; do
    if chkconfig --list $s >/dev/null 2>&1; then
        chkconfig --del $s || printf "Could not remove $s init script."
    fi
    chkconfig --add $s || printf "Could not add $s init script."
    chkconfig $s on || printf "Could not enable $s init script."
done

# Configure system to use Open vSwitch
echo vswitch > /etc/xensource/network.conf

if [ "$1" = "1" ]; then    # $1 = 2 for upgrade
    printf "\nYou MUST reboot the server NOW to complete the change to\n"
    printf "Open vSwitch.  Attempts to modify networking on the server\n"
    printf "or any hosted VM will fail until after the reboot and could\n"
    printf "leave the server in an state requiring manual recovery.\n\n"
else
    printf "\nTo use the new Open vSwitch install, you should reboot the\n" 
    printf "server now.  Failure to do so may result in incorrect operation."
    printf "\n\n"
fi

%preun
if [ "$1" = "0" ]; then     # $1 = 1 for upgrade
    for s in openvswitch openvswitch-xapi-update; do
        chkconfig --del $s || printf "Could not remove $s init script."
    done
fi


%postun
if [ "$1" = "0" ]; then     # $1 = 1 for upgrade
    . /etc/xensource-inventory
    if test "$PRODUCT_VERSION" = "5.5.0"; then
        XSS=/opt/xensource/libexec/xapi-startup-script
        rm -f $XSS
    fi

    rm -f /usr/lib/xsconsole/plugins-base/XSFeatureVSwitch.pyc \
        /usr/lib/xsconsole/plugins-base/XSFeatureVSwitch.pyo

    rm -f /usr/share/openvswitch/scripts/InterfaceReconfigure.pyc \
        /usr/share/openvswitch/scripts/InterfaceReconfigure.pyo \
        /usr/share/openvswitch/scripts/InterfaceReconfigureBridge.pyc \
        /usr/share/openvswitch/scripts/InterfaceReconfigureBridge.pyo \
        /usr/share/openvswitch/scripts/InterfaceReconfigureVSwitch.pyc \
        /usr/share/openvswitch/scripts/InterfaceReconfigureVSwitch.pyo 

    # Restore original XenServer scripts
    for f in \
        /opt/xensource/libexec/interface-reconfigure \
        /opt/xensource/libexec/InterfaceReconfigure.py \
        /opt/xensource/libexec/InterfaceReconfigureBridge.py \
        /opt/xensource/libexec/InterfaceReconfigureVswitch.py \
        /etc/xensource/scripts/vif \
        /usr/sbin/xen-bugtool \
        /usr/sbin/brctl
    do
        s=$(basename "$f")
        if [ ! -f "/usr/lib/openvswitch/xs-original/$s" ]; then
            printf "Original XenServer $s script not present in /usr/lib/openvswitch/xs-original\n"
            printf "Could not restore original XenServer script.\n"
        else
            (rm -f "$f" \
                && mv "/usr/lib/openvswitch/xs-original/$s" "$f") \
                || printf "Could not restore original XenServer $s script.\n"
        fi
    done

    # Remove all configuration files
    rm -f /etc/openvswitch/conf.db
    rm -f /etc/sysconfig/openvswitch
    rm -f /etc/openvswitch/vswitchd.cacert
    rm -f /var/xapi/network.dbcache

    if test "$PRODUCT_VERSION" != "5.5.0"; then
        # Configure system to use bridge
        echo bridge > /etc/xensource/network.conf
    else
        # Get rid of network.conf entirely, to make the system pristine.
        rm -f /etc/xensource/network.conf
    fi

    printf "\nYou MUST reboot the server now to complete the change to\n"
    printf "standard Xen networking.  Attempts to modify networking on the\n"
    printf "server or any hosted VM will fail until after the reboot and\n"
    printf "could leave the server in a state requiring manual recovery.\n\n"
fi


%files
%defattr(-,root,root)
/etc/init.d/openvswitch
/etc/init.d/openvswitch-xapi-update
/etc/xapi.d/plugins/openvswitch-cfg-update
/etc/logrotate.d/openvswitch
/etc/profile.d/openvswitch.sh
/lib/modules/%{xen_version}/kernel/extra/openvswitch/openvswitch_mod.ko
/lib/modules/%{xen_version}/kernel/extra/openvswitch/brcompat_mod.ko
/usr/share/openvswitch/python/ovs/__init__.py
/usr/share/openvswitch/python/ovs/daemon.py
/usr/share/openvswitch/python/ovs/db/__init__.py
/usr/share/openvswitch/python/ovs/db/data.py
/usr/share/openvswitch/python/ovs/db/error.py
/usr/share/openvswitch/python/ovs/db/idl.py
/usr/share/openvswitch/python/ovs/db/parser.py
/usr/share/openvswitch/python/ovs/db/schema.py
/usr/share/openvswitch/python/ovs/db/types.py
/usr/share/openvswitch/python/ovs/dirs.py
/usr/share/openvswitch/python/ovs/fatal_signal.py
/usr/share/openvswitch/python/ovs/json.py
/usr/share/openvswitch/python/ovs/jsonrpc.py
/usr/share/openvswitch/python/ovs/ovsuuid.py
/usr/share/openvswitch/python/ovs/poller.py
/usr/share/openvswitch/python/ovs/process.py
/usr/share/openvswitch/python/ovs/reconnect.py
/usr/share/openvswitch/python/ovs/socket_util.py
/usr/share/openvswitch/python/ovs/stream.py
/usr/share/openvswitch/python/ovs/timeval.py
/usr/share/openvswitch/python/ovs/util.py
/usr/share/openvswitch/python/uuid.py
/usr/share/openvswitch/scripts/monitor-external-ids
/usr/share/openvswitch/scripts/refresh-xs-network-uuids
/usr/share/openvswitch/scripts/interface-reconfigure
/usr/share/openvswitch/scripts/InterfaceReconfigure.py
/usr/share/openvswitch/scripts/InterfaceReconfigureBridge.py
/usr/share/openvswitch/scripts/InterfaceReconfigureVswitch.py
/usr/share/openvswitch/scripts/vif
/usr/share/openvswitch/scripts/xen-bugtool
/usr/share/openvswitch/scripts/brctl
/usr/share/openvswitch/scripts/sysconfig.template
/usr/share/openvswitch/vswitch.ovsschema
/usr/sbin/ovs-brcompatd
/usr/sbin/ovs-vswitchd
/usr/sbin/ovsdb-server
/usr/bin/ovs-appctl
/usr/bin/ovs-dpctl
/usr/bin/ovs-ofctl
/usr/bin/ovs-vsctl
/usr/bin/ovsdb-client
/usr/bin/ovsdb-tool
/usr/lib/xsconsole/plugins-base/XSFeatureVSwitch.py
/usr/share/man/man1/ovsdb-client.1.gz
/usr/share/man/man1/ovsdb-server.1.gz
/usr/share/man/man1/ovsdb-tool.1.gz
/usr/share/man/man5/ovs-vswitchd.conf.db.5.gz
/usr/share/man/man8/ovs-appctl.8.gz
/usr/share/man/man8/ovs-brcompatd.8.gz
/usr/share/man/man8/ovs-dpctl.8.gz
/usr/share/man/man8/ovs-ofctl.8.gz
/usr/share/man/man8/ovs-parse-leaks.8.gz
/usr/share/man/man8/ovs-vsctl.8.gz
/usr/share/man/man8/ovs-vswitchd.8.gz
/var/lib/openvswitch
%exclude /usr/lib/xsconsole/plugins-base/*.py[co]
%exclude /usr/share/openvswitch/scripts/*.py[co]
%exclude /usr/share/openvswitch/python/*.py[co]
%exclude /usr/share/openvswitch/python/ovs/*.py[co]
%exclude /usr/share/openvswitch/python/ovs/db/*.py[co]
