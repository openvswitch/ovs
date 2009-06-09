# Spec file for vswitch and related programs.

# Copyright (C) 2009 Nicira Networks, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

# When building, the rpmbuild command line should define
# vswitch_version, xen_version, and build_number using -D arguments.
# for example:
#
#    rpmbuild -D "vswitch_version 0.8.9~1+build123" -D "xen_version 2.6.18-128.1.1.el5.xs5.1.0.483.1000xen" -D "build_number --with-build-number=123" -bb /usr/src/redhat/SPECS/vswitch-xen.spec
#
%define version %{vswitch_version}-%{xen_version}
%define _prefix /root/vswitch

Name: vswitch
Summary: Virtual switch
Group: System Environment/Daemons
URL: http://www.openvswitch.org/
Version: %{vswitch_version}
License: GPL3
Release: 1
Source: openvswitch-%{vswitch_version}.tar.gz
Buildroot: /tmp/vswitch-xen-rpm
Requires: kernel-xen = %(echo '%{xen_version}' | sed 's/xen$//')

%description
The vswitch provides standard network bridging functions augmented with
support for the OpenFlow protocol for remote per-flow control of
traffic.

%prep
%setup -q -n openvswitch-%{vswitch_version}

%build
./configure --prefix=%{_prefix} --localstatedir=%{_localstatedir} --with-l26=/lib/modules/%{xen_version}/build --enable-ssl %{build_number}
make %{_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT prefix=%{_prefix}
install -d -m 755 $RPM_BUILD_ROOT/etc
install -d -m 755 $RPM_BUILD_ROOT/etc/init.d
install -m 755 xenserver/etc_init.d_vswitch \
         $RPM_BUILD_ROOT/etc/init.d/vswitch
install -m 755 xenserver/etc_init.d_vswitch-xapi-update \
         $RPM_BUILD_ROOT/etc/init.d/vswitch-xapi-update
install -d -m 755 $RPM_BUILD_ROOT/etc/sysconfig
install -m 755 xenserver/etc_sysconfig_vswitch.example \
         $RPM_BUILD_ROOT/etc/sysconfig/vswitch.example
install -d -m 755 $RPM_BUILD_ROOT/etc/logrotate.d
install -m 755 xenserver/etc_logrotate.d_vswitch \
         $RPM_BUILD_ROOT/etc/logrotate.d/vswitch
install -d -m 755 $RPM_BUILD_ROOT/etc/profile.d
install -m 755 xenserver/etc_profile.d_vswitch.sh \
         $RPM_BUILD_ROOT/etc/profile.d/vswitch.sh
install -d -m 755 $RPM_BUILD_ROOT/etc/xapi.d/plugins
install -m 755 xenserver/etc_xapi.d_plugins_vswitch-cfg-update \
         $RPM_BUILD_ROOT/etc/xapi.d/plugins/vswitch-cfg-update
install -d -m 755 $RPM_BUILD_ROOT%{_prefix}/scripts
install -m 755 xenserver/opt_xensource_libexec_interface-reconfigure \
             $RPM_BUILD_ROOT%{_prefix}/scripts/interface-reconfigure
install -m 755 xenserver/etc_xensource_scripts_vif \
             $RPM_BUILD_ROOT%{_prefix}/scripts/vif
install -m 755 \
        xenserver/usr_lib_xsconsole_plugins-base_XSFeatureVSwitch.py \
               $RPM_BUILD_ROOT%{_prefix}/scripts/XSFeatureVSwitch.py

install -d -m 755 $RPM_BUILD_ROOT%{_prefix}/kernel_modules
find datapath/linux-2.6 -name *.ko -exec install -m 755  \{\} $RPM_BUILD_ROOT%{_prefix}/kernel_modules/ \;

# Get rid of stuff we don't want to make RPM happy.
rm -rf \
    $RPM_BUILD_ROOT/root/vswitch/bin/ezio-term \
    $RPM_BUILD_ROOT/root/vswitch/bin/ovs-controller \
    $RPM_BUILD_ROOT/root/vswitch/bin/ovs-discover \
    $RPM_BUILD_ROOT/root/vswitch/bin/ovs-kill \
    $RPM_BUILD_ROOT/root/vswitch/bin/ovs-pki \
    $RPM_BUILD_ROOT/root/vswitch/bin/ovs-switchui \
    $RPM_BUILD_ROOT/root/vswitch/bin/ovs-wdt \
    $RPM_BUILD_ROOT/root/vswitch/bin/secchan \
    $RPM_BUILD_ROOT/root/vswitch/sbin/ovs-monitor \
    $RPM_BUILD_ROOT/root/vswitch/share/man/man8/ovs-controller.8 \
    $RPM_BUILD_ROOT/root/vswitch/share/man/man8/ovs-discover.8 \
    $RPM_BUILD_ROOT/root/vswitch/share/man/man8/ovs-kill.8 \
    $RPM_BUILD_ROOT/root/vswitch/share/man/man8/ovs-pki.8 \
    $RPM_BUILD_ROOT/root/vswitch/share/man/man8/secchan.8 \
    $RPM_BUILD_ROOT/root/vswitch/share/openvswitch

%clean
rm -rf $RPM_BUILD_ROOT

%pre
if [ ! -f /etc/xensource-inventory ]; then
    printf "XenSource inventory not present in /etc/xensource-inventory"
    exit 1
fi

if [ "$1" = "1" ]; then
    if ! md5sum -c --status <<EOF
b8e9835862ef1a9cec2a3f477d26c989  /etc/xensource/scripts/vif
51970ad613a3996d5997e18e44db47da  /opt/xensource/libexec/interface-reconfigure
EOF
    then
        printf "\nThe original XenServer scripts replaced by this package\n"
        printf "are different than expected.  This could lead to unexpected\n"
        printf "behavior of your server.  Unless you are sure you know what\n"
        printf "you are doing, it is highly recomended that you remove this\n"
        printf "package immediately after the install completes, which\n"
        printf "will restore the XenServer scripts that you were previously\n"
        printf "using.\n\n"
    fi
fi

if test ! -e /etc/ovs-vswitch.dbcache; then
    if test "$1" = 1; then
        printf "Creating xapi database cache...  "
    else
        printf "warning: Open vSwitch is being re-installed or upgraded,\n"
        printf "         but the xapi database cache is missing.\n"
        printf "Re-creating xapi database cache...  "
    fi

    source /etc/xensource-inventory
    if python - "$INSTALLATION_UUID" <<EOF
import XenAPI
import pickle
import sys

session = XenAPI.xapi_local()
try:
    session.xenapi.login_with_password("root", "")

    vlans = session.xenapi.VLAN.get_all_records()
    bonds = session.xenapi.Bond.get_all_records()
    pifs = session.xenapi.PIF.get_all_records()
    networks = session.xenapi.network.get_all_records()
    host = session.xenapi.host.get_by_uuid(sys.argv[1])
finally:
    session.xenapi.session.logout()

dbcache_file = "/etc/ovs-vswitch.dbcache"
f = open(dbcache_file, 'w')
pickle.dump({'vlans': vlans,
             'bonds': bonds,
             'pifs': pifs,
             'networks': networks}, f)
pickle.dump({'host': host}, f)
f.close()
EOF
    then
        printf "done.\n"
    else
        printf "FAILED\n"
        printf "Open vSwitch can only be installed on a XenServer that\n"
        printf "has connectivity to xapi on the pool master.  Please\n"
        printf "fix connectivity to the pool master, then try again.\n"
        exit 1
    fi
fi

%post
source /etc/xensource-inventory

xe host-param-set \
    "other-config:vSwitchVersion=%{version}" uuid="$INSTALLATION_UUID" ||
    echo "Could not set vSwitchVersion config parameter"

# Ensure ovs-vswitchd.conf exists
touch /etc/ovs-vswitchd.conf

# Replace original XenServer files
mkdir -p %{_prefix}/xs-original \
    || printf "Could not create script backup directory.\n"
for f in \
    /opt/xensource/libexec/interface-reconfigure \
    /etc/xensource/scripts/vif
do
    s=$(basename "$f")
    t=$(readlink "$f")
    if [ "$t" != "%{_prefix}/scripts/$s" ]; then
        mv "$f" %{_prefix}/xs-original/ \
            || printf "Could not save original XenServer $s script\n"
        ln -s "%{_prefix}/scripts/$s" "$f" \
            || printf "Could not link to vSwitch $s script\n"
    fi
done

# Install xsconsole plugin
plugin=$(readlink /usr/lib/xsconsole/plugins-base/XSFeatureVSwitch.py)
if [ "$plugin" != "/root/vswitch/scripts/XSFeatureVSwitch.py" ]; then
    rm -f /usr/lib/xsconsole/plugins-base/XSFeatureVSwitch.py
    ln -s /root/vswitch/scripts/XSFeatureVSwitch.py /usr/lib/xsconsole/plugins-base/ || printf "Could not link to vSswitch xsconsole plugin.\n"
fi

# Ensure all required services are set to run
for s in vswitch vswitch-xapi-update; do
    if chkconfig --list $s >/dev/null 2>&1; then
        chkconfig --del $s || printf "Could not remove $s init script."
    fi
    chkconfig --add $s || printf "Could not add $s init script."
    chkconfig $s on || printf "Could not enable $s init script."
done

if [ "$1" = "1" ]; then    # $1 = 2 for upgrade
    printf "\nYou MUST reboot the server NOW to complete the change to the\n"
    printf "the vSwitch.  Attempts to modify networking on the server\n"
    printf "or any hosted VM will fail until after the reboot and could\n"
    printf "leave the server in an state requiring manual recovery.\n\n"
else
    printf "\nTo use the new vSwitch, you should reboot the server\n"
    printf "now.  Failure to do so may result in incorrect operation.\n\n"
fi

%preun
if [ "$1" = "0" ]; then     # $1 = 1 for upgrade
    for s in vswitch vswitch-xapi-update; do
        chkconfig --del $s || printf "Could not remove $s init script."
    done
fi


%postun
if [ "$1" = "0" ]; then     # $1 = 1 for upgrade

    rm -f /usr/lib/xsconsole/plugins-base/XSFeatureVSwitch.py \
        /usr/lib/xsconsole/plugins-base/XSFeatureVSwitch.pyc \
        /usr/lib/xsconsole/plugins-base/XSFeatureVSwitch.pyo \
        || printf "Could not remove vSwitch xsconsole plugin.\n"

    # Restore original XenServer scripts
    for f in \
        /opt/xensource/libexec/interface-reconfigure \
        /etc/xensource/scripts/vif
    do
        s=$(basename "$f")
        if [ ! -f "%{_prefix}/xs-original/$s" ]; then
            printf "Original XenServer $s script not present in %{_prefix}/xs-original\n"
            printf "Could not restore original XenServer script.\n"
        else
            (rm -f "$f" \
                && mv "%{_prefix}/xs-original/$s" "$f") \
                || printf "Could not restore original XenServer $s script.\n"
        fi
    done

    find  %{_prefix} -type d -depth -exec rmdir \{\} \; \
        || printf "Could not remove vSwitch install directory.\n"

    # Remove all configuration and log files
    rm -f /etc/ovs-vswitchd.conf
    rm -f /etc/sysconfig/vswitch
    rm -f /var/log/vswitch*
    rm -f /etc/ovs-vswitchd.cacert

    if [ ! -f /etc/xensource-inventory ]; then
        printf "XenSource inventory not present in /etc/xensource-inventory\n"
        printf "Could not remove vSwitchVersion from XAPI database.\n"
        exit 1
    else
        source /etc/xensource-inventory
        xe host-param-remove \
            param-name=other-config param-key=vSwitchVersion \
            uuid="$INSTALLATION_UUID" ||
            echo "Could not clear vSwitchVersion config parameter."
    fi

    printf "\nYou MUST reboot the server now to complete the change to\n"
    printf "standard Xen networking.  Attempts to modify networking on the\n"
    printf "server or any hosted VM will fail until after the reboot and\n"
    printf "could leave the server in a state requiring manual recovery.\n\n"
fi


%files
%defattr(-,root,root)
/etc/init.d/vswitch
/etc/init.d/vswitch-xapi-update
/etc/xapi.d/plugins/vswitch-cfg-update
/etc/sysconfig/vswitch.example
/etc/logrotate.d/vswitch
/etc/profile.d/vswitch.sh
/root/vswitch/kernel_modules/brcompat_mod.ko
/root/vswitch/kernel_modules/openvswitch_mod.ko
/root/vswitch/kernel_modules/veth_mod.ko
/root/vswitch/scripts/interface-reconfigure
/root/vswitch/scripts/vif
/root/vswitch/scripts/XSFeatureVSwitch.py
# Following two files are generated automatically by rpm.  We don't
# really need them and they won't be used on the XenServer, but there
# isn't an obvious place to get rid of them since they are generated
# after the install script runs.  Since they are small, we just
# include them.
/root/vswitch/scripts/XSFeatureVSwitch.pyc
/root/vswitch/scripts/XSFeatureVSwitch.pyo
/root/vswitch/sbin/ovs-brcompatd
/root/vswitch/sbin/ovs-vswitchd
/root/vswitch/bin/ovs-appctl
/root/vswitch/bin/ovs-cfg-mod
/root/vswitch/bin/ovs-dpctl
/root/vswitch/bin/ovs-ofctl
/root/vswitch/share/man/man5/ovs-vswitchd.conf.5
/root/vswitch/share/man/man8/ovs-appctl.8
/root/vswitch/share/man/man8/ovs-brcompatd.8
/root/vswitch/share/man/man8/ovs-cfg-mod.8
/root/vswitch/share/man/man8/ovs-dpctl.8
/root/vswitch/share/man/man8/ovs-ofctl.8
/root/vswitch/share/man/man8/ovs-vswitchd.8
