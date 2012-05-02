# Copyright (C) 2009, 2010, 2011 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

alias vswitch='service openvswitch'
alias openvswitch='service openvswitch'

function watchdp {
	watch ovs-dpctl show "$@"
}

function watchdpflows {
	local grep=""
	local dp=$1
	shift
	if [ $# -gt 0 ]; then
		grep="| grep $@"
	fi
	watch "ovs-dpctl dump-flows $dp $grep"
}

function watchflows {
	local grep=""
	local dp=$1
	shift
	bridge=$(ovs-dpctl show $dp | grep 'port 0:' | cut -d' ' -f 3)
	if [ $# -gt 0 ]; then
		grep="| grep $@"
	fi
	watch "ovs-ofctl dump-flows unix:/var/run/$bridge.mgmt $grep"
}

function monitorlogs {
    local grep=""
    if [ $# -gt 0 ]; then
        grep="| grep --line-buffered '^==> .* <==$"
        for i in "$@"; do
            grep="$grep\|$i"
        done
        grep="$grep'"
    fi
    cmd="tail -F /var/log/messages /var/log/openvswitch/ovs-vswitchd.log /var/log/openvswitch/ovsdb-server /var/log/xensource.log $grep | tee /var/log/monitorlogs.out"
    printf "cmd: $cmd\n"
    eval "$cmd"
}
