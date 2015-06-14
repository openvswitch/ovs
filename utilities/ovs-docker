#!/bin/bash
# Copyright (C) 2014 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Check for programs we'll need.
search_path () {
    save_IFS=$IFS
    IFS=:
    for dir in $PATH; do
        IFS=$save_IFS
        if test -x "$dir/$1"; then
            return 0
        fi
    done
    IFS=$save_IFS
    echo >&2 "$0: $1 not found in \$PATH, please install and try again"
    exit 1
}

ovs_vsctl () {
    ovs-vsctl --timeout=60 "$@"
}

create_netns_link () {
    mkdir -p /var/run/netns
    if [ ! -e /var/run/netns/"$PID" ]; then
        ln -s /proc/"$PID"/ns/net /var/run/netns/"$PID"
        trap 'delete_netns_link' 0
        for signal in 1 2 3 13 14 15; do
            trap 'delete_netns_link; trap - $signal; kill -$signal $$' $signal
        done
    fi
}

delete_netns_link () {
    rm -f /var/run/netns/"$PID"
}

get_port_for_container_interface () {
    CONTAINER="$1"
    INTERFACE="$2"

    PORT=`ovs_vsctl --data=bare --no-heading --columns=name find interface \
             external_ids:container_id="$CONTAINER"  \
             external_ids:container_iface="$INTERFACE"`
    if [ -z "$PORT" ]; then
        echo >&2 "$UTIL: Failed to find any attached port" \
                 "for CONTAINER=$CONTAINER and INTERFACE=$INTERFACE"
    fi
    echo "$PORT"
}

add_port () {
    BRIDGE="$1"
    INTERFACE="$2"
    CONTAINER="$3"

    if [ -z "$BRIDGE" ] || [ -z "$INTERFACE" ] || [ -z "$CONTAINER" ]; then
        echo >&2 "$UTIL add-port: not enough arguments (use --help for help)"
        exit 1
    fi

    shift 3
    while [ $# -ne 0 ]; do
        case $1 in
            --ipaddress=*)
                ADDRESS=`expr X"$1" : 'X[^=]*=\(.*\)'`
                shift
                ;;
            --macaddress=*)
                MACADDRESS=`expr X"$1" : 'X[^=]*=\(.*\)'`
                shift
                ;;
            --gateway=*)
                GATEWAY=`expr X"$1" : 'X[^=]*=\(.*\)'`
                shift
                ;;
            --mtu=*)
                MTU=`expr X"$1" : 'X[^=]*=\(.*\)'`
                shift
                ;;
            *)
                echo >&2 "$UTIL add-port: unknown option \"$1\""
                exit 1
                ;;
        esac
    done

    # Check if a port is already attached for the given container and interface
    PORT=`get_port_for_container_interface "$CONTAINER" "$INTERFACE" \
            2>/dev/null`
    if [ -n "$PORT" ]; then
        echo >&2 "$UTIL: Port already attached" \
                 "for CONTAINER=$CONTAINER and INTERFACE=$INTERFACE"
        exit 1
    fi

    if ovs_vsctl br-exists "$BRIDGE" || \
        ovs_vsctl add-br "$BRIDGE"; then :; else
        echo >&2 "$UTIL: Failed to create bridge $BRIDGE"
        exit 1
    fi

    if PID=`docker inspect -f '{{.State.Pid}}' "$CONTAINER"`; then :; else
        echo >&2 "$UTIL: Failed to get the PID of the container"
        exit 1
    fi

    create_netns_link

    # Create a veth pair.
    ID=`uuidgen | sed 's/-//g'`
    PORTNAME="${ID:0:13}"
    ip link add "${PORTNAME}_l" type veth peer name "${PORTNAME}_c"

    # Add one end of veth to OVS bridge.
    if ovs_vsctl --may-exist add-port "$BRIDGE" "${PORTNAME}_l" \
       -- set interface "${PORTNAME}_l" \
       external_ids:container_id="$CONTAINER" \
       external_ids:container_iface="$INTERFACE"; then :; else
        echo >&2 "$UTIL: Failed to add "${PORTNAME}_l" port to bridge $BRIDGE"
        ip link delete "${PORTNAME}_l"
        exit 1
    fi

    ip link set "${PORTNAME}_l" up

    # Move "${PORTNAME}_c" inside the container and changes its name.
    ip link set "${PORTNAME}_c" netns "$PID"
    ip netns exec "$PID" ip link set dev "${PORTNAME}_c" name "$INTERFACE"
    ip netns exec "$PID" ip link set "$INTERFACE" up

    if [ -n "$MTU" ]; then
        ip netns exec "$PID" ip link set dev "$INTERFACE" mtu "$MTU"
    fi

    if [ -n "$ADDRESS" ]; then
        ip netns exec "$PID" ip addr add "$ADDRESS" dev "$INTERFACE"
    fi

    if [ -n "$MACADDRESS" ]; then
        ip netns exec "$PID" ip link set dev "$INTERFACE" address "$MACADDRESS"
    fi

    if [ -n "$GATEWAY" ]; then
        ip netns exec "$PID" ip route add default via "$GATEWAY"
    fi
}

del_port () {
    BRIDGE="$1"
    INTERFACE="$2"
    CONTAINER="$3"

    if [ "$#" -lt 3 ]; then
        usage
        exit 1
    fi

    PORT=`get_port_for_container_interface "$CONTAINER" "$INTERFACE"`
    if [ -z "$PORT" ]; then
        exit 1
    fi

    ovs_vsctl --if-exists del-port "$PORT"

    ip link delete "$PORT"
}

del_ports () {
    BRIDGE="$1"
    CONTAINER="$2"
    if [ "$#" -lt 2 ]; then
        usage
        exit 1
    fi

    PORTS=`ovs_vsctl --data=bare --no-heading --columns=name find interface \
             external_ids:container_id="$CONTAINER"`
    if [ -z "$PORTS" ]; then
        exit 0
    fi

    for PORT in $PORTS; do
        ovs_vsctl --if-exists del-port "$PORT"
        ip link delete "$PORT"
    done
}

set_vlan () {
    BRIDGE="$1"
    INTERFACE="$2"
    CONTAINER_ID="$3"
    VLAN="$4"

    if [ "$#" -lt 4 ]; then
        usage
        exit 1
    fi

    PORT=`get_port_for_container_interface "$CONTAINER_ID" "$INTERFACE"`
    if [ -z "$PORT" ]; then
        exit 1
    fi
    ovs_vsctl set port "$PORT" tag="$VLAN"
}

usage() {
    cat << EOF
${UTIL}: Performs integration of Open vSwitch with Docker.
usage: ${UTIL} COMMAND

Commands:
  add-port BRIDGE INTERFACE CONTAINER [--ipaddress="ADDRESS"]
                    [--gateway=GATEWAY] [--macaddress="MACADDRESS"]
                    [--mtu=MTU]
                    Adds INTERFACE inside CONTAINER and connects it as a port
                    in Open vSwitch BRIDGE. Optionally, sets ADDRESS on
                    INTERFACE. ADDRESS can include a '/' to represent network
                    prefix length. Optionally, sets a GATEWAY, MACADDRESS
                    and MTU.  e.g.:
                    ${UTIL} add-port br-int eth1 c474a0e2830e
                    --ipaddress=192.168.1.2/24 --gateway=192.168.1.1
                    --macaddress="a2:c3:0d:49:7f:f8" --mtu=1450
  del-port BRIDGE INTERFACE CONTAINER
                    Deletes INTERFACE inside CONTAINER and removes its
                    connection to Open vSwitch BRIDGE. e.g.:
                    ${UTIL} del-port br-int eth1 c474a0e2830e
  del-ports BRIDGE CONTAINER
                    Removes all Open vSwitch interfaces from CONTAINER. e.g.:
                    ${UTIL} del-ports br-int c474a0e2830e
  set-vlan BRIDGE INTERFACE CONTAINER VLAN
                    Configures the INTERFACE of CONTAINER attached to BRIDGE
                    to become an access port of VLAN. e.g.:
                    ${UTIL} set-vlan br-int eth1 c474a0e2830e 5
Options:
  -h, --help        display this help message.
EOF
}

UTIL=$(basename $0)
search_path ovs-vsctl
search_path docker
search_path uuidgen

if (ip netns) > /dev/null 2>&1; then :; else
    echo >&2 "$UTIL: ip utility not found (or it does not support netns),"\
             "cannot proceed"
    exit 1
fi

if [ $# -eq 0 ]; then
    usage
    exit 0
fi

case $1 in
    "add-port")
        shift
        add_port "$@"
        exit 0
        ;;
    "del-port")
        shift
        del_port "$@"
        exit 0
        ;;
    "del-ports")
        shift
        del_ports "$@"
        exit 0
        ;;
    "set-vlan")
        shift
        set_vlan "$@"
        exit 0
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        echo >&2 "$UTIL: unknown command \"$1\" (use --help for help)"
        exit 1
        ;;
esac
