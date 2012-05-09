#! /bin/sh

# Copyright (c) 2012 Nicira, Inc.
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

# Have a look at /usr/share/doc/openvswitch-switch/README.Debian
# for more information about configuring the /etc/network/interfaces.

if [ -z "${IF_OVS_TYPE}" ]; then
    exit 0
fi

ovs_vsctl() {
    ovs-vsctl --timeout=5 "$@"
}

if (ovs_vsctl --version) > /dev/null 2>&1; then :; else
    exit 0
fi

if [ "${MODE}" = "start" ]; then
    eval OVS_EXTRA=\"${IF_OVS_EXTRA}\"

    case "${IF_OVS_TYPE}" in
        OVSBridge)
                ovs_vsctl -- --may-exist add-br "${IFACE}" ${IF_OVS_OPTIONS}\
                         ${OVS_EXTRA+-- $OVS_EXTRA}

                if [ ! -z "${IF_OVS_PORTS}" ]; then
                    ifup --allow="${IFACE}" ${IF_OVS_PORTS}
                fi
                ;;
        OVSPort)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    "${IFACE}" ${IF_OVS_OPTIONS} \
                    ${OVS_EXTRA+-- $OVS_EXTRA}

                ifconfig "${IFACE}" up
                ;;
        OVSIntPort)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    "${IFACE}" ${IF_OVS_OPTIONS} -- set Interface "${IFACE}"\
                    type=internal ${OVS_EXTRA+-- $OVS_EXTRA}

                ifconfig "${IFACE}" up
                ;;
        OVSBond)
                ovs_vsctl -- --fake-iface add-bond "${IF_OVS_BRIDGE}"\
                    "${IFACE}" ${IF_OVS_BONDS} ${IF_OVS_OPTIONS} \
                    ${OVS_EXTRA+-- $OVS_EXTRA}

                ifconfig "${IFACE}" up
                ;;
        *)
                exit 0
                ;;
    esac
elif [ "${MODE}" = "stop" ]; then
    case "${IF_OVS_TYPE}" in
        OVSBridge)
                if [ ! -z "${IF_OVS_PORTS}" ]; then
                    ifdown --allow="${IFACE}" ${IF_OVS_PORTS}
                fi

                ovs_vsctl -- --if-exists del-br "${IFACE}"
                ;;
        OVSPort|OVSIntPort|OVSBond)
                ovs_vsctl -- --if-exists del-port "${IF_OVS_BRIDGE}" "${IFACE}"
                ;;
        *)
                exit 0
                ;;
    esac
fi

exit 0
