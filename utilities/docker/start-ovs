#!/bin/bash
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

case $1 in
        "ovsdb-server") /usr/share/openvswitch/scripts/ovs-ctl start \
                        --system-id=random --no-ovs-vswitchd
                        /usr/share/openvswitch/scripts/ovs-ctl stop
                        ovsdb-server --pidfile /etc/openvswitch/conf.db \
                        -vconsole:emer -vsyslog:err -vfile:info \
                        --remote=punix:/var/run/openvswitch/db.sock \
                        --private-key=db:Open_vSwitch,SSL,private_key \
                        --certificate=db:Open_vSwitch,SSL,certificate \
                        --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
                        --log-file=/var/log/openvswitch/ovsdb-server.log \
                        --no-chdir
        ;;
        "ovs-vswitchd") depmod -a
                        modprobe openvswitch
                        modprobe vport_stt
                        modprobe vport_geneve
                        /usr/share/openvswitch/scripts/ovs-ctl \
                        --no-ovsdb-server start
                        /usr/share/openvswitch/scripts/ovs-ctl \
                        --no-ovsdb-server force-reload-kmod
                        /usr/share/openvswitch/scripts/ovs-ctl stop
                        ovs-vswitchd --pidfile -vconsole:emer -vsyslog:err \
                        -vfile:info --mlockall --no-chdir \
                        --log-file=/var/log/openvswitch/ovs-vswitchd.log
        ;;
        "ovs-vswitchd-host") /usr/share/openvswitch/scripts/ovs-ctl \
                             --no-ovsdb-server start
                             /usr/share/openvswitch/scripts/ovs-ctl stop
                             ovs-vswitchd --pidfile -vconsole:emer \
                             -vsyslog:err -vfile:info --mlockall --no-chdir \
                             --log-file=/var/log/openvswitch/ovs-vswitchd.log
        ;;
        *) echo "$0 [ovsdb-server|ovs-vswitchd|ovs-vswitchd-host]"
esac