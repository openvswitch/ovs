#!/bin/sh
#
ovn-nbctl lswitch-add sw0

ovn-nbctl lport-add sw0 sw0-port1
ovn-nbctl lport-add sw0 sw0-port2
ovn-nbctl lport-add sw0 sw0-portf1
ovn-nbctl lport-add sw0 sw0-portf2

ovn-nbctl lport-set-addresses sw0-port1 "52:54:00:45:b9:cc 172.16.33.1"
ovn-nbctl lport-set-addresses sw0-port2 "52:54:00:f6:2e:85 172.16.33.2"
ovn-nbctl lport-set-addresses sw0-portf1 52:54:00:7f:d3:b8
ovn-nbctl lport-set-addresses sw0-portf2 52:54:00:8f:75:d4

#ovs-vsctl add-br br-sfi
# Bind sw0-port1 and sw0-port2 to the local chassis
ovs-vsctl set Interface lport1 external_ids:iface-id=sw0-port1
ovs-vsctl set Interface lport2 external_ids:iface-id=sw0-port2
ovs-vsctl set Interface lportf1 external_ids:iface-id=sw0-portf1
ovs-vsctl set Interface lportf2 external_ids:iface-id=sw0-portf2
