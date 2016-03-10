#! /bin/sh
#
set -o xtrace
#
# Trace a packet from sw0-portf1 to sw0-port1.
ovs-appctl ofproto/trace br-int in_port=1,dl_src=fe:54:00:7f:d3:b8,dl_dst=fe:54:00:45:b9:cc -generate
#
# Trace a packet from sw0-portf1 to sw0-port2
ovs-appctl ofproto/trace br-int in_port=1,dl_src=fe:54:00:7f:d3:b8,dl_dst=fe:54:00:f6:2e:85 -generate
