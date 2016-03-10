#! /bin/sh
#
set -o xtrace

# Trace a packet from sw0-port1 to sw0-port2.
ovs-appctl ofproto/trace br-int in_port=4,dl_src=52:54:00:45:b9:cc,dl_dst=52:54:00:f6:2e:85 -generate
#
# Reverse Direction
ovs-appctl ofproto/trace br-int in_port=3,dl_dst=52:54:00:45:b9:cc,dl_src=52:54:00:f6:2e:85 -generate
