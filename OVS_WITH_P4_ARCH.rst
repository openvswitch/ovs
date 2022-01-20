Open vSwitch With P4 Architecture
=================================

Introduction:
-------------------------------------------------------------------------------

P4-OVS is a a fork of Open vSwitch to support programming offloads to 
programmable pipelines via P4 language/specification. These patches will be 
upstreamed back to the OVS community and are being hosted temporarily on 
ipdk.io to get early feedback.

Overview:
--------------------------------------------------------------------------------

P4 with OVS adds a new dataplane option (in addition to 'ofproto'), called 
'p4proto' which connects up the kernel and OVS control planes into a P4 
pipeline via the TDI (Table Driven Inteface) interface of IPDK.

p4proto:
--------------------------------------------------------------------------------

P4proto has the following functions:

1. OVS Control Plane:  Interconnect the existing components of such that a user 
familiar with OVS can use P4-OVS in the same way.  Connecting to OVSDB, setting 
up mirrors, doing debug, reading stats, loading/unloading rules should have 
a similar look-and-feel, with the core OpenFlow semantics replaced with P4.

2. Kernel Control Plane:  Interconnects the kernel functions that OVS usually 
depends on (netdevs, LACP, LLDP, routing, VXLAN, IPSec).  This is achieved 
primarily by listening in on the netlink sockets for these structures and 
replicating the kernel configuration into the P4 pipeline dataplane.  This is 
leveraging the design patterns from SONIC, including calling the SAI interface 
to translate the kernel configuration into the right functions into BfRt.

3. SDN Control Plane:  Serves as the southbound for the P4Runtime and OpenConfig 
agent, which is converting the P4Runtime protobufs into operations into p4proto 
and (ultimately) into target API calls. P4proto implements P4Runtime and 
Openconfig server functionality using code from the Stratum Project.

4. P4 Pipeline Management:  Loading/reloading the P4 program, connecting to the
pipeline instance, and detecting what P4 pipelines are available on this 
platform.

We have built P4-OVS as an integrated solution with OVS and the p4proto resides 
within OVS as a library similar to OVS ofproto layer. There may be other 
constructions that can enable P4 in OVS and we are open to different ways to
structure this addition to minimize disruption inside the OVS codebase. P4-OVS 
is compiled with default options and '--with-p4' to activate the p4proto path. 

P4Runtime server uses p4info and bfrt.json as inputs to build the p4Info and 
interfaces with the Target APIs for the southbound interfaces. The current
codebase uses 'Barefoot Runtime' BFRT code as the Target API but will 
transition to the 'Table Driven Interface' TDI which was recently upstreamed 
onto p4.org's Github:

  https://github.com/p4lang/tdi

For P4Runtime, OpenConfig and the TDI/BFRT interfaces P4-OVS leverages 
ONF Stratum code for the P4Runtime C++ files for the gRPC server implementation 
which translates the gRPC messages into the Target API (BFRT today, TDI in the 
future).

Current Backends Supported:

 - P4 DPDK : https://github.com/p4lang/p4-dpdk-target

Backends for hardware targets are in development and will use the same Target 
APIs across all backends both software and hardware.  This will linkage to a
target at Runtime while still using an upstreamed OVS as part of Linux.

A new CLI, 'ovs-p4ctl' tool has partially been implemented as a P4Runtime
Client application to program the P4Runtime server. Currently 'gnmi-cli' 
implemented by Startum is used to configure OpenConfig, this will transition 
to an ovs native CLI over time.  Part of the development process is to prune 
away as much of the Stratum poject as possible, to minimize the additional 
code being added into the OVS codebase.

Current implementation:
--------------------------------------------------------------------------------

This is what is currently implemented within OVS-

1. P4Runtime Server using Stratum
2. OpenConfig Server using Stratum
3. Interface to P4-DPDK-Backend by modifying BFNode code in Stratum
4. The 'ovs-p4ctl' CLI as a P4Runtime Client for set-pipeline, add-flow and del-flow functions
5. Stratum's gnmi-cli is enhanced and used as the OpenConfig Client to add vhost ports.
6. Base code for Switchlink, SwitchSai interfaces for enabling Kernel Control Plane. (work in-progress, not yet functional)


What's next:
--------------------------------------------------------------------------------


1. Kernel control plane enabled with linux_networking.p4 supported for VXLAN, L2, Routing and ECMP (Some basic use cases supported and added as a demo run)
2. Port adds via ovs-vsctl OVS CLI and Openconfig CLIs (TAP, Veth etc)
3. Port counter support
4. Hot Plug into Qemu for vhost ports
5. Action selector support
6. Direct and Indirect Counters
7. Direct and Indirect Meters
8. Connection tracking support added and supported in linux_networking.p4
9. Mirroring support via P4
10. Multiple pipeline support
11. Stacked pipeline support
12. TLS support in grpc.
13. Better integration with Stratum
