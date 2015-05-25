How to Use Open vSwitch with Docker
====================================

This document describes how to use Open vSwitch with Docker 1.2.0 or
later.  This document assumes that you installed Open vSwitch by following
[INSTALL.md] or by using the distribution packages such as .deb or .rpm.
Consult www.docker.com for instructions on how to install Docker.

Limitations
-----------
Currently there is no native integration of Open vSwitch in Docker, i.e.,
one cannot use the Docker client to automatically add a container's
network interface to an Open vSwitch bridge during the creation of the
container.  This document describes addition of new network interfaces to an
already created container and in turn attaching that interface as a port to an
Open vSwitch bridge.  If and when there is a native integration of Open vSwitch
with Docker, the ovs-docker utility described in this document is expected to
be retired.

Setup
-----
* Create your container, e.g.:

```
% docker run -d ubuntu:14.04 /bin/sh -c \
"while true; do echo hello world; sleep 1; done"
```

The above command creates a container with one network interface 'eth0'
and attaches it to a Linux bridge called 'docker0'.  'eth0' by default
gets an IP address in the 172.17.0.0/16 space.  Docker sets up iptables
NAT rules to let this interface talk to the outside world.  Also since
it is connected to 'docker0' bridge, it can talk to all other containers
connected to the same bridge.  If you prefer that no network interface be
created by default, you can start your container with
the option '--net=none', e,g.:

```
% docker run -d --net=none ubuntu:14.04 /bin/sh -c \
"while true; do echo hello world; sleep 1; done"
```

The above commands will return a container id.  You will need to pass this
value to the utility 'ovs-docker' to create network interfaces attached to an
Open vSwitch bridge as a port.  This document will reference this value
as $CONTAINER_ID in the next steps.

* Add a new network interface to the container and attach it to an Open vSwitch
  bridge.  e.g.:

`% ovs-docker add-port br-int eth1 $CONTAINER_ID`

The above command will create a network interface 'eth1' inside the container
and then attaches it to the Open vSwitch bridge 'br-int'.  This is done by
creating a veth pair.  One end of the interface becomes 'eth1' inside the
container and the other end attaches to 'br-int'.

The script also lets one to add IP address, MAC address, Gateway address and
MTU for the interface.  e.g.:

```
% ovs-docker add-port br-int eth1 $CONTAINER_ID --ipaddress=192.168.1.2/24 \
--macaddress=a2:c3:0d:49:7f:f8 --gateway=192.168.1.1 --mtu=1450
```

* A previously added network interface can be deleted.  e.g.:

`% ovs-docker del-port br-int eth1 $CONTAINER_ID`

All the previously added Open vSwitch interfaces inside a container can be
deleted.  e.g.:

`% ovs-docker del-ports br-int $CONTAINER_ID`

It is important that the same $CONTAINER_ID be passed to both add-port
and del-port[s] commands.

* More network control.

Once a container interface is added to an Open vSwitch bridge, one can
set VLANs, create Tunnels, add OpenFlow rules etc for more network control.
Many times, it is important that the underlying network infrastructure is
plumbed (or programmed) before the application inside the container starts.
To handle this, one can create a micro-container, attach an Open vSwitch
interface to that container, set the UUIDS in OVSDB as mentioned in
[IntegrationGuide.md] and then program the bridge to handle traffic coming out
of that container. Now, you can start the main container asking it
to share the network of the micro-container. When your application starts,
the underlying network infrastructure would be ready. e.g.:

```
% docker run -d --net=container:$MICROCONTAINER_ID ubuntu:14.04 /bin/sh -c \
"while true; do echo hello world; sleep 1; done"
```

Please read the man pages of ovs-vsctl, ovs-ofctl, ovs-vswitchd,
ovsdb-server and ovs-vswitchd.conf.db etc for more details about Open vSwitch.

Docker networking is quite flexible and can be used in multiple ways.  For more
information, please read:
https://docs.docker.com/articles/networking

Bug Reporting
-------------

Please report problems to bugs@openvswitch.org.

[INSTALL.md]:INSTALL.md
[IntegrationGuide.md]:IntegrationGuide.md
