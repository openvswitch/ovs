How to Use Open vSwitch with Docker
====================================

This document describes how to use Open vSwitch with Docker 1.9.0 or
later.  This document assumes that you installed Open vSwitch by following
[INSTALL.md] or by using the distribution packages such as .deb or .rpm.
Consult www.docker.com for instructions on how to install Docker.

Docker 1.9.0 comes with support for multi-host networking.  Integration
of Docker networking and Open vSwitch can be achieved via Open vSwitch
virtual network (OVN).


Setup
=====

For multi-host networking with OVN and Docker, Docker has to be started
with a destributed key-value store.  For e.g., if you decide to use consul
as your distributed key-value store, and your host IP address is $HOST_IP,
start your Docker daemon with:

```
docker daemon --cluster-store=consul://127.0.0.1:8500 \
--cluster-advertise=$HOST_IP:0
```

OVN provides network virtualization to containers.  OVN's integration with
Docker currently works in two modes - the "underlay" mode or the "overlay"
mode.

In the "underlay" mode, OVN requires a OpenStack setup to provide container
networking.  In this mode, one can create logical networks and can have
containers running inside VMs, standalone VMs (without having any containers
running inside them) and physical machines connected to the same logical
network.  This is a multi-tenant, multi-host solution.

In the "overlay" mode, OVN can create a logical network amongst containers
running on multiple hosts.  This is a single-tenant (extendable to
multi-tenants depending on the security characteristics of the workloads),
multi-host solution.  In this mode, you do not need a pre-created OpenStack
setup.

For both the modes to work, a user has to install and start Open vSwitch in
each VM/host that he plans to run his containers.


The "overlay" mode
==================

OVN in "overlay" mode needs a minimum Open vSwitch version of 2.5.

* Start the central components.

OVN architecture has a central component which stores your networking intent
in a database.  On one of your machines, with an IP Address of $CENTRAL_IP,
where you have installed and started Open vSwitch, you will need to start some
central components.

Begin by making ovsdb-server listen on a TCP port by running:

```
ovs-appctl -t ovsdb-server ovsdb-server/add-remote ptcp:6640
```

Start ovn-northd daemon.  This daemon translates networking intent from Docker
stored in the OVN_Northbound database to logical flows in OVN_Southbound
database.

```
/usr/share/openvswitch/scripts/ovn-ctl start_northd
```

* One time setup.

On each host, where you plan to spawn your containers, you will need to
run the following command once.  (You need to run it again if your OVS database
gets cleared.  It is harmless to run it again in any case.)

$LOCAL_IP in the below command is the IP address via which other hosts
can reach this host.  This acts as your local tunnel endpoint.

$ENCAP_TYPE is the type of tunnel that you would like to use for overlay
networking.  The options are "geneve" or "stt".  (Please note that your
kernel should have support for your chosen $ENCAP_TYPE.  Both geneve
and stt are part of the Open vSwitch kernel module that is compiled from this
repo.  If you use the Open vSwitch kernel module from upstream Linux,
you will need a minumum kernel version of 3.18 for geneve.  There is no stt
support in upstream Linux.  You can verify whether you have the support in your
kernel by doing a "lsmod | grep $ENCAP_TYPE".)

```
ovs-vsctl set Open_vSwitch . external_ids:ovn-remote="tcp:$CENTRAL_IP:6640" \
  external_ids:ovn-encap-ip=$LOCAL_IP external_ids:ovn-encap-type="$ENCAP_TYPE"
```

And finally, start the ovn-controller.  (You need to run the below command
on every boot)

```
/usr/share/openvswitch/scripts/ovn-ctl start_controller
```

* Start the Open vSwitch network driver.

By default Docker uses Linux bridge for networking.  But it has support
for external drivers.  To use Open vSwitch instead of the Linux bridge,
you will need to start the Open vSwitch driver.

The Open vSwitch driver uses the Python's flask module to listen to
Docker's networking api calls.  So, if your host does not have Python's
flask module, install it with:

```
easy_install -U pip
pip install Flask
```

Start the Open vSwitch driver on every host where you plan to create your
containers.

```
ovn-docker-overlay-driver --detach
```

Docker has inbuilt primitives that closely match OVN's logical switches
and logical port concepts.  Please consult Docker's documentation for
all the possible commands.  Here are some examples.

* Create your logical switch.

To create a logical switch with name 'foo', on subnet '192.168.1.0/24' run:

```
NID=`docker network create -d openvswitch --subnet=192.168.1.0/24 foo`
```

* List your logical switches.

```
docker network ls
```

You can also look at this logical switch in OVN's northbound database by
running the following command.

```
ovn-nbctl --db=tcp:$CENTRAL_IP:6640 lswitch-list
```

* Docker creates your logical port and attaches it to the logical network
in a single step.

For e.g., to attach a logical port to network 'foo' inside cotainer busybox,
run:

```
docker run -itd --net=foo --name=busybox busybox
```

* List all your logical ports.

Docker currently does not have a CLI command to list all your logical ports.
But you can look at them in the OVN database, by running:

```
ovn-nbctl --db=tcp:$CENTRAL_IP:6640 lport-list $NID
```

* You can also create a logical port and attach it to a running container.

```
docker network create -d openvswitch --subnet=192.168.2.0/24 bar
docker network connect bar busybox
```

You can delete your logical port and detach it from a running container by
running:

```
docker network disconnect bar busybox
```

* You can delete your logical switch by running:

```
docker network rm bar
```


The "underlay" mode
===================

This mode requires that you have a OpenStack setup pre-installed with OVN
providing the underlay networking.

* One time setup.

A OpenStack tenant creates a VM with a single network interface (or multiple)
that belongs to management logical networks.  The tenant needs to fetch the
port-id associated with the interface via which he plans to send the container
traffic inside the spawned VM.  This can be obtained by running the
below command to fetch the 'id'  associated with the VM.

```
nova list
```

and then by running:

```
neutron port-list --device_id=$id
```

Inside the VM, download the OpenStack RC file that contains the tenant
information (henceforth referred to as 'openrc.sh').  Edit the file and add the
previously obtained port-id information to the file by appending the following
line: export OS_VIF_ID=$port_id.  After this edit, the file will look something
like:

```
#!/bin/bash
export OS_AUTH_URL=http://10.33.75.122:5000/v2.0
export OS_TENANT_ID=fab106b215d943c3bad519492278443d
export OS_TENANT_NAME="demo"
export OS_USERNAME="demo"
export OS_VIF_ID=e798c371-85f4-4f2d-ad65-d09dd1d3c1c9
```

* Create the Open vSwitch bridge.

If your VM has one ethernet interface (e.g.: 'eth0'), you will need to add
that device as a port to an Open vSwitch bridge 'breth0' and move its IP
address and route related information to that bridge. (If it has multiple
network interfaces, you will need to create and attach an Open vSwitch bridge
for the interface via which you plan to send your container traffic.)

If you use DHCP to obtain an IP address, then you should kill the DHCP client
that was listening on the physical Ethernet interface (e.g. eth0) and start
one listening on the Open vSwitch bridge (e.g. breth0).

Depending on your VM, you can make the above step persistent across reboots.
For e.g.:, if your VM is Debian/Ubuntu, you can read
[openvswitch-switch.README.Debian].  If your VM is RHEL based, you can read
[README.RHEL]


* Start the Open vSwitch network driver.

The Open vSwitch driver uses the Python's flask module to listen to
Docker's networking api calls.  The driver also uses OpenStack's
python-neutronclient libraries.  So, if your host does not have Python's
flask module or python-neutronclient install them with:

```
easy_install -U pip
pip install python-neutronclient
pip install Flask
```

Source the openrc file. e.g.:
````
. ./openrc.sh
```

Start the network driver and provide your OpenStack tenant password
when prompted.

```
ovn-docker-underlay-driver --bridge breth0 --detach
```

From here-on you can use the same Docker commands as described in the
section 'The "overlay" mode'.

Please read 'man ovn-architecture' to understand OVN's architecture in
detail.

[INSTALL.md]: INSTALL.md
[openvswitch-switch.README.Debian]: debian/openvswitch-switch.README.Debian
[README.RHEL]: rhel/README.RHEL
