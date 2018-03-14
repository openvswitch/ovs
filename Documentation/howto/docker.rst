..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

===================================
Open Virtual Networking With Docker
===================================

This document describes how to use Open Virtual Networking with Docker 1.9.0
or later.

.. important::

  Requires Docker version 1.9.0 or later. Only Docker 1.9.0+ comes with support
  for multi-host networking. Consult www.docker.com for instructions on how to
  install Docker.

.. note::

  You must build and install Open vSwitch before proceeding with the below
  guide. Refer to :doc:`/intro/install/index` for more information.

Setup
-----

For multi-host networking with OVN and Docker, Docker has to be started with a
distributed key-value store. For example, if you decide to use consul as your
distributed key-value store and your host IP address is ``$HOST_IP``, start
your Docker daemon with::

    $ docker daemon --cluster-store=consul://127.0.0.1:8500 \
        --cluster-advertise=$HOST_IP:0

OVN provides network virtualization to containers. OVN's integration with
Docker currently works in two modes - the "underlay" mode or the "overlay"
mode.

In the "underlay" mode, OVN requires a OpenStack setup to provide container
networking. In this mode, one can create logical networks and can have
containers running inside VMs, standalone VMs (without having any containers
running inside them) and physical machines connected to the same logical
network. This is a multi-tenant, multi-host solution.

In the "overlay" mode, OVN can create a logical network amongst containers
running on multiple hosts. This is a single-tenant (extendable to multi-tenants
depending on the security characteristics of the workloads), multi-host
solution. In this mode, you do not need a pre-created OpenStack setup.

For both the modes to work, a user has to install and start Open vSwitch in
each VM/host that they plan to run their containers on.

.. _docker-overlay:

The "overlay" mode
------------------

.. note::

  OVN in "overlay" mode needs a minimum Open vSwitch version of 2.5.

1. Start the central components.

  OVN architecture has a central component which stores your networking intent
  in a database. On one of your machines, with an IP Address of
  ``$CENTRAL_IP``, where you have installed and started Open vSwitch, you will
  need to start some central components.

  Start ovn-northd daemon. This daemon translates networking intent from Docker
  stored in the OVN\_Northbound database to logical flows in ``OVN_Southbound``
  database. For example::

      $ /usr/share/openvswitch/scripts/ovn-ctl start_northd

  With Open vSwitch version of 2.7 or greater, you need to run the following
  additional commands (Please read the manpages of ovn-nb for more control
  on the types of connection allowed.) ::

      $ ovn-nbctl set-connection ptcp:6641
      $ ovn-sbctl set-connection ptcp:6642

2. One time setup

   On each host, where you plan to spawn your containers, you will need to run
   the below command once. You may need to run it again if your OVS database
   gets cleared. It is harmless to run it again in any case::

       $ ovs-vsctl set Open_vSwitch . \
           external_ids:ovn-remote="tcp:$CENTRAL_IP:6642" \
           external_ids:ovn-nb="tcp:$CENTRAL_IP:6641" \
           external_ids:ovn-encap-ip=$LOCAL_IP \
           external_ids:ovn-encap-type="$ENCAP_TYPE"

   where:

   ``$LOCAL_IP``
     is the IP address via which other hosts can reach this host.  This acts as
     your local tunnel endpoint.

   ``$ENCAP_TYPE``
     is the type of tunnel that you would like to use for overlay networking.
     The options are ``geneve`` or ``stt``. Your kernel must have support for
     your chosen ``$ENCAP_TYPE``. Both ``geneve`` and ``stt`` are part of the
     Open vSwitch kernel module that is compiled from this repo. If you use the
     Open vSwitch kernel module from upstream Linux, you will need a minimum
     kernel version of 3.18 for ``geneve``. There is no ``stt`` support in
     upstream Linux. You can verify whether you have the support in your kernel
     as follows::

         $ lsmod | grep $ENCAP_TYPE

   In addition, each Open vSwitch instance in an OVN deployment needs a unique,
   persistent identifier, called the ``system-id``.  If you install OVS from
   distribution packaging for Open vSwitch (e.g. .deb or .rpm packages), or if
   you use the ovs-ctl utility included with Open vSwitch, it automatically
   configures a system-id.  If you start Open vSwitch manually, you should set
   one up yourself. For example::

       $ id_file=/etc/openvswitch/system-id.conf
       $ test -e $id_file || uuidgen > $id_file
       $ ovs-vsctl set Open_vSwitch . external_ids:system-id=$(cat $id_file)

3. Start the ``ovn-controller``.

   You need to run the below command on every boot::

       $ /usr/share/openvswitch/scripts/ovn-ctl start_controller

4. Start the Open vSwitch network driver.

   By default Docker uses Linux bridge for networking. But it has support for
   external drivers. To use Open vSwitch instead of the Linux bridge, you will
   need to start the Open vSwitch driver.

   The Open vSwitch driver uses the Python's flask module to listen to Docker's
   networking api calls. So, if your host does not have Python's flask module,
   install it::

       $ sudo pip install Flask

   Start the Open vSwitch driver on every host where you plan to create your
   containers. Refer to the note on ``$OVS_PYTHON_LIBS_PATH`` that is used below
   at the end of this document::

       $ PYTHONPATH=$OVS_PYTHON_LIBS_PATH ovn-docker-overlay-driver --detach

   .. note::

     The ``$OVS_PYTHON_LIBS_PATH`` variable should point to the directory where
     Open vSwitch Python modules are installed. If you installed Open vSwitch
     Python modules via the Debian package of ``python-openvswitch`` or via pip
     by running ``pip install ovs``, you do not need to specify the PATH. If
     you installed it by following the instructions in
     :doc:`/intro/install/general`, then you should specify the PATH. In this
     case, the PATH depends on the options passed to ``./configure``. It is
     usually either ``/usr/share/openvswitch/python`` or
     ``/usr/local/share/openvswitch/python``

Docker has inbuilt primitives that closely match OVN's logical switches and
logical port concepts. Consult Docker's documentation for all the possible
commands. Here are some examples.

Create a logical switch
~~~~~~~~~~~~~~~~~~~~~~~

To create a logical switch with name 'foo', on subnet '192.168.1.0/24', run::

    $ NID=`docker network create -d openvswitch --subnet=192.168.1.0/24 foo`

List all logical switches
~~~~~~~~~~~~~~~~~~~~~~~~~

::

    $ docker network ls

You can also look at this logical switch in OVN's northbound database by
running the following command::

    $ ovn-nbctl --db=tcp:$CENTRAL_IP:6640 ls-list

Delete a logical switch
~~~~~~~~~~~~~~~~~~~~~~~

::

    $ docker network rm bar


Create a logical port
~~~~~~~~~~~~~~~~~~~~~

Docker creates your logical port and attaches it to the logical network in a
single step. For example, to attach a logical port to network ``foo`` inside
container busybox, run::

    $ docker run -itd --net=foo --name=busybox busybox

List all logical ports
~~~~~~~~~~~~~~~~~~~~~~

Docker does not currently have a CLI command to list all logical ports but you
can look at them in the OVN database by running::

    $ ovn-nbctl --db=tcp:$CENTRAL_IP:6640 lsp-list $NID

Create and attach a logical port to a running container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    $ docker network create -d openvswitch --subnet=192.168.2.0/24 bar
    $ docker network connect bar busybox

Detach and delete a logical port from a running container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can delete your logical port and detach it from a running container
by running:

::

    $ docker network disconnect bar busybox

.. _docker-underlay:

The "underlay" mode
-------------------

.. note::

  This mode requires that you have a OpenStack setup pre-installed with
  OVN providing the underlay networking.

1. One time setup

   A OpenStack tenant creates a VM with a single network interface (or multiple)
   that belongs to management logical networks. The tenant needs to fetch the
   port-id associated with the interface via which he plans to send the container
   traffic inside the spawned VM. This can be obtained by running the below
   command to fetch the 'id' associated with the VM::

       $ nova list

   and then by running::

       $ neutron port-list --device_id=$id

   Inside the VM, download the OpenStack RC file that contains the tenant
   information (henceforth referred to as ``openrc.sh``). Edit the file and add the
   previously obtained port-id information to the file by appending the following
   line::

       $ export OS_VIF_ID=$port_id

   After this edit, the file will look something like::

       #!/bin/bash
       export OS_AUTH_URL=http://10.33.75.122:5000/v2.0
       export OS_TENANT_ID=fab106b215d943c3bad519492278443d
       export OS_TENANT_NAME="demo"
       export OS_USERNAME="demo"
       export OS_VIF_ID=e798c371-85f4-4f2d-ad65-d09dd1d3c1c9

2. Create the Open vSwitch bridge

   If your VM has one ethernet interface (e.g.: 'eth0'), you will need to add
   that device as a port to an Open vSwitch bridge 'breth0' and move its IP
   address and route related information to that bridge. (If it has multiple
   network interfaces, you will need to create and attach an Open vSwitch
   bridge for the interface via which you plan to send your container
   traffic.)

   If you use DHCP to obtain an IP address, then you should kill the DHCP
   client that was listening on the physical Ethernet interface (e.g. eth0) and
   start one listening on the Open vSwitch bridge (e.g. breth0).

   Depending on your VM, you can make the above step persistent across reboots.
   For example, if your VM is Debian/Ubuntu-based, read
   `openvswitch-switch.README.Debian` found in `debian` folder. If your VM is
   RHEL-based, refer to :doc:`/intro/install/rhel`.

3. Start the Open vSwitch network driver

   The Open vSwitch driver uses the Python's flask module to listen to Docker's
   networking api calls. The driver also uses OpenStack's
   ``python-neutronclient`` libraries. If your host does not have Python's
   ``flask`` module or ``python-neutronclient`` you must install them. For
   example::

       $ pip install python-neutronclient
       $ pip install Flask

   Once installed, source the ``openrc`` file::

       $ . ./openrc.sh

   Start the network driver and provide your OpenStack tenant password when
   prompted::

       $ PYTHONPATH=$OVS_PYTHON_LIBS_PATH ovn-docker-underlay-driver \
           --bridge breth0 --detach

From here-on you can use the same Docker commands as described in
`docker-overlay`_.

Refer to the ovs-architecture man pages (``man ovn-architecture``) to
understand OVN's architecture in detail.
