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

================================================
Integration of Containers with OVN and OpenStack
================================================

Isolation between containers is weaker than isolation between VMs, so some
environments deploy containers for different tenants in separate VMs as an
additional security measure.  This document describes creation of containers
inside VMs and how they can be made part of the logical networks securely.  The
created logical network can include VMs, containers and physical machines as
endpoints.  To better understand the proposed integration of containers with
OVN and OpenStack, this document describes the end to end workflow with an
example.

* A OpenStack tenant creates a VM (say VM-A) with a single network interface
  that belongs to a management logical network.  The VM is meant to host
  containers.  OpenStack Nova chooses the hypervisor on which VM-A is created.

* A Neutron port may have been created in advance and passed in to Nova with
  the request to create a new VM.  If not, Nova will issue a request to Neutron
  to create a new port.  The ID of the logical port from Neutron will also be
  used as the vif-id for the virtual network interface (VIF) of VM-A.

* When VM-A is created on a hypervisor, its VIF gets added to the Open vSwitch
  integration bridge.  This creates a row in the Interface table of the
  ``Open_vSwitch`` database.  As explained in the :doc:`integration guide
  </topics/integration>`, the vif-id associated with the VM network interface
  gets added in the ``external_ids:iface-id`` column of the newly created row
  in the Interface table.

* Since VM-A belongs to a logical network, it gets an IP address.  This IP
  address is used to spawn containers (either manually or through container
  orchestration systems) inside that VM and to monitor the health of the
  created containers.

* The vif-id associated with the VM's network interface can be obtained by
  making a call to Neutron using tenant credentials.

* This flow assumes a component called a "container network plugin".  If you
  take Docker as an example for containers, you could envision the plugin to be
  either a wrapper around Docker or a feature of Docker itself that understands
  how to perform part of this workflow to get a container connected to a
  logical network managed by Neutron.  The rest of the flow refers to this
  logical component that does not yet exist as the "container network plugin".

* All the calls to Neutron will need tenant credentials.  These calls can
  either be made from inside the tenant VM as part of a container network
  plugin or from outside the tenant VM (if the tenant is not comfortable using
  temporary Keystone tokens from inside the tenant VMs).  For simplicity, this
  document explains the work flow using the former method.

* The container hosting VM will need Open vSwitch installed in it.  The only
  work for Open vSwitch inside the VM is to tag network traffic coming from
  containers.

* When a container needs to be created inside the VM with a container network
  interface that is expected to be attached to a particular logical switch, the
  network plugin in that VM chooses any unused VLAN (This VLAN tag only needs
  to be unique inside that VM.  This limits the number of container interfaces
  to 4096 inside a single VM).  This VLAN tag is stripped out in the hypervisor
  by OVN and is only useful as a context (or metadata) for OVN.

* The container network plugin then makes a call to Neutron to create a logical
  port.  In addition to all the inputs that a call to create a port in Neutron
  that are currently needed, it sends the vif-id and the VLAN tag as inputs.

* Neutron in turn will verify that the vif-id belongs to the tenant in question
  and then uses the OVN specific plugin to create a new row in the
  Logical_Switch_Port table of the OVN Northbound Database.  Neutron responds
  back with an IP address and MAC address for that network interface.  So
  Neutron becomes the IPAM system and provides unique IP and MAC addresses
  across VMs and containers in the same logical network.

* The Neutron API call above to create a logical port for the container could
  add a relatively significant amount of time to container creation.  However,
  an optimization is possible here.  Logical ports could be created in advance
  and reused by the container system doing container orchestration.  Additional
  Neutron API calls would only be needed if the port needs to be attached to a
  different logical network.

* When a container is eventually deleted, the network plugin in that VM may
  make a call to Neutron to delete that port.  Neutron in turn will delete the
  entry in the ``Logical_Switch_Port`` table of the OVN Northbound Database.

As an example, consider Docker containers.  Since Docker currently does not
have a network plugin feature, this example uses a hypothetical wrapper around
Docker to make calls to Neutron.

* Create a Logical switch::

      $ ovn-docker --cred=cca86bd13a564ac2a63ddf14bf45d37f create network LS1

  The above command will make a call to Neutron with the credentials to create
  a logical switch.  The above is optional if the logical switch has already
  been created from outside the VM.

* List networks available to the tenant::

      $ ovn-docker --cred=cca86bd13a564ac2a63ddf14bf45d37f list networks

* Create a container and attach a interface to the previously created switch as
  a logical port::

      $ ovn-docker --cred=cca86bd13a564ac2a63ddf14bf45d37f --vif-id=$VIF_ID \
          --network=LS1 run -d --net=none ubuntu:14.04 /bin/sh -c \
          "while true; do echo hello world; sleep 1; done"

  The above command will make a call to Neutron with all the inputs it
  currently needs to create a logical port.  In addition, it passes the $VIF_ID
  and a unused VLAN.  Neutron will add that information in OVN and return back
  a MAC address and IP address for that interface.  ovn-docker will then create
  a veth pair, insert one end inside the container as 'eth0' and the other end
  as a port of a local OVS bridge as an access port of the chosen VLAN.
