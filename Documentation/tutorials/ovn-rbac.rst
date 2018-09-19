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

=============================================
OVN Role-Based Access Control (RBAC) Tutorial
=============================================

This document provides a step-by-step guide for setting up role-based access
control (RBAC) in OVN. In OVN, hypervisors (chassis) read and write the
southbound database to do configuration. Without restricting hypervisor's
access to the southbound database, a compromised hypervisor might disrupt the
entire OVN deployment by corrupting the database. RBAC ensures that each
hypervisor can only modify its own data and thus improves the security of OVN.
More details about the RBAC design can be found in ``ovn-architecture``\(7)
manpage.

This document assumes OVN is installed in your system and runs normally.

.. _gen-certs-keys:

Generating Certificates and Keys
--------------------------------

In the OVN RBAC deployment, ovn-controller connects to the southbound database
via SSL connection. The southbound database uses CA-signed certificate to
authenticate ovn-controller.

Suppose there are three machines in your deployment. `machine_1` runs
`chassis_1` and has IP address `machine_1-ip`. `machine_2` runs `chassis_2` and
has IP address `machine_2-ip`. `machine_3` hosts southbound database and has IP
address `machine_3-ip`. `machine_3` also hosts public key infrastructure (PKI).

1. Initiate PKI.

   In `machine_3`::

      $ ovs-pki init

2. Generate southbound database's certificate request. Sign the certificate
   request with the CA key.

   In `machine_3`::

      $ ovs-pki req -u sbdb
      $ ovs-pki sign sbdb switch

3. Generate chassis certificate requests. Copy the certificate requests to
   `machine_3`.

   In `machine_1`::

      $ ovs-pki req -u chassis_1
      $ scp chassis_1-req.pem \
                    machine_3@machine_3-ip:/path/to/chassis_1-req.pem

   In `machine_2`::

      $ ovs-pki req -u chassis_2
      $ scp chassis_2-req.pem \
                    machine_3@machine_3-ip:/path/to/chassis_2-req.pem

   .. note::

     chassis_1 must be the same string as ``external_ids:system-id`` in the
     Open_vSwitch table (the chassis name) of machine_1. Same applies for
     chassis_2.

4. Sign the chassis certificate requests with the CA key. Copy `chassis_1`'s
   signed certificate and the CA certificate to `machine_1`. Copy `chassis_2`'s
   signed certificate and the CA certificate to `machine_2`.

   In `machine_3`::

      $ ovs-pki sign chassis_1 switch
      $ ovs-pki sign chassis_2 switch
      $ scp chassis_1-cert.pem \
                    machine_1@machine_1-ip:/path/to/chassis_1-cert.pem
      $ scp /var/lib/openvswitch/pki/switchca/cacert.pem \
                    machine_1@machine_1-ip:/path/to/cacert.pem
      $ scp chassis_2-cert.pem \
                    machine_2@machine_2-ip:/path/to/chassis_2-cert.pem
      $ scp /var/lib/openvswitch/pki/switchca/cacert.pem \
                    machine_2@machine_2-ip:/path/to/cacert.pem

Configuring RBAC
----------------

1. Set certificate, private key, and CA certificate for the southbound
   database. Configure the southbound database to listen on SSL connection and
   enforce role-based access control.

   In `machine_3`::

      $ ovn-sbctl set-ssl /path/to/sbdb-privkey.pem \
                          /path/to/sbdb-cert.pem /path/to/cacert.pem
      $ ovn-sbctl set-connection role=ovn-controller pssl:6642

2. Set certificate, private key, and CA certificate for `chassis_1` and
   `chassis_2`. Configure `chassis_1` and `chassis_2` to connect southbound
   database via SSL.

   In `machine_1`::

      $ ovs-vsctl set-ssl /path/to/chassis_1-privkey.pem \
                    /path/to/chassis_1-cert.pem /path/to/cacert.pem
      $ ovs-vsctl set open_vswitch . \
                    external_ids:ovn-remote=ssl:machine_3-ip:6642

   In `machine_2`::

      $ ovs-vsctl set-ssl /path/to/chassis_2-privkey.pem \
                    /path/to/chassis_2-cert.pem /path/to/cacert.pem
      $ ovs-vsctl set open_vswitch . \
                    external_ids:ovn-remote=ssl:machine_3-ip:6642
