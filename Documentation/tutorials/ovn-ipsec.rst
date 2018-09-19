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

==================
OVN IPsec Tutorial
==================

This document provides a step-by-step guide for encrypting tunnel traffic with
IPsec in Open Virtual Network (OVN). OVN tunnel traffic is transported by
physical routers and switches. These physical devices could be untrusted
(devices in public network) or might be compromised.  Enabling IPsec encryption
for the tunnel traffic can prevent the traffic data from being monitored and
manipulated. More details about the OVN IPsec design can be found in
``ovn-architecture``\(7) manpage.

This document assumes OVN is installed in your system and runs normally. Also,
you need to install OVS IPsec packages in each chassis (refer to
:ref:`install-ovs-ipsec`).

Generating Certificates and Keys
--------------------------------

OVN chassis uses CA-signed certificate to authenticate peer chassis for
building IPsec tunnel. If you have enabled Role-Based Access Control (RBAC) in
OVN, you can use the RBAC SSL certificates and keys to set up OVN IPsec. Or you
can generate separate certificates and keys with ``ovs-pki`` (refer to
:ref:`gen-certs-keys`).

.. note::

   OVN IPsec requires x.509 version 3 certificate with the subjectAltName DNS
   field setting the same string as the common name (CN) field. CN should be
   set as the chassis name.  ``ovs-pki`` in Open vSwitch 2.10.90 and later
   generates such certificates.  Please generate compatible certificates if you
   use another PKI tool, or an older version of ``ovs-pki``, to manage
   certificates.

Configuring OVN IPsec
---------------------

You need to install the CA certificate, chassis certificate and private key in
each chassis. Use the following command::

    $ ovs-vsctl set Open_vSwitch . \
            other_config:certificate=/path/to/chassis-cert.pem \
            other_config:private_key=/path/to/chassis-privkey.pem \
            other_config:ca_cert=/path/to/cacert.pem

Enabling OVN IPsec
------------------

To enable OVN IPsec, set ``ipsec`` column in ``NB_Global`` table of the
northbound database to true::

    $ ovn-nbctl set nb_global . ipsec=true

With OVN IPsec enabled, all tunnel traffic in OVN will be encrypted with IPsec.
To disable it, set ``ipsec`` column in ``NB_Global`` table of the northbound
database to false::

    $ ovn-nbctl set nb_global . ipsec=false

Troubleshooting
---------------

The ``ovs-monitor-ipsec`` daemon in each chassis manages and monitors the IPsec
tunnel state. Use the following ``ovs-appctl`` command to view
``ovs-monitor-ipsec`` internal representation of tunnel configuration::

    $ ovs-appctl -t ovs-monitor-ipsec tunnels/show

If there is a misconfiguration, then ``ovs-appctl`` should indicate why.
For example::

   Interface name: ovn-host_2-0 v1 (CONFIGURED) <--- Should be set
                                             to CONFIGURED. Otherwise,
                                             error message will be
                                             provided
   Tunnel Type:    geneve
   Remote IP:      2.2.2.2
   SKB mark:       None
   Local cert:     /path/to/chassis-cert.pem
   Local name:     host_1
   Local key:      /path/to/chassis-privkey.pem
   Remote cert:    None
   Remote name:    host_2
   CA cert:        /path/to/cacert.pem
   PSK:            None
   Ofport:         2          <--- Whether ovs-vswitchd has assigned Ofport
                                   number to this Tunnel Port
   CFM state:      Disabled     <--- Whether CFM declared this tunnel healthy
   Kernel policies installed:
   ...                          <--- IPsec policies for this OVS tunnel in
                                     Linux Kernel installed by strongSwan
   Kernel security associations installed:
   ...                          <--- IPsec security associations for this OVS
                                     tunnel in Linux Kernel installed by
                                     strongswan
   IPsec connections that are active:
   ...                          <--- IPsec "connections" for this OVS
                                     tunnel

If you don't see any active connections, try to run the following command to
refresh the ``ovs-monitor-ipsec`` daemon::

    $ ovs-appctl -t ovs-monitor-ipsec refresh

You can also check the logs of the ``ovs-monitor-ipsec`` daemon and the IKE
daemon to locate issues.  ``ovs-monitor-ipsec`` outputs log messages to
``/var/log/openvswitch/ovs-monitor-ipsec.log``.

Bug Reporting
-------------

If you think you may have found a bug with security implications, like

1. IPsec protected tunnel accepted packets that came unencrypted; OR
2. IPsec protected tunnel allowed packets to leave unencrypted;

Then report such bugs according to :doc:`/internals/security`.

If bug does not have security implications, then report it according to
instructions in :doc:`/internals/bugs`.

If you have suggestions to improve this tutorial, please send a email to
ovs-discuss@openvswitch.org.
