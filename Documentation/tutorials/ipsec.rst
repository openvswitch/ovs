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
OVS IPsec Tutorial
==================

This document provides a step-by-step guide for running IPsec tunnel in Open
vSwitch. A more detailed description on OVS IPsec tunnel and its
configuration modes can be found in :doc:`/howto/ipsec`.

Requirements
------------

OVS IPsec tunnel requires Linux kernel (>= v3.10.0) and OVS out-of-tree kernel
module. The compatible IKE daemons are LibreSwan (>= v3.23) and StrongSwan
(>= v5.3.5).

.. _install-ovs-ipsec:

Installing OVS and IPsec Packages
---------------------------------

OVS IPsec has .deb and .rpm packages. You should use the right package
based on your Linux distribution. This tutorial uses Ubuntu 16.04 and Fedora 32
as examples.

Ubuntu
~~~~~~

1. Follow :doc:`/intro/install/debian` to build debian packages.

   .. note::

     If you have already installed OVS, then you only need to install
     openvswitch-pki_*.deb and openvswitch-ipsec_*.deb in the following step.
     If your kernel version is below v4.13.0, update your kernel to v4.13.0 or
     above.

2. Install the related packages::

       # apt-get install dkms strongswan
       # dpkg -i libopenvswitch_*.deb openvswitch-common_*.deb \
             openvswitch-switch_*.deb openvswitch-datapath-dkms_*.deb \
             python-openvswitch_*.deb openvswitch-pki_*.deb \
             openvswitch-ipsec_*.deb

   If the installation is successful, you should be able to see the
   ovs-monitor-ipsec daemon is running in your system.

Fedora
~~~~~~

1. Install the related packages. Fedora 32 does not require installation of
   the out-of-tree kernel module::

       # dnf install python3-openvswitch libreswan \
                     openvswitch openvswitch-ipsec

2. Install firewall rules to allow ESP and IKE traffic::

       # systemctl start firewalld
       # firewall-cmd --add-service ipsec

   Or to make permanent::

       # systemctl enable firewalld
       # firewall-cmd --permanent --add-service ipsec

3. Run the openvswitch-ipsec service::

       # systemctl start openvswitch-ipsec.service

   .. note::

     The SELinux policies might prevent openvswitch-ipsec.service to access
     certain resources. You can configure SELinux to remove such restrictions.

Configuring IPsec tunnel
------------------------

Suppose you want to build an IPsec tunnel between two hosts. Assume `host_1`'s
external IP is 1.1.1.1, and `host_2`'s external IP is 2.2.2.2. Make sure
`host_1` and `host_2` can ping each other via these external IPs.

0. Set up some variables to make life easier.  On both hosts, set ``ip_1`` and
   ``ip_2`` variables, e.g.::

     # ip_1=1.1.1.1
     # ip_2=2.2.2.2

1. Set up OVS bridges in both hosts.

   In `host_1`::

       # ovs-vsctl add-br br-ipsec
       # ip addr add 192.0.0.1/24 dev br-ipsec
       # ip link set br-ipsec up

   In `host_2`::

       # ovs-vsctl add-br br-ipsec
       # ip addr add 192.0.0.2/24 dev br-ipsec
       # ip link set br-ipsec up

2. Set up IPsec tunnel.

   There are three authentication methods.  Choose one method to set up your
   IPsec tunnel and follow the steps below.

   a) Using pre-shared key:

      In `host_1`::

          # ovs-vsctl add-port br-ipsec tun -- \
                      set interface tun type=gre \
                                    options:remote_ip=$ip_2 \
                                    options:psk=swordfish

      In `host_2`::

          # ovs-vsctl add-port br-ipsec tun -- \
                      set interface tun type=gre \
                                    options:remote_ip=$ip_1 \
                                    options:psk=swordfish

      .. note::

        Pre-shared key (PSK) based authentication is easy to set up but less
        secure compared with other authentication methods. You should use it
        cautiously in production systems.

   b) Using self-signed certificate:

      Generate self-signed certificate in both `host_1` and `host_2`. Then copy
      the certificate of `host_1` to `host_2` and the certificate of `host_2`
      to `host_1`.

      In `host_1`::

          # ovs-pki req -u host_1
          # ovs-pki self-sign host_1
          # scp host_1-cert.pem $ip_2:/etc/keys/host_1-cert.pem

      In `host_2`::

          # ovs-pki req -u host_2
          # ovs-pki self-sign host_2
          # scp host_2-cert.pem $ip_1:/etc/keys/host_2-cert.pem

      .. note::

        If you use StrongSwan as IKE daemon, please move the host certificates
        to /etc/ipsec.d/certs/ and private key to /etc/ipsec.d/private/ so that
        StrongSwan has permission to access those files.

      Configure IPsec tunnel to use self-signed certificates.

      In `host_1`::

          # ovs-vsctl set Open_vSwitch . \
                     other_config:certificate=/etc/keys/host_1-cert.pem \
                     other_config:private_key=/etc/keys/host_1-privkey.pem
          # ovs-vsctl add-port br-ipsec tun -- \
                      set interface tun type=gre \
                             options:remote_ip=$ip_2 \
                             options:remote_cert=/etc/keys/host_2-cert.pem

      In `host_2`::

          # ovs-vsctl set Open_vSwitch . \
                     other_config:certificate=/etc/keys/host_2-cert.pem \
                     other_config:private_key=/etc/keys/host_2-privkey.pem
          # ovs-vsctl add-port br-ipsec tun -- \
                      set interface tun type=gre \
                             options:remote_ip=$ip_1 \
                             options:remote_cert=/etc/keys/host_1-cert.pem

      .. note::

        The confidentiality of the private key is very critical.  Don't copy it
        to places where it might be compromised.  (The certificate need not be
        kept confidential.)

   c) Using CA-signed certificate:

      First you need to establish a public key infrastructure (PKI). Suppose
      you choose `host_1` to host PKI.

      In `host_1`::

          # ovs-pki init

      Generate certificate requests and copy the certificate request of
      `host_2` to `host_1`.

      In `host_1`::

          # ovs-pki req -u host_1

      In `host_2`::

          # ovs-pki req -u host_2
          # scp host_2-req.pem $ip_1:/etc/keys/host_2-req.pem

      Sign the certificate requests with the CA key. Copy `host_2`'s signed
      certificate and the CA certificate to `host_2`.

      In `host_1`::

          # ovs-pki sign host_1 switch
          # ovs-pki sign host_2 switch
          # scp host_2-cert.pem $ip_2:/etc/keys/host_2-cert.pem
          # scp /var/lib/openvswitch/pki/switchca/cacert.pem \
                    $ip_2:/etc/keys/cacert.pem

      .. note::

        If you use StrongSwan as IKE daemon, please move the host certificates
        to /etc/ipsec.d/certs/, CA certificate to /etc/ipsec.d/cacerts/, and
        private key to /etc/ipsec.d/private/ so that StrongSwan has permission
        to access those files.

      Configure IPsec tunnel to use CA-signed certificate.

      In `host_1`::

          # ovs-vsctl set Open_vSwitch . \
                  other_config:certificate=/etc/keys/host_1-cert.pem \
                  other_config:private_key=/etc/keys/host_1-privkey.pem \
                  other_config:ca_cert=/etc/keys/cacert.pem
          # ovs-vsctl add-port br-ipsec tun -- \
                   set interface tun type=gre \
                                 options:remote_ip=$ip_2 \
                                 options:remote_name=host_2

      In `host_2`::

          # ovs-vsctl set Open_vSwitch . \
                  other_config:certificate=/etc/keys/host_2-cert.pem \
                  other_config:private_key=/etc/keys/host_2-privkey.pem \
                  other_config:ca_cert=/etc/keys/cacert.pem
          # ovs-vsctl add-port br-ipsec tun -- \
                   set interface tun type=gre \
                                 options:remote_ip=$ip_1 \
                                 options:remote_name=host_1

      .. note::

        remote_name is the common name (CN) of the signed-certificate.  It must
        match the name given as the argument to the ``ovs-pki sign command``.
        It ensures that only certificate with the expected CN can be
        authenticated; otherwise, any certificate signed by the CA would be
        accepted.

3. Set the `local_ip` field in the Interface table (Optional)

    Make sure that the `local_ip` field in the Interface table is set to the
    NIC used for egress traffic.

    On `host 1`::

       # ovs-vsctl set Interface tun options:local_ip=$ip_1

    Similarly, on `host 2`::

       # ovs-vsctl set Interface tun options:local_ip=$ip_2

   .. note::

        It is not strictly necessary to set the `local_ip` field if your system
        only has one NIC or the default gateway interface is set to the NIC
        used for egress traffic.

4. Test IPsec tunnel.

   Now you should have an IPsec GRE tunnel running between two hosts. To verify
   it, in `host_1`::

       # ping 192.0.0.2 &
       # tcpdump -ni any net $ip_2

   You should be able to see that ESP packets are being sent from `host_1` to
   `host_2`.

Troubleshooting
---------------

The ``ovs-monitor-ipsec`` daemon manages and monitors the IPsec tunnel state.
Use the following ``ovs-appctl`` command to view ``ovs-monitor-ipsec`` internal
representation of tunnel configuration::

    # ovs-appctl -t ovs-monitor-ipsec tunnels/show

If there is misconfiguration, then ``ovs-appctl`` should indicate why.
For example::

   Interface name: gre0 v5 (CONFIGURED) <--- Should be set to CONFIGURED.
                                             Otherwise, error message will
                                             be provided
   Tunnel Type:    gre
   Local IP:       %defaultroute
   Remote IP:      2.2.2.2
   SKB mark:       None
   Local cert:     None
   Local name:     None
   Local key:      None
   Remote cert:    None
   Remote name:    None
   CA cert:        None
   PSK:            swordfish
   Ofport:         1          <--- Whether ovs-vswitchd has assigned Ofport
                                   number to this Tunnel Port
   CFM state:      Up         <--- Whether CFM declared this tunnel healthy
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

    # ovs-appctl -t ovs-monitor-ipsec refresh

You can also check the logs of the ``ovs-monitor-ipsec`` daemon and the IKE
daemon to locate issues. ``ovs-monitor-ipsec`` outputs log messages to
/var/log/openvswitch/ovs-monitor-ipsec.log.

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
