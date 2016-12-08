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

=====================
Open vSwitch with SSL
=====================

If you plan to configure Open vSwitch to connect across the network to an
OpenFlow controller, then we recommend that you build Open vSwitch with
OpenSSL. SSL support ensures integrity and confidentiality of the OpenFlow
connections, increasing network security.

This document describes how to configure an Open vSwitch to connect to an
OpenFlow controller over SSL.  Refer to :doc:`/intro/install/general`. for
instructions on building Open vSwitch with SSL support.

Open vSwitch uses TLS version 1.0 or later (TLSv1), as specified by RFC 2246,
which is very similar to SSL version 3.0.  TLSv1 was released in January 1999,
so all current software and hardware should implement it.

This document assumes basic familiarity with public-key cryptography and
public-key infrastructure.

SSL Concepts for OpenFlow
-------------------------

This section is an introduction to the public-key infrastructure architectures
that Open vSwitch supports for SSL authentication.

To connect over SSL, every Open vSwitch must have a unique private/public key
pair and a certificate that signs that public key.  Typically, the Open vSwitch
generates its own public/private key pair.  There are two common ways to obtain
a certificate for a switch:

* Self-signed certificates: The Open vSwitch signs its certificate with its own
  private key.  In this case, each switch must be individually approved by the
  OpenFlow controller(s), since there is no central authority.

  This is the only switch PKI model currently supported by NOX
  (http://noxrepo.org).

* Switch certificate authority: A certificate authority (the "switch CA") signs
  each Open vSwitch's public key.  The OpenFlow controllers then check that any
  connecting switches' certificates are signed by that certificate authority.

  This is the only switch PKI model supported by the simple OpenFlow controller
  included with Open vSwitch.

Each Open vSwitch must also have a copy of the CA certificate for the
certificate authority that signs OpenFlow controllers' keys (the "controller
CA" certificate).  Typically, the same controller CA certificate is installed
on all of the switches within a given administrative unit.  There are two
common ways for a switch to obtain the controller CA certificate:

* Manually copy the certificate to the switch through some secure means, e.g.
  using a USB flash drive, or over the network with "scp", or even FTP or HTTP
  followed by manual verification.

* Open vSwitch "bootstrap" mode, in which Open vSwitch accepts and saves the
  controller CA certificate that it obtains from the OpenFlow controller on its
  first connection.  Thereafter the switch will only connect to controllers
  signed by the same CA certificate.

Establishing a Public Key Infrastructure
----------------------------------------

Open vSwitch can make use of your existing public key infrastructure.  If you
already have a PKI, you may skip forward to the next section.  Otherwise, if
you do not have a PKI, the ovs-pki script included with Open vSwitch can help.
To create an initial PKI structure, invoke it as:

::

    $ ovs-pki init

This will create and populate a new PKI directory.  The default location for
the PKI directory depends on how the Open vSwitch tree was configured (to see
the configured default, look for the ``--dir`` option description in the output
of ``ovs-pki --help``).

The pki directory contains two important subdirectories.  The `controllerca`
subdirectory contains controller CA files, including the following:

`cacert.pem`
  Root certificate for the controller certificate authority.  Each Open vSwitch
  must have a copy of this file to allow it to authenticate valid controllers.

`private/cakey.pem`
  Private signing key for the controller certificate authority.  This file must
  be kept secret.  There is no need for switches or controllers to have a copy
  of it.

The `switchca` subdirectory contains switch CA files, analogous to those in the
`controllerca` subdirectory:

`cacert.pem`
  Root certificate for the switch certificate authority.  The OpenFlow
  controller must have this file to enable it to authenticate valid switches.

`private/cakey.pem`
  Private signing key for the switch certificate authority.  This file must be
  kept secret.  There is no need for switches or controllers to have a copy of
  it.

After you create the initial structure, you can create keys and certificates
for switches and controllers with ovs-pki.  Refer to the ovs-pki(8) manage for
complete details.  A few examples of its use follow:

Controller Key Generation
~~~~~~~~~~~~~~~~~~~~~~~~~

To create a controller private key and certificate in files named
ctl-privkey.pem and ctl-cert.pem, run the following on the machine that
contains the PKI structure:

::

    $ ovs-pki req+sign ctl controller

ctl-privkey.pem and ctl-cert.pem would need to be copied to the controller for
its use at runtime.  If, for testing purposes, you were to use
ovs-testcontroller, the simple OpenFlow controller included with Open vSwitch,
then the --private-key and --certificate options, respectively, would point to
these files.

It is very important to make sure that no stray copies of ctl-privkey.pem are
created, because they could be used to impersonate the controller.

Switch Key Generation with Self-Signed Certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you are using self-signed certificates (see "SSL Concepts for OpenFlow"),
this is one way to create an acceptable certificate for your controller to
approve.

1. Run the following command on the Open vSwitch itself::

       $ ovs-pki self-sign sc

   .. note::
     This command does not require a copy of any of the PKI files generated by
     ``ovs-pki init``, and you should not copy them to the switch because some
     of them have contents that must remain secret for security.)

   The ``ovs-pki self-sign`` command has the following output:

   sc-privkey.pem
     the switch private key file.  For security, the contents of this file must
     remain secret.  There is ordinarily no need to copy this file off the Open
     vSwitch.

   sc-cert.pem
     the switch certificate, signed by the switch's own private key.  Its
     contents are not a secret.

2. Optionally, copy `controllerca/cacert.pem` from the machine that has the
   OpenFlow PKI structure and verify that it is correct.  (Otherwise, you will
   have to use CA certificate bootstrapping when you configure Open vSwitch in
   the next step.)

3. Configure Open vSwitch to use the keys and certificates (see "Configuring
   SSL Support", below).

Switch Key Generation with a Switch PKI (Easy Method)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you are using a switch PKI (see "SSL Concepts for OpenFlow", above), this
method of switch key generation is a little easier than the alternate method
described below, but it is also a little less secure because it requires
copying a sensitive private key from file from the machine hosting the PKI to
the switch.

1. Run the following on the machine that contains the PKI structure::

       $ ovs-pki req+sign sc switch

   This command has the following output:

   sc-privkey.pem
     the switch private key file.  For security, the contents of this file must
     remain secret.

   sc-cert.pem
     the switch certificate.  Its contents are not a secret.

2. Copy sc-privkey.pem and sc-cert.pem, plus controllerca/cacert.pem, to the
   Open vSwitch.

3. Delete the copies of sc-privkey.pem and sc-cert.pem on the PKI machine and
   any other copies that may have been made in transit.  It is very important
   to make sure that there are no stray copies of sc-privkey.pem, because they
   could be used to impersonate the switch.

   .. warning::
     Don't delete controllerca/cacert.pem!  It is not security-sensitive and
     you will need it to configure additional switches.

4. Configure Open vSwitch to use the keys and certificates (see "Configuring
   SSL Support", below).

Switch Key Generation with a Switch PKI (More Secure)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you are using a switch PKI (see "SSL Concepts for OpenFlow", above), then,
compared to the previous method, the method described here takes a little more
work, but it does not involve copying the private key from one machine to
another, so it may also be a little more secure.

1. Run the following command on the Open vSwitch itself::

       $ ovs-pki req sc

   .. note::
     This command does not require a copy of any of the PKI files generated by
     "ovs-pki init", and you should not copy them to the switch because some of
     them have contents that must remain secret for security.

   The "ovs-pki req" command has the following output:

   sc-privkey.pem
     the switch private key file.  For security, the contents of this file must
     remain secret.  There is ordinarily no need to copy this file off the Open
     vSwitch.

   sc-req.pem
     the switch "certificate request", which is essentially the switch's public
     key.  Its contents are not a secret.

   a fingerprint
     this is output on stdout.

2. Write the fingerprint down on a slip of paper and copy `sc-req.pem` to the
   machine that contains the PKI structure.

3. On the machine that contains the PKI structure, run::

       $ ovs-pki sign sc switch

   This command will output a fingerprint to stdout and request that you verify
   it.  Check that it is the same as the fingerprint that you wrote down on the
   slip of paper before you answer "yes".

   ``ovs-pki sign`` creates a file named `sc-cert.pem`, which is the switch
   certificate.  Its contents are not a secret.

4. Copy the generated `sc-cert.pem`, plus `controllerca/cacert.pem` from the
   PKI structure, to the Open vSwitch, and verify that they were copied
   correctly.

   You may delete `sc-cert.pem` from the machine that hosts the PKI
   structure now, although it is not important that you do so.

   .. warning::
     Don't delete `controllerca/cacert.pem`!  It is not security-sensitive and
     you will need it to configure additional switches.

5. Configure Open vSwitch to use the keys and certificates (see "Configuring
   SSL Support", below).

Configuring SSL Support
-----------------------

SSL configuration requires three additional configuration files.  The first two
of these are unique to each Open vSwitch.  If you used the instructions above
to build your PKI, then these files will be named `sc-privkey.pem` and
`sc-cert.pem`, respectively:

- A private key file, which contains the private half of an RSA or DSA key.

  This file can be generated on the Open vSwitch itself, for the greatest
  security, or it can be generated elsewhere and copied to the Open vSwitch.

  The contents of the private key file are secret and must not be exposed.

- A certificate file, which certifies that the private key is that of a
  trustworthy Open vSwitch.

  This file has to be generated on a machine that has the private key for the
  switch certification authority, which should not be an Open vSwitch; ideally,
  it should be a machine that is not networked at all.

  The certificate file itself is not a secret.

The third configuration file is typically the same across all the switches in a
given administrative unit.  If you used the instructions above to build your
PKI, then this file will be named `cacert.pem`:

- The root certificate for the controller certificate authority.  The Open
  vSwitch verifies it that is authorized to connect to an OpenFlow controller
  by verifying a signature against this CA certificate.

Once you have these files, configure ovs-vswitchd to use them using the
``ovs-vsctl set-ssl`` command, e.g.::

    $ ovs-vsctl set-ssl /etc/openvswitch/sc-privkey.pem \
        /etc/openvswitch/sc-cert.pem /etc/openvswitch/cacert.pem

Substitute the correct file names, of course, if they differ from the ones used
above.  You should use absolute file names (ones that begin with ``/``),
because ovs-vswitchd's current directory is unrelated to the one from which you
run ovs-vsctl.

If you are using self-signed certificates (see "SSL Concepts for OpenFlow") and
you did not copy controllerca/cacert.pem from the PKI machine to the Open
vSwitch, then add the ``--bootstrap`` option, e.g.::

    $ ovs-vsctl -- --bootstrap set-ssl /etc/openvswitch/sc-privkey.pem \
        /etc/openvswitch/sc-cert.pem /etc/openvswitch/cacert.pem

After you have added all of these configuration keys, you may specify ``ssl:``
connection methods elsewhere in the configuration database.  ``tcp:`` connection
methods are still allowed even after SSL has been configured, so for security
you should use only ``ssl:`` connections.

Reporting Bugs
--------------

Report problems to bugs@openvswitch.org.
