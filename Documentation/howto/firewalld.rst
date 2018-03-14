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
Open Virtual Network With firewalld
===================================

firewalld is a service that allows for easy administration of firewalls. OVN
ships with a set of service files that can be used with firewalld to allow
for remote connections to the northbound and southbound databases.

This guide will describe how you can use these files with your existing
firewalld setup. Setup and administration of firewalld is outside the scope
of this document.

Installation
------------

If you have installed OVN from an RPM, then the service files for firewalld
will automatically be installed in ``/usr/lib/firewalld/services``.
Installation from RPM includes installation from the yum or dnf package
managers.

If you have installed OVN from source, then from the top level source
directory, issue the following commands to copy the firewalld service files:

::

    $ cp rhel/usr_lib_firewalld_services_ovn-central-firewall-service.xml \
    /etc/firewalld/services/
    $ cp rhel/usr_lib_firewalld_services_ovn-host-firewall-service.xml \
    /etc/firewalld/services/


Activation
----------

Assuming you are already running firewalld, you can issue the following
commands to enable the OVN services.

On the central server (the one running ``ovn-northd``), issue the following::

$ firewall-cmd --zone=public --add-service=ovn-central-firewall-service

This will open TCP ports 6641 and 6642, allowing for remote connections to the
northbound and southbound databases.

On the OVN hosts (the ones running ``ovn-controller``), issue the following::

$ firewall-cmd --zone=public --add-service=ovn-host-firewall-service

This will open UDP port 6081, allowing for geneve traffic to flow between the
controllers.

Variations
----------

When installing the XML service files, you have the choice of copying them to
``/etc/firewalld/services`` or ``/usr/lib/firewalld/services``. The former is
recommend since the latter can be overwritten if firewalld is upgraded.

The above commands assumed your underlay network interfaces are in the
"public" firewalld zone. If your underlay network interfaces are in a separate
zone, then adjust the above commands accordingly.

The ``--permanent`` option may be passed to the above firewall-cmd invocations
in order for the services to be permanently added to the firewalld
configuration. This way it is not necessary to re-issue the commands each
time the firewalld service restarts.

The ovn-host-firewall-service only opens port 6081. This is because the
default protocol for OVN tunnels is geneve. If you are using a different
encapsulation protocol, you will need to modify the XML service file to open
the appropriate port(s). For VXLAN, open port 4789. For STT, open port 7471.

Recommendations
---------------

The firewalld service files included with the OVS repo are meant as a
convenience for firewalld users. All that the service files do is to open
the common ports used by OVN. No additional security is provided. To ensure a
more secure environment, it is a good idea to do the following

* Use tools such as iptables or nftables to restrict access to known hosts.
* Use SSL for all remote connections to OVN databases.
* Use role-based access control for connections to the OVN southbound
  database.
