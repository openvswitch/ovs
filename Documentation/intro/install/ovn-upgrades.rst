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

============
OVN Upgrades
============

Since OVN is a distributed system, special consideration must be given to
the process used to upgrade OVN across a deployment.  This document discusses
the recommended upgrade process.

Release Notes
-------------

You should always check the OVS and OVN release notes (NEWS file) for any
release specific notes on upgrades.

OVS
---

OVN depends on and is included with OVS.  It's expected that OVS and OVN are
upgraded together, partly for convenience.  OVN is included in OVS releases
so it's easiest to upgrade them together.  OVN may also make use of new
features of OVS only available in that release.

Upgrade ovn-controller
----------------------

You should start by upgrading ovn-controller on each host it's running on.
First, you upgrade the OVS and OVN packages.  Then, restart the
ovn-controller service.  You can restart with ovn-ctl::

    $ sudo /usr/share/openvswitch/scripts/ovn-ctl restart_controller

or with systemd::

    $ sudo systemd restart ovn-controller

Upgrade OVN Databases and ovn-northd
------------------------------------

The OVN databases and ovn-northd should be upgraded next.  Since ovn-controller
has already been upgraded, it will be ready to operate on any new functionality
specified by the database or logical flows created by ovn-northd.

Upgrading the OVN packages installs everything needed for an upgrade.  The only
step required after upgrading the packages is to restart ovn-northd, which
automatically restarts the databases and upgrades the database schema, as well.

You may perform this restart using the ovn-ctl script::

    $ sudo /usr/share/openvswitch/scripts/ovn-ctl restart_northd

or if you're using a Linux distribution with systemd::

    $ sudo systemctl restart ovn-northd

Upgrading OVN Integration
-------------------------

Lastly, you may also want to upgrade integration with OVN that you may be
using.  For example, this could be the OpenStack Neutron driver or
ovn-kubernetes.

OVN's northbound database schema is a backwards compatible interface, so
you should be able to safely complete an OVN upgrade before upgrading
any integration in use.
