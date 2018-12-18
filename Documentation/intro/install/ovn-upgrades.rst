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

Schema Change
^^^^^^^^^^^^^

During database upgrading, if there is schema change, the DB file will be
converted to the new schema automatically, if the schema change is backward
compatible.  OVN tries the best to keep the DB schemas backward compatible.

However, there can be situations that an incompatible change is reasonble.  An
example of such case is to add constraints in the table to ensure correctness.
If there were already data that violates the new constraints got added somehow,
it will result in DB upgrade failures.  In this case, user should manually
correct data using ovn-nbctl (for north-bound DB) or ovn-sbctl (for south-
bound DB), and then upgrade again following previous steps.  Below is a list
of known impactible schema changes and how to fix when error encountered.

#. Release 2.11: index [type, ip] added for Encap table of south-bound DB to
   prevent duplicated IPs being used for same tunnel type.  If there are
   duplicated data added already (e.g. due to improper chassis management),
   a convenient way to fix is to find the chassis that is using the IP
   with command::

    $ ovn-sbctl show

   Then delete the chassis with command::

    $ ovn-sbctl chassis-del <chassis>


Upgrading OVN Integration
-------------------------

Lastly, you may also want to upgrade integration with OVN that you may be
using.  For example, this could be the OpenStack Neutron driver or
ovn-kubernetes.

OVN's northbound database schema is a backwards compatible interface, so
you should be able to safely complete an OVN upgrade before upgrading
any integration in use.
