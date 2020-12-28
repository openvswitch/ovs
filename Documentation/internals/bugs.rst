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

==============
Reporting Bugs
==============

We are eager to hear from users about problems that they have encountered with
Open vSwitch. This file documents how best to report bugs so as to ensure that
they can be fixed as quickly as possible.

Please report bugs by sending email to bugs@openvswitch.org.

For reporting security vulnerabilities, please read :doc:`security`.

The most important parts of your bug report are the following:

- What you did that make the problem appear.

- What you expected to happen.

- What actually happened.

Please also include the following information:

- The Open vSwitch version number (as output by ``ovs-vswitchd --version``).

- The Git commit number (as output by ``git rev-parse HEAD``), if you built
  from a Git snapshot.

- Any local patches or changes you have applied (if any).

The following are also handy sometimes:

- The kernel version on which Open vSwitch is running (from ``/proc/version``)
  and the distribution and version number of your OS (e.g. "Centos 5.0").

- The contents of the vswitchd configuration database (usually
  ``/etc/openvswitch/conf.db``).

- The output of ``ovs-dpctl show``.

- If you have Open vSwitch configured to connect to an OpenFlow
  controller, the output of ``ovs-ofctl show <bridge>`` for each
  ``<bridge>`` configured in the vswitchd configuration database.

- A fix or workaround, if you have one.

- Any other information that you think might be relevant.

.. important::
  bugs@openvswitch.org is a public mailing list, to which anyone can subscribe,
  so do not include confidential information in your bug report.
