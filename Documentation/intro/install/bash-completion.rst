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

====================================
Bash command-line completion scripts
====================================

There are two completion scripts available: ``ovs-appctl-bashcomp.bash`` and
``ovs-vsctl-bashcomp.bash``.

ovs-appctl-bashcomp
-------------------

``ovs-appctl-bashcomp.bash`` adds bash command-line completion support for
``ovs-appctl``, ``ovs-dpctl``, ``ovs-ofctl`` and ``ovsdb-tool`` commands.

Features
~~~~~~~~

- Display available completion or complete on unfinished user input (long
  option, subcommand, and argument).

- Subcommand hints

- Convert between keywords like ``bridge``, ``port``, ``interface``, or ``dp``
  and the available record in ovsdb.

Limitations
~~~~~~~~~~~

- Only supports a small set of important keywords (``dp``, ``datapath``,
  ``bridge``, ``switch``, ``port``, ``interface``, ``iface``).

- Does not support parsing of nested options. For example::

      $ ovsdb-tool create [db [schema]]

- Does not support expansion on repeated argument. For example::

      $ ovs-dpctl show [dp...]).

- Only supports matching on long options, and only in the format ``--option
  [arg]``. Do not use ``--option=[arg]``.

ovs-vsctl-bashcomp
-------------------

``ovs-vsctl-bashcomp.bash`` adds Bash command-line completion support for
``ovs-vsctl`` command.

Features
~~~~~~~~

- Display available completion and complete on user input for global/local
  options, command, and argument.

- Query database and expand keywords like ``table``, ``record``, ``column``, or
  ``key``, to available completions.

- Deal with argument relations like 'one and more', 'zero or one'.

- Complete multiple ``ovs-vsctl`` commands cascaded via ``--``.

Limitations
~~~~~~~~~~~

Completion of very long ``ovs-vsctl`` commands can take up to several seconds.

Usage
-----

The bashcomp scripts should be placed at ``/etc/bash_completion.d/`` to be
available for all bash sessions.  Running ``make install`` will place the
scripts to ``$(sysconfdir)/bash_completion.d/``, thus, the user should specify
``--sysconfdir=/etc`` at configuration.  If OVS is installed from packages, the
scripts will automatically be placed inside ``/etc/bash_completion.d/``.

If you just want to run the scripts in one bash, you can remove them from
``/etc/bash_completion.d/`` and run the scripts via ``.
ovs-appctl-bashcomp.bash`` or ``. ovs-vsctl-bashcomp.bash``.

Tests
-----

Unit tests are added in ``tests/completion.at`` and integrated into autotest
framework.  To run the tests, just run ``make check``.
