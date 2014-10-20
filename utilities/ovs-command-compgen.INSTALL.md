Using bash command-line completion script
-----------------------------------------

ovs-command-compgen.bash adds bash command-line completion support
for ovs-appctl, ovs-dpctl, ovs-ofctl and ovsdb-tool commands.

Features:
---------

   display available completion or complete on unfinished user input
   (long option, subcommand, and argument).

   once the subcommand (e.g. ofproto/trace) has been given, the
   script will print the subcommand format.

   the script can convert between keywords like 'bridge/port/interface/dp'
   and the available record in ovsdb.

Limitations:
------------

   only support small set of important keywords
   (dp, datapath, bridge, switch, port, interface, iface).

   does not support parsing of nested options
   (e.g. ovsdb-tool create [db [schema]]).

   does not support expansion on repeatitive argument
   (e.g. ovs-dpctl show [dp...]).

   only support matching on long options, and only in the format
   (--option [arg], i.e. should not use --option=[arg]).


How to use:
-----------

   To use the script, either copy it inside /etc/bash_completion.d/
   or manually run it via . ovs-command-compgen.bash.

Test:
-----

   An unit testsuite is provided as ovs-command-compgen-test.bash.
   To run the test, first enter ovs sandbox via:

        make sandbox && cd sandbox

   Then copy both ovs-command-compgen-test.bash and ovs-command-compgen.bash
   to the current directory.  Finally, run the test via:

        bash ovs-command-compgen-test.bash

Bug Reporting:
--------------

Please report problems to bugs@openvswitch.org.