Using bash command-line completion scripts
------------------------------------------

There are two completion scripts available, ovs-appctl-bashcomp.bash
and ovs-vsctl-bashcomp.bash respectively.

ovs-appctl-bashcomp
-------------------

   ovs-appctl-bashcomp.bash adds bash command-line completion support
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

ovs-vsctl-bashcomp
-------------------

   ovs-vsctl-bashcomp.bash adds bash command-line completion support
   for ovs-vsctl command.

   Features:
   ---------

      display available completion and complete on user input for
      global/local options, command, and argument.

      query database and expand keywords like 'table/record/column/key'
      to available completions.

      deal with argument relations like 'one and more', 'zero or one'.

      complete multiple ovs-vsctl commands cascaded via '--'.

   Limitations:
   ------------

      completion of very long ovs-vsctl command can take up to several
      seconds.

How to use:
-----------

   The bashcomp scripts should be placed at /etc/bash_completion.d/
   to be available for all bash sessions.  Running 'make install'
   will place the scripts to $(sysconfdir)/bash_completion.d/.  So user
   should specify --sysconfdir=/etc at configuration.  Meanwhile, if OVS is
   installed from packages, the scripts will automatically be placed inside
   /etc/bash_completion.d/.

   If you just want to run the scripts in one bash, you can remove them from
   /etc/bash_completion.d/ and run the scripts via '. ovs-appctl-bashcomp.bash'
   or '. ovs-vsctl-bashcomp.bash'.

Test:
-----

   Unit tests are added in tests/completion.at and integrated into autotest
   framework.  To run the tests, just do make check.

Bug Reporting:
--------------

Please report problems to bugs@openvswitch.org.