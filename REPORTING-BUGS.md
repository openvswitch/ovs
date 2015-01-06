Reporting Bugs in Open vSwitch
==============================

We are eager to hear from users about problems that they have
encountered with Open vSwitch.  This file documents how best to report
bugs so as to ensure that they can be fixed as quickly as possible.

Please report bugs by sending email to bugs@openvswitch.org.  

For reporting security vulnerabilities, please read SECURITY.md.

The most important parts of your bug report are the following:

  * What you did that make the problem appear.

  * What you expected to happen.

  * What actually happened.

Please also include the following information:

  * The Open vSwitch version number (as output by `ovs-vswitchd
    --version`).

  * The Git commit number (as output by `git rev-parse HEAD`),
    if you built from a Git snapshot.

  * Any local patches or changes you have applied (if any).

The following are also handy sometimes:

  * The kernel version on which Open vSwitch is running (from
    `/proc/version`) and the distribution and version number of
    your OS (e.g. "Centos 5.0").

  * The contents of the vswitchd configuration database (usually
    `/etc/openvswitch/conf.db`).

  * The output of `ovs-dpctl show`.

  * If you have Open vSwitch configured to connect to an
    OpenFlow controller, the output of `ovs-ofctl show <bridge>`
    for each `<bridge>` configured in the vswitchd configuration
    database.

  * A fix or workaround, if you have one.

  * Any other information that you think might be relevant.

bugs@openvswitch.org is a public mailing list, to which anyone can
subscribe, so please do not include confidential information in your
bug report.

Contact 
-------

bugs@openvswitch.org
http://openvswitch.org/
