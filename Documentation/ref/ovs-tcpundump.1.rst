=============
ovs-tcpundump
=============

Synopsis
========

``ovs-tcpundump < <file>``

``ovs-tcpundump -h | --help``

``ovs-tcpundump -V | --version``

The ``ovs-tcpundump`` program reads ``tcpdump -xx output`` from stdin,
looking for hexadecimal packet data, and dumps each Ethernet as a
single hexadecimal string on stdout.  This format is suitable for use
with the ``ofproto/trace`` command supported by ``ovs-vswitchd(8)``
via ``ovs-appctl(8)``.

At least two ``-x`` or ``-X`` options must be given, otherwise the
output will omit the Ethernet header, which prevents the output from
being used with ``ofproto/trace``.

Options
=======

* ``-h`` or ``--help``

  Prints a brief help message to the console.

* ``-V`` or ``--version``

  Prints version information to the console.

See Also
========

``ovs-appctl(8)``, ``ovs-vswitchd(8)``, ``ovs-pcap(1)``,
``tcpdump(8)``, ``wireshark(8)``.
