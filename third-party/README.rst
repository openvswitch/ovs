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

================================
Third-party software integration
================================

This directory contains third-party software that may be useful for debugging.

tcpdump
-------

The ``ofp-tcpdump.patch`` patch adds the ability to parse OpenFlow messages to
tcpdump.  These instructions assume that tcpdump 4.3.0 is going to be used, but
it should work with other versions that are not substantially different.  To
begin, download tcpdump and apply the patch:

::

    $ wget http://www.tcpdump.org/release/tcpdump-4.3.0.tar.gz
    $ tar xzf tcpdump-4.3.0.tar.gz
    $ ln -s tcpdump-4.3.0 tcpdump
    $ patch -p0 < ofp-tcpdump.patch

Then build the new version of tcpdump:

::

    $ cd tcpdump
    $ ./configure
    $ make

Clearly, tcpdump can only parse unencrypted packets, so you will need to
connect the controller and datapath using plain TCP.  To look at the traffic,
tcpdump will be started in a manner similar to the following:

::

    $ sudo ./tcpdump -s0 -i eth0 port 6653

The ``-s0`` flag indicates that tcpdump should capture the entire packet.  If
the OpenFlow message is not received in its entirety, ``[|openflow]`` will be
printed instead of the OpenFlow message contents.

The verbosity of the output may be increased by adding additional ``-v`` flags.
If ``-vvv`` is used, the raw OpenFlow data is also printed in hex and ASCII.
