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

=====
pdump
=====

.. versionadded:: 2.6.0

pdump allows you to listen on DPDK ports and view the traffic that is passing
on them. To use this utility, one must have libpcap installed on the system.
Furthermore, DPDK must be built with ``CONFIG_RTE_LIBRTE_PDUMP=y`` and
``CONFIG_RTE_LIBRTE_PMD_PCAP=y``.

.. warning::

   A performance decrease is expected when using a monitoring application like
   the DPDK pdump app.

To use pdump, simply launch OVS as usual, then navigate to the ``app/pdump``
directory in DPDK, ``make`` the application and run like so::

    $ sudo ./build/app/dpdk-pdump -- \
        --pdump port=0,queue=0,rx-dev=/tmp/pkts.pcap \
        --server-socket-path=/usr/local/var/run/openvswitch

The above command captures traffic received on queue 0 of port 0 and stores it
in ``/tmp/pkts.pcap``. Other combinations of port numbers, queues numbers and
pcap locations are of course also available to use. For example, to capture all
packets that traverse port 0 in a single pcap file::

    $ sudo ./build/app/dpdk-pdump -- \
        --pdump 'port=0,queue=*,rx-dev=/tmp/pkts.pcap,tx-dev=/tmp/pkts.pcap' \
        --server-socket-path=/usr/local/var/run/openvswitch

``server-socket-path`` must be set to the value of ``ovs_rundir()`` which
typically resolves to ``/usr/local/var/run/openvswitch``.

Many tools are available to view the contents of the pcap file. Once example is
tcpdump. Issue the following command to view the contents of ``pkts.pcap``::

    $ tcpdump -r pkts.pcap

More information on the pdump app and its usage can be found in the `DPDK
documentation`__.

__ http://dpdk.org/doc/guides/tools/pdump.html
