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

===============
DPDK Ring Ports
===============

.. warning::

   DPDK ring interfaces cannot be used for guest communication and are retained
   mainly for backwards compatibility purposes. In nearly all cases,
   :doc:`vhost-user ports <vhost-user>` are a better choice and should be used
   instead.

The DPDK datapath provides DPDK-backed ring ports that are implemented using
DPDK's ``librte_ring`` library. For more information on this library, refer to
the `DPDK documentation`_.

.. important::

   To use any DPDK-backed interface, you must ensure your bridge is configured
   correctly. For more information, refer to :doc:`bridge`.

Quick Example
-------------

This example demonstrates how to add a ``dpdkr`` port to an existing bridge
called ``br0``::

    $ ovs-vsctl add-port br0 dpdkr0 -- set Interface dpdkr0 type=dpdkr

dpdkr
-----

To use ring ports, you must first add said ports to the switch. Unlike
:doc:`vhost-user ports <vhost-user>`, ring port names must take a specific
format, ``dpdkrNN``, where ``NN`` is the port ID. For example::

    $ ovs-vsctl add-port br0 dpdkr0 -- set Interface dpdkr0 type=dpdkr

Once the port has been added to the switch, they can be used by host processes.
A sample loopback application - ``test-dpdkr`` - is included with Open vSwitch.
To use this, run the following::

    $ ./tests/test-dpdkr -c 1 -n 4 --proc-type=secondary -- -n 0

Further functionality would require developing your own application. Refer to
the `DPDK documentation`_ for more information on how to do this.

Adding dpdkr ports to the guest
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is **not** recommended to use ring ports from guests. Historically, this was
possible using a patched version of QEMU and the IVSHMEM feature provided with
DPDK. However, this functionality was removed because:

- The IVSHMEM library was removed from DPDK in DPDK 16.11

- Support for IVSHMEM was never upstreamed to QEMU and has been publicly
  rejected by the QEMU community

- :doc:`vhost-user interfaces <vhost-user>` are the de facto DPDK-based path to
  guests

.. _DPDK documentation: https://dpdk.readthedocs.io/en/v17.11/prog_guide/ring_lib.html
