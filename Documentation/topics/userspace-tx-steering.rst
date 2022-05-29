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

============================
Userspace Tx packet steering
============================

The userspace datapath supports two transmit packet steering modes.

Thread mode
~~~~~~~~~~~

This mode is automatically selected when the port's ``tx-steering`` option is
set to ``thread`` or unset.

Thread mode enables static (1:1) thread-to-txq mapping when the number of Tx
queues is greater than number of PMD threads, and dynamic (N:1) mapping if
equal or lower.  In this mode a single thread can not use more than 1 transmit
queue of a given port.

This is the recommended mode for performance reasons if the number of Tx queues
is greater than the number of PMD threads, because the Tx lock is not acquired.

If the number of Tx queues is greater than the number of threads (including the
main thread), the remaining Tx queues will not be used.

This mode is enabled by default.

Hash mode
~~~~~~~~~

Hash-based Tx packet steering mode distributes the packets on all the port's
transmit queues, whatever the number of PMD threads.  The queue selection is
based on the 5-tuples hash to build the flows batches, the selected queue being
the modulo between the hash and the number of Tx queues of the port.

Hash mode may be used for example with vhost-user ports, when the number of
vCPUs and queues of the guest are greater than the number of PMD threads.
Without hash mode, the Tx queues used would be limited to the number of
threads.

Hash-based Tx packet steering may have an impact on the performance, given the
Tx lock acquisition is always required and a second level of batching is
performed.

Usage
~~~~~

To enable hash mode::

    $ ovs-vsctl set Interface <iface> other_config:tx-steering=hash

To disable hash mode::

    $ ovs-vsctl set Interface <iface> other_config:tx-steering=thread
