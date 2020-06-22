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

===========================
OVSDB Clustering To-do List
===========================

* Ephemeral columns.

* Locks.

* Tons of unit tests.

* Increase exponential backoff cap.  Introduce randomization.

* Include index with monitor update?

* Testing with replication.

* Handling bad transactions in read_db().  (Kill the database?)

* Documentation:

  * ACID (and CAP?) explanation.

  * Overall diagram explaining the cluster and ovsdb protocol pieces

* Future work:

  * File format with diff support.

  * Future work: DNS or directory support
