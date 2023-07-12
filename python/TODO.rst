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

==========================
Python Bindings To-do List
==========================

* IDL:

  * Support incremental change tracking monitor mode (equivalent of
    OVSDB_IDL_TRACK).

  * Support write-only-changed monitor mode (equivalent of
    OVSDB_IDL_WRITE_CHANGED_ONLY).

* socket_util:

  * Add equivalent fuctions to inet_parse_passive, parse_sockaddr_components,
    et al. to better support using async dns. The reconnect code will
    currently log a warning when inet_parse_active() returns w/o yet having
    resolved an address, but will continue to connect and eventually succeed.
