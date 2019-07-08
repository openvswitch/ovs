..
      Copyright (c) 2016, Stephen Finucane <stephen@that.guru>

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
Security Analysis of OVS Fuzzers
================================

OvS fuzzer harnesses test different components of OvS. This document
performs a security analysis of these harnesses. The intention is to
not only tabulate what is currently done but also to help expand
on the set of harnesses.

    ========================   =================   ==============
    Fuzzer harness             Interface           Input source
    ========================   =================   ==============
    flow_extract_target        External            Untrusted
    json_parser_target         OVS DB              Trusted
    miniflow_target            External            Untrusted
    odp_target                 North-bound         Trusted
    ofctl_parse_target         Management          Trusted
    ofp_print_target           South/North-bound   Trusted
    ========================   =================   ==============
