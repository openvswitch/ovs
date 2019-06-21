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

===========
OVS Fuzzers
===========

OvS fuzzer test harnesses define the libFuzzer fuzz API. In doing so,
they define what is to be done with the input supplied by the fuzzer.

At a minimum, the libfuzzer API is defined as follows::

  // input_ is a byte array, size is the length of said byte array
  int
  LLVMFuzzerTestOneInput(const uint8_t *input, size_t size)
  {
      // Input processing
      process_input(input, size);

      // Must always return 0. Non-zero return codes are reserved by libFuzzer.
      return 0;
  }

In certain scenarios, it may be necessary to constrain the input supplied by
the fuzzer. One scenario is when `process_input` accepts a C string. One
way to do this would be as follows::

  // input_ is a byte array, size is the length of said byte array
  int
  LLVMFuzzerTestOneInput(const uint8_t *input, size_t size)
  {
      // Constrain input
      // Check if input is null terminated
      const char *cstring = (const char*) input;
      if (cstring[size - 1] != '\0')
          return 0;

      // Input processing
      process_input(cstring);

      // Must always return 0. Non-zero return codes are reserved by libFuzzer.
      return 0;
  }

OvS fuzzer test harnesses are located in the `tests/oss-fuzz` sub-directory.
At the time of writing, there are a total of six harnesses:

  * `flow_extract_target.c`
  * `json_parser_target.c`
  * `miniflow_target.c`
  * `odp_target.c`
  * `ofctl_parse_target.c`
  * `ofp_print_target.c`

--------------------
flow_extract_target
--------------------

Extracts flow from and parses fuzzer supplied packet payload.

--------------------
json_parser_target
--------------------

Parses fuzzer supplied string as JSON, encoding the parsed JSON
into a JSON RPC message, and finally decoding the encoded JSON
RPC message back to JSON.

--------------------
miniflow_target
--------------------

Extracts flow from fuzzer supplied packet payload, converts flow
to a miniflow and performs various miniflow operations.

--------------------
odp_target
--------------------

Parses fuzzer supplied string as an ODP flow, and the same string as
an ODP action.

--------------------
ofctl_parse_target
--------------------

Treats fuzzer supplied input as a <flow_command> followed by a
<flow_mod_string>, invoking the `parse_ofp_flow_mod_str` on the pair.

--------------------
ofp_print_target
--------------------

Parses fuzzer supplied data as an Open Flow Protocol buffer.
