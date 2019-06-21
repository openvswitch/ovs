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

================
What is Fuzzing?
================


Usually, software teams do functional testing (which is great) but not
security testing of their code. For example::

  func_add(int x, int y) { return x+y; }

may have a unit test like so::

  ASSERT((func_add(4,5)==9))

However, corner cases are usually not tested so that `x=INT_MAX; y=1`
demonstrates a problem in the implementation.

Fuzz testing is routinely used to probabilistically generate such corner
cases and feed them to program APIs to test their behavior.
