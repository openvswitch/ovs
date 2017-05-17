..
      Copyright (c) 2017 Red Hat, Inc.

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

===================================
Open vSwitch Library ABI Updates
===================================

This file describes the manner in which the Open vSwitch shared library
manages different ABI and API revisions.  This document aims to describe
the background, goals, and concrete mechanisms used to export code-space
functionality so that it may be shared between multiple applications.

.. _definitions:

Definitions
-----------

.. csv-table:: Definitions for terms appearing in this document
   :header: "Term", "Definition"

   "ABI", "Abbreviation of Application Binary Interface"
   "API", "Abbreviation of Application Programming Interface"
   "Application Binary Interface", "The low-level runtime interface exposed
   by an object file."
   "Application Programming Interface", "The source-code interface descriptions
   intended for use in multiple translation units when compiling."
   "Code library", "A collection of function implementations and definitions
   intended to be exported and called through a well-defined interface."
   "Shared Library", "A code library which is imported at run time."

.. _overview:

Overview
----------

C and C++ applications often use 'external' functionality, such as printing
specialized data types or parsing messages, which has been exported for common
use.  There are many possible ways for applications to call such external
functionality, for instance by including an appropriate inline definition which
the compiler can emit as code in each function it appears.  One such way of
exporting and importing such functionality is through the use of a library
of code.

When a compiler builds object code from source files to produce object code,
the results are binary data arranged with specific calling conventions,
alignments, and order suitable for a run-time environment or linker.  This
result defines a specific ABI.

As library of code develops and its exported interfaces change over time, the
resulting ABI may change as well.  Therefore, care must be taken to ensure the
changes made to libraries of code are effectively communicated to applications
which use them.  This includes informing the applications when incompatible
changes are made.

The Open vSwitch project exports much of its functionality through multiple
such libraries of code.  These libraries are intended for multiple applications
to import and use.  As the Open vSwitch project continues to evolve and change,
its exported code will evolve as well.  To ensure that applications linking to
these libraries are aware of these changes, Open vSwitch employs libtool
version stamps.

.. _policies:

ABI Policy
----------

Open vSwitch will export the ABI version at the time of release, such that the
library name will be the major.minor version, and the rest of the release
version information will be conveyed with a libtool interface version.

The intent is for Open vSwitch to maintain an ABI stability for each minor
revision only (so that Open vSwitch release 2.5 carries a guarantee for all
2.5.ZZ micro-releases). This means that any porting effort to stable branches
must take not to disrupt the existing ABI.

In the event that a bug must be fixed in a backwards-incompatible way,
developers must bump the libtool 'current' version to inform the linker of the
ABI breakage. This will signal that libraries exposed by the subsequent release
will not maintain ABI stability with the previous version.

Coding
-------

At build time, if building shared libraries by passing the `--enable-shared`
arguments to `./configure`, version information is extracted from
the ``$PACKAGE_VERSION`` automake variable and formatted into the appropriate
arguments.  These get exported for use in Makefiles as ``$OVS_LTINFO``, and
passed to each exported library along with other ``LDFLAGS``.

Therefore, when adding a new library to the build system, these version flags
should be included with the ``$LDFLAGS`` variable.  Nothing else needs to be
done.

Changing an exported function definition (from a file in, for instance
`lib/*.h`) is only permitted from minor release to minor release.  Likewise
changes to library data structures should only occur from minor release to
minor release.
