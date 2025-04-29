..
      Copyright (c) 2017 Nicira, Inc.

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

===================
Backporting patches
===================

.. note::

    This is an advanced topic for developers and maintainers. Readers should
    familiarize themselves with building and running Open vSwitch, with the git
    tool, and with the Open vSwitch patch submission process.

The backporting of patches from one git tree to another takes multiple forms
within Open vSwitch, but is broadly applied in the following fashion:

- Contributors submit their proposed changes to the latest development branch
- Contributors and maintainers provide feedback on the patches
- When the change is satisfactory, maintainers apply the patch to the
  development branch.
- Maintainers backport changes from a development branch to release branches.

With regards to Open vSwitch user space code and code that does not comprise
the Linux datapath and compat code, the development branch is `main` in the
Open vSwitch repository. Patches are applied first to this branch, then to the
most recent `branch-X.Y`, then earlier `branch-X.Z`, and so on. The most common
kind of patch in this category is a bugfix which affects main and other
branches.

Changes to userspace components
-------------------------------

Patches which are fixing bugs should be considered for backporting from
`main` to release branches. Open vSwitch contributors submit their patches
targeted to the `main` branch, using the ``Fixes`` tag described in
:doc:`submitting-patches`. The maintainer first applies the patch to `main`,
then backports the patch to each older affected tree, as far back as it goes or
at least to all currently supported branches. This is usually each branch back
to the oldest maintained LTS release branch or the last 4 release branches if
the oldest LTS is newer.

If the fix only affects a particular branch and not `main`, contributors
should submit the change with the target branch listed in the subject line of
the patch. Contributors should list all versions that the bug affects. The
``git format-patch`` argument ``--subject-prefix`` may be used when posting the
patch, for example:

::

    $ git format-patch HEAD --subject-prefix="PATCH branch-2.7"

If a maintainer is backporting a change to older branches and the backport is
not a trivial cherry-pick, then the maintainer may opt to submit the backport
for the older branch on the mailing list for further review. This should be done
in the same manner as described above.

Changes to Linux kernel components
----------------------------------

Changes to the Linux kernel components in Open vSwitch go through review in
the upstream Linux Netdev community. The `Netdev Maintainer Handbook`_
describes the general process for merging patches to the upstream Linux
kernel networking subsystem.

Backports to older kernel versions are handled via the `Stable tree`_
mechanism.

Backports for Linux datapath code are no longer accepted into the Open
vSwitch tree as that code is not present in the Open vSwitch distribution
since Open vSwitch 3.0.

.. _Netdev Maintainer Handbook: https://docs.kernel.org/process/maintainer-netdev.html
.. _Stable tree: https://docs.kernel.org/process/maintainer-netdev.html#stable-tree
