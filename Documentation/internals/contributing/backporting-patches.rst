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
the Linux datapath and compat code, the development branch is `master` in the
Open vSwitch repository. Patches are applied first to this branch, then to the
most recent `branch-X.Y`, then earlier `branch-X.Z`, and so on. The most common
kind of patch in this category is a bugfix which affects master and other
branches.

For Linux datapath code, the primary development branch is in the `net-next`_
tree as described in the section below, and patch discussion occurs on the
`netdev`__ mailing list. Patches are first applied to the upstream branch by the
networking maintainer, then the contributor backports the patch to the Open
vSwitch `master` development branch. Patches in this category may include
features which have been applied upstream, or bugfixes to the Open vSwitch
datapath code. For bugfixes, the patches subsequently follow the regular Open
vSwitch process as described above to reach older branches.

__ http://vger.kernel.org/vger-lists.html#netdev

Changes to userspace components
-------------------------------

Patches which are fixing bugs should be considered for backporting from
`master` to release branches. Open vSwitch contributors submit their patches
targeted to the `master` branch, using the ``Fixes`` tag described in
:doc:`submitting-patches`. The maintainer first applies the patch to `master`,
then backports the patch to each older affected tree, as far back as it goes or
at least to all currently supported branches. This is usually each branch back
to the most recent LTS release branch.

If the fix only affects a particular branch and not `master`, contributors
should submit the change with the target branch listed in the subject line of
the patch. Contributors should list all versions that the bug affects. The
``git format-patch`` argument ``--subject-prefix`` may be used when posting the
patch, for example:

::

    $ git format-patch HEAD --subject-prefix="PATCH branch-2.7"

If a maintainer is backporting a change to older branches and the backport is
not a trivial cherry-pick, then the maintainer may opt to submit the backport
for the older branch on the mailinglist for further review. This should be done
in the same manner as described above.

Changes to Linux kernel components
----------------------------------

The Linux kernel components in Open vSwitch go through initial review in the
upstream Linux netdev community before they go into the Open vSwitch tree. As
such, backports from upstream to the Open vSwitch tree may include bugfixes or
new features. The `netdev-FAQ`_ describes the general process for merging
patches to the upstream Linux tree.

To keep track of the changes which are made upstream against the changes which
have been backported to the Open vSwitch tree, backports should be done in the
order that they are applied to the upstream `net-next`_ tree. For example, if
the git history in ``linux/net/openvswitch/`` in the `net-next` tree lists
patches A, B and C that were applied (in that order), then the backports of
these patches to ``openvswitch/datapath/`` should be done submitted in the
order A, B, then C.

Patches that are proposed against the Open vSwitch tree, including backports,
should follow the guidelines described in :doc:`submitting-patches`. Ideally,
a series which backports new functionality would also include a series of
patches for the userspace components which show how to use the new
functionality, and include tests to validate the behaviour. However, in the
interests of keeping the Open vSwitch tree in sync with upstream `net-next`,
contributors may send Open vSwitch kernel module changes independently of
userspace changes.

.. _netdev-faq: https://www.kernel.org/doc/Documentation/networking/netdev-FAQ.txt
.. _net-next: http://git.kernel.org/cgit/linux/kernel/git/davem/net-next.git

How to backport kernel patches
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First, the patch should be submitted upstream to `netdev`. When the patch has
been applied to `net-next`, it is ready to be backported. Starting from the
Linux tree, use ``git format-patch`` to format each patch that should be
backported. For each of these patches, they may only include changes to
``linux/net/openvswitch/``, or they may include changes to other directories.
Depending on which files the patch touches, the backport may be easier or more
difficult to undertake.

Start by formatting the relevant patches from the Linux tree. For example, to
format the last 5 patches to ``net/openvswitch``, going back from OVS commit
``1234c0ffee5``, placing them into ``/tmp/``:

::

    $ git format-patch -5 1234c0ffee5 net/openvswitch/ -o /tmp

Next, change into the Open vSwitch directory and apply the patch:

::

    $ git am -p3 --reject --directory=datapath/ <patch>

If this is successful, proceed to the next patch:

::

    $ git am --continue

If this is unsuccessful, the above command applies all changes that it can
to the working tree, and leaves rejected hunks in corresponding \*.rej
files. Proceed by using ``git diff`` to identify the changes, and edit the
files so that the hunk matches what the file looks like when the
corresponding commit is checked out in the linux tree. When all hunks are
fixed, add the files to the index using ``git add``.


If the patch only changes filepaths under ``linux/net/openvswitch``, then most
likely the patch is fully backported. At this point, review the patch's changes
and compare with the latest upstream code for the modified functions.
Occasionally, there may be bugs introduced in a particular patch which were
fixed in a later patch upstream. To prevent breakage in the OVS tree, consider
rolling later bugfixes into the current patch - particularly if they are small,
clear bugfixes in the logic of this patch. Then proceed to the next patch using
``git am --continue``. If you made any changes to the patch compared with the
original version, describe the changes in the commit message.

If the changes affects other paths, then you may also need to backport function
definitions from the upstream tree into the ``datapath/linux/compat``
directory. First, attempt to compile the datapath. If this is successful, then
most likely there is no further work required. As per the previous paragraph,
consider reviewing and backporting any minor fixes to this code if applicable,
then proceed to the next patch using ``git am --continue``.

If compilation fails, the compiler will show which functions are missing or
broken. Typically this should match with some function definitions provided in
the patch file. The following command will attempt to apply all such changes
from the patch into the ``openvswitch/datapath/linux/compat`` directory; Like
the previous ``git am`` command above, it may succeed or fail. If it succeeds,
review the patch and proceed to the next patch using ``git am --continue``.

::

    $ git am -p3 --reject --directory='datapath/linux/compat/' <patch>

For each conflicting hunk, attempt to resolve the change so that the function
reflects what the function looks like in the upstream Linux tree. After
resolving these changes, compile the changes, add the modified files to the
index using ``git add``, review the patch, and proceed to the next patch using
``git am --continue``.

Submission
~~~~~~~~~~

Once the patches are all assembled and working on the Open vSwitch tree, they
need to be formatted again using ``git format-patch``. The common format for
commit messages for Linux backport patches is as follows:

::

    datapath: Remove incorrect WARN_ONCE().

    Upstream commit:
        commit c6b2aafffc6934be72d96855c9a1d88970597fbc
        Author: Jarno Rajahalme <jarno@ovn.org>
        Date:   Mon Aug 1 19:08:29 2016 -0700

        openvswitch: Remove incorrect WARN_ONCE().

        ovs_ct_find_existing() issues a warning if an existing conntrack entry
        classified as IP_CT_NEW is found, with the premise that this should
        not happen.  However, a newly confirmed, non-expected conntrack entry
        remains IP_CT_NEW as long as no reply direction traffic is seen.  This
        has resulted into somewhat confusing kernel log messages.  This patch
        removes this check and warning.

        Fixes: 289f2253 ("openvswitch: Find existing conntrack entry after upcall.")
        Suggested-by: Joe Stringer <joe@ovn.org>
        Signed-off-by: Jarno Rajahalme <jarno@ovn.org>
        Acked-by: Joe Stringer <joe@ovn.org>

    Signed-off-by: Jarno Rajahalme <jarno@ovn.org>

The upstream commit SHA should be the one that appears in Linus' tree so that
reviewers can compare the backported patch with the one upstream.  Note that
the subject line for the backported patch replaces the original patch's
``openvswitch`` prefix with ``datapath``. Patches which only affect the
``datapath/linux/compat`` directory should be prefixed with ``compat``.

The contents of a backport should be equivalent to the changes made by the
original patch; explain any variations from the original patch in the commit
message - For instance if you rolled in a bugfix. Reviewers will verify that
the changes made by the backport patch are the same as the changes made in the
original commit which the backport is based upon. Patch submission should
otherwise follow the regular steps described in :doc:`submitting-patches`. In
particular, if performing kernel patch backports, pay attention to
:ref:`datapath-testing`.
