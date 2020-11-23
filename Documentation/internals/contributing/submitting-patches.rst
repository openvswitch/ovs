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

==================
Submitting Patches
==================

Send changes to Open vSwitch as patches to dev@openvswitch.org.  One patch per
email.  More details are included below.

If you are using Git, then `git format-patch` takes care of most of the
mechanics described below for you.

Before You Start
----------------

Before you send patches at all, make sure that each patch makes sense.  In
particular:

- A given patch should not break anything, even if later patches fix the
  problems that it causes.  The source tree should still build and work after
  each patch is applied.  (This enables `git bisect` to work best.)

- A patch should make one logical change.  Don't make multiple, logically
  unconnected changes to disparate subsystems in a single patch.

- A patch that adds or removes user-visible features should also
  update the appropriate user documentation or manpages.  Consider
  adding an item to NEWS for nontrivial changes.  Check "Feature
  Deprecation Guidelines" section in this document if you intend to
  remove user-visible feature.

Testing is also important:

- Test a patch that modifies existing code with ``make check`` before
  submission.  Refer to the "Unit Tests" in :doc:`/topics/testing`, for more
  information.  We also encourage running the kernel and userspace system
  tests.

- Consider testing a patch that adds or deletes files with ``make
  distcheck`` before submission.

- A patch that modifies Linux kernel code should be at least build-tested on
  various Linux kernel versions before submission.  I suggest versions 3.10 and
  whatever the current latest release version is at the time.

- A patch that adds a new feature should add appropriate tests for the
  feature.  A bug fix patch should preferably add a test that would
  fail if the bug recurs.

If you are using GitHub, then you may utilize the travis-ci.org and the GitHub
Actions CI build systems.  They will run some of the above tests automatically
when you push changes to your repository.  See the "Continuous Integration with
Travis-CI" in :doc:`/topics/testing` for details on how to set it up.

Email Subject
-------------

The subject line of your email should be in the following format:

    [PATCH <n>/<m>] <area>: <summary>

Where:

``[PATCH <n>/<m>]``:
  indicates that this is the nth of a series of m patches.  It helps reviewers
  to read patches in the correct order.  You may omit this prefix if you are
  sending only one patch.

``<area>``:
  indicates the area of the Open vSwitch to which the change applies (often the
  name of a source file or a directory).  You may omit it if the change crosses
  multiple distinct pieces of code.

``<summary>``:

  briefly describes the change.  Use the imperative form,
  e.g. "Force SNAT for multiple gateway routers." or "Fix daemon exit
  for bad datapaths or flows."  Try to keep the summary short, about
  50 characters wide.

The subject, minus the ``[PATCH <n>/<m>]`` prefix, becomes the first line of
the commit's change log message.

Description
-----------

The body of the email should start with a more thorough description of the
change.  This becomes the body of the commit message, following the subject.
There is no need to duplicate the summary given in the subject.

Please limit lines in the description to 75 characters in width.  That
allows the description to format properly even when indented (e.g. by
"git log" or in email quotations).

The description should include:

- The rationale for the change.

- Design description and rationale (but this might be better added as code
  comments).

- Testing that you performed (or testing that should be done but you could not
  for whatever reason).

- Tags (see below).

There is no need to describe what the patch actually changed, if the reader can
see it for himself.

If the patch refers to a commit already in the Open vSwitch repository, please
include both the commit number and the subject of the patch, e.g. 'commit
632d136c (vswitch: Remove restriction on datapath names.)'.

If you, the person sending the patch, did not write the patch yourself, then
the very first line of the body should take the form ``From: <author name>
<author email>``, followed by a blank line.  This will automatically cause the
named author to be credited with authorship in the repository.

Tags
----

The description ends with a series of tags, written one to a line as the last
paragraph of the email.  Each tag indicates some property of the patch in an
easily machine-parseable manner.

Please don't wrap a tag across multiple lines.  If necessary, it's OK to have a
tag extend beyond the customary maximum width of a commit message.

Examples of common tags follow.

``Signed-off-by: Author Name <author.name@email.address...>``

  Informally, this indicates that Author Name is the author or submitter of a
  patch and has the authority to submit it under the terms of the license.  The
  formal meaning is to agree to the Developer's Certificate of Origin (see
  below).

  If the author and submitter are different, each must sign off.  If the patch
  has more than one author, all must sign off.

  Signed-off-by tags should be the last tags in the commit message.  If the
  author (or authors) and submitter are different, the author tags should come
  first.  More generally, occasionally a patch might pass through a chain of
  submitters, and in such a case the sign-offs should be arranged in
  chronological order.

  ::

      Signed-off-by: Author Name <author.name@email.address...>
      Signed-off-by: Submitter Name <submitter.name@email.address...>

``Co-authored-by: Author Name <author.name@email.address...>``

  Git can only record a single person as the author of a given patch.  In the
  rare event that a patch has multiple authors, one must be given the credit in
  Git and the others must be credited via Co-authored-by: tags.  (All
  co-authors must also sign off.)

``Acked-by: Reviewer Name <reviewer.name@email.address...>``

  Reviewers will often give an ``Acked-by:`` tag to code of which they approve.
  It is polite for the submitter to add the tag before posting the next version
  of the patch or applying the patch to the repository.  Quality reviewing is
  hard work, so this gives a small amount of credit to the reviewer.

  Not all reviewers give ``Acked-by:`` tags when they provide positive reviews.
  It's customary only to add tags from reviewers who actually provide them
  explicitly.

``Tested-by: Tester Name <reviewer.name@email.address...>``

  When someone tests a patch, it is customary to add a Tested-by: tag
  indicating that.  It's rare for a tester to actually provide the tag; usually
  the patch submitter makes the tag himself in response to an email indicating
  successful testing results.

``Tested-at: <URL>``

  When a test report is publicly available, this provides a way to reference
  it.  Typical <URL>s would be build logs from autobuilders or references to
  mailing list archives.

  Some autobuilders only retain their logs for a limited amount of time.  It is
  less useful to cite these because they may be dead links for a developer
  reading the commit message months or years later.

``Reported-by: Reporter Name <reporter.name@email.address...>``

  When a patch fixes a bug reported by some person, please credit the reporter
  in the commit log in this fashion.  Please also add the reporter's name and
  email address to the list of people who provided helpful bug reports in the
  AUTHORS file at the top of the source tree.

  Fairly often, the reporter of a bug also tests the fix.  Occasionally one
  sees a combined "Reported-and-tested-by:" tag used to indicate this.  It is
  also acceptable, and more common, to include both tags separately.

  (If a bug report is received privately, it might not always be appropriate to
  publicly credit the reporter.  If in doubt, please ask the reporter.)

``Requested-by: Requester Name <requester.name@email.address...>``

  When a patch implements a request or a suggestion made by some
  person, please credit that person in the commit log in this
  fashion.  For a helpful suggestion, please also add the
  person's name and email address to the list of people who
  provided suggestions in the AUTHORS file at the top of the
  source tree.

  (If a suggestion or a request is received privately, it might
  not always be appropriate to publicly give credit.  If in
  doubt, please ask.)

``Suggested-by: Suggester Name <suggester.name@email.address...>``

  See ``Requested-by:``.

``CC: Person <name@email>``

  This is a way to tag a patch for the attention of a person
  when no more specific tag is appropriate.  One use is to
  request a review from a particular person.  It doesn't make
  sense to include the same person in CC and another tag, so
  e.g. if someone who is CCed later provides an Acked-by, add
  the Acked-by and remove the CC at the same time.

``Reported-at: <URL>``

  If a patch fixes or is otherwise related to a bug reported in
  a public bug tracker, please include a reference to the bug in
  the form of a URL to the specific bug, e.g.:

  ::

      Reported-at: https://bugs.debian.org/743635

  This is also an appropriate way to refer to bug report emails
  in public email archives, e.g.:

  ::

      Reported-at: https://mail.openvswitch.org/pipermail/ovs-dev/2014-June/284495.html

``Submitted-at: <URL>``

  If a patch was submitted somewhere other than the Open vSwitch
  development mailing list, such as a GitHub pull request, this header can
  be used to reference the source.

  ::

      Submitted-at: https://github.com/openvswitch/ovs/pull/92

``VMware-BZ: #1234567``

  If a patch fixes or is otherwise related to a bug reported in
  a private bug tracker, you may include some tracking ID for
  the bug for your own reference.  Please include some
  identifier to make the origin clear, e.g. "VMware-BZ" refers
  to VMware's internal Bugzilla instance and "ONF-JIRA" refers
  to the Open Networking Foundation's JIRA bug tracker.

``ONF-JIRA: EXT-12345``

  See ``VMware-BZ:``.

``Bug #1234567.``

  These are obsolete forms of VMware-BZ: that can still be seen
  in old change log entries.  (They are obsolete because they do
  not tell the reader what bug tracker is referred to.)

``Issue: 1234567``

  See ``Bug:``.

``Fixes: 63bc9fb1c69f (“packets: Reorder CS_* flags to remove gap.”)``

  If you would like to record which commit introduced a bug being fixed,
  you may do that with a “Fixes” header.  This assists in determining
  which OVS releases have the bug, so the patch can be applied to all
  affected versions.  The easiest way to generate the header in the
  proper format is with this git command.  This command also CCs the
  author of the commit being fixed, which makes sense unless the
  author also made the fix or is already named in another tag:

  ::

      $ git log -1 --pretty=format:"CC: %an <%ae>%nFixes: %h (\"%s\")" \
        --abbrev=12 COMMIT_REF

``Vulnerability: CVE-2016-2074``

  Specifies that the patch fixes or is otherwise related to a
  security vulnerability with the given CVE identifier.  Other
  identifiers in public vulnerability databases are also
  suitable.

  If the vulnerability was reported publicly, then it is also
  appropriate to cite the URL to the report in a Reported-at
  tag.  Use a Reported-by tag to acknowledge the reporters.

Developer's Certificate of Origin
---------------------------------

To help track the author of a patch as well as the submission chain, and be
clear that the developer has authority to submit a patch for inclusion in
Open vSwitch please sign off your work.  The sign off certifies the following:

::

    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.

See also http://developercertificate.org/.

Feature Deprecation Guidelines
------------------------------

Open vSwitch is intended to be user friendly.  This means that under normal
circumstances we don't abruptly remove features from OVS that some users might
still be using.  Otherwise, if we would, then we would possibly break our user
setup when they upgrade and would receive bug reports.

Typical process to deprecate a feature in Open vSwitch is to:

(a) Mention deprecation of a feature in the NEWS file.  Also, mention expected
    release or absolute time when this feature would be removed from OVS
    altogether.  Don't use relative time (e.g. "in 6 months") because that is
    not clearly interpretable.

(b) If Open vSwitch is configured to use deprecated feature it should print
    a warning message to the log files clearly indicating that feature is
    deprecated and that use of it should be avoided.

(c) If this feature is mentioned in man pages, then add "Deprecated" keyword
    to it.

Also, if there is alternative feature to the one that is about to be marked as
deprecated, then mention it in (a), (b) and (c) as well.

Remember to follow-up and actually remove the feature from OVS codebase once
deprecation grace period has expired and users had opportunity to use at least
one OVS release that would have informed them about feature deprecation!

Comments
--------

If you want to include any comments in your email that should not be part of
the commit's change log message, put them after the description, separated by a
line that contains just ``---``.  It may be helpful to include a diffstat here
for changes that touch multiple files.

Patch
-----

The patch should be in the body of the email following the description,
separated by a blank line.

Patches should be in ``diff -up`` format.  We recommend that you use Git to
produce your patches, in which case you should use the ``-M -C`` options to
``git diff`` (or other Git tools) if your patch renames or copies files.
`Quilt <http://savannah.nongnu.org/projects/quilt>`__ might be useful if you do
not want to use Git.

Patches should be inline in the email message.  Some email clients corrupt
white space or wrap lines in patches.  There are hints on how to configure many
email clients to avoid this problem on `kernel.org
<https://static.lwn.net/kerneldoc/process/email-clients.html>`__.  If you
cannot convince your email client not to mangle patches, then sending the patch
as an attachment is a second choice.

Follow the style used in the code that you are modifying. :doc:`coding-style`
file describes the coding style used in most of Open vSwitch. Use Linux kernel
coding style for Linux kernel code.

If your code is non-datapath code, you may use the ``utilities/checkpatch.py``
utility as a quick check for certain commonly occurring mistakes (improper
leading/trailing whitespace, missing signoffs, some improper formatted patch
files).  For Linux datapath code, it is a good idea to use the Linux script
``checkpatch.pl``.

Example
-------

::

    From fa29a1c2c17682879e79a21bb0cdd5bbe67fa7c0 Mon Sep 17 00:00:00 2001
    From: Jesse Gross <jesse@nicira.com>
    Date: Thu, 8 Dec 2011 13:17:24 -0800
    Subject: [PATCH] datapath: Alphabetize include/net/ipv6.h compat header.

    Signed-off-by: Jesse Gross <jesse@nicira.com>
    ---
     datapath/linux/Modules.mk |    2 +-
     1 files changed, 1 insertions(+), 1 deletions(-)

    diff --git a/datapath/linux/Modules.mk b/datapath/linux/Modules.mk
    index fdd952e..f6cb88e 100644
    --- a/datapath/linux/Modules.mk
    +++ b/datapath/linux/Modules.mk
    @@ -56,11 +56,11 @@ openvswitch_headers += \
     	linux/compat/include/net/dst.h \
     	linux/compat/include/net/genetlink.h \
     	linux/compat/include/net/ip.h \
    +	linux/compat/include/net/ipv6.h \
     	linux/compat/include/net/net_namespace.h \
     	linux/compat/include/net/netlink.h \
     	linux/compat/include/net/protocol.h \
     	linux/compat/include/net/route.h \
    -	linux/compat/include/net/ipv6.h \
     	linux/compat/genetlink.inc

     both_modules += brcompat
    -- 
    1.7.7.3
