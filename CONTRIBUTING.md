How to Submit Patches for Open vSwitch
======================================

Send changes to Open vSwitch as patches to dev@openvswitch.org.
One patch per email, please.  More details are included below.

If you are using Git, then `git format-patch` takes care of most of
the mechanics described below for you.

Before You Start
----------------

Before you send patches at all, make sure that each patch makes sense.
In particular:

  - A given patch should not break anything, even if later
    patches fix the problems that it causes.  The source tree
    should still build and work after each patch is applied.
    (This enables `git bisect` to work best.)

  - A patch should make one logical change.  Don't make
    multiple, logically unconnected changes to disparate
    subsystems in a single patch.

  - A patch that adds or removes user-visible features should
    also update the appropriate user documentation or manpages.

Testing is also important:

  - A patch that modifies existing code should be tested with
    `make check` before submission.

  - A patch that adds or deletes files should also be tested with
    `make distcheck` before submission.

  - A patch that modifies Linux kernel code should be at least
    build-tested on various Linux kernel versions before
    submission.  I suggest versions 2.6.32 and whatever
    the current latest release version is at the time.

  - A patch that modifies the ofproto or vswitchd code should be
    tested in at least simple cases before submission.

  - A patch that modifies xenserver code should be tested on
    XenServer before submission.

If you are using GitHub, then you may utilize the travis-ci.org CI build
system by linking your GitHub repository to it. This will run some of
the above tests automatically when you push changes to your repository.
See the "Continuous Integration with Travis-CI" in the [INSTALL.md] file
for details on how to set it up.

Email Subject
-------------

The subject line of your email should be in the following format:
`[PATCH <n>/<m>] <area>: <summary>`

  - `[PATCH <n>/<m>]` indicates that this is the nth of a series
    of m patches.  It helps reviewers to read patches in the
    correct order.  You may omit this prefix if you are sending
    only one patch.

  - `<area>:` indicates the area of the Open vSwitch to which the
    change applies (often the name of a source file or a
    directory).  You may omit it if the change crosses multiple
    distinct pieces of code.

  - `<summary>` briefly describes the change.

The subject, minus the `[PATCH <n>/<m>]` prefix, becomes the first line
of the commit's change log message.

Description
-----------

The body of the email should start with a more thorough description of
the change.  This becomes the body of the commit message, following
the subject.  There is no need to duplicate the summary given in the
subject.

Please limit lines in the description to 79 characters in width.

The description should include:

  - The rationale for the change.

  - Design description and rationale (but this might be better
    added as code comments).

  - Testing that you performed (or testing that should be done
    but you could not for whatever reason).

  - Tags (see below).

There is no need to describe what the patch actually changed, if the
reader can see it for himself.

If the patch refers to a commit already in the Open vSwitch
repository, please include both the commit number and the subject of
the patch, e.g. 'commit 632d136c (vswitch: Remove restriction on
datapath names.)'.

If you, the person sending the patch, did not write the patch
yourself, then the very first line of the body should take the form
`From: <author name> <author email>`, followed by a blank line.  This
will automatically cause the named author to be credited with
authorship in the repository.

Tags
----

The description ends with a series of tags, written one to a line as
the last paragraph of the email.  Each tag indicates some property of
the patch in an easily machine-parseable manner.

Examples of common tags follow.

    Signed-off-by: Author Name <author.name@email.address...>

        Informally, this indicates that Author Name is the author or
        submitter of a patch and has the authority to submit it under
        the terms of the license.  The formal meaning is to agree to
        the Developer's Certificate of Origin (see below).

        If the author and submitter are different, each must sign off.
        If the patch has more than one author, all must sign off.

        Signed-off-by: Author Name <author.name@email.address...>
        Signed-off-by: Submitter Name <submitter.name@email.address...>

    Co-authored-by: Author Name <author.name@email.address...>

        Git can only record a single person as the author of a given
        patch.  In the rare event that a patch has multiple authors,
        one must be given the credit in Git and the others must be
        credited via Co-authored-by: tags.  (All co-authors must also
        sign off.)

    Acked-by: Reviewer Name <reviewer.name@email.address...>

        Reviewers will often give an Acked-by: tag to code of which
        they approve.  It is polite for the submitter to add the tag
        before posting the next version of the patch or applying the
        patch to the repository.  Quality reviewing is hard work, so
        this gives a small amount of credit to the reviewer.

        Not all reviewers give Acked-by: tags when they provide
        positive reviews.  It's customary only to add tags from
        reviewers who actually provide them explicitly.

    Tested-by: Tester Name <reviewer.name@email.address...>

        When someone tests a patch, it is customary to add a
        Tested-by: tag indicating that.  It's rare for a tester to
        actually provide the tag; usually the patch submitter makes
        the tag himself in response to an email indicating successful
        testing results.

    Reported-by: Reporter Name <reporter.name@email.address...>

        When a patch fixes a bug reported by some person, please
        credit the reporter in the commit log in this fashion.  Please
        also add the reporter's name and email address to the list of
        people who provided helpful bug reports in the AUTHORS file at
        the top of the source tree.

        Fairly often, the reporter of a bug also tests the fix.
        Occasionally one sees a combined "Reported-and-tested-by:" tag
        used to indicate this.  It is also acceptable, and more
        common, to include both tags separately.

        (If a bug report is received privately, it might not always be
        appropriate to publicly credit the reporter.  If in doubt,
        please ask the reporter.)

    Requested-by: Requester Name <requester.name@email.address...>
    Suggested-by: Suggester Name <suggester.name@email.address...>

        When a patch implements a request or a suggestion made by some
        person, please credit that person in the commit log in this
        fashion.  For a helpful suggestion, please also add the
        person's name and email address to the list of people who
        provided suggestions in the AUTHORS file at the top of the
        source tree.

        (If a suggestion or a request is received privately, it might
        not always be appropriate to publicly give credit.  If in
        doubt, please ask.)

    Reported-at: <URL>

        If a patch fixes or is otherwise related to a bug reported in
        a public bug tracker, please include a reference to the bug in
        the form of a URL to the specific bug, e.g.:

        Reported-at: https://bugs.debian.org/743635

        This is also an appropriate way to refer to bug report emails
        in public email archives, e.g.:

        Reported-at: http://openvswitch.org/pipermail/dev/2014-June/040952.html

    VMware-BZ: #1234567
    ONF-JIRA: EXT-12345

        If a patch fixes or is otherwise related to a bug reported in
        a private bug tracker, you may include some tracking ID for
        the bug for your own reference.  Please include some
        identifier to make the origin clear, e.g. "VMware-BZ" refers
        to VMware's internal Bugzilla instance and "ONF-JIRA" refers
        to the Open Networking Foundation's JIRA bug tracker.

    Bug #1234567.
    Issue: 1234567

        These are obsolete forms of VMware-BZ: that can still be seen
        in old change log entries.  (They are obsolete because they do
        not tell the reader what bug tracker is referred to.)

Developer's Certificate of Origin
---------------------------------

To help track the author of a patch as well as the submission chain,
and be clear that the developer has authority to submit a patch for
inclusion in openvswitch please sign off your work.  The sign off
certifies the following:

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

Comments
--------

If you want to include any comments in your email that should not be
part of the commit's change log message, put them after the
description, separated by a line that contains just `---`.  It may be
helpful to include a diffstat here for changes that touch multiple
files.

Patch
-----

The patch should be in the body of the email following the description,
separated by a blank line.

Patches should be in `diff -up` format.  We recommend that you use Git
to produce your patches, in which case you should use the `-M -C`
options to `git diff` (or other Git tools) if your patch renames or
copies files.  Quilt (http://savannah.nongnu.org/projects/quilt) might
be useful if you do not want to use Git.

Patches should be inline in the email message.  Some email clients
corrupt white space or wrap lines in patches.  There are hints on how
to configure many email clients to avoid this problem at:
        http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=blob_plain;f=Documentation/email-clients.txt
If you cannot convince your email client not to mangle patches, then
sending the patch as an attachment is a second choice.

Please follow the style used in the code that you are modifying.  The
[CodingStyle.md] file describes the coding style used in most of Open
vSwitch. Use Linux kernel coding style for Linux kernel code.

Example
-------

```
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
```

[INSTALL.md]:INSTALL.md
[CodingStyle.md]:CodingStyle.md
