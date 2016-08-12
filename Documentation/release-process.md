Open vSwitch Release Process
============================

This document describes the process ordinarily used for Open vSwitch
development and release.  Exceptions are sometimes necessary, so all
of the statements here should be taken as subject to change through
rough consensus of Open vSwitch contributors, obtained through public
discussion on, e.g., ovs-dev or the #openvswitch IRC channel.

Release Strategy
----------------

Open vSwitch feature development takes place on the "master" branch.
Ordinarily, new features are rebased against master and applied
directly.  For features that take significant development, sometimes
it is more appropriate to merge a separate branch into master; please
discuss this on ovs-dev in advance.

Periodically, the OVS developers fork a branch from master to become
an official release.  These release branches are named for expected
release number, e.g. "branch-2.3" for the branch that will yield Open
vSwitch 2.3.x.  Release branches should receive only bug fixes, not
new features.  Bug fixes applied to release branches should be
backports of corresponding bug fixes to the master branch, except for
bugs present only on release branches (which are rare in practice).

Sometimes there can be exceptions to the rule that a release branch
receives only bug fixes.  In particular, after a release branch is
created, but before the first actual release from that branch, it can
be appropriate to add features.  Like bug fixes, new features on
release branches should be backports of the corresponding commits on
the master branch.  Features to be added to release branches should be
limited in scope and risk and discussed on ovs-dev before creating the
branch.

After a period of testing and stabilization, and rough consensus
obtained from contributors that the release is ready, the developers
release the .0 release on its branch, e.g. 2.3.0 for branch-2.3.  To
make the actual release, a developer pushes a signed tag named,
e.g. v2.3.0, to the Open vSwitch repository, makes a release tarball
available on openvswitch.org, and posts a release announcement to
ovs-announce.

As a number of bug fixes accumulate, or after important bugs or
vulnerabilities are fixed, the OVS developers may make additional
releases from a branch: 2.3.1, 2.3.2, and so on.  The process is the
same for these additional release as for a .0 release.

At most two release branches are formally maintained at any given
time: the latest release and the latest release designed as LTS.  An
LTS release is one that the OVS project has designated as being
maintained for a longer period of time.  Currently, an LTS release is
maintained until the next LTS is chosen.  There is not currently a
strict guideline on how often a new LTS release is chosen, but so far
it has been about every 2 years.  That could change based on the
current state of OVS development.  For example, we do not want to
designate a new release as LTS that includes disruptive internal
changes, as that may make it harder to support for a longer period of
time.  Discussion about choosing the next LTS release occurs on the
OVS development mailing list.

Release Numbering
-----------------

The version number on master should normally end in .90.  This
indicates that the Open vSwitch version is "almost" the next version
to branch.

Forking master into branch-x.y requires two commits to master.  The
first is titled "Prepare for x.y.0" and increments the version number
to x.y.  This is the initial commit on branch-x.y.  The second is
titled "Prepare for post-x.y.0 (x.y.90)" and increments the version
number to x.y.90.

The version number on a release branch is x.y.z, where z is initially
0.  Making a release requires two commits.  The first is titled "Set
release dates for x.y.z." and updates NEWS and debian/changelog to
specify the release date of the new release.  This commit is the one
made into a tarball and tagged.  The second is titled "Prepare for
x.y.(z+1)." and increments the version number and adds a blank item to
NEWS with an unspecified date.

Release Scheduling
------------------

Open vSwitch makes releases at the following six-month cadence, which
of course is subject to change.

| Time (months) | Approximate Dates | Event                                |
|---------------|-------------------|--------------------------------------|
| T             | Apr 1, Oct 1      | Release cycle for version x.y begins |
| T + 4         | Aug 1, Feb 1      | branch-x.y forks from master         |
| T + 5.5       | Sep 15, Mar 15    | branch-x.y released as version x.y.0 |

Contact
-------

Please use dev@openvswitch.org to discuss the Open vSwitch development
and release process.
