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

===============
Release Process
===============

This document describes the process ordinarily used for Open vSwitch
development and release.  Exceptions are sometimes necessary, so all of the
statements here should be taken as subject to change through rough consensus of
Open vSwitch contributors, obtained through public discussion on, e.g., ovs-dev
or the #openvswitch IRC channel.

Release Strategy
----------------

Open vSwitch feature development takes place on the "master" branch.
Ordinarily, new features are rebased against master and applied directly.  For
features that take significant development, sometimes it is more appropriate to
merge a separate branch into master; please discuss this on ovs-dev in advance.

The process of making a release has the following stages.  See `Release
Scheduling`_ for the timing of each stage:

1. "Soft freeze" of the master branch.

   During the freeze, we ask committers to refrain from applying patches that
   add new features unless those patches were already being publicly discussed
   and reviewed before the freeze began.  Bug fixes are welcome at any time.
   Please propose and discuss exceptions on ovs-dev.
 
2. Fork a release branch from master, named for the expected release number,
   e.g. "branch-2.3" for the branch that will yield Open vSwitch 2.3.x.

   Release branches are intended for testing and stabilization.  At this stage
   and in later stages, they should receive only bug fixes, not new features.
   Bug fixes applied to release branches should be backports of corresponding
   bug fixes to the master branch, except for bugs present only on release
   branches (which are rare in practice).

   At this stage, sometimes there can be exceptions to the rule that a release
   branch receives only bug fixes.  Like bug fixes, new features on release
   branches should be backports of the corresponding commits on the master
   branch.  Features to be added to release branches should be limited in scope
   and risk and discussed on ovs-dev before creating the branch.

3. When committers come to rough consensus that the release is ready, they
   release the .0 release on its branch, e.g. 2.3.0 for branch-2.3.  To make
   the actual release, a committer pushes a signed tag named, e.g. v2.3.0, to
   the Open vSwitch repository, makes a release tarball available on
   openvswitch.org, and posts a release announcement to ovs-announce.

4. As bug fixes accumulate, or after important bugs or vulnerabilities are
   fixed, committers may make additional releases from a branch: 2.3.1, 2.3.2,
   and so on.  The process is the same for these additional release as for a .0
   release.

At most three release branches are formally maintained at any given time: the
latest release, the latest release designed as LTS and a previous LTS release
during the transition period.  An LTS release is one that the OVS project has
designated as being maintained for a longer period of time.
Currently, an LTS release is maintained until the next major release after the
new LTS is chosen.  This one release time frame is a transition period which is
intended for users to upgrade from old LTS to new one.

New LTS release is chosen every 2 years.  The process is that current latest
stable release becomes an LTS release at the same time the next major release
is out.  That could change based on the current state of OVS development.  For
example, we do not want to designate a new release as LTS that includes
disruptive internal changes, as that may make it harder to support for a longer
period of time.  Discussion about skipping designation of the next LTS release
occurs on the OVS development mailing list.

LTS designation schedule example (depends on current state of development):

+---------+--------------+--------------------------------------------------+
| Version | Release Date | Actions                                          |
+---------+--------------+--------------------------------------------------+
| 2.14    | Aug 2020     | 2.14 - new latest stable, 2.13 stable ⟶ new LTS  |
+---------+--------------+--------------------------------------------------+
| 2.15    | Feb 2021     | 2.12 - new latest stable, 2.5  LTS ⟶ EOL         |
+---------+--------------+--------------------------------------------------+
| 2.16    | Aug 2021     | 2.16 - new latest stable                         |
+---------+--------------+--------------------------------------------------+
| 2.17    | Feb 2022     | 2.17 - new latest stable                         |
+---------+--------------+--------------------------------------------------+
| 2.18    | Aug 2022     | 2.18 - new latest stable, 2.17 stable ⟶ new LTS  |
+---------+--------------+--------------------------------------------------+
| 2.19    | Feb 2023     | 2.19 - new latest stable, 2.13 LTS ⟶ EOL         |
+---------+--------------+--------------------------------------------------+

While branches other than LTS and the latest release are not formally
maintained, the OVS project usually provides stable releases for these branches
for at least 2 years, i.e. stable releases are provided for the last 4
release branches.  However, these branches may not include all the fixes that
LTS has in case backporting is not straightforward and developers are not
willing to spend their time on that (this mostly affects branches that are
older than the LTS, because backporting to LTS implies backporting to all
intermediate branches).

Release Numbering
-----------------

The version number on master should normally end in .90.  This indicates that
the Open vSwitch version is "almost" the next version to branch.

Forking master into branch-x.y requires two commits to master.  The first is
titled "Prepare for x.y.0" and increments the version number to x.y.  This is
the initial commit on branch-x.y.  The second is titled "Prepare for post-x.y.0
(x.y.90)" and increments the version number to x.y.90.

The version number on a release branch is x.y.z, where z is initially 0.
Making a release requires two commits.  The first is titled *Set release dates
for x.y.z.* and updates NEWS and debian/changelog to specify the release date
of the new release.  This commit is the one made into a tarball and tagged.
The second is titled *Prepare for x.y.(z+1).* and increments the version number
and adds a blank item to NEWS with an unspecified date.

Release Scheduling
------------------

Open vSwitch makes releases at the following six-month cadence.  All dates are
approximate:

+---------------+----------------+--------------------------------------+
| Time (months) | Dates          | Stage                                |
+---------------+----------------+--------------------------------------+
| T             | Mar 1, Sep 1   | Begin x.y release cycle              |
+---------------+----------------+--------------------------------------+
| T + 4         | Jul 1, Jan 1   | "Soft freeze" master for x.y release |
+---------------+----------------+--------------------------------------+
| T + 4.5       | Jul 15, Jan 15 | Fork branch-x.y from master          |
+---------------+----------------+--------------------------------------+
| T + 5.5       | Aug 15, Feb 15 | Release version x.y.0                |
+---------------+----------------+--------------------------------------+

How to Branch
-------------

To branch "master" for the eventual release of OVS version x.y.0,
prepare two patches against master:

1. "Prepare for x.y.0." following the model of commit 836d1973c56e
   ("Prepare for 2.11.0.").

2. "Prepare for post-x.y.0 (x.y.90)." following the model of commit
   fe2870c574db ("Prepare for post-2.11.0 (2.11.90).")

Post both patches to ovs-dev.  Get them reviewed in the usual way.

Apply both patches to master, and create branch-x.y by pushing only
the first patch.  The following command illustrates how to do both of
these at once assuming the local repository HEAD points to the
"Prepare for post-x.y.0" commit:

        git push origin HEAD:master HEAD^:refs/heads/branch-x.y

Branching should be announced on ovs-dev.

How to Release
--------------

Follow these steps to release version x.y.z of OVS from branch-x.y.

1. Prepare two patches against branch-x.y:

   a. "Set release date for x.y.z".  For z = 0, follow the model of
      commit d11f4cbbfe05 ("Set release date for 2.12.0."); for z > 0,
      follow the model of commit 53d5c18118b0 ("Set release date for
      2.11.3.").

   b. "Prepare for x.y.(z+1)." following the model of commit
      db02dd23e48a ("Prepare for 2.11.1.").

3. Post the patches to ovs-dev.  Get them reviewed in the usual way.

4. Apply the patches to branch-x.y.

5. If z = 0, apply the first patch (only) to master.

6. Sign a tag vx.y.z "Open vSwitch version x.y.z" and push it to the
   repo.

7. Update http://www.openvswitch.org/download/.  See commit
   31eaa72cafac ("Add 2.12.0 and older release announcements.") in the
   website repo (https://github.com/openvswitch/openvswitch.github.io)
   for an example.

8. Consider updating the Wikipedia page for Open vSwitch at
   https://en.wikipedia.org/wiki/Open_vSwitch

9. Tweet.

Contact
-------

Use dev@openvswitch.org to discuss the Open vSwitch development and release
process.
