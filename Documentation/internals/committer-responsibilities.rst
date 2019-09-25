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

=========================================================
Expectations for Developers with Open vSwitch Repo Access
=========================================================

Pre-requisites
--------------

Be familiar with the guidelines and standards defined in
:doc:`contributing/index`.

Review
------

Code (yours or others') must be reviewed publicly (by you or others) before you
push it to the repository. With one exception (see below), every change needs
at least one review.

If one or more people know an area of code particularly well, code that affects
that area should ordinarily get a review from one of them.

The riskier, more subtle, or more complicated the change, the more careful the
review required. When a change needs careful review, use good judgment
regarding the quality of reviews. If a change adds 1000 lines of new code, and
a review posted 5 minutes later says just "Looks good," then this is probably
not a quality review.

(The size of a change is correlated with the amount of care needed in review,
but it is not strictly tied to it. A search and replace across many files may
not need much review, but one-line optimization changes can have widespread
implications.)

Your own small changes to fix a recently broken build ("make") or tests ("make
check"), that you believe to be visible to a large number of developers, may be
checked in without review. If you are not sure, ask for review. If you do push
a build fix without review, send the patch to ovs-dev afterward as usual,
indicating in the email that you have already pushed it.

Regularly review submitted code in areas where you have expertise. Consider
reviewing other code as well.

Git conventions
---------------

Do not push merge commits to the Git repository without prior discussion on
ovs-dev.

If you apply a change (yours or another's) then it is your responsibility to
handle any resulting problems, especially broken builds and other regressions.
If it is someone else's change, then you can ask the original submitter to
address it. Regardless, you need to ensure that the problem is fixed in a
timely way. The definition of "timely" depends on the severity of the problem.

If a bug is present on master and other branches, fix it on master first, then
backport the fix to other branches. Straightforward backports do not require
additional review (beyond that for the fix on master).

Feature development should be done only on master. Occasionally it makes sense
to add a feature to the most recent release branch, before the first actual
release of that branch. These should be handled in the same way as bug fixes,
that is, first implemented on master and then backported.

Keep the authorship of a commit clear by maintaining a correct list of
"Signed-off-by:"s. If a confusing situation comes up, as it occasionally does,
bring it up on the mailing list. If you explain the use of "Signed-off-by:" to
a new developer, explain not just how but why, since the intended meaning of
"Signed-off-by:" is more important than the syntax. As part of your
explanation, quote or provide a URL to the Developer's Certificate of Origin in
:doc:`contributing/submitting-patches`.

Use Reported-by: and Tested-by: tags in commit messages to indicate the
source of a bug report.

Keep the ``AUTHORS.rst`` file up to date.

Pre-Push Hook
-------------

The following script can be helpful because it provides an extra
chance to check for mistakes while pushing to the master branch of OVS
or OVN.  If you would like to use it, install it as ``hooks/pre-push``
in your ``.git`` directory and make sure to mark it as executable with
``chmod +x``.  For maximum utility, make sure ``checkpatch.py`` is in
``$PATH``:

.. code-block:: bash

  #! /bin/bash

  remote=$1

  case $remote in
      ovs|ovn|origin) ;;
      *) exit 0 ;;
  esac

  while read local_ref local_sha1 remote_ref remote_sha1; do
      case $remote_ref in
          refs/heads/master)
              n=0
              while read sha
              do
                  n=$(expr $n + 1)
                  git log -1 $sha
                  echo
                  checkpatch.py -1 $sha
              done <<EOF
  $(git --no-pager log --pretty=%H $local_sha1...$remote_sha1)
  EOF

              b=${remote_ref#refs/heads/}
              echo "You're about to push $n commits to protected branch $b on $remote."

              read -p "Do you want to proceed? [y|n] " reply < /dev/tty
              if echo $reply | grep -E '^[Yy]$' > /dev/null; then
                  :
              else
                  exit 1
              fi
              ;;
      esac
  done

  exit 0
