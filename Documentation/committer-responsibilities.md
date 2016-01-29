Expectations for Developers with Open vSwitch Repo Access
=========================================================

Prerequisites
-------------

Be familiar with [CodingStyle.md](../CodingStyle.md) and
[CONTRIBUTING.md](../CONTRIBUTING.md).

Review
------

Code (yours or others') must be reviewed publicly (by you or others)
before you push it to the repository. With one exception (see below),
every change needs at least one review.

If one or more people know an area of code particularly well, code
that affects that area should ordinarily get a review from one of
them.

The riskier, more subtle, or more complicated the change, the more
careful the review required. When a change needs careful review, use
good judgment regarding the quality of reviews. If a change adds 1000
lines of new code, and a review posted 5 minutes later says just
"Looks good," then this is probably not a quality review.

(The size of a change is correlated with the amount of care needed in
review, but it is not strictly tied to it. A search and replace
across many files may not need much review, but one-line optimization
changes can have widespread implications.)

Your own small changes to fix a recently broken build ("make") or
tests ("make check"), that you believe to be visible to a large number
of developers, may be checked in without review. If you are not sure,
ask for review. If you do push a build fix without review, send the
patch to ovs-dev afterward as usual, indicating in the email that you
have already pushed it.

Regularly review submitted code in areas where you have expertise.
Consider reviewing other code as well.

Git conventions
---------------

Do not push merge commits to the Git repository without prior
discussion on ovs-dev.

If you apply a change (yours or another's) then it is your
responsibility to handle any resulting problems, especially broken
builds and other regressions. If it is someone else's change, then
you can ask the original submitter to address it. Regardless, you
need to ensure that the problem is fixed in a timely way. The
definition of "timely" depends on the severity of the problem.

If a bug is present on master and other branches, fix it on master
first, then backport the fix to other branches. Straightforward
backports do not require additional review (beyond that for the fix on
master).

Feature development should be done only on master. Occasionally it
makes sense to add a feature to the most recent release branch, before
the first actual release of that branch. These should be handled in
the same way as bug fixes, that is, first implemented on master and
then backported.

Keep the authorship of a commit clear by maintaining a correct list of
"Signed-off-by:"s. If a confusing situation comes up, as it
occasionally does, bring it up on the mailing list. If you explain
the use of "Signed-off-by:" to a new developer, explain not just how but
why, since the intended meaning of "Signed-off-by:" is more important
than the syntax. As part of your explanation, quote or provide a URL
to the Developer's Certificate of Origin in
[CONTRIBUTING.md](../CONTRIBUTING.md).

Use Reported-by: and Tested-by: tags in commit messages to indicate
the source of a bug report.

Keep the [AUTHORS](../AUTHORS) file up to date.
