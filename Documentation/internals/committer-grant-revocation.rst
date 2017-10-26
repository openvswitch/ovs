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

=====================================
OVS Committer Grant/Revocation Policy
=====================================

An OVS committer is a participant in the project with the ability to commit
code directly to the master repository. Commit access grants a broad ability to
affect the progress of the project as presented by its most important artifact,
the code and related resources that produce working binaries of Open vSwitch.
As such it represents a significant level of trust in an individual's
commitment to working with other committers and the community at large for the
benefit of the project. It can not be granted lightly and, in the worst case,
must be revocable if the trust placed in an individual was inappropriate.

This document suggests guidelines for granting and revoking commit access. It
is intended to provide a framework for evaluation of such decisions without
specifying deterministic rules that wouldn't be sensitive to the nuance of
specific situations. In the end the decision to grant or revoke committer
privileges is a judgment call made by the existing set of committers.

Granting Commit Access
----------------------

Granting commit access should be considered when a candidate has demonstrated
the following in their interaction with the project:

- Contribution of significant new features through the patch submission
  process where:

  - Submissions are free of obvious critical defects
  - Submissions do not typically require many iterations of improvement
    to be accepted

- Consistent participation in code review of other's patches, including
  existing committers, with comments consistent with the overall project
  standards

- Assistance to those in the community who are less knowledgeable through
  active participation in project forums such as the ovs-discuss mailing list.

- Plans for sustained contribution to the project compatible with the project's
  direction as viewed by current committers.

- Commitment to meet the expectations described in the "Expectations of
  Developer's with Open vSwitch Access"

The process to grant commit access to a candidate is simple:

- An existing committer nominates the candidate by sending an email to all
  existing committers with information substantiating the contributions of the
  candidate in the areas described above.

- All existing committers discuss the pros and cons of granting commit
  access to the candidate in the email thread.

- When the discussion has converged or a reasonable time has elapsed without
  discussion developing (e.g. a few business days) the nominator calls for a
  final decision on the candidate with a followup email to the thread.

- Each committer may vote yes, no, or abstain by replying to the email thread.
  A failure to reply is an implicit abstention.

- After votes from all existing committers have been collected or a reasonable
  time has elapsed for them to be provided (e.g. a couple of business days) the
  votes are evaluated. To be granted commit access the candidate must receive
  yes votes from a majority of the existing committers and zero no votes. Since
  a no vote is effectively a veto of the candidate it should be accompanied by
  a reason for the vote.

- The nominator summarizes the result of the vote in an email to all existing
  committers.

- If the vote to grant commit access passed, the candidate is contacted with an
  invitation to become a committer to the project which asks them to agree to
  the committer expectations documented on the project web site.

- If the candidate agrees access is granted by setting up commit access to the
  repos on github.

Revoking Commit Access
----------------------

When a committer behaves in a manner that other committers view as detrimental
to the future of the project, it raises a delicate situation with the potential
for the creation of division within the greater community.  These situations
should be handled with care.  The process in this case is:

- Discuss the behavior of concern with the individual privately and explain why
  you believe it is detrimental to the project. Stick to the facts and keep the
  email professional. Avoid personal attacks and the temptation to hypothesize
  about unknowable information such as the other's motivations. Make it clear
  that you would prefer not to discuss the behavior more widely but will have
  to raise it with other contributors if it does not change. Ideally the
  behavior is eliminated and no further action is required. If not,

- Start an email thread with all committers, including the source of the
  behavior, describing the behavior and the reason it is detrimental to the
  project. The message should have the same tone as the private discussion and
  should generally repeat the same points covered in that discussion. The
  person whose behavior is being questioned should not be surprised by anything
  presented in this discussion. Ideally the wider discussion provides more
  perspective to all participants and the issue is resolved. If not,

- Start an email thread with all committers except the source of the
  detrimental behavior requesting a vote on revocation of commit
  rights. Cite the discussion among all committers and describe all the
  reasons why it was not resolved satisfactorily. This email should be
  carefully written with the knowledge that the reasoning it contains
  may be published to the larger community to justify the decision.

- Each committer may vote yes, no, or abstain by replying to the email
  thread. A failure to reply is an implicit abstention.

- After all votes have been collected or a reasonable time has elapsed
  for them to be provided (e.g. a couple of business days) the votes
  are evaluated. For the request to revoke commit access for the
  candidate to pass it must receive yes votes from two thirds of the
  existing committers.

- anyone that votes no must provide their reasoning, and

- if the proposal passes then counter-arguments for the reasoning in no
  votes should also be documented along with the initial reasons the
  revocation was proposed. Ideally there should be no new
  counter-arguments supplied in a no vote as all concerns should have
  surfaced in the discussion before the vote.

- The original person to propose revocation summarizes the result of
  the vote in an email to all existing committers excepting the
  candidate for removal.

- If the vote to revoke commit access passes, access is removed and the
  candidate for revocation is informed of that fact and the reasons for
  it as documented in the email requesting the revocation vote.

- Ideally the revoked committer peacefully leaves the community and no
  further action is required. However, there is a distinct possibility
  that he/she will try to generate support for his/her point of view
  within the larger community. In this case the reasoning for removing
  commit access as described in the request for a vote will be
  published to the community.

Changing the Policy
-------------------

The process for changing the policy is:

- Propose the changes to the policy in an email to all current committers and
  request discussion.

- After an appropriate period of discussion (a few days) update the proposal
  based on feedback if required and resend it to all current committers with a
  request for a formal vote.

- After all votes have been collected or a reasonable time has elapsed for them
  to be provided (e.g. a couple of business days) the votes are evaluated. For
  the request to modify the policy to pass it must receive yes votes from two
  thirds of the existing committers.

Template Emails
===============

Nomination to Grant Commit Access
---------------------------------

    I would like to nominate *[candidate]* for commit access. I believe
    *[he/she]* has met the conditions for commit access described in the
    committer grant policy on the project web site in the following ways:

    *[list of requirements & evidence]*

    Please reply to all in this message thread with your comments and
    questions. If that discussion concludes favorably I will request a formal
    vote on the nomination in a few days.

Vote to Grant Commit Access
---------------------------

    I nominated *[candidate]* for commit access on *[date]*. Having allowed
    sufficient time for discussion it's now time to formally vote on the
    proposal.

    Please reply to all in this thread with your vote of: YES, NO, or ABSTAIN.
    A failure to reply will be counted as an abstention. If you vote NO, by our
    policy you must include the reasons for that vote in your reply. The
    deadline for votes is *[date and time]*.

    If a majority of committers vote YES and there are zero NO votes commit
    access will be granted.

Vote Results for Grant of Commit Access
---------------------------------------

    The voting period for granting to commit access to *[candidate]* initiated
    at *[date and time]* is now closed with the following results:

    YES: *[count of yes votes]* (*[% of voters]*)

    NO: *[count of no votes]* (*[% of voters]*)

    ABSTAIN: *[count of abstentions]* (*[% of voters]*)

    Based on these results commit access *[is/is NOT]* granted.

Invitation to Accepted Committer
--------------------------------

    Due to your sustained contributions to the Open vSwitch (OVS) project we
    would like to provide you with commit access to the project repository.
    Developers with commit access must agree to fulfill specific
    responsibilities described in the source repository:

        /Documentation/internals/committer-responsibilities.rst

    Please let us know if you would like to accept commit access and if so that
    you agree to fulfill these responsibilities. Once we receive your response
    we'll set up access. We're looking forward continuing to work together to
    advance the Open vSwitch project.

Proposal to Revoke Commit Access for Detrimental Behavior
---------------------------------------------------------

    I regret that I feel compelled to propose revocation of commit access for
    *[candidate]*. I have privately discussed with *[him/her]* the following
    reasons I believe *[his/her]* actions are detrimental to the project and we
    have failed to come to a mutual understanding:

    *[List of reasons and supporting evidence]*

    Please reply to all in this thread with your thoughts on this proposal.  I
    plan to formally propose a vote on the proposal on or after *[date and
    time]*.

    It is important to get all discussion points both for and against the
    proposal on the table during the discussion period prior to the vote.
    Please make it a high priority to respond to this proposal with your
    thoughts.

Vote to Revoke Commit Access
----------------------------

    I nominated *[candidate]* for revocation of commit access on *[date]*.
    Having allowed sufficient time for discussion it's now time to formally
    vote on the proposal.

    Please reply to all in this thread with your vote of: YES, NO, or ABSTAIN.
    A failure to reply will be counted as an abstention. If you vote NO, by our
    policy you must include the reasons for that vote in your reply. The
    deadline for votes is *[date and time]*.

    If 2/3rds of committers vote YES commit access will be revoked.

    The following reasons for revocation have been given in the original
    proposal or during discussion:

    *[list of reasons to remove access]*

    The following reasons for retaining access were discussed:

    *[list of reasons to retain access]*

    The counter-argument for each reason for retaining access is:

    *[list of counter-arguments for retaining access]*

Vote Results for Revocation of Commit Access
--------------------------------------------

    The voting period for revoking the commit access of *[candidate]* initiated
    at *[date and time]* is now closed with the following results:

    -  YES: *[count of yes votes]* (*[% of voters]*)

    -  NO: *[count of no votes]* (*[% of voters]*)

    -  ABSTAIN: *[count of abstentions]* (*[% of voters]*)

    Based on these results commit access *[is/is NOT]* revoked. The following
    reasons for retaining commit access were proposed in NO votes:

    *[list of reasons]*

    The counter-arguments for each of these reasons are:

    *[list of counter-arguments]*

Notification of Commit Revocation for Detrimental Behavior
----------------------------------------------------------

    After private discussion with you and careful consideration of the
    situation, the other committers to the Open vSwitch (OVS) project have
    concluded that it is in the best interest of the project that your commit
    access to the project repositories be revoked and this has now occurred.

    The reasons for this decision are:

    *[list of reasons for removing access]*

    While your goals and those of the project no longer appear to be aligned we
    greatly appreciate all the work you have done for the project and wish you
    continued success in your future work.
