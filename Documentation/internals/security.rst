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

===============================
Open vSwitch's Security Process
===============================

This is a proposed security vulnerability reporting and handling process for
Open vSwitch. It is based on the OpenStack vulnerability management process
described at https://wiki.openstack.org/wiki/Vulnerability\_Management.

The OVS security team coordinates vulnerability management using the
ovs-security mailing list. Membership in the security team and subscription to
its mailing list consists of a small number of trustworthy people, as
determined by rough consensus of the Open vSwitch committers on the
ovs-committers mailing list. The Open vSwitch security team should include Open
vSwitch committers, to ensure prompt and accurate vulnerability assessments and
patch review.

We encourage everyone involved in the security process to GPG-sign their
emails. We additionally encourage GPG-encrypting one-on-one conversations as
part of the security process.

What is a vulnerability?
------------------------

All vulnerabilities are bugs, but not every bug is a vulnerability.
Vulnerabilities compromise one or more of:

* Confidentiality (personal or corporate confidential data).

* Integrity (trustworthiness and correctness).

* Availability (uptime and service).

Here are some examples of vulnerabilities to which one would expect to apply
this process:

* A crafted packet that causes a kernel or userspace crash (Availability).

* A flow translation bug that misforwards traffic in a way likely to hop over
  security boundaries (Integrity).

* An OpenFlow protocol bug that allows a controller to read arbitrary files
  from the file system (Confidentiality).

* Misuse of the OpenSSL library that allows bypassing certificate checks
  (Integrity).

* A bug (memory corruption, overflow, ...) that allows one to modify the
  behaviour of OVS through external configuration interfaces such as OVSDB
  (Integrity).

* Privileged information is exposed to unprivileged users (Confidentiality).

If in doubt, please do use the vulnerability management process. At worst, the
response will be to report the bug through the usual channels.

Step 1: Reception
-----------------

To report an Open vSwitch vulnerability, send an email to the ovs-security
mailing list (see contact_ at the end of this document). A security team
member should reply to the reporter acknowledging that the report has been
received.

Consider reporting the information mentioned in :doc:`bugs`, where relevant.

Reporters may ask for a GPG key while initiating contact with the security team
to deliver more sensitive reports.

The Linux kernel has `its own vulnerability management process
<https://static.lwn.net/kerneldoc/admin-guide/security-bugs.html>`__.  Handling
of vulnerabilities that affect both the Open vSwitch tree and the upstream
Linux kernel should be reported through both processes.  Send your report as a
single email to both the kernel and OVS security teams to allow those teams to
most easily coordinate among themselves.

Step 2: Assessment
------------------

The security team should discuss the vulnerability. The reporter should be
included in the discussion (via "CC") to an appropriate degree.

The assessment should determine which Open vSwitch versions are affected (e.g.
every version, only the latest release, only unreleased versions), the
privilege required to take advantage of the vulnerability (e.g. any network
user, any local L2 network user, any local system user, connected OpenFlow
controllers), the severity of the vulnerability, and how the vulnerability may
be mitigated (e.g. by disabling a feature).

The treatment of the vulnerability could end here if the team determines that
it is not a realistic vulnerability.

Step 3a: Document
-----------------

The security team develops a security advisory document. The security team may,
at its discretion, include the reporter (via "CC") in developing the security
advisory document, but in any case should accept feedback from the reporter
before finalizing the document. When the document is final, the security team
should obtain a CVE for the vulnerability from a CNA
(https://cve.mitre.org/cve/cna.html).

The document credits the reporter and describes the vulnerability, including
all of the relevant information from the assessment in step 2.  Suitable
sections for the document include:

::

    * Title: The CVE identifier, a short description of the
      vulnerability.  The title should mention Open vSwitch.

      In email, the title becomes the subject.  Pre-release advisories
      are often passed around in encrypted email, which have plaintext
      subjects, so the title should not be too specific.

    * Description: A few paragraphs describing the general
      characteristics of the vulnerability, including the versions of
      Open vSwitch that are vulnerable, the kind of attack that
      exposes the vulnerability, and potential consequences of the
      attack.

      The description should re-state the CVE identifier, in case the
      subject is lost when an advisory is sent over email.

    * Mitigation: How an Open vSwitch administrator can minimize the
      potential for exploitation of the vulnerability, before applying
      a fix.  If no mitigation is possible or recommended, explain
      why, to reduce the chance that at-risk users believe they are
      not at risk.

    * Fix: Describe how to fix the vulnerability, perhaps in terms of
      applying a source patch.  The patch or patches themselves, if
      included in the email, should be at the very end of the advisory
      to reduce the risk that a reader would stop reading at this
      point.

    * Recommendation: A concise description of the security team's
      recommendation to users.

    * Acknowledgments: Thank the reporters.

    * Vulnerability Check: A step-by-step procedure by which a user
      can determine whether an installed copy of Open vSwitch is
      vulnerable.

      The procedure should clearly describe how to interpret the
      results, including expected results in vulnerable and
      not-vulnerable cases.  Thus, procedures that produce clear and
      easily distinguished results are preferred.

      The procedure should assume as little understanding of Open
      vSwitch as possible, to make it more likely that a competent
      administrator who does not specialize in Open vSwitch can
      perform it successfully.

      The procedure should have minimal dependencies on tools that are
      not widely installed.

      Given a choice, the procedure should be one that takes at least
      some work to turn into a useful exploit.  For example, a
      procedure based on "ovs-appctl" commands, which require local
      administrator access, is preferred to one that sends test
      packets to a machine, which only requires network connectivity.

      The section should say which operating systems it is designed
      for.  If the procedure is likely to be specific to particular
      architectures (e.g. x86-64, i386), it should state on which ones
      it has been tested.

      This section should state the risks of the procedure.  For
      example, if it can crash Open vSwitch or disrupt packet
      forwarding, say so.

      It is more useful to explain how to check an installed and
      running Open vSwitch than one built locally from source, but if
      it is easy to use the procedure from a sandbox environment, it
      can be helpful to explain how to do so.

    * Patch: If a patch or patches are available, and it is practical
      to include them in the email, put them at the end.  Format them
      as described in :doc:`contributing/submitting-patches`, that is, as
      output by "git format-patch".

      The patch subjects should include the version for which they are
      suited, e.g. "[PATCH branch-2.3]" for a patch against Open
      vSwitch 2.3.x.  If there are multiple patches for multiple
      versions of Open vSwitch, put them in separate sections with
      clear titles.

      Multiple patches for a single version of Open vSwitch, that must
      be stacked on top of each other to fix a single vulnerability,
      are undesirable because users are less likely to apply all of
      them correctly and in the correct order.

      Each patch should include a Vulnerability tag with the CVE
      identifier, a Reported-by tag or tags to credit the reporters,
      and a Signed-off-by tag to acknowledge the Developer's
      Certificate of Origin.  It should also include other appropriate
      tags, such as Acked-by tags obtained during review.

`CVE-2016-2074
<https://mail.openvswitch.org/pipermail/ovs-announce/2016-March/000082.html>`__
is an example advisory document.

Step 3b: Fix
------------

Steps 3a and 3b may proceed in parallel.

The security team develops and obtains (private) reviews for patches that fix
the vulnerability. If necessary, the security team pulls in additional
developers, who must agree to maintain confidentiality.

Step 4: Embargoed Disclosure
----------------------------

The security advisory and patches are sent to downstream stakeholders, with an
embargo date and time set from the time sent. Downstream stakeholders are
expected not to deploy or disclose patches until the embargo is passed.

A disclosure date is negotiated by the security team working with the bug
submitter as well as vendors. However, the Open vSwitch security team holds the
final say when setting a disclosure date. The timeframe for disclosure is from
immediate (esp. if it's already publicly known) to a few weeks. As a basic
default policy, we expect report date to disclosure date to be 10 to 15
business days.

Operating system vendors are obvious downstream stakeholders. It may not be
necessary to be too choosy about who to include: any major Open vSwitch user
who is interested and can be considered trustworthy enough could be included.
To become a downstream stakeholder, email the ovs-security mailing list.

If the vulnerability is already public, skip this step.

Step 5: Public Disclosure
-------------------------

When the embargo expires, push the (reviewed) patches to appropriate branches,
post the patches to the ovs-dev mailing list (noting that they have already
been reviewed and applied), post the security advisory to appropriate mailing
lists (ovs-announce, ovs-discuss), and post the security advisory on the Open
vSwitch webpage.

When the patch is applied to LTS (long-term support) branches, a new version
should be released.

The security advisory should be GPG-signed by a security team member with a key
that is in a public web of trust.

.. _contact:

Contact
=======

Report security vulnerabilities to the ovs-security mailing list:
security@openvswitch.org

Report problems with this document to the ovs-bugs mailing list:
bugs@openvswitch.org
