Security Process
================

This is a proposed security vulnerability reporting and handling
process for Open vSwitch.  It is based on the OpenStack vulnerability
management process described at
https://wiki.openstack.org/wiki/Vulnerability_Management.

The OVS security team coordinates vulnerability management using the
ovs-security mailing list.  Membership in the security team and
subscription to its mailing list consists of a small number of
trustworthy people, as determined by rough consensus of the Open
vSwitch committers on the ovs-committers mailing list.  The Open
vSwitch security team should include Open vSwitch committers, to
ensure prompt and accurate vulnerability assessments and patch review.

We encourage everyone involved in the security process to GPG-sign
their emails.  We additionally encourage GPG-encrypting one-on-one
conversations as part of the security process.


What is a vulnerability?
------------------------

All vulnerabilities are bugs, but not every bug is a vulnerability.
Vulnerabilities compromise one or more of:

    * Confidentiality (personal or corporate confidential data).
    * Integrity (trustworthiness and correctness).
    * Availability (uptime and service).

Here are some examples of vulnerabilities to which one would expect to
apply this process:

    * A crafted packet that causes a kernel or userspace crash
      (Availability).

    * A flow translation bug that misforwards traffic in a way likely
      to hop over security boundaries (Integrity).

    * An OpenFlow protocol bug that allows a controller to read
      arbitrary files from the file system (Confidentiality).

    * Misuse of the OpenSSL library that allows bypassing certificate
      checks (Integrity).

    * A bug (memory corruption, overflow, ...) that allows one to
      modify the behaviour of OVS through external configuration
      interfaces such as OVSDB (Integrity).

    * Privileged information is exposed to unprivileged users
      (Confidentiality).

If in doubt, please do use the vulnerability management process.  At
worst, the response will be to report the bug through the usual
channels.


Step 1: Reception
-----------------

To report an Open vSwitch vulnerability, send an email to the
ovs-security mailing list (see "Contact" at the end of this document).
A security team member should reply to the reporter acknowledging that
the report has been received.

Please consider reporting the information mentioned in
REPORTING-BUGS.md, where relevant.

Reporters may ask for a GPG key while initiating contact with the
security team to deliver more sensitive reports.

The Linux kernel has its own vulnerability management process:
https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/Documentation/SecurityBugs
Handling of vulnerabilities that affect both the Open vSwitch tree and
the upstream Linux kernel should be reported through both processes.
Please send your report as a single email to both the kernel and OVS
security teams to allow those teams to most easily coordinate among
themselves.


Step 2: Assessment
------------------

The security team should discuss the vulnerability.  The reporter
should be included in the discussion (via "CC") to an appropriate
degree.

The assessment should determine which Open vSwitch versions are
affected (e.g. every version, only the latest release, only unreleased
versions), the privilege required to take advantage of the
vulnerability (e.g. any network user, any local L2 network user, any
local system user, connected OpenFlow controllers), the severity of
the vulnerability, and how the vulnerability may be mitigated (e.g. by
disabling a feature).

The treatment of the vulnerability could end here if the team
determines that it is not a realistic vulnerability.


Step 3a: Document
----------------

The security team develops a security advisory document.  The document
credits the reporter and describes the vulnerability, including all of
the relevant information from the assessment in step 2.  The security
team may, at its discretion, include the reporter (via "CC") in
developing the security advisory document, but in any case should
accept feedback from the reporter before finalizing the document.

When the document is final, the security team should obtain a CVE for
the vulnerability from a CNA (https://cve.mitre.org/cve/cna.html).


Step 3b: Fix
------------

Steps 3a and 3b may proceed in parallel.

The security team develops and obtains (private) reviews for patches
that fix the vulnerability.  If necessary, the security team pulls in
additional developers, who must agree to maintain confidentiality.


Step 4: Embargoed Disclosure
----------------------------

The security advisory and patches are sent to downstream stakeholders,
with an embargo date and time set from the time sent.  Downstream
stakeholders are expected not to deploy or disclose patches until
the embargo is passed.

A disclosure date is negotiated by the security team working with the
bug submitter as well as vendors.  However, the Open vSwitch security
team holds the final say when setting a disclosure date.  The timeframe
for disclosure is from immediate (esp. if it's already publicly known)
to a few weeks.  As a basic default policy, we expect report date to
disclosure date to be 3~5 business days.

Operating system vendors are obvious downstream stakeholders.  It may
not be necessary to be too choosy about who to include: any major Open
vSwitch user who is interested and can be considered trustworthy
enough could be included.  To become a downstream stakeholder, email
the ovs-security mailing list.

If the vulnerability is already public, skip this step.


Step 5: Public Disclosure
-------------------------

When the embargo expires, push the (reviewed) patches to appropriate
branches, post the patches to the ovs-dev mailing list (noting that
they have already been reviewed and applied), post the security
advisory to appropriate mailing lists (ovs-announce, ovs-discuss), and
post the security advisory on the Open vSwitch webpage.

When the patch is applied to LTS (long-term support) branches, a new
version should be released.

The security advisory should be GPG-signed by a security team member
with a key that is in a public web of trust.


Contact
=======

Report security vulnerabilities to the ovs-security mailing list:
security@openvswitch.org

Report problems with this document to the ovs-bugs mailing list:
bugs@openvswitch.org

Visit http://openvswitch.org/ to learn more about Open vSwitch.
