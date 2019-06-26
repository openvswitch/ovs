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

===========
Development
===========

Q: How do I implement a new OpenFlow message?

    A: Add your new message to ``enum ofpraw`` and ``enum ofptype`` in
    ``include/openvswitch/ofp-msgs.h``, following the existing pattern.
    Then recompile and fix all of the new warnings, implementing new functionality
    for the new message as needed.  (If you configure with ``--enable-Werror``, as
    described in :doc:`/intro/install/general`, then it is impossible to miss any
    warnings.)

    To add an OpenFlow vendor extension message (aka experimenter message) for
    a vendor that doesn't yet have any extension messages, you will also need
    to edit ``build-aux/extract-ofp-msgs`` and at least ``ofphdrs_decode()``
    and ``ofpraw_put__()`` in ``lib/ofp-msgs.c``.  OpenFlow doesn't standardize
    vendor extensions very well, so it's hard to make the process simpler than
    that.  (If you have a choice of how to design your vendor extension
    messages, it will be easier if you make them resemble the ONF and OVS
    extension messages.)

Q: How do I add support for a new field or header?

    A: Add new members for your field to ``struct flow`` in
    ``include/openvswitch/flow.h``, and add new enumerations for your new field
    to ``enum mf_field_id`` in ``include/openvswitch/meta-flow.h``, following
    the existing pattern.  If the field uses a new OXM class, add it to
    OXM_CLASSES in ``build-aux/extract-ofp-fields``.  Also, add support to
    ``miniflow_extract()`` in ``lib/flow.c`` for extracting your new field from
    a packet into struct miniflow, and to ``nx_put_raw()`` in
    ``lib/nx-match.c`` to output your new field in OXM matches.  Then recompile
    and fix all of the new warnings, implementing new functionality for the new
    field or header as needed.  (If you configure with ``--enable-Werror``, as
    described in :doc:`/intro/install/general`, then it is impossible to miss
    any warnings.)

    If you want kernel datapath support for your new field, you also need to
    modify the kernel module for the operating systems you are interested in.
    This isn't mandatory, since fields understood only by userspace work too
    (with a performance penalty), so it's reasonable to start development
    without it.  If you implement kernel module support for Linux, then the
    Linux kernel "netdev" mailing list is the place to submit that support
    first; please read up on the Linux kernel development process separately.
    The Windows datapath kernel module support, on the other hand, is
    maintained within the OVS tree, so patches for that can go directly to
    ovs-dev.

Q: How do I add support for a new OpenFlow action?

    A: Add your new action to ``enum ofp_raw_action_type`` in
    ``lib/ofp-actions.c``, following the existing pattern.  Then recompile and
    fix all of the new warnings, implementing new functionality for the new
    action as needed.  (If you configure with ``--enable-Werror``, as described
    in the :doc:`/intro/install/general`, then it is impossible to miss any
    warnings.)

    If you need to add an OpenFlow vendor extension action for a vendor that
    doesn't yet have any extension actions, then you will also need to add the
    vendor to ``vendor_map`` in ``build-aux/extract-ofp-actions``.  Also, you
    will need to add support for the vendor to ``ofpact_decode_raw()`` and
    ``ofpact_put_raw()`` in ``lib/ofp-actions.c``.  (If you have a choice of
    how to design your vendor extension actions, it will be easier if you make
    them resemble the ONF and OVS extension actions.)

Q: How do I add support for a new OpenFlow error message?

    A: Add your new error to ``enum ofperr`` in
    ``include/openvswitch/ofp-errors.h``.  Read the large comment at the top of
    the file for details.  If you need to add an OpenFlow vendor extension
    error for a vendor that doesn't yet have any, first add the vendor ID to
    the ``<name>_VENDOR_ID`` list in ``include/openflow/openflow-common.h``.

Q: What's a Signed-off-by and how do I provide one?

    A: Free and open source software projects usually require a contributor to
    provide some assurance that they're entitled to contribute the code that
    they provide.  Some projects, for example, do this with a Contributor
    License Agreement (CLA) or a copyright assignment that is signed on paper
    or electronically.

    For this purpose, Open vSwitch has adopted something called the Developer's
    Certificate of Origin (DCO), which is also used by the Linux kernel and
    originated there.  Informally stated, agreeing to the DCO is the
    developer's way of attesting that a particular commit that they are
    contributing is one that they are allowed to contribute.  You should visit
    https://developercertificate.org/ to read the full statement of the DCO,
    which is less than 200 words long.

    To certify compliance with the Developer's Certificate of Origin for a
    particular commit, just add the following line to the end of your commit
    message, properly substituting your name and email address:

        Signed-off-by: Firstname Lastname <email@example.org>

    Git has special support for adding a Signed-off-by line to a commit
    message: when you run "git commit", just add the -s option, as in "git
    commit -s".  If you use the "git citool" GUI for commits, you can add a
    Signed-off-by line to the commit message by pressing Control+S.  Other Git
    user interfaces may provide similar support.

Q: How do I apply patches from email?

   A: You can use ``git am`` on raw email contents, either from a file saved by
   or piped from an email client.  In ``mutt``, for example, when you are
   viewing a patch, you can apply it to the tree in ~/ovs by issuing the
   command ``|cd ~/ovs && git am``.  If you are an OVS committer, you might
   want to add ``-s`` to sign off on the patch as part of applying it.  If you
   do this often, then you can make the keystrokes ``,a`` shorthand for it by
   adding the following line to your ``.muttrc``:

     macro index,pager ,a "<pipe-message>cd ~/ovs && git am -s" "apply patch"

   ``git am`` has a problem with some email messages from the ovs-dev list for
   which the mailing list manager edits the From: address, replacing it by the
   list's own address.  The mailing list manager must do this for messages
   whose sender's email domain has DMARC configured, because receivers will
   otherwise discard these messages when they do not come directly from the
   sender's email domain.  This editing makes the patches look like they come
   from the mailing list instead of the author.  To work around this problem,
   one can use the following wrapper script for ``git am``::

     #! /bin/sh
     tmp=$(mktemp)
     cat >$tmp
     if grep '^From:.*via dev.*' "$tmp" >/dev/null 2>&1; then
        sed '/^From:.*via dev.*/d
             s/^[Rr]eply-[tT]o:/From:/' $tmp
     else
        cat "$tmp"
     fi | git am "$@"
     rm "$tmp"

   Another way to apply emailed patches is to use the ``pwclient`` program,
   which can obtain patches from patchwork and apply them directly.  Download
   ``pwclient`` at https://patchwork.ozlabs.org/project/openvswitch/.  You
   probably want to set up a ``.pwclientrc`` that looks something like this::

     [options]
     default=openvswitch
     signoff=true

     [openvswitch]
     url=https://patchwork.ozlabs.org/xmlrpc/

   After you install ``pwclient``, you can apply a patch from patchwork with
   ``pwclient git-am #``, where # is the patch's number.  (This fails with
   certain patches that contain form-feeds, due to a limitation of the protocol
   underlying ``pwclient``.)

   Another way to apply patches directly from patchwork which supports applying
   patch series is to use the ``git-pw`` program. It can be obtained with
   ``pip install git-pw``. Alternative installation instructions and general
   documentation can be found at
   https://patchwork.readthedocs.io/projects/git-pw/en/latest/. You need to
   use your openvswitch patchwork login or create one at
   https://patchwork.ozlabs.org/register/. The following can then be set on
   the command line with ``git config`` or through a ``.gitconfig`` like this::

     [pw]
     server=https://patchwork.ozlabs.org/api/1.0
     project=openvswitch
     username=<username>
     password=<password>

   Patch series can be listed with ``git-pw series list`` and applied with
   ``git-pw series apply #``, where # is the series number. Individual patches
   can be applied with ``git-pw patch apply #``, where # is the patch number.
