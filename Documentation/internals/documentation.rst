..
      Copyright (c) 2017 Stephen Finucane <stephen@that.guru>

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

======================================
How Open vSwitch's Documentation Works
======================================

This document provides a brief overview on how the documentation build system
within Open vSwitch works. This is intended to maximize the "bus factor" and
share best practices with other projects.

reStructuredText and Sphinx
---------------------------

Nearly all of Open vSwitch's documentation is written in `reStructuredText`__,
with man pages being the sole exception. Of this documentation, most of it is
fed into `Sphinx`__, which provides not only the ability to convert rST to a
variety of other output formats but also allows for things like
cross-referencing and indexing. for more information on the two, refer to the
:doc:`contributing/documentation-style`.

ovs-sphinx-theme
----------------

The documentation uses its own theme, `ovs-sphinx-theme`, which can be found on
GitHub__ and is published on pypi__. This is packaged separately from Open
vSwitch itself to ensure all documentation gets the latest version of the theme
(assuming there are no major version bumps in that package). If building
locally and the package is installed, it will be used. If the package is not
installed, Sphinx will fallback to the default theme.

The package is currently maintained by Stephen Finucane and Russell Bryant.

Read the Docs
-------------

The documentation is hosted on readthedocs.org and a CNAME redirect is in place
to allow access from docs.openvswitch.org. *Read the Docs* provides a couple of
nifty features for us, such as automatic building of docs whenever there are
changes and versioning of documentation.

The *Read the Docs* project is currently maintained by Stephen Finucane,
Russell Bryant and Ben Pfaff.

openvswitch.org
---------------

The sources for openvswitch.org are maintained separately from
docs.openvswitch.org. For modifications to this site, refer to the `GitHub
project`__.

__ http://docutils.sourceforge.net/rst.html
__ http://www.sphinx-doc.org/
__ https://github.com/openvswitch/ovs-sphinx-theme
__ https://pypi.python.org/pypi/ovs-sphinx-theme
__ https://github.com/openvswitch/openvswitch.github.io
