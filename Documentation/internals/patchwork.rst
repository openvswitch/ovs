..
      Copyright (C) 2016, Stephen Finucane <stephen@that.guru>

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

=========
Patchwork
=========

Open vSwitch uses `Patchwork`__ to track the status of patches sent to the
:doc:`ovs-dev mailing list <mailing-lists>`. The Open vSwitch Patchwork
instance can be found on `ozlabs.org`__.

Patchwork provides a number of useful features for developers working on Open
vSwitch:

- Tracking the lifecycle of patches (accepted, rejected, under-review, ...)
- Assigning reviewers (delegates) to patches
- Downloading/applying patches, series, and bundles via the web UI or the REST
  API (see :ref:`git-pw`)
- A usable UI for viewing patch discussions

__ https://github.com/getpatchwork/patchwork
__ https://patchwork.ozlabs.org/project/openvswitch/list/

.. _git-pw:

git-pw
------

The *git-pw* tool provides a way to download and apply patches, series, and
bundles. You can install *git-pw* from `PyPi`__ like so::

    $ pip install --user git-pw

To actually use *git-pw*, you must configure it with the Patchwork instance
URL, Patchwork project, and your Patchwork user authentication token. The URL
and project are provided below, but you must obtain your authentication token
from your `Patchwork User Profile`__ page. If you do not already have a
Patchwork user account, you should create one now.

Once your token is obtained, configure *git-pw* as below. Note that this must
be run from within the Open vSwitch Git repository::

    $ git config pw.server https://patchwork.ozlabs.org/
    $ git config pw.project openvswitch
    $ git config pw.token $PW_TOKEN  # using the token obtained earlier

Once configured, run the following to get information about available
commands::

    $ git pw --help

__ https://pypi.python.org/pypi/git-pw
__ https://patchwork.ozlabs.org/user/

.. _pwclient:

pwclient
--------

The *pwclient* is a legacy tool that provides some of the functionality of
*git-pw* but uses the legacy XML-RPC API. It is considered deprecated in its
current form and *git-pw* should be used instead.
