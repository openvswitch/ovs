..
      Copyright (c) 2016 Stephen Finucane <stephen@that.guru>

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

==========================
Open vSwitch Documentation
==========================

This document describes how to build the OVS documentation for use offline. A
continuously updated, online version can be found at `docs.openvswitch.org
<http://docs.openvswitch.org>`__.

.. note::
  These instructions provide information on building the documentation locally.
  For information on writing documentation, refer to
  :doc:`/internals/contributing/documentation-style`

Build Requirements
------------------

As described in the :doc:`/internals/contributing/documentation-style`, the
Open vSwitch documentation is written in reStructuredText and built with
Sphinx. A detailed guide on installing Sphinx in many environments is available
on the `Sphinx website`__ but, for most Linux distributions, you can install
with your package manager. For example, on Debian/Ubuntu run::

    $ sudo apt-get install python-sphinx

Similarly, on RHEL/Fedora run::

    $ sudo dnf install python-sphinx

A ``requirements.txt`` is also provided in the ``/Documentation``, should you
wish to install using ``pip``::

    $ virtualenv .venv
    $ source .venv/bin/activate
    $ pip install -r Documentation/requirements.txt

__ http://www.sphinx-doc.org/install.html

Configuring
-----------

It's unlikely that you'll need to customize any aspect of the configuration.
However, the ``Documentation/conf.py`` is the go-to place for all
configuration. This file is well documented and further information is
available on the `Sphinx website`__.

Building
--------

Once Sphinx installed, the documentation can be built using the provided
Makefile targets::

    $ make docs-check

.. important::

   The ``docs-check`` target will fail if there are any syntax errors.
   However, it won't catch more succint issues such as style or grammar issues.
   As a result, you should always inspect changes visually to ensure the result
   is as intended.

Once built, documentation is available in the ``/Documentation/_build`` folder.
Open the root ``index.html`` to browse the documentation.

__ http://www.sphinx-doc.org/config.html
