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

================================
Open vSwitch Documentation Style
================================

This file describes the documentation style used in all documentation found in
Open vSwitch. Documentation includes any documents found in ``Documentation``
along with any ``README``, ``MAINTAINERS``, or generally ``rst`` suffixed
documents found in the project tree.

.. note::

   This guide only applies to documentation for Open vSwitch v2.7. or greater.
   Previous versions of Open vSwitch used a combination of Markdown and raw
   plain text, and guidelines for these are not detailed here.

reStructuredText vs. Sphinx
---------------------------

`reStructuredText (rST)`__ is the syntax, while `Sphinx`__ is a documentation
generator.  Sphinx introduces a number of extensions to rST, like the ``:ref:``
role, which can and should be used in documentation, but these will not work
correctly on GitHub. As such, these extensions should not be used in any
documentation in the root level, such as the ``README``.

__ http://docutils.sourceforge.net/rst.html
__ http://www.sphinx-doc.org/

rST Conventions
---------------

Basics
~~~~~~

Many of the basic documentation guidelines match those of the
:doc:`coding-style`.

- Use reStructuredText (rST) for all documentation.

  Sphinx extensions can be used, but only for documentation in the
  ``Documentation`` folder.

- Limit lines at 79 characters.

  .. note::

     An exception to this rule is text within code-block elements that cannot
     be wrapped and links within references.

- Use spaces for indentation.

- Match indentation levels.

  A change in indentation level usually signifies a change in content nesting,
  by either closing the existing level or introducing a new level.

- Avoid trailing spaces on lines.

- Include a license (see this file) in all docs.

- Most importantly, always build and display documentation before submitting
  changes! Docs aren't unit testable, so visible inspection is necessary.

File Names
~~~~~~~~~~

- Use hyphens as space delimiters. For example: ``my-readme-document.rst``

  .. note::

     An exception to this rule is any man pages, which take an trailing number
     corresponding to the number of arguments required. This number is preceded
     by an underscore.

- Use lowercase filenames.

  .. note::

     An exception to this rule is any documents found in the root-level of the
     project.

Titles
~~~~~~

- Use the following headers levels.

  | ``=======``  Heading 0 (reserved for the title in a document)
  | ``-------``  Heading 1
  | ``~~~~~~~``  Heading 2
  | ``+++++++``  Heading 3
  | ``'''''''``  Heading 4

  .. note::

     Avoid using lower heading levels by rewriting and reorganizing the
     information.

- Under- and overlines should be of the same length as that of the heading
  text.

- Use "title case" for headers.

Code
~~~~

- Use ``::`` to prefix code.

- Don't use syntax highlighting such as ``.. highlight:: <syntax>`` or
  ``code-block:: <syntax>`` because it depends on external ``pygments``
  library.

- Prefix commands with ``$``.

- Where possible, include fully-working snippets of code. If there
  pre-requisites, explain what they are and how to achieve them.

Admonitions
~~~~~~~~~~~

- Use admonitions to call attention to important information.::

      .. note::

         This is a sample callout for some useful tip or trick.

  Example admonitions include: ``warning``, ``important``, ``note``, ``tip`` or
  ``seealso``.

- Use notes sparingly. Avoid having more than one per subsection.

Tables
~~~~~~

- Use either graphic tables, list tables or CSV tables.

Graphic tables
++++++++++++++

::

    .. table:: OVS-Linux kernel compatibility

      ============ ==============
      Open vSwitch Linux kernel
      ============ ==============
      1.4.x        2.6.18 to 3.2
      1.5.x        2.6.18 to 3.2
      1.6.x        2.6.18 to 3.2
      ============ ==============

::

    .. table:: OVS-Linux kernel compatibility

      +--------------+---------------+
      | Open vSwitch | Linux kernel  |
      +==============+===============+
      | 1.4.x        | 2.6.18 to 3.2 |
      +--------------+---------------+
      | 1.5.x        | 2.6.18 to 3.2 |
      +--------------+---------------+
      | 1.6.x        | 2.6.18 to 3.2 |
      +--------------+---------------+

.. note::
  The ``table`` role - ``.. table:: <name>`` -  can be safely omitted.

List tables
+++++++++++

::

    .. list-table:: OVS-Linux kernel compatibility
       :widths: 10 15
       :header-rows: 1

       * - Open vSwitch
         - Linux kernel
       * - 1.4.x
         - 2.6.18 to 3.2
       * - 1.5.x
         - 2.6.18 to 3.2
       * - 1.6.x
         - 2.6.18 to 3.2

CSV tables
++++++++++

::

    .. csv-table:: OVS-Linux kernel compatibility
       :header: Open vSwitch, Linux kernel
       :widths: 10 15

       1.4.x, 2.6.18 to 3.2
       1.5.x, 2.6.18 to 3.2
       1.6.x, 2.6.18 to 3.2

Cross-referencing
~~~~~~~~~~~~~~~~~

- To link to an external file or document, include as a link.::

      Here's a `link <http://openvswitch.org>`__ to the Open vSwitch website.


      Here's a `link`_ in reference style.

      .. _link: http://openvswitch.org

- You can also use citations.::

      Refer to the Open vSwitch documentation [1]_.

      References
      ----------

      .. [1]: http://openvswitch.org

- To cross-reference another doc, use the ``doc`` role.::

      Here is a link to the :doc:`/README.rst`

  .. note::

     This is a Sphinx extension. Do not use this in any top-level documents.

- To cross-reference an arbitrary location in a doc, use the ``ref`` role.::

      .. _sample-crossref

      Title
      ~~~~~

      Hello, world.

      Another Title
      ~~~~~~~~~~~~~

      Here is a cross-reference to :ref:`sample-crossref`.

  .. note::

     This is a Sphinx extension. Do not use this in any top-level documents.

Figures and Other Media
~~~~~~~~~~~~~~~~~~~~~~~

- All images should be in PNG format and compressed where possible. For PNG
  files, use OptiPNG and AdvanceCOMP's ``advpng``:

  ::

     $ optipng -o7 -zm1-9 -i0 -strip all <path_to_png>
     $ advpng -z4 <path_to_png>

- Any ASCII text "images" should be included in code-blocks to preserve
  formatting

- Include other reStructuredText verbatim in a current document

Comments
~~~~~~~~

- Comments are indicated by means of the ``..`` marker.::

      .. TODO(stephenfin) This section needs some work. This TODO will not
         appear in the final generated document, however.

Man Pages
---------

In addition to the above, man pages have some specific requirements:

- You **must** define the following sections:

  - Synopsis

  - Description

  - Options

  Note that `NAME` is not included - this is automatically generated by Sphinx
  and should not be manually defined. Also note that these do not need to be
  uppercase - Sphinx will do this automatically.

  Additional sections are allowed. Refer to `man-pages(8)` for information on
  the sections generally allowed.

- You **must not** define a `NAME` section.

  See above.

- The `OPTIONS` section must describe arguments and options using the
  `program`__ and `option`__ directives.

  This ensures the output is formatted correctly and that you can
  cross-reference various programs and commands from the documentation. For
  example::

      .. program:: ovs-do-something

      .. option:: -f, --force

          Force the operation

      .. option:: -b <bridge>, --bridge <bridge>

          Name or ID of bridge

  .. important::

     Option argument names should be enclosed in angle brackets, as above.

- Any references to the application or any other Open vSwitch application must
  be marked up using the `program` role.

  This allows for easy linking in the HTML output and correct formatting in the
  man page output. For example::

      To do something, run :program:`ovs-do-something`.

- The man page must be included in the list of man page documents found in
  `conf.py`__

Refer to existing man pages, such as :doc:`/ref/ovs-vlan-test.8` for a worked
example.

__ http://www.sphinx-doc.org/en/stable/domains.html#directive-program
__ http://www.sphinx-doc.org/en/stable/domains.html#directive-option
__ http://www.sphinx-doc.org/en/stable/config.html#confval-man_pages

Writing Style
-------------

Follow these guidelines to ensure readability and consistency of the Open
vSwitch documentation. These guidelines are based on the `IBM Style Guide
<http://www.redbooks.ibm.com/Redbooks.nsf/ibmpressisbn/9780132101301?Open>`__.

- Use standard US English

  Use a spelling and grammar checking tool as necessary.

- Expand initialisms and acronyms on first usage.

  Commonly used terms like CPU or RAM are allowed.

  .. list-table::
     :header-rows: 1

     * - Do not use
       - Do use
     * - OVS is a virtual switch. OVS has...
       - Open vSwitch (OVS) is a virtual switch. OVS has...
     * - The VTEP emulator is...
       - The Virtual Tunnel Endpoint (VTEP) emulator is...

- Write in the active voice

  The subject should do the verb's action, rather than be acted upon.

  .. list-table::
     :header-rows: 1

     * - Do not use
       - Do use
     * - A bridge is created by you
       - Create a bridge

- Write in the present tense

  .. list-table::
     :header-rows: 1

     * - Do not use
       - Do use
     * - Once the bridge is created, you can create a port
       - Once the bridge is created, create a port

- Write in second person

  .. list-table::
     :header-rows: 1

     * - Do not use
       - Do use
     * - To create a bridge, the user runs:
       - To create a bridge, run:

- Keep sentences short and concise

- Eliminate needless politeness

  Avoid "please" and "thank you"

Helpful Tools
-------------

There are a number of tools, online and offline, which can be used to preview
documents are you edit them:

- `rst.ninjs.org <http://rst.ninjs.org/>`__

  An online rST editor/previewer

- `ReText <https://github.com/retext-project/retext>`__

  A simple but powerful editor for Markdown and reStructuredText. ReText is
  written in Python.

- `restview <https://mg.pov.lt/restview/>`__

  A viewer for ReStructuredText documents that renders them on the fly.

Useful Links
------------

- `Quick reStructuredText
  <http://docutils.sourceforge.net/docs/user/rst/quickref.html>`__

- `Sphinx Documentation <http://sphinx.readthedocs.io/en/latest/rest.html>`__
