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

============
Open vSwitch
============

The ``openvswitch`` package provides the `official Python language bindings`__
for `Open vSwitch`__. They are developed in-tree as part of the `Open vSwitch
Package`__.

.. __: https://docs.openvswitch.org/en/latest/topics/language-bindings/
.. __: https://docs.openvswitch.org/en/latest/
.. __: https://github.com/openvswitch/ovs/tree/main/python/ovs


Installation
------------

You can install the package using ``pip``:

.. code-block:: shell

    $ pip install ovs

The package include an optional flow parsing library. To use this package, you
must install its required dependencies. The ``flow`` `extra`__ is provided for
this purpose:

.. code-block:: shell

    $ pip install ovs[flow]

.. __: https://packaging.python.org/en/latest/tutorials/installing-packages/#installing-extras


Documentation
-------------

Documentation is included in the Python source. To view this, you can install
the package and use `pydoc`__. For example:

.. code-block:: shell

    $ python -m pydoc ovs

Alternatively, you can use the ``help`` function from the Python REPL:

.. code-block:: python

    >>> import ovs
    >>> help(ovs)

.. __: https://docs.python.org/3/library/pydoc.html
