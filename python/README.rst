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


Examples
--------

.. _example-database-schema:

Inspecting the database schema
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The OVSDB schema is described in a JSON file, typically called
``vswitch.ovsschema``. It can be inspected via schema provided locally on the
host or remotely via the JSON-RPC API. For example, to view it from the local
file:

.. code-block:: python

    import json
    import ovs.dirs

    schema_path = f'{ovs.dirs.PKGDATADIR}/vswitch.ovsschema'

    with open(schema_path) as fh:
        schema = json.load(fh)

    print(schema)

To do the same via the JSON-RPC, using TCP:

.. code-block:: python

    import json
    import sys
    import ovs.jsonrpc

    remote = 'tcp:127.0.0.1:6640'

    error, stream = ovs.stream.Stream.open_block(ovs.stream.Stream.open(remote))
    if error:
        print(error)
        sys.exit(1)

    rpc = ovs.jsonrpc.Connection(stream)
    request = ovs.jsonrpc.Message.create_request('get_schema', ['Open_vSwitch'])
    error, reply = rpc.transact_block(request)
    rpc.close()
    if error:
        print(error)
        sys.exit(1)

    schema = reply.result
    print(schema)

.. note::

    The above assumes the default port (``6640``) is used and Open vSwitch is
    running on the localhost (``127.0.0.1``).

.. _example-dumping-tables-ports-interfaces:

Dumping tables, ports and interfaces
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Open vSwitch Database (OVSDB) Interface Definition Language (IDL) maintains
an in-memory replica of a database. It issues RPC requests to an OVSDB database
server and parses the responses, converting raw JSON into data structures that
are easier for clients to digest. You can use the IDL for database transactions
along with simpler operations such as dumping information about the schema.
The Python implementation of the OVSDB IDL is provided in ``ovs.db.idl`` via
the ``Idl`` class. To initialise this, you need a schema helper and a "remote"
or interface through which to communicate with the OVSDB. We can re-use and
build upon the `schema example from above <example-database-schema>`__ to
create an instance of ``ovs.db.idl.SchemaHelper``. Once done, you can create an
instance of ``ovs.db.idl.IDL`` and use this to iterate over the bridges, ports
and interfaces available:

.. code-block:: python

    import ovs.db.idl
    import ovs.dirs

    # Create the schema helper.
    schema_path = f'{ovs.dirs.PKGDATADIR}/vswitch.ovsschema'
    schema_helper = ovs.db.idl.SchemaHelper(schema_path)
    schema_helper.register_all()  # Register all tables for monitoring.

    # Connect over TCP.
    remote = 'tcp:127.0.0.1:6640'

    idl = ovs.db.idl.Idl(remote, schema_helper)

    # Wait until we have all information retrieved from the database.
    while not idl.has_ever_connected():
        poller = ovs.poller.Poller()
        idl.wait(poller)
        poller.block()
        idl.run()

    # Print bridges, ports and interfaces, à la 'ovs-vsctl show'.
    for bridge in idl.tables['Bridge'].rows.values():
        print(f'Bridge {bridge.name}')
        for port in bridge.ports:
            print(f'\tPort {port.name}')
            for interface in port.interfaces:
                print(f'\t\tInterface {interface.name}')
                print(f'\t\t\ttype: {interface.type}')

.. note::

    The above connects to OVSDB via TCP. You could also connect via the unix
    socket by replacing the `remote` with e.g.

    .. code-block:: python

        remote = f'unix:{ovs.dirs.RUNDIR}/db.sock'

.. note::

    This is only an example. Production code should be prepared for failures
    while retrieving information and may wish to incorporate retry logic.


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
