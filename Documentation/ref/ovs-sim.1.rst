=======
ovs-sim
=======

Synopsis
========

``ovs-sim`` [*option*]... [*script*]...

Description
===========

``ovs-sim`` provides a convenient environment for running one or more Open
vSwitch instances and related software in a sandboxed simulation environment.

To use ``ovs-sim``, first build Open vSwitch, then invoke it directly from the
build directory, e.g.::

    git clone https://github.com/openvswitch/ovs.git
    cd ovs
    ./configure
    make
    utilities/ovs-sim

When invoked in the most ordinary way as shown above, ovs-sim does  the
following:

1. Creates a directory ``sandbox`` as a subdirectory of the current
   directory (first destroying such a directory if it already exists)
   and makes it the current directory.

2. Installs all of the Open vSwitch manpages into a ``man``
   subdirectory of sandbox and adjusts the ``MANPATH`` environment
   variable so that ``man`` and other manpage viewers can find them.

3. Creates a simulated Open vSwitch named ``main`` and sets it up as the
   default target for OVS commands, as if the following ``ovs-sim``
   commands had been run::

            sim_add main
            as main

  See `Commands`_, below, for an explanation.

4. Runs  any  scripts  specified on the command line (see `Options`_,
   below). The scripts can use arbitrary Bash  syntax,  plus  the
   additional commands described under `Commands`_, below.

5. If no scripts were specified, or if ``-i`` or ``--interactive`` was
   specified, invokes an interactive Bash subshell. The user can use
   arbitrary Bash commands, plus the additional commands described under
   `Commands`_, below.

``ovs-sim`` and the sandbox environment that it creates does not require
superuser or other special privileges.  Generally, it should not be run with
such privileges.

Options
=======

.. program: ovs-sim

*script*
    Runs *script*, which should be a Bash script, within a subshell
    after initializing.  If multiple script arguments are given, then
    they are run in the order given.  If any script exits with a
    nonzero exit code, then ``ovs-sim`` exits immediately with the
    same exit code.

``-i`` or ``--interactive``
    By default, if any script is specified, ``ovs-sim`` exits as soon as the
    scripts finish executing. With this option, or if no scripts are specified,
    ``ovs-sim`` instead starts an interactive Bash session.

Commands
========

Scripts and interactive usage may use the following commands
implemented by ``ovs-sim``.  They are implemented as Bash shell functions
exported to subshells.

Basic Commands
--------------

These  are  the  basic commands for working with sandboxed Open vSwitch
instances.

``sim_add`` *sandbox*
    Starts a new simulated Open vSwitch instance named *sandbox*.
    Files related to the instance, such as logs, databases, sockets,
    and pidfiles, are created in a subdirectory also named
    *sandbox*. Afterward, the ``as`` command (see below) can be used
    to run Open vSwitch utilities in the context of the new sandbox.

    The new sandbox starts out without any bridges. Use ``ovs-vsctl``
    in the context of the new sandbox to create a bridge, e.g.::

        sim_add hv0           # Create sandbox hv0.
        as hv0                # Set hv0 as default sandbox.
        ovs-vsctl add-br br0  # Add bridge br0 inside hv0.

    The Open vSwitch instances that ``sim_add`` creates enable
    ``dummy`` devices.  This means that bridges and interfaces can be
    created with type ``dummy`` to indicate that they should be
    totally simulated, without any reference to system entities.  In
    fact, ``ovs-sim`` also configures Open vSwitch so that the default
    system type of bridges and interfaces are replaced by dummy
    devices.  Other types of devices, however, retain their usual
    functions, which means that, e.g., vxlan tunnels still act as
    tunnels (refer to the documentation).

``as`` *sandbox*
    Sets sandbox as the default simulation target for Open vSwitch
    commands (e.g. ``ovs-vsctl``, ``ovs-ofctl``, ``ovs-appctl``).

    This command updates the beginning of the shell prompt to indicate
    the new default target.

``as`` *sandbox* *command* *arg*...
    Runs the given command with *sandbox* as the simulation target,
    e.g.  ``as hv0 ovs-vsctl add-br br0`` runs ``ovs-vsctl add-br
    br0`` within sandbox ``hv0``.  The default target is unchanged.

Interconnection Network Commands
--------------------------------

When multiple sandboxed Open vSwitch instances exist, one will
inevitably want to connect them together.  These commands allow for
that.  Conceptually, an interconnection network is a switch that
``ovs-sim`` makes it easy to plug into other switches in other
sandboxed Open vSwitch instances.  Interconnection networks are
implemented as bridges in the ``main`` switch that ``ovs-sim`` creates
by default, so to use interconnection networks please avoid working
with ``main`` directly.

``net_add`` *network*
    Creates a new interconnection network named *network*.

``net_attach`` *network* *bridge*
    Adds a new port to *bridge* in the default sandbox (as set with
    ``as``) and plugs it into interconnection network *network*, which
    must already have been created by a previous invocation of
    ``net_add``. The default sandbox must not be ``main``.

