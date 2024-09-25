# Copyright (c) 2023 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import click

from ovs.flowviz.main import maincli
from ovs.flowviz.odp.html import HTMLTreeProcessor
from ovs.flowviz.odp.tree import ConsoleTreeProcessor
from ovs.flowviz.process import (
    ConsoleProcessor,
    JSONDatapathProcessor,
)


@maincli.group(subcommand_metavar="FORMAT")
@click.pass_obj
def datapath(opts):
    """Process Datapath Flows."""
    pass


@datapath.command()
@click.pass_obj
def json(opts):
    """Print the flows in JSON format."""
    proc = JSONDatapathProcessor(opts)
    proc.process()
    print(proc.json_string())


@datapath.command()
@click.option(
    "-h",
    "--heat-map",
    is_flag=True,
    default=False,
    show_default=True,
    help="Create heat-map with packet and byte counters",
)
@click.pass_obj
def console(opts, heat_map):
    """Print the flows in the console with some style."""
    proc = ConsoleProcessor(
        opts, "odp", heat_map=["packets", "bytes"] if heat_map else []
    )
    proc.process()
    proc.print()


@datapath.command()
@click.option(
    "-h",
    "--heat-map",
    is_flag=True,
    default=False,
    show_default=True,
    help="Create heat-map with packet and byte counters",
)
@click.pass_obj
def tree(opts, heat_map):
    """Print the flows in a tree based on the 'recirc_id'."""
    processor = ConsoleTreeProcessor(
        opts, heat_map=["packets", "bytes"] if heat_map else []
    )
    processor.process()
    processor.print()


@datapath.command()
@click.pass_obj
def html(opts):
    """Print the flows in an HTML list sorted by recirc_id."""
    processor = HTMLTreeProcessor(opts)
    processor.process()
    processor.print()
