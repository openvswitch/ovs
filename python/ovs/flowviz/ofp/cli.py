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

import os

import click

from ovs.flowviz.main import maincli
from ovs.flowviz.ofp.html import HTMLProcessor
from ovs.flowviz.ofp.logic import CookieProcessor, LogicFlowProcessor
from ovs.flowviz.process import (
    ConsoleProcessor,
    JSONOpenFlowProcessor,
)


@maincli.group(subcommand_metavar="FORMAT")
@click.pass_obj
def openflow(opts):
    """Process OpenFlow Flows."""
    pass


@openflow.command()
@click.pass_obj
def json(opts):
    """Print the flows in JSON format."""
    proc = JSONOpenFlowProcessor(opts)
    proc.process()
    print(proc.json_string())


@openflow.command()
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
        opts,
        "ofp",
        heat_map=["n_packets", "n_bytes"] if heat_map else [],
    )
    proc.process()
    proc.print()


def ovn_detrace_callback(ctx, param, value):
    """click callback to add detrace information to config object and
    set general ovn-detrace flag to True
    """
    ctx.obj[param.name] = value
    if value != param.default:
        ctx.obj["ovn_detrace_flag"] = True
    return value


@openflow.command()
@click.option(
    "-d",
    "--ovn-detrace",
    "ovn_detrace_flag",
    is_flag=True,
    show_default=True,
    help="Use ovn-detrace to extract cookie information (implies '-c')",
)
@click.option(
    "--ovn-detrace-path",
    default="/usr/bin",
    type=click.Path(),
    help="Use an alternative path to where ovn_detrace.py is located. "
    "Instead of using this option you can just set PYTHONPATH accordingly.",
    show_default=True,
    callback=ovn_detrace_callback,
)
@click.option(
    "--ovnnb-db",
    default=os.getenv("OVN_NB_DB") or "unix:/var/run/ovn/ovnnb_db.sock",
    help="Specify the OVN NB database string (implies -d). "
    "If the OVN_NB_DB environment variable is set, it's used as default. "
    "Otherwise, the default is unix:/var/run/ovn/ovnnb_db.sock",
    callback=ovn_detrace_callback,
)
@click.option(
    "--ovnsb-db",
    default=os.getenv("OVN_SB_DB") or "unix:/var/run/ovn/ovnsb_db.sock",
    help="Specify the OVN NB database string (implies -d). "
    "If the OVN_NB_DB environment variable is set, it's used as default. "
    "Otherwise, the default is unix:/var/run/ovn/ovnnb_db.sock",
    callback=ovn_detrace_callback,
)
@click.option(
    "-o",
    "--ovn-filter",
    help="Specify a filter to be run on ovn-detrace information (implied -d). "
    "Format: python regular expression "
    "(see https://docs.python.org/3/library/re.html)",
    callback=ovn_detrace_callback,
)
@click.option(
    "-s",
    "--show-flows",
    is_flag=True,
    default=False,
    show_default=True,
    help="Show the full flows under each logical flow",
)
@click.option(
    "-c",
    "--cookie",
    "cookie_flag",
    is_flag=True,
    default=False,
    show_default=True,
    help="Consider the cookie in the logical flow",
)
@click.option(
    "-h",
    "--heat-map",
    is_flag=True,
    default=False,
    show_default=True,
    help="Create heat-map with packet and byte counters (when -s is used)",
)
@click.pass_obj
def logic(
    opts,
    ovn_detrace_flag,
    ovn_detrace_path,
    ovnnb_db,
    ovnsb_db,
    ovn_filter,
    show_flows,
    cookie_flag,
    heat_map,
):
    """
    Print the logical structure of the flows.

    First, sorts the flows based on tables and priorities.
    Then, deduplicates logically equivalent flows: these a flows that match
    on the same set of fields (regardless of the values they match against),
    have the same priority, and actions (regardless of action arguments,
    except in the case of output and recirculate).
    Optionally, the cookie can also be considered to be part of the logical
    flow.
    """
    if ovn_detrace_flag:
        opts["ovn_detrace_flag"] = True
    if opts.get("ovn_detrace_flag"):
        cookie_flag = True

    processor = LogicFlowProcessor(opts, cookie_flag, heat_map)
    processor.process()
    processor.print(show_flows)


@openflow.command()
@click.option(
    "-d",
    "--ovn-detrace",
    "ovn_detrace_flag",
    is_flag=True,
    show_default=True,
    help="Use ovn-detrace to extract cookie information",
)
@click.option(
    "--ovn-detrace-path",
    default="/usr/bin",
    type=click.Path(),
    help="Use an alternative path to where ovn_detrace.py is located. "
    "Instead of using this option you can just set PYTHONPATH accordingly",
    show_default=True,
    callback=ovn_detrace_callback,
)
@click.option(
    "--ovnnb-db",
    default=os.getenv("OVN_NB_DB") or "unix:/var/run/ovn/ovnnb_db.sock",
    help="Specify the OVN NB database string (implies -d). "
    "If the OVN_NB_DB environment variable is set, it's used as default. "
    "Otherwise, the default is unix:/var/run/ovn/ovnnb_db.sock",
    callback=ovn_detrace_callback,
)
@click.option(
    "--ovnsb-db",
    default=os.getenv("OVN_SB_DB") or "unix:/var/run/ovn/ovnsb_db.sock",
    help="Specify the OVN NB database string (implies -d). "
    "If the OVN_NB_DB environment variable is set, it's used as default. "
    "Otherwise, the default is unix:/var/run/ovn/ovnnb_db.sock",
    callback=ovn_detrace_callback,
)
@click.option(
    "-o",
    "--ovn-filter",
    help="Specify a filter to be run on ovn-detrace information (implied -d). "
    "Format: python regular expression "
    "(see https://docs.python.org/3/library/re.html)",
    callback=ovn_detrace_callback,
)
@click.pass_obj
def cookie(
    opts, ovn_detrace_flag, ovn_detrace_path, ovnnb_db, ovnsb_db, ovn_filter
):
    """Print the flow tables sorted by cookie."""
    if ovn_detrace_flag:
        opts["ovn_detrace_flag"] = True

    processor = CookieProcessor(opts)
    processor.process()
    processor.print()


@openflow.command()
@click.pass_obj
def html(opts):
    """Print the flows in an linked HTML list arranged by tables."""
    processor = HTMLProcessor(opts)
    processor.process()
    print(processor.html())
