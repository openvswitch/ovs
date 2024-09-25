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

import configparser
import click
import os

from ovs.flow.filter import OFFilter
from ovs.dirs import PKGDATADIR

_default_config_file = "ovs-flowviz.conf"
_default_config_path = next(
    (
        p
        for p in [
            os.path.join(
                os.getenv("HOME"), ".config", "ovs", _default_config_file
            ),
            os.path.join(PKGDATADIR, _default_config_file),
            os.path.abspath(
                os.path.join(os.path.dirname(__file__), _default_config_file)
            ),
        ]
        if os.path.exists(p)
    ),
    "",
)


class Options(dict):
    """Options dictionary"""


def validate_input(ctx, param, value):
    """Validate the "-i" option"""
    result = list()
    for input_str in value:
        parts = input_str.strip().split(",")
        if len(parts) == 2:
            file_parts = tuple(parts)
        elif len(parts) == 1:
            file_parts = tuple(["Filename: " + parts[0], parts[0]])
        else:
            raise click.BadParameter(
                "input filename should have the following format: "
                "[alias,]FILENAME"
            )

        if not os.path.isfile(file_parts[1]):
            raise click.BadParameter(
                "input filename %s does not exist" % file_parts[1]
            )
        result.append(file_parts)
    return result


@click.group(
    context_settings=dict(help_option_names=["-h", "--help"]),
)
@click.option(
    "-c",
    "--config",
    help="Use config file",
    type=click.Path(),
    default=_default_config_path,
    show_default=True,
)
@click.option(
    "--style",
    help="Select style (defined in config file)",
    default=None,
    show_default=True,
)
@click.option(
    "-i",
    "--input",
    "filename",
    help="Read flows from specified filepath. If not provided, flows will be"
    " read from stdin. This option can be specified multiple times."
    " Format [alias,]FILENAME. Where alias is a name that shall be used to"
    " refer to this FILENAME",
    multiple=True,
    type=click.Path(),
    callback=validate_input,
)
@click.option(
    "-f",
    "--filter",
    help="Filter flows that match the filter expression."
    "Run 'ovs-flowviz filter' for a detailed description of the filtering "
    "syntax",
    type=str,
    show_default=False,
)
@click.option(
    "-l",
    "--highlight",
    help="Highlight flows that match the filter expression."
    "Run 'ovs-flowviz filter' for a detailed description of the filtering "
    "syntax",
    type=str,
    show_default=False,
)
@click.pass_context
def maincli(ctx, config, style, filename, filter, highlight):
    """
    OpenvSwitch flow visualization utility.

    It reads openflow and datapath flows
    (such as the output of ovs-ofctl dump-flows or ovs-appctl dpctl/dump-flows)
    and prints them in different formats.
    """
    ctx.obj = Options()
    ctx.obj["filename"] = filename or None
    if filter:
        try:
            ctx.obj["filter"] = OFFilter(filter)
        except Exception as e:
            raise click.BadParameter("Wrong filter syntax: {}".format(e))

    if highlight:
        try:
            ctx.obj["highlight"] = OFFilter(highlight)
        except Exception as e:
            raise click.BadParameter("Wrong filter syntax: {}".format(e))

    config_file = config or _default_config_path
    parser = configparser.ConfigParser()
    parser.read(config_file)

    ctx.obj["config"] = parser
    ctx.obj["style"] = style


@maincli.command(hidden=True)
@click.pass_context
def filter(ctx):
    """
    \b
    Filter Syntax
    *************

     [! | not ] {key}[[.subkey]...] [OPERATOR] {value})] [LOGICAL OPERATOR] ...

    \b
    Comparison operators are:
        =   equality
        <   less than
        >   more than
        ~=  masking (valid for IP and Ethernet fields)

    \b
    Logical operators are:
        !{expr}:  NOT
        {expr} && {expr}: AND
        {expr} || {expr}: OR

    \b
    Matches and flow metadata:
        To compare against a match or info field, use the field directly, e.g:
            priority=100
            n_bytes>10
        Use simple keywords for flags:
            tcp and ip_src=192.168.1.1
    \b
    Actions:
        Actions values might be dictionaries, use subkeys to access individual
        values, e.g:
            output.port=3
        Use simple keywords for flags
            drop

    \b
    Examples of valid filters.
        nw_addr~=192.168.1.1 && (tcp_dst=80 || tcp_dst=443)
        arp=true && !arp_tsa=192.168.1.1
        n_bytes>0 && drop=true"""
    click.echo(ctx.command.get_help(ctx))


def main():
    """
    Main Function
    """
    maincli()
