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

import colorsys

from rich.console import Console
from rich.color import Color
from rich.text import Text
from rich.style import Style

from ovs.flowviz.format import FlowFormatter, FlowBuffer


def file_header(name):
    return Text(f"### {name} ###")


class ConsoleBuffer(FlowBuffer):
    """ConsoleBuffer implements FlowBuffer to provide console-based text
    formatting based on rich.Text.

    Append functions accept a rich.Style.

    Args:
        rtext(rich.Text): Optional; text instance to reuse
    """

    def __init__(self, rtext):
        self._text = rtext or Text()

    @property
    def text(self):
        return self._text

    def _append(self, string, style):
        """Append to internal text."""
        return self._text.append(string, style)

    def append_key(self, kv, style):
        """Append a key.
        Args:
            kv (KeyValue): the KeyValue instance to append
            style (rich.Style): the style to use
        """
        return self._append(kv.meta.kstring, style)

    def append_delim(self, kv, style):
        """Append a delimiter.
        Args:
            kv (KeyValue): the KeyValue instance to append
            style (rich.Style): the style to use
        """
        return self._append(kv.meta.delim, style)

    def append_end_delim(self, kv, style):
        """Append an end delimiter.
        Args:
            kv (KeyValue): the KeyValue instance to append
            style (rich.Style): the style to use
        """
        return self._append(kv.meta.end_delim, style)

    def append_value(self, kv, style):
        """Append a value.
        Args:
            kv (KeyValue): the KeyValue instance to append
            style (rich.Style): the style to use
        """
        return self._append(kv.meta.vstring, style)

    def append_extra(self, extra, style):
        """Append extra string.
        Args:
            kv (KeyValue): the KeyValue instance to append
            style (rich.Style): the style to use
        """
        return self._append(extra, style)


class ConsoleFormatter(FlowFormatter):
    """ConsoleFormatter is a FlowFormatter that formats flows into the console
    using rich.Console.

    Args:
        console (rich.Console): Optional, an existing console to use
        max_value_len (int): Optional; max length of the printed values
        kwargs (dict): Optional; Extra arguments to be passed down to
            rich.console.Console()
    """

    def __init__(self, opts=None, console=None, **kwargs):
        super(ConsoleFormatter, self).__init__()
        self.style = self.style_from_opts(opts)
        self.console = console or Console(color_system="256", **kwargs)

    def style_from_opts(self, opts):
        return self._style_from_opts(opts, "console", Style)

    def print_flow(self, flow, highlighted=None):
        """Prints a flow to the console.

        Args:
            flow (ovs_dbg.OFPFlow): the flow to print
            style (dict): Optional; style dictionary to use
            highlighted (list): Optional; list of KeyValues to highlight
        """

        buf = ConsoleBuffer(Text())
        self.format_flow(buf, flow, highlighted)
        self.console.print(buf.text)

    def format_flow(self, buf, flow, highlighted=None):
        """Formats the flow into the provided buffer as a rich.Text.

        Args:
            buf (FlowBuffer): the flow buffer to append to
            flow (ovs_dbg.OFPFlow): the flow to format
            style (FlowStyle): Optional; style object to use
            highlighted (list): Optional; list of KeyValues to highlight
        """
        return super(ConsoleFormatter, self).format_flow(
            buf, flow, self.style, highlighted
        )


def heat_pallete(min_value, max_value):
    """Generates a color pallete based on the 5-color heat pallete so that
    for each value between min and max a color is returned that represents it's
    relative size.
    Args:
        min_value (int): minimum value
        max_value (int) maximum value
    """
    h_min = 0  # red
    h_max = 220 / 360  # blue

    def heat(value):
        if max_value == min_value:
            r, g, b = colorsys.hsv_to_rgb(h_max / 2, 1.0, 1.0)
        else:
            normalized = (int(value) - min_value) / (max_value - min_value)
            hue = ((1 - normalized) + h_min) * (h_max - h_min)
            r, g, b = colorsys.hsv_to_rgb(hue, 1.0, 1.0)
        return Style(color=Color.from_rgb(r * 255, g * 255, b * 255))

    return heat


def default_highlight():
    """Generates a default style for highlights."""
    return Style(underline=True)
