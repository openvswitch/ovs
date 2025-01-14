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

""" Defines a Datapath Graph using graphviz. """
import colorsys
import random
import sys

from ovs.flowviz.odp.html import HTMLTree, HTMLFormatter
from ovs.flowviz.odp.tree import FlowTree
from ovs.flowviz.process import FileProcessor

try:
    import graphviz
except ImportError:
    graphviz = None


class GraphProcessor(FileProcessor):
    def __init__(self, opts):
        if graphviz is None:
            print("ERROR: The graph sub-command depends on the graphviz "
                  "Python library, which does not appear to be installed.",
                  file=sys.stderr)
            sys.exit(1)
        super().__init__(opts, "odp")

    def start_file(self, name, filename):
        self.tree = FlowTree()

    def start_thread(self, name):
        pass

    def stop_thread(self, name):
        pass

    def process_flow(self, flow, name):
        self.tree.add(flow, self.opts.get("filter"))

    def process(self):
        super().process(False)

    def print(self, html):
        self.tree.build()

        if len(self.tree.all_recirc_nodes) == 0:
            return

        dpg = DatapathGraph(self.tree, self.opts)
        if not html:
            print(dpg.source())
            return

        html_obj = "<html>"
        html_obj += "<head>"
        html_obj += HTMLTree.head()
        html_obj += "</head>"

        html_obj += "<body>"
        html_obj += HTMLTree.begin_body(self.opts)
        html_obj += "<h1> Flow Graph </h1>"
        html_obj += """<div style="resize:both;
                                   overflow-y:scroll;
                                   overflow-x:scroll;
                                   border: 1px solid;
                                   width:2000px;
                                   height:1200px;">"""
        svg = dpg.pipe(format="svg")
        html_obj += svg.decode("utf-8")
        html_obj += "</div>"
        html_tree = HTMLTree("graph", self.tree, self.opts)
        html_obj += html_tree.format()
        html_obj += HTMLTree.end_body()
        html_obj += "</body>"
        html_obj += "</html>"

        print(html_obj)


class DatapathGraph:
    """A DatapathGraph is a class that renders a set of datapath flows into
    graphviz graphs.

    Args:
        tree: FlowTree
    """

    ct_styles = {}
    node_styles = {
        "default": {
            "style": {},
            "desc": "Default",
        },
        "match": {
            "style": {"color": "#0000ff"},
            "desc": "Flow matches on CT",
        },
        "action": {
            "style": {"color": "#ff0000"},
            "desc": "Flow(s) has CT as action",
        },
    }

    def __init__(self, tree, opts):
        self._tree = tree
        self._opts = opts

        style = HTMLFormatter(self._opts).style

        self.bgcolor = (
            style.get("background").color
            if style.get("background")
            else "#f0f0f0"
        )
        self.fgcolor = (
            style.get("default").color if style.get("default") else "black"
        )

        self._output_nodes = []
        self._graph = graphviz.Digraph(
            "DP flows",
            node_attr={
                "shape": "rectangle",
                "fontcolor": self.fgcolor,
                "color": self.fgcolor,
            },
            edge_attr={
                "color": self.fgcolor,
            },
        )
        self._graph.attr(color=self.fgcolor)
        self._graph.attr(fontcolor=self.fgcolor)
        self._graph.attr(bgcolor=self.bgcolor)
        self._graph.attr(compound="true")
        self._graph.attr(rankdir="LR")
        self._graph.attr(ranksep="3")

        self._populate_graph()

    def source(self):
        """Return the graphviz source representation of the graph."""
        return self._graph.source

    def pipe(self, *args, **kwargs):
        """Output the graph based on arguments given to graphviz.pipe."""
        return self._graph.pipe(*args, **kwargs)

    @classmethod
    def recirc_cluster_name(cls, node):
        """Name of the recirculation cluster."""
        return "cluster_recirc_{}_{}".format(hex(node.recirc), node.in_port)

    @classmethod
    def inport_cluster_name(cls, inport):
        """Name of the input port cluster."""
        return "cluster_inport_{}".format(inport)

    @classmethod
    def invis_node_name(cls, cluster_name):
        """Name of the invisible node."""
        return "invis_{}".format(cluster_name)

    @classmethod
    def output_node_name(cls, port):
        """Name of the ouput node."""
        return "output_{}".format(port)

    @classmethod
    def block_node_name(cls, block):
        """Name of the flow block node."""
        return "flow_block_{}".format(block.flows[0].flow.id)

    def _block_node(self, block):
        """Returns the dictionary of attributes of a graphviz node that
        represents the FlowBlock."""

        url = "#block_{}".format(block.flows[0].flow.id)

        # Graphviz supports HTML-ish syntax. Use it to create a table and
        # place each (summarized) match in each row and the (also summarized)
        # action in the last one.
        # A port is added to the actions row called "actions" that helps make
        # edges start from it.
        label = (
            """<<table border="0" """
            + """cellborder="1" """
            + """cellspacing="0" """
            + """cellpadding="4">"""
        )

        for i, tflow in enumerate(block.flows):
            style = "default"

            # Full representation of the flow to be used in the tooltip.
            full = (
                tflow.flow.section("info").string
                + " "
                + tflow.flow.section("match").string
            )

            # Summarized match: comma separated list of match keys with
            # their ommitted with "..." or "---" depending on whether the
            # match is the same for the entire block or not.
            flowstr = ""
            equal_keys = [m[1].key for m in block.equal_match]
            for m in tflow.flow.match_kv:
                fill = "..."
                if m.key in equal_keys:
                    fill = "---"

                flowstr += (
                    m.meta.kstring + m.meta.delim + fill + m.meta.end_delim
                )

                if m.key == "ct_state" and m.value != "0/0":
                    style = "match"

                flowstr += ","

            flowstr.strip(",")
            color = self.node_styles.get(style)["style"].get(
                "color", self.fgcolor
            )

            label += f"""<tr>
            <td tooltip="{full}" href="{url}" color="{color}">{flowstr}</td>
            </tr>"""

        # Add a row for the action.
        fullact = "actions: " + block.flows[0].flow.section("actions").string
        actstr = ",".join([a.key for a in block.flows[0].flow.actions_kv])

        has_ct_action = bool(
            next(
                filter(
                    lambda x: x.key in ["ct", "ct_clear"],
                    block.flows[0].flow.actions_kv,
                ),
                None,
            )
        )

        style = "action" if has_ct_action else "default"

        color = self.node_styles.get(style)["style"].get("color", self.fgcolor)

        label += f"""<tr>
            <td cellpadding="4"
                border="2"
                href="{url}"
                tooltip="{fullact}"
                color="{color}"
                port="actions">"""
        label += f"<B>actions:</B>  {actstr}"
        label += "</td></tr>"

        label += "</table>>"

        return {
            "name": self.block_node_name(block),
            "label": label,
            "fontsize": "10",
            "nojustify": "true",
            "URL": url,
        }

    def _create_recirc_cluster(self, node):
        """Create a cluster for the RecircNode."""

        cluster_name = self.recirc_cluster_name(node)

        label = "<<B>[recirc 0x{:0x} in_port {}]</B>>".format(
            node.recirc, node.in_port
        )

        cluster = self._graph.subgraph(name=cluster_name, comment=label)
        with cluster as sg:
            sg.attr(rankdir="TB")
            sg.attr(ranksep="0.02")
            sg.attr(label=label)
            sg.attr(margin="5")
            self._add_blocks_to_graph(sg, node.visible_blocks())

        self.processed_recircs.append((node.recirc, node.in_port))

    def _add_blocks_to_graph(self, graph, blocks):
        """Add FlowBlock objects in interable to the graph."""

        # Create an invisible node and an edge to the first block so that
        # it ends up at the top of the cluster.
        invis = self.invis_node_name(graph.name)
        graph.node(invis)
        graph.node(
            invis,
            color=self.bgcolor,
            len="0",
            shape="point",
            width="0",
            height="0",
        )
        first = True

        for block in blocks:
            graph.node(**self._block_node(block))
            if first:
                with graph.subgraph() as c:
                    c.attr(rank="same")
                    c.edge(self.block_node_name(block), invis, style="invis")
                first = False

            # Determine next hop based on block actions.
            self._set_next_node_from_block(block)

    def _set_next_node_from_block(self, block):
        """Create edges to other nodes based on the block's next RecircNodes
        and special actions."""
        created = False

        # Start edges from the "actions" port of the block node.
        name = self.block_node_name(block) + ":actions"

        # Deal with RecircNodes first.
        for node in block.next_recirc_nodes:
            # If the target recirculation cluster has not yet been created,
            # do it now.
            if (node.recirc, node.in_port) not in self.processed_recircs:
                self._create_recirc_cluster(node)

            cname = self.recirc_cluster_name(node)
            self._graph.edge(
                name,
                self.invis_node_name(cname),
                lhead=cname,
                _attributes={"weight": "20"},
            )
            created = True

        # Then, deal with special actions.
        created |= self._set_next_node_from_actions(
            name, block.flows[0].flow.actions
        )

        if not created:
            self._graph.edge(name, "end")

    def _set_next_node_from_actions(self, name, actions):
        """Create edges to other nodes based on the action list."""
        created = False

        for action in actions:
            key, value = next(iter(action.items()))
            if key == "check_pkt_len":
                created |= self._set_next_node_from_actions(
                    name, value.get("gt")
                )
                created |= self._set_next_node_from_actions(
                    name, value.get("le")
                )
            elif key == "sample":
                created |= self._set_next_node_from_actions(
                    name, value.get("actions")
                )
            elif key == "clone":
                created |= self._set_next_node_from_actions(
                    name, value.get("actions")
                )
            else:
                created |= self._set_next_node_action(name, key, value)
        return created

    def _set_next_node_action(self, name, action_name, action_obj):
        """Based on the action object, set the next node."""
        if action_name == "output":
            port = action_obj.get("port")
            if port not in self._output_nodes:
                self._output_nodes.append(port)
            self._graph.edge(
                name, self.output_node_name(port), _attributes={"weight": "1"}
            )
            return True
        elif action_name in ["drop", "userspace", "controller"]:
            if action_name not in self._output_nodes:
                self._output_nodes.append(action_name)
            self._graph.edge(name, action_name, _attributes={"weight": "1"})
            return True
        elif action_name == "ct":
            zone = action_obj.get("zone", 0)
            node_name = "CT zone {}".format(action_obj.get("zone", "default"))
            if zone not in self.ct_styles:
                # Pick a random (highly saturated) color.
                (r, g, b) = colorsys.hsv_to_rgb(random.random(), 1, 1)
                color = "#%02x%02x%02x" % (
                    int(r * 255),
                    int(g * 255),
                    int(b * 255),
                )
                self.ct_styles[zone] = color
                self._graph.node(node_name, color=color)

            color = self.ct_styles[zone]
            self._graph.edge(name, node_name, style="dashed", color=color)
            name = node_name
            return True
        return False

    def _populate_graph(self):
        """Populate the the internal graph."""
        self.processed_recircs = []

        # RecircNode clusters are created recursively when an edge is found
        # pointing to them. Therefore, starting with recirc = 0 nodes.
        for node in self._tree.recirc_nodes.get(0).values():
            if node.visible:
                self._create_recirc_cluster(node)

        # Create an input node that points to each input subgraph
        # They are all inside an anonymous subgraph so that they can be
        # alligned.
        with self._graph.subgraph() as s:
            s.attr(rank="same")
            for inport, node in self._tree.recirc_nodes.get(0).items():
                if not node.visible:
                    continue

                node_name = "input_{}".format(inport)
                cluster_name = self.recirc_cluster_name(node)
                s.node(
                    node_name,
                    shape="Mdiamond",
                    label="input port {}".format(inport),
                )
                self._graph.edge(
                    node_name,
                    self.invis_node_name(cluster_name),
                    lhead=cluster_name,
                    _attributes={"weight": "20"},
                )

        # Create the output nodes in a subgraph so that they are aligned.
        with self._graph.subgraph() as s:
            for port in self._output_nodes:
                s.attr(rank="same")
                if port == "drop":
                    s.node(
                        "drop",
                        shape="Msquare",
                        color="red",
                        label="DROP",
                        rank="sink",
                    )
                elif port == "controller":
                    s.node(
                        "controller",
                        shape="Msquare",
                        color="blue",
                        label="CONTROLLER",
                        rank="sink",
                    )
                elif port == "userspace":
                    s.node(
                        "userspace",
                        shape="Msquare",
                        color="blue",
                        label="CONTROLLER",
                        rank="sink",
                    )
                else:
                    s.node(
                        self.output_node_name(port),
                        shape="Msquare",
                        color="green",
                        label="Port {}".format(port),
                        rank="sink",
                    )

        # Print node style legend.
        with self._graph.subgraph(name="cluster_legend") as s:
            s.attr(label="Legend")
            for style in self.node_styles.values():
                s.node(name=style.get("desc"), _attributes=style.get("style"))
