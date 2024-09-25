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

from ovs.flowviz.html_format import HTMLBuffer, HTMLFormatter
from ovs.flowviz.odp.tree import FlowTree
from ovs.flowviz.process import FileProcessor


class HTMLTree:
    """Class capable of printing a FlowTree in HTML."""

    BODY_STYLE = """
    <style>
    body {{
        background-color: {bg};
        color: {fg};
    }}
    </style>"""

    STYLE = """
    <style>
    .recirc {
        font-weight: bold;
        font-family: monospace;
        font-size: 1.1rem;
        border: 3px solid #ccc;
        width: fit-content;
        block-size: fit-content;
    }

    .block-matches {
        font-family: monospace;
        border: 1px solid #ccc;
        width: fit-content;
        block-size: fit-content;
        margin-left: 1em;
        padding: 4px;
    }

    .block-actions {
        font-family: monospace;
        border: 2px solid #ccc;
        width: fit-content;
        block-size: fit-content;
        margin-top: 0.5em;
        margin-bottom : 2em;
        margin-left: 1em;
        padding: 4px;
    }

    /* List styling */
    ul il {
        list-style-type: disc;
    }

    .flowlist > li::marker {
        list-style: disc;
    }

    .actions > li::marker  {
        content: "\\21B3";
        font-size: 1.5em;
    }

    /* Caret styling */
    .caret {
        cursor: pointer;
        user-select: none;
    }

    .caret::before {
        content: "\\25B6";
        font-size: 1.2em;
        display: inline-block;
        margin-right: 5px;cursor: pointer;
    }

    /* Rotate the caret/arrow icon when clicked on. */
    .caret-down::before {
        transform: rotate(90deg);
    }

    .nested {
        display: none;
    }

    .active {
        display: block;
    }

    .focused {
        border: 2px solid #0008ff;
    }
    </style>
    """  # noqa: E501

    SCRIPT = """
    <script>
    var caret = document.getElementsByClassName("caret");
    var blocks = document.getElementsByClassName("block-matches");
    var i;

    for (i = 0; i < caret.length; i++) {
        caret[i].addEventListener("click", function() {
            this.parentElement.querySelector(".nested").classList.toggle("active");
            this.classList.toggle("caret-down");
        });
    }

    // Set focus to a flow block, expanding all parent elements.
    function setFocus(targetId) {
        var target = document.getElementById(targetId);
        var others = document.getElementsByClassName("focused");
        var i;
        for (i = 0; i < others.length; i++) {
            others[i].classList.remove("focused");
        }
        if (target) {
            var element = target;
            while (element !== null) {
            if (element.classList.contains("nested")) {
                element.classList.add("active");
            }
            if (element.previousElementSibling && element.previousElementSibling.classList.contains("caret")) {
                element.previousElementSibling.classList.add("caret-down");
            }
            element = element.parentElement;
            }
        }
        target.classList.toggle("focused");
    }

    window.addEventListener('hashchange', function () {
        var targetId = window.location.hash.substring(1);
        setFocus(targetId);
    });
    </script>
    """  # noqa: E501

    def __init__(self, name, flowtree, opts):
        self.name = name.replace(" ", "_")
        self.tree = flowtree
        self.opts = opts
        self.formatter = HTMLFormatter(opts)

    @classmethod
    def head(cls):
        html = "<head>"
        html += cls.STYLE
        html += "</head>"

        return html

    @classmethod
    def begin_body(cls, opts):
        style = HTMLFormatter(opts).style
        bg = (
            style.get("background").color
            if style.get("background")
            else "#f0f0f0"
        )
        fg = style.get("default").color if style.get("default") else "black"
        return cls.BODY_STYLE.format(bg=bg, fg=fg)

    @classmethod
    def end_body(cls):
        return cls.SCRIPT

    def format(self):
        html_obj = f"<div id=flow_list-{self.name}>"

        html_obj += '<ul class="active flowlist">'
        for in_port in sorted(self.tree.recirc_nodes[0].keys()):
            node = self.tree.recirc_nodes[0][in_port]
            if node.visible:
                html_obj += "<li>"
                html_obj += self.format_recirc_node(node)
                html_obj += "</li>"

        html_obj += "</ul>"
        html_obj += "</div>"
        return html_obj

    def format_recirc_node(self, node):
        html_obj = '<div class="recirc">'
        html_obj += "[recirc_id({}) in_port({})]".format(
            hex(node.recirc), node.in_port
        )
        html_obj += "</div>"

        html_obj += '<ul class="flowlist">'  # nested

        for block in node.visible_blocks():
            html_block = "<li>"
            html_block += self.format_block(block)
            html_block += "</li>"
            html_obj += html_block

        html_obj += "</ul>"
        return html_obj

    def format_single_block(self, block):
        block_id = "block_{}".format(block.flows[0].flow.id)
        html_obj = f'<div id="{block_id}" class="block-matches">'

        omit_first = {
            "actions": "all",
        }
        omit_rest = {
            "actions": "all",
            "match": [kv.key for _, kv in block.equal_match],
        }

        for i, flow in enumerate(filter(lambda x: x.visible, block.flows)):
            html_obj += '<div class="flow">'

            omit = omit_rest if i > 0 else omit_first
            buf = HTMLBuffer()
            hl = None
            if self.opts.get("highlight"):
                result = self.opts.get("highlight").evaluate(flow.flow)
                if result:
                    hl = result.kv

            self.formatter.format_flow(buf, flow.flow, hl, omitted=omit)
            html_obj += buf.text
            html_obj += "</div>"

        html_obj += "</div>"  # Match list.

        html_obj += '<ul class="actions"><li>'
        html_obj += "<div>"  # Match list.
        if block.next_recirc_nodes:
            html_obj += '<div class="caret block-actions">'
        else:
            html_obj += '<div class="block-actions">'

        omit = {
            "match": "all",
            "info": "all",
            "ufid": "all",
            "dp_extra_info": "all",
        }
        buf = HTMLBuffer()
        buf.append_extra("actions: ", None)

        hl = None
        if self.opts.get("highlight"):
            result = self.opts.get("highlight").evaluate(block.flows[0].flow)
            if result:
                hl = result.kv

        self.formatter.format_flow(buf, block.flows[0].flow, hl, omitted=omit)
        html_obj += buf.text
        html_obj += "</div>"
        return html_obj

    def format_block(self, block):
        html_obj = self.format_single_block(block)

        html_obj += '<ul class="nested recirclist">'
        for node in block.next_recirc_nodes:
            if node.visible:
                html_obj += "<li>"
                html_obj += self.format_recirc_node(node)
                html_obj += "</li>"
        html_obj += "</ul>"
        html_obj += "</li>"
        html_obj += "</ul>"
        return html_obj


class HTMLTreeProcessor(FileProcessor):
    def __init__(self, opts):
        super().__init__(opts, "odp")
        self.trees = {}
        self.opts = opts
        self.tree = None
        self.curr_file = ""

    def start_file(self, name, filename):
        self.tree = FlowTree()
        self.curr_file = name

    def start_thread(self, name):
        if not self.tree:
            self.tree = FlowTree()

    def stop_thread(self, name):
        full_name = self.curr_file + f" ({name})"
        if self.tree:
            self.trees[full_name] = self.tree
            self.tree = None

    def process_flow(self, flow, name):
        self.tree.add(flow, self.opts.get("filter"))

    def process(self):
        super().process(False)

    def stop_file(self, name, filename):
        if self.tree:
            self.trees[name] = self.tree
            self.tree = None

    def print(self):
        html_obj = "<html>"
        html_obj += "<head>"
        html_obj += HTMLTree.head()
        html_obj += "</head>"

        html_obj += "<body>"
        html_obj += HTMLTree.begin_body(self.opts)

        for name, tree in self.trees.items():
            tree.build()
            html_tree = HTMLTree(name, tree, self.opts)
            html_obj += "<div>"
            html_obj += "<h2>{}</h2>".format(name)
            html_obj += html_tree.format()
            html_obj += "</div>"

        html_obj += HTMLTree.end_body()
        html_obj += "</body>"
        html_obj += "</html>"
        print(html_obj)
