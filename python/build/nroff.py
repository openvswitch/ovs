# Copyright (c) 2010, 2011, 2012, 2015 Nicira, Inc.
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

import re

from ovs.db import error

def text_to_nroff(s, font=r'\fR'):
    def escape(match):
        c = match.group(0)

        # In Roman type, let -- in XML be \- in nroff.  That gives us a way to
        # write minus signs, which is important in some places in manpages.
        #
        # Bold in nroff usually represents literal text, where there's no
        # distinction between hyphens and minus sign.  The convention in nroff
        # appears to be to use a minus sign in such cases, so we follow that
        # convention.
        #
        # Finally, we always output - as a minus sign when it is followed by a
        # digit.
        if c.startswith('-'):
            if c == '--' and font == r'\fR':
                return r'\-'
            if c != '-' or font in (r'\fB', r'\fL'):
                return c.replace('-', r'\-')
            else:
                return '-'

        if c == '\\':
            return r'\e'
        elif c == '"':
            return r'\(dq'
        elif c == "'":
            return r'\(cq'
        elif c == ".":
            # groff(7) says that . can be escaped by \. but in practice groff
            # still gives an error with \. at the beginning of a line.
            return r'\[char46]'
        else:
            raise error.Error("bad escape")

    # Escape - \ " ' . as needed by nroff.
    s = re.sub('(-[0-9]|--|[-"\'\\\\.])', escape, s)
    return s

def escape_nroff_literal(s, font=r'\fB'):
    return font + r'%s\fR' % text_to_nroff(s, font)

def inline_xml_to_nroff(node, font, to_upper=False):
    if node.nodeType == node.TEXT_NODE:
        if to_upper:
            return text_to_nroff(node.data.upper(), font)
        else:
            return text_to_nroff(node.data, font)
    elif node.nodeType == node.ELEMENT_NODE:
        if node.tagName in ['code', 'em', 'option', 'env']:
            s = r'\fB'
            for child in node.childNodes:
                s += inline_xml_to_nroff(child, r'\fB')
            return s + font
        elif node.tagName == 'ref':
            s = r'\fB'
            if node.hasAttribute('column'):
                s += node.attributes['column'].nodeValue
                if node.hasAttribute('key'):
                    s += ':' + node.attributes['key'].nodeValue
            elif node.hasAttribute('table'):
                s += node.attributes['table'].nodeValue
            elif node.hasAttribute('group'):
                s += node.attributes['group'].nodeValue
            elif node.hasAttribute('db'):
                s += node.attributes['db'].nodeValue
            else:
                raise error.Error("'ref' lacks required attributes: %s" % node.attributes.keys())
            return s + font
        elif node.tagName == 'var' or node.tagName == 'dfn':
            s = r'\fI'
            for child in node.childNodes:
                s += inline_xml_to_nroff(child, r'\fI')
            return s + font
        else:
            raise error.Error("element <%s> unknown or invalid here" % node.tagName)
    else:
        raise error.Error("unknown node %s in inline xml" % node)

def pre_to_nroff(nodes, para, font):
    s = para + '\n.nf\n'
    for node in nodes:
        if node.nodeType != node.TEXT_NODE:
            fatal("<pre> element may only have text children")
        for line in node.data.split('\n'):
            s += escape_nroff_literal(line, font) + '\n.br\n'
    s += '.fi\n'
    return s

def block_xml_to_nroff(nodes, para='.PP'):
    s = ''
    for node in nodes:
        if node.nodeType == node.TEXT_NODE:
            s += text_to_nroff(node.data)
            s = s.lstrip()
        elif node.nodeType == node.ELEMENT_NODE:
            if node.tagName in ['ul', 'ol']:
                if s != "":
                    s += "\n"
                s += ".RS\n"
                i = 0
                for li_node in node.childNodes:
                    if (li_node.nodeType == node.ELEMENT_NODE
                        and li_node.tagName == 'li'):
                        i += 1
                        if node.tagName == 'ul':
                            s += ".IP \\(bu\n"
                        else:
                            s += ".IP %d. .25in\n" % i
                        s += block_xml_to_nroff(li_node.childNodes, ".IP")
                    elif (li_node.nodeType != node.TEXT_NODE
                          or not li_node.data.isspace()):
                        raise error.Error("<%s> element may only have <li> children" % node.tagName)
                s += ".RE\n"
            elif node.tagName == 'dl':
                if s != "":
                    s += "\n"
                s += ".RS\n"
                prev = "dd"
                for li_node in node.childNodes:
                    if (li_node.nodeType == node.ELEMENT_NODE
                        and li_node.tagName == 'dt'):
                        if prev == 'dd':
                            s += '.TP\n'
                        else:
                            s += '.TQ .5in\n'
                        prev = 'dt'
                    elif (li_node.nodeType == node.ELEMENT_NODE
                          and li_node.tagName == 'dd'):
                        if prev == 'dd':
                            s += '.IP\n'
                        prev = 'dd'
                    elif (li_node.nodeType != node.TEXT_NODE
                          or not li_node.data.isspace()):
                        raise error.Error("<dl> element may only have <dt> and <dd> children")
                    s += block_xml_to_nroff(li_node.childNodes, ".IP")
                s += ".RE\n"
            elif node.tagName == 'p':
                if s != "":
                    if not s.endswith("\n"):
                        s += "\n"
                    s += para + "\n"
                s += block_xml_to_nroff(node.childNodes, para)
            elif node.tagName in ('h1', 'h2', 'h3'):
                if s != "":
                    if not s.endswith("\n"):
                        s += "\n"
                nroffTag = {'h1': 'SH', 'h2': 'SS', 'h3': 'ST'}[node.tagName]
                s += '.%s "' % nroffTag
                for child_node in node.childNodes:
                    s += inline_xml_to_nroff(child_node, r'\fR',
                                          to_upper=(nroffTag == 'SH'))
                s += '"\n'
            elif node.tagName == 'pre':
                fixed = node.getAttribute('fixed')
                if fixed == 'yes':
                    font = r'\fL'
                else:
                    font = r'\fB'
                s += pre_to_nroff(node.childNodes, para, font)
            else:
                s += inline_xml_to_nroff(node, r'\fR')
        else:
            raise error.Error("unknown node %s in block xml" % node)
    if s != "" and not s.endswith('\n'):
        s += '\n'
    return s
