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
import sys

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


def inline_xml_to_nroff(node, font, to_upper=False, newline='\n'):
    if node.nodeType == node.TEXT_NODE:
        if to_upper:
            s = text_to_nroff(node.data.upper(), font)
        else:
            s = text_to_nroff(node.data, font)
        return s.replace('\n', newline)
    elif node.nodeType == node.ELEMENT_NODE:
        if node.tagName in ['code', 'em', 'option', 'env', 'b']:
            s = r'\fB'
            for child in node.childNodes:
                s += inline_xml_to_nroff(child, r'\fB', to_upper, newline)
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
                raise error.Error("'ref' lacks required attributes: %s"
                                  % list(node.attributes.keys()))
            return s + font
        elif node.tagName in ['var', 'dfn', 'i']:
            s = r'\fI'
            for child in node.childNodes:
                s += inline_xml_to_nroff(child, r'\fI', to_upper, newline)
            return s + font
        else:
            raise error.Error("element <%s> unknown or invalid here"
                              % node.tagName)
    elif node.nodeType == node.COMMENT_NODE:
        return ''
    else:
        raise error.Error("unknown node %s in inline xml" % node)


def pre_to_nroff(nodes, para, font):
    # This puts 'font' at the beginning of each line so that leading and
    # trailing whitespace stripping later doesn't removed leading spaces
    # from preformatted text.
    s = para + '\n.nf\n' + font
    for node in nodes:
        s += inline_xml_to_nroff(node, font, False, '\n.br\n' + font)
    s += '\n.fi\n'
    return s


def fatal(msg):
    sys.stderr.write('%s\n' % msg)
    sys.exit(1)


def diagram_header_to_nroff(header_node):
    header_fields = []
    i = 0
    for node in header_node.childNodes:
        if node.nodeType == node.ELEMENT_NODE and node.tagName == 'bits':
            name = node.attributes['name'].nodeValue
            width = node.attributes['width'].nodeValue
            above = node.getAttribute('above')
            below = node.getAttribute('below')
            fill = node.getAttribute('fill')
            header_fields += [{"name": name,
                              "tag": "B%d" % i,
                              "width": width,
                              "above": above,
                              "below": below,
                              "fill": fill}]
            i += 1
        elif node.nodeType == node.COMMENT_NODE:
            pass
        elif node.nodeType == node.TEXT_NODE and node.data.isspace():
            pass
        else:
            fatal("unknown node %s in diagram <header> element" % node)

    pic_s = ""
    for f in header_fields:
        pic_s += "  %s: box \"%s\" width %s" % (f['tag'], f['name'],
                                                f['width'])
        if f['fill'] == 'yes':
            pic_s += " fill"
        pic_s += '\n'
    for f in header_fields:
        pic_s += "  \"%s\" at %s.n above\n" % (f['above'], f['tag'])
        pic_s += "  \"%s\" at %s.s below\n" % (f['below'], f['tag'])
    name = header_node.getAttribute('name')
    if name == "":
        visible = " invis"
    else:
        visible = ""
    pic_s += "line <->%s \"%s\" above " % (visible, name)
    pic_s += "from %s.nw + (0,textht) " % header_fields[0]['tag']
    pic_s += "to %s.ne + (0,textht)\n" % header_fields[-1]['tag']

    text_s = ""
    for f in header_fields:
        text_s += """.IP \\(bu
%s bits""" % (f['above'])
        if f['name']:
            text_s += ": %s" % f['name']
        if f['below']:
            text_s += " (%s)" % f['below']
        text_s += "\n"
    return pic_s, text_s


def diagram_to_nroff(nodes, para):
    pic_s = ''
    text_s = ''
    move = False
    for node in nodes:
        if node.nodeType == node.ELEMENT_NODE and node.tagName == 'header':
            if move:
                pic_s += "move .1\n"
                text_s += ".sp\n"
            pic_header, text_header = diagram_header_to_nroff(node)
            pic_s += "[\n" + pic_header + "]\n"
            text_s += text_header
            move = True
        elif node.nodeType == node.ELEMENT_NODE and node.tagName == 'nospace':
            move = False
        elif node.nodeType == node.ELEMENT_NODE and node.tagName == 'dots':
            pic_s += "move .1\n"
            pic_s += '". . ." ljust\n'
            text_s += ".sp\n"
        elif node.nodeType == node.COMMENT_NODE:
            pass
        elif node.nodeType == node.TEXT_NODE and node.data.isspace():
            pass
        else:
            fatal("unknown node %s in diagram <header> element" % node)
    return para + """
.\\" check if in troff mode (TTY)
.if t \{
.PS
boxht = .2
textht = 1/6
fillval = .2
""" + pic_s + """\
.PE
\\}
.\\" check if in nroff mode:
.if n \{
.RS
""" + text_s + """\
.RE
\\}"""


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
                    elif li_node.nodeType == node.COMMENT_NODE:
                        pass
                    elif (li_node.nodeType != node.TEXT_NODE
                          or not li_node.data.isspace()):
                        raise error.Error("<%s> element may only have "
                                          "<li> children" % node.tagName)
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
                    elif li_node.nodeType == node.COMMENT_NODE:
                        continue
                    elif (li_node.nodeType != node.TEXT_NODE
                          or not li_node.data.isspace()):
                        raise error.Error("<dl> element may only have "
                                          "<dt> and <dd> children")
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
            elif node.tagName == 'diagram':
                s += diagram_to_nroff(node.childNodes, para)
            else:
                s += inline_xml_to_nroff(node, r'\fR')
        elif node.nodeType == node.COMMENT_NODE:
            pass
        else:
            raise error.Error("unknown node %s in block xml" % node)
    if s != "" and not s.endswith('\n'):
        s += '\n'
    return s
