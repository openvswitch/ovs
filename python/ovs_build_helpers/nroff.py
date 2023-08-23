# Copyright (c) 2010, 2011, 2012, 2015, 2016, 2017 Nicira, Inc.
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


def text_to_nroff(s, font=r'\fR', escape_dot=True):
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
            if escape_dot:
                # groff(7) says that . can be escaped by \. but in practice
                # groff still gives an error with \. at the beginning of a
                # line.
                return r'\[char46]'
            else:
                return '.'
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
            if node.hasAttribute('column'):
                s = node.attributes['column'].nodeValue
                if node.hasAttribute('key'):
                    s += ':' + node.attributes['key'].nodeValue
            elif node.hasAttribute('table'):
                s = node.attributes['table'].nodeValue
            elif node.hasAttribute('group'):
                s = node.attributes['group'].nodeValue
            elif node.hasAttribute('db'):
                s = node.attributes['db'].nodeValue
            elif node.hasAttribute('field'):
                s = node.attributes['field'].nodeValue
            elif node.hasAttribute('section'):
                s = node.attributes['section'].nodeValue
            else:
                raise error.Error("'ref' lacks required attributes: %s"
                                  % list(node.attributes.keys()))
            return r'\fB' + re.sub(r'\s+', ' ', s) + font
        elif node.tagName in ['var', 'dfn', 'i', 'cite']:
            s = r'\fI'
            for child in node.childNodes:
                s += inline_xml_to_nroff(child, r'\fI', to_upper, newline)
            return s + font
        elif node.tagName in ['literal']:
            s = r'\fL'
            for child in node.childNodes:
                s += inline_xml_to_nroff(child, r'\fL')
            return s + font
        elif node.tagName == 'url':
            return ('\n.URL "'
                    + text_to_nroff(node.attributes['href'].nodeValue,
                                    escape_dot=False)
                    + '"\n')
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
        s += inline_xml_to_nroff(node, font, False, '\n.br\n' + font) + '\\fR'
    s += '\n.fi\n'
    return s


def tbl_to_nroff(nodes, para):
    s = para + '\n.TS\n'
    for node in nodes:
        if node.nodeType != node.TEXT_NODE:
            fatal("<tbl> element may only have text children")
        s += node.data + '\n'
    s += '.TE\n'
    return s


def fatal(msg):
    sys.stderr.write('%s\n' % msg)
    sys.exit(1)


def put_text(text, x, y, s):
    x = int(x)
    y = int(y)
    extend = x + len(s) - len(text[y])
    if extend > 0:
        text[y] += ' ' * extend
    text[y] = text[y][:x] + s + text[y][x + len(s):]


def put_centered(text, x, width, y, s):
    put_text(text, x + (width - len(s)) / 2, y, s)


def diagram_header_to_nroff(header_node, text, x):
    # Parse header.
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

    # Format pic version.
    pic_s = ""
    for f in header_fields:
        name = f['name'].replace('...', '. . .')
        pic_s += "  %s: box \"%s\" width %s" % (f['tag'], name, f['width'])
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

    # Format text version.
    header_width = 1
    for f in header_fields:
        field_width = max(len(f['above']), len(f['below']), len(f['name']))
        f['width'] = field_width
        header_width += field_width + 1
    min_header_width = 2 + len(name)
    while min_header_width > header_width:
        for f in header_fields:
            f['width'] += 1
            header_width += 1
            if header_width >= min_header_width:
                break

    if name != "":
        put_centered(text, x, header_width, 0, name)
        if header_width >= 4:
            arrow = '<' + '-' * (header_width - 4) + '>'
            put_text(text, x + 1, 1, arrow)
    for f in header_fields:
        box1 = '+' + '-' * f['width'] + '+'
        box2 = '|' + ' ' * f['width'] + '|'
        put_text(text, x, 3, box1)
        put_text(text, x, 4, box2)
        put_text(text, x, 5, box1)

        put_centered(text, x + 1, f['width'], 2, f['above'])
        put_centered(text, x + 1, f['width'], 4, f['name'])
        put_centered(text, x + 1, f['width'], 6, f['below'])

        x += f['width'] + 1

    return pic_s, x + 1


def diagram_to_nroff(nodes, para):
    pic_s = ''
    text = [''] * 7
    x = 0
    move = False
    for node in nodes:
        if node.nodeType == node.ELEMENT_NODE and node.tagName == 'header':
            if move:
                pic_s += "move .1\n"
                x += 1
            elif x > 0:
                x -= 1
            pic_header, x = diagram_header_to_nroff(node, text, x)
            pic_s += "[\n" + pic_header + "]\n"
            move = True
        elif node.nodeType == node.ELEMENT_NODE and node.tagName == 'nospace':
            move = False
        elif node.nodeType == node.ELEMENT_NODE and node.tagName == 'dots':
            pic_s += "move .1\n"
            pic_s += '". . ." ljust\n'

            put_text(text, x, 4, " ... ")
            x += 5
        elif node.nodeType == node.COMMENT_NODE:
            pass
        elif node.nodeType == node.TEXT_NODE and node.data.isspace():
            pass
        else:
            fatal("unknown node %s in diagram <header> element" % node)

    text_s = '.br\n'.join(["\\fL%s\n" % s for s in text if s != ""])
    return para + """
.\\" check if in troff mode (TTY)
.if t \\{
.PS
boxht = .2
textht = 1/6
fillval = .2
""" + pic_s + """\
.PE
\\}
.\\" check if in nroff mode:
.if n \\{
.nf
""" + text_s + """\
.fi
\\}"""


def flatten_header(s):
    s = s.strip()
    return re.sub(r'\s+', ' ', s)


def block_xml_to_nroff(nodes, para='.PP'):
    HEADER_TAGS = ('h1', 'h2', 'h3', 'h4')
    s = ''
    prev = ''
    for node in nodes:
        if node.nodeType == node.TEXT_NODE:
            if s == '' and para != '.IP':
                s = para + '\n'
            text = re.sub(r'\s+', ' ', node.data)
            if s.endswith(' '):
                text = text.lstrip()
            s += text_to_nroff(text)
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
                            s += ".IP %d. .4in\n" % i
                        s += block_xml_to_nroff(li_node.childNodes, ".IP")
                    elif li_node.nodeType == node.COMMENT_NODE:
                        pass
                    elif (li_node.nodeType != node.TEXT_NODE
                          or not li_node.data.isspace()):
                        raise error.Error("<%s> element may only have "
                                          "<li> children" % node.tagName)
                s += ".RE\n"
            elif node.tagName == 'dl':
                indent = True
                if prev in HEADER_TAGS:
                    indent = False
                if s != "":
                    s += "\n"
                if indent:
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
                if indent:
                    s += ".RE\n"
            elif node.tagName == 'p':
                if s != "":
                    if not s.endswith("\n"):
                        s += "\n"
                    s += para + "\n"
                s += block_xml_to_nroff(node.childNodes, para)
            elif node.tagName in HEADER_TAGS:
                if s != "":
                    if not s.endswith("\n"):
                        s += "\n"
                nroffTag, font = {'h1': ('SH', r'\fR'),
                                  'h2': ('SS', r'\fB'),
                                  'h3': ('ST', r'\fI'),
                                  'h4': ('SU', r'\fI')}[node.tagName]
                to_upper = node.tagName == 'h1'
                s += ".%s \"" % nroffTag
                s += flatten_header(''.join([
                    inline_xml_to_nroff(child_node, font, to_upper)
                    for child_node in node.childNodes]))
                s += "\"\n"
            elif node.tagName == 'pre':
                fixed = node.getAttribute('fixed')
                if fixed == 'yes':
                    font = r'\fL'
                else:
                    font = r'\fB'
                s += pre_to_nroff(node.childNodes, para, font)
            elif node.tagName == 'tbl':
                s += tbl_to_nroff(node.childNodes, para)
            elif node.tagName == 'diagram':
                s += diagram_to_nroff(node.childNodes, para)
            else:
                s += inline_xml_to_nroff(node, r'\fR')
            prev = node.tagName
        elif node.nodeType == node.COMMENT_NODE:
            pass
        else:
            raise error.Error("unknown node %s in block xml" % node)
    if s != "" and not s.endswith('\n'):
        s += '\n'
    return s
