# Copyright (c) 2010, 2011, 2012 Nicira, Inc.
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

from __future__ import absolute_import

import functools
import json
import re
import sys

PARSER_C = 'C'
PARSER_PY = 'PYTHON'
try:
    import ovs._json
    PARSER = PARSER_C
except ImportError:
    PARSER = PARSER_PY

__pychecker__ = 'no-stringiter'

SPACES_PER_LEVEL = 2
dumper = functools.partial(json.dumps, separators=(",", ":"))


def to_stream(obj, stream, pretty=False, sort_keys=True):
    stream.write(dumper(obj, indent=SPACES_PER_LEVEL if pretty else None,
                        sort_keys=sort_keys))


def to_file(obj, name, pretty=False, sort_keys=True):
    with open(name, "w") as stream:
        to_stream(obj, stream, pretty, sort_keys)


def to_string(obj, pretty=False, sort_keys=True):
    return dumper(obj, indent=SPACES_PER_LEVEL if pretty else None,
                  sort_keys=sort_keys)


def from_stream(stream):
    p = Parser(check_trailer=True)
    while True:
        buf = stream.read(4096)
        if buf == "" or p.feed(buf) != len(buf):
            break
    return p.finish()


def from_file(name):
    stream = open(name, "r")
    try:
        return from_stream(stream)
    finally:
        stream.close()


def from_string(s):
    if not isinstance(s, str):
        # We assume the input is a string.  We will only hit this case for a
        # str in Python 2 which is not unicode, so we need to go ahead and
        # decode it.
        try:
            s = str(s, 'utf-8')
        except UnicodeDecodeError as e:
            seq = ' '.join(["0x%2x" % ord(c)
                           for c in e.object[e.start:e.end] if ord(c) >= 0x80])
            return "not a valid UTF-8 string: invalid UTF-8 sequence %s" % seq
    p = Parser(check_trailer=True)
    p.feed(s)
    return p.finish()


class Parser(object):
    # Maximum height of parsing stack. #
    MAX_HEIGHT = 1000

    def __new__(cls, *args, **kwargs):
        if PARSER == PARSER_C:
            return ovs._json.Parser(*args, **kwargs)
        return super(Parser, cls).__new__(cls)

    def __init__(self, check_trailer=False):
        self.check_trailer = check_trailer

        # Lexical analysis.
        self.lex_state = Parser.__lex_start
        self.buffer = ""
        self.line_number = 0
        self.column_number = 0
        self.byte_number = 0

        # Parsing.
        self.parse_state = Parser.__parse_start
        self.stack = []
        self.member_name = None

        # Parse status.
        self.done = False
        self.error = None

    def __lex_start_space(self, c):
        pass

    def __lex_start_alpha(self, c):
        self.buffer = c
        self.lex_state = Parser.__lex_keyword

    def __lex_start_token(self, c):
        self.__parser_input(c)

    def __lex_start_number(self, c):
        self.buffer = c
        self.lex_state = Parser.__lex_number

    def __lex_start_string(self, _):
        self.lex_state = Parser.__lex_string

    def __lex_start_error(self, c):
        if ord(c) >= 32 and ord(c) < 128:
            self.__error("invalid character '%s'" % c)
        else:
            self.__error("invalid character U+%04x" % ord(c))

    __lex_start_actions = {}
    for c in " \t\n\r":
        __lex_start_actions[c] = __lex_start_space
    for c in "abcdefghijklmnopqrstuvwxyz":
        __lex_start_actions[c] = __lex_start_alpha
    for c in "[{]}:,":
        __lex_start_actions[c] = __lex_start_token
    for c in "-0123456789":
        __lex_start_actions[c] = __lex_start_number
    __lex_start_actions['"'] = __lex_start_string

    def __lex_start(self, c):
        Parser.__lex_start_actions.get(
            c, Parser.__lex_start_error)(self, c)
        return True

    __lex_alpha = {}
    for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
        __lex_alpha[c] = True

    def __lex_finish_keyword(self):
        if self.buffer == "false":
            self.__parser_input(False)
        elif self.buffer == "true":
            self.__parser_input(True)
        elif self.buffer == "null":
            self.__parser_input(None)
        else:
            self.__error("invalid keyword '%s'" % self.buffer)

    def __lex_keyword(self, c):
        if c in Parser.__lex_alpha:
            self.buffer += c
            return True
        else:
            self.__lex_finish_keyword()
            return False

    __number_re = re.compile("(-)?(0|[1-9][0-9]*)"
            r"(?:\.([0-9]+))?(?:[eE]([-+]?[0-9]+))?$")

    def __lex_finish_number(self):
        s = self.buffer
        m = Parser.__number_re.match(s)
        if m:
            sign, integer, fraction, exp = m.groups()
            if (exp is not None and
                (int(exp) > sys.maxsize or int(exp) < -sys.maxsize - 1)):
                self.__error("exponent outside valid range")
                return

            if fraction is not None and len(fraction.lstrip('0')) == 0:
                fraction = None

            sig_string = integer
            if fraction is not None:
                sig_string += fraction
            significand = int(sig_string)

            pow10 = 0
            if fraction is not None:
                pow10 -= len(fraction)
            if exp is not None:
                pow10 += int(exp)

            if significand == 0:
                self.__parser_input(0)
                return
            elif significand <= 2 ** 63:
                while pow10 > 0 and significand <= 2 ** 63:
                    significand *= 10
                    pow10 -= 1
                while pow10 < 0 and significand % 10 == 0:
                    significand //= 10
                    pow10 += 1
                if (pow10 == 0 and
                    ((not sign and significand < 2 ** 63) or
                     (sign and significand <= 2 ** 63))):
                    if sign:
                        self.__parser_input(-significand)
                    else:
                        self.__parser_input(significand)
                    return

            value = float(s)
            if value == float("inf") or value == float("-inf"):
                self.__error("number outside valid range")
                return
            if value == 0:
                # Suppress negative zero.
                value = 0
            self.__parser_input(value)
        elif re.match("-?0[0-9]", s):
            self.__error("leading zeros not allowed")
        elif re.match("-([^0-9]|$)", s):
            self.__error("'-' must be followed by digit")
        elif re.match(r"-?(0|[1-9][0-9]*)\.([^0-9]|$)", s):
            self.__error("decimal point must be followed by digit")
        elif re.search("e[-+]?([^0-9]|$)", s):
            self.__error("exponent must contain at least one digit")
        else:
            self.__error("syntax error in number")

    def __lex_number(self, c):
        if c in ".0123456789eE-+":
            self.buffer += c
            return True
        else:
            self.__lex_finish_number()
            return False

    __4hex_re = re.compile("[0-9a-fA-F]{4}")

    def __lex_4hex(self, s):
        if len(s) < 4:
            self.__error("quoted string ends within \\u escape")
        elif not Parser.__4hex_re.match(s):
            self.__error("malformed \\u escape")
        elif s == "0000":
            self.__error("null bytes not supported in quoted strings")
        else:
            return int(s, 16)

    @staticmethod
    def __is_leading_surrogate(c):
        """Returns true if 'c' is a Unicode code point for a leading
        surrogate."""
        return c >= 0xd800 and c <= 0xdbff

    @staticmethod
    def __is_trailing_surrogate(c):
        """Returns true if 'c' is a Unicode code point for a trailing
        surrogate."""
        return c >= 0xdc00 and c <= 0xdfff

    @staticmethod
    def __utf16_decode_surrogate_pair(leading, trailing):
        """Returns the unicode code point corresponding to leading surrogate
        'leading' and trailing surrogate 'trailing'.  The return value will not
        make any sense if 'leading' or 'trailing' are not in the correct ranges
        for leading or trailing surrogates."""
        #  Leading surrogate:         110110wwwwxxxxxx
        # Trailing surrogate:         110111xxxxxxxxxx
        #         Code point: 000uuuuuxxxxxxxxxxxxxxxx
        w = (leading >> 6) & 0xf
        u = w + 1
        x0 = leading & 0x3f
        x1 = trailing & 0x3ff
        return (u << 16) | (x0 << 10) | x1
    __unescape = {'"': u'"',
                  "\\": u"\\",
                  "/": u"/",
                  "b": u"\b",
                  "f": u"\f",
                  "n": u"\n",
                  "r": u"\r",
                  "t": u"\t"}

    def __lex_finish_string(self):
        inp = self.buffer
        out = u""
        while len(inp):
            backslash = inp.find('\\')
            if backslash == -1:
                out += inp
                break
            out += inp[:backslash]
            inp = inp[backslash + 1:]
            if inp == "":
                self.__error("quoted string may not end with backslash")
                return

            replacement = Parser.__unescape.get(inp[0])
            if replacement is not None:
                out += replacement
                inp = inp[1:]
                continue
            elif inp[0] != u'u':
                self.__error("bad escape \\%s" % inp[0])
                return

            c0 = self.__lex_4hex(inp[1:5])
            if c0 is None:
                return
            inp = inp[5:]

            if Parser.__is_leading_surrogate(c0):
                if inp[:2] != u'\\u':
                    self.__error("malformed escaped surrogate pair")
                    return
                c1 = self.__lex_4hex(inp[2:6])
                if c1 is None:
                    return
                if not Parser.__is_trailing_surrogate(c1):
                    self.__error("second half of escaped surrogate pair is "
                                 "not trailing surrogate")
                    return
                code_point = Parser.__utf16_decode_surrogate_pair(c0, c1)
                inp = inp[6:]
            else:
                code_point = c0
            out += chr(code_point)
        self.__parser_input('string', out)

    def __lex_string_escape(self, c):
        self.buffer += c
        self.lex_state = Parser.__lex_string
        return True

    def __lex_string(self, c):
        if c == '\\':
            self.buffer += c
            self.lex_state = Parser.__lex_string_escape
        elif c == '"':
            self.__lex_finish_string()
        elif ord(c) >= 0x20:
            self.buffer += c
        else:
            self.__error("U+%04X must be escaped in quoted string" % ord(c))
        return True

    def __lex_input(self, c):
        eat = self.lex_state(self, c)
        assert eat is True or eat is False
        return eat

    def __parse_start(self, token, unused_string):
        if token == '{':
            self.__push_object()
        elif token == '[':
            self.__push_array()
        else:
            self.__error("syntax error at beginning of input")

    def __parse_end(self, unused_token, unused_string):
        self.__error("trailing garbage at end of input")

    def __parse_object_init(self, token, string):
        if token == '}':
            self.__parser_pop()
        else:
            self.__parse_object_name(token, string)

    def __parse_object_name(self, token, string):
        if token == 'string':
            self.member_name = string
            self.parse_state = Parser.__parse_object_colon
        else:
            self.__error("syntax error parsing object expecting string")

    def __parse_object_colon(self, token, unused_string):
        if token == ":":
            self.parse_state = Parser.__parse_object_value
        else:
            self.__error("syntax error parsing object expecting ':'")

    def __parse_object_value(self, token, string):
        self.__parse_value(token, string, Parser.__parse_object_next)

    def __parse_object_next(self, token, unused_string):
        if token == ",":
            self.parse_state = Parser.__parse_object_name
        elif token == "}":
            self.__parser_pop()
        else:
            self.__error("syntax error expecting '}' or ','")

    def __parse_array_init(self, token, string):
        if token == ']':
            self.__parser_pop()
        else:
            self.__parse_array_value(token, string)

    def __parse_array_value(self, token, string):
        self.__parse_value(token, string, Parser.__parse_array_next)

    def __parse_array_next(self, token, unused_string):
        if token == ",":
            self.parse_state = Parser.__parse_array_value
        elif token == "]":
            self.__parser_pop()
        else:
            self.__error("syntax error expecting ']' or ','")

    def __parser_input(self, token, string=None):
        self.lex_state = Parser.__lex_start
        self.buffer = ""
        self.parse_state(self, token, string)

    def __put_value(self, value):
        top = self.stack[-1]
        if isinstance(top, dict):
            top[self.member_name] = value
        else:
            top.append(value)

    def __parser_push(self, new_json, next_state):
        if len(self.stack) < Parser.MAX_HEIGHT:
            if len(self.stack) > 0:
                self.__put_value(new_json)
            self.stack.append(new_json)
            self.parse_state = next_state
        else:
            self.__error("input exceeds maximum nesting depth %d" %
                         Parser.MAX_HEIGHT)

    def __push_object(self):
        self.__parser_push({}, Parser.__parse_object_init)

    def __push_array(self):
        self.__parser_push([], Parser.__parse_array_init)

    def __parser_pop(self):
        if len(self.stack) == 1:
            self.parse_state = Parser.__parse_end
            if not self.check_trailer:
                self.done = True
        else:
            self.stack.pop()
            top = self.stack[-1]
            if isinstance(top, list):
                self.parse_state = Parser.__parse_array_next
            else:
                self.parse_state = Parser.__parse_object_next

    def __parse_value(self, token, string, next_state):
        number_types = [int]
        number_types.extend([float])
        number_types = tuple(number_types)
        if token in [False, None, True] or isinstance(token, number_types):
            self.__put_value(token)
        elif token == 'string':
            self.__put_value(string)
        else:
            if token == '{':
                self.__push_object()
            elif token == '[':
                self.__push_array()
            else:
                self.__error("syntax error expecting value")
            return
        self.parse_state = next_state

    def __error(self, message):
        if self.error is None:
            self.error = ("line %d, column %d, byte %d: %s"
                          % (self.line_number, self.column_number,
                             self.byte_number, message))
            self.done = True

    def feed(self, s):
        i = 0
        while True:
            if self.done or i >= len(s):
                return i

            c = s[i]
            if self.__lex_input(c):
                self.byte_number += 1
                if c == '\n':
                    self.column_number = 0
                    self.line_number += 1
                else:
                    self.column_number += 1

                i += 1

    def is_done(self):
        return self.done

    def finish(self):
        if self.lex_state == Parser.__lex_start:
            pass
        elif self.lex_state in (Parser.__lex_string,
                                Parser.__lex_string_escape):
            self.__error("unexpected end of input in quoted string")
        else:
            self.__lex_input(" ")

        if self.parse_state == Parser.__parse_start:
            self.__error("empty input stream")
        elif self.parse_state != Parser.__parse_end:
            self.__error("unexpected end of input")

        if self.error is None:
            assert len(self.stack) == 1
            return self.stack.pop()
        else:
            return self.error
