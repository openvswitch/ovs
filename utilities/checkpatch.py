#!/usr/bin/env python
# Copyright (c) 2016 Red Hat, Inc.
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
from __future__ import print_function

import email
import getopt
import re
import sys

__errors = 0
__warnings = 0


def print_error(message, lineno=None):
    global __errors
    if lineno is not None:
        print("E(%d): %s" % (lineno, message))
    else:
        print("E: %s" % (message))

    __errors = __errors + 1


def print_warning(message, lineno=None):
    global __warnings
    if lineno:
        print("W(%d): %s" % (lineno, message))
    else:
        print("W: %s" % (message))

    __warnings = __warnings + 1


__regex_added_line = re.compile(r'^\+{1,2}[^\+][\w\W]*')
__regex_leading_with_whitespace_at_all = re.compile(r'^\s+')
__regex_leading_with_spaces = re.compile(r'^ +[\S]+')
__regex_trailing_whitespace = re.compile(r'[^\S]+$')
__regex_single_line_feed = re.compile(r'^\f$')
__regex_for_if_missing_whitespace = re.compile(r'(if|for|while)[\(]')
__regex_for_if_too_much_whitespace = re.compile(r'(if|for|while)  +[\(]')
__regex_for_if_parens_whitespace = re.compile(r'(if|for|while) \( +[\s\S]+\)')
__regex_is_for_if_single_line_bracket = \
    re.compile(r'^ +(if|for|while) \(.*\)')

__regex_ends_with_bracket = re.compile(r'[^\s]\) {$')

skip_leading_whitespace_check = False
skip_trailing_whitespace_check = False
skip_block_whitespace_check = False
skip_signoff_check = False

# Don't enforce character limit on files that include these characters in their
# name, as they may have legitimate reasons to have longer lines.
#
# Python isn't checked as flake8 performs these checks during build.
line_length_blacklist = ['.am', '.at', 'etc', '.in', '.m4', '.mk', '.patch',
                         '.py']


def is_added_line(line):
    """Returns TRUE if the line in question is an added line.
    """
    return __regex_added_line.search(line) is not None


def leading_whitespace_is_spaces(line):
    """Returns TRUE if the leading whitespace in added lines is spaces
    """
    if skip_leading_whitespace_check:
        return True
    if (__regex_leading_with_whitespace_at_all.search(line) is not None and
            __regex_single_line_feed.search(line) is None):
        return __regex_leading_with_spaces.search(line) is not None

    return True


def trailing_whitespace_or_crlf(line):
    """Returns TRUE if the trailing characters is whitespace
    """
    if skip_trailing_whitespace_check:
        return False
    return (__regex_trailing_whitespace.search(line) is not None and
            __regex_single_line_feed.search(line) is None)


def if_and_for_whitespace_checks(line):
    """Return TRUE if there is appropriate whitespace after if, for, while
    """
    if skip_block_whitespace_check:
        return True
    if (__regex_for_if_missing_whitespace.search(line) is not None or
            __regex_for_if_too_much_whitespace.search(line) is not None or
            __regex_for_if_parens_whitespace.search(line)):
        return False
    return True


def if_and_for_end_with_bracket_check(line):
    """Return TRUE if there is not a bracket at the end of an if, for, while
       block which fits on a single line ie: 'if (foo)'"""

    def balanced_parens(line):
        """This is a rather naive counter - it won't deal with quotes"""
        balance = 0
        for letter in line:
            if letter is '(':
                balance += 1
            elif letter is ')':
                balance -= 1
        return balance is 0

    if __regex_is_for_if_single_line_bracket.search(line) is not None:
        if not balanced_parens(line):
            return True
        if __regex_ends_with_bracket.search(line) is None:
            return False
    return True


def ovs_checkpatch_parse(text):
    lineno = 0
    signatures = []
    co_authors = []
    parse = 0
    current_file = ''
    previous_file = ''
    scissors = re.compile(r'^[\w]*---[\w]*')
    hunks = re.compile('^(---|\+\+\+) (\S+)')
    is_signature = re.compile(r'((\s*Signed-off-by: )(.*))$',
                              re.I | re.M | re.S)
    is_co_author = re.compile(r'(\s*(Co-authored-by: )(.*))$',
                              re.I | re.M | re.S)
    skip_line_length_check = False

    for line in text.split('\n'):
        if current_file != previous_file:
            previous_file = current_file
            if any([fmt in current_file for fmt in line_length_blacklist]):
                skip_line_length_check = True
            else:
                skip_line_length_check = False

        lineno = lineno + 1
        if len(line) <= 0:
            continue

        if parse == 1:
            match = hunks.match(line)
            if match:
                parse = parse + 1
                current_file = match.group(2)
            continue
        elif parse == 0:
            if scissors.match(line):
                parse = parse + 1
                if not skip_signoff_check:
                    if len(signatures) == 0:
                        print_error("No signatures found.")
                    if len(signatures) != 1 + len(co_authors):
                        print_error("Too many signoffs; "
                                    "are you missing Co-authored-by lines?")
                    if not set(co_authors) <= set(signatures):
                        print_error("Co-authored-by/Signed-off-by corruption")
            elif is_signature.match(line):
                m = is_signature.match(line)
                signatures.append(m.group(3))
            elif is_co_author.match(line):
                m = is_co_author.match(line)
                co_authors.append(m.group(3))
        elif parse == 2:
            print_line = False
            newfile = hunks.match(line)
            if newfile:
                current_file = newfile.group(2)
                continue
            if not is_added_line(line):
                continue
            # Skip files which have /datapath in them, since they are
            # linux or windows coding standards
            if '/datapath' in current_file:
                continue
            if (not current_file.endswith('.mk') and
                    not leading_whitespace_is_spaces(line[1:])):
                print_line = True
                print_warning("Line has non-spaces leading whitespace",
                              lineno)
            if trailing_whitespace_or_crlf(line[1:]):
                print_line = True
                print_warning("Line has trailing whitespace", lineno)
            if len(line[1:]) > 79 and not skip_line_length_check:
                print_line = True
                print_warning("Line is greater than 79-characters long",
                              lineno)
            if not if_and_for_whitespace_checks(line[1:]):
                print_line = True
                print_warning("Improper whitespace around control block",
                              lineno)
            if not if_and_for_end_with_bracket_check(line[1:]):
                print_line = True
                print_warning("Inappropriate bracing around statement",
                              lineno)
            if print_line:
                print(line)
    if __errors or __warnings:
        return -1
    return 0


def usage():
    print("Open vSwitch checkpatch.py")
    print("Checks a patch for trivial mistakes.")
    print("usage:")
    print("%s [options] [patch file]" % sys.argv[0])
    print("options:")
    print("-h|--help\t\t\t\tThis help message")
    print("-b|--skip-block-whitespace\t"
          "Skips the if/while/for whitespace tests")
    print("-l|--skip-leading-whitespace\t"
          "Skips the leading whitespace test")
    print("-s|--skip-signoff-lines\t"
          "Do not emit an error if no Signed-off-by line is present")
    print("-t|--skip-trailing-whitespace\t"
          "Skips the trailing whitespace test")


def ovs_checkpatch_file(filename):
    try:
        mail = email.message_from_file(open(filename, 'r'))
    except:
        print_error("Unable to parse file '%s'. Is it a patch?" % filename)
        return -1

    for part in mail.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        return ovs_checkpatch_parse(part.get_payload(decode=True))

if __name__ == '__main__':
    try:
        optlist, args = getopt.getopt(sys.argv[1:], 'bhlst',
                                      ["help",
                                       "skip-block-whitespace",
                                       "skip-leading-whitespace",
                                       "skip-signoff-lines",
                                       "skip-trailing-whitespace"])
    except:
        print("Unknown option encountered. Please rerun with -h for help.")
        sys.exit(-1)

    for o, a in optlist:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif o in ("-b", "--skip-block-whitespace"):
            skip_block_whitespace_check = True
        elif o in ("-l", "--skip-leading-whitespace"):
            skip_leading_whitespace_check = True
        elif o in ("-s", "--skip-signoff-lines"):
            skip_signoff_check = True
        elif o in ("-t", "--skip-trailing-whitespace"):
            skip_trailing_whitespace_check = True
        else:
            print("Unknown option '%s'" % o)
            sys.exit(-1)
    try:
        filename = args[0]
    except:
        if sys.stdin.isatty():
            usage()
            sys.exit(-1)
        sys.exit(ovs_checkpatch_parse(sys.stdin.read()))
    sys.exit(ovs_checkpatch_file(filename))
