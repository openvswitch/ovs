#!/usr/bin/env python
# Copyright (c) 2016, 2017 Red Hat, Inc.
# Copyright (c) 2018 Nicira, Inc.
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
import os
import re
import sys

__errors = 0
__warnings = 0
print_file_name = None
checking_file = False
total_line = 0
colors = False


def get_color_end():
    global colors
    if colors:
        return "\033[00m"
    return ""


def get_red_begin():
    global colors
    if colors:
        return "\033[91m"
    return ""


def get_yellow_begin():
    global colors
    if colors:
        return "\033[93m"
    return ""


def print_error(message):
    global __errors
    print("%sERROR%s: %s" % (get_red_begin(), get_color_end(), message))

    __errors = __errors + 1


def print_warning(message):
    global __warnings
    print("%sWARNING%s: %s" % (get_yellow_begin(), get_color_end(), message))

    __warnings = __warnings + 1


def reset_counters():
    global __errors, __warnings, total_line

    __errors = 0
    __warnings = 0
    total_line = 0


# These are keywords whose names are normally followed by a space and
# something in parentheses (usually an expression) then a left curly brace.
#
# 'do' almost qualifies but it's also used as "do { ... } while (...);".
__parenthesized_constructs = 'if|for|while|switch|[_A-Z]+FOR_EACH[_A-Z]*'

__regex_added_line = re.compile(r'^\+{1,2}[^\+][\w\W]*')
__regex_subtracted_line = re.compile(r'^\-{1,2}[^\-][\w\W]*')
__regex_leading_with_whitespace_at_all = re.compile(r'^\s+')
__regex_leading_with_spaces = re.compile(r'^ +[\S]+')
__regex_trailing_whitespace = re.compile(r'[^\S]+$')
__regex_single_line_feed = re.compile(r'^\f$')
__regex_for_if_missing_whitespace = re.compile(r' +(%s)[\(]'
                                               % __parenthesized_constructs)
__regex_for_if_too_much_whitespace = re.compile(r' +(%s)  +[\(]'
                                                % __parenthesized_constructs)
__regex_for_if_parens_whitespace = \
    re.compile(r' +(%s) \( +[\s\S]+\)' % __parenthesized_constructs)
__regex_is_for_if_single_line_bracket = \
    re.compile(r'^ +(%s) \(.*\)' % __parenthesized_constructs)
__regex_ends_with_bracket = \
    re.compile(r'[^\s]\) {(\s+/\*[\s\Sa-zA-Z0-9\.,\?\*/+-]*)?$')
__regex_ptr_declaration_missing_whitespace = re.compile(r'[a-zA-Z0-9]\*[^*]')
__regex_is_comment_line = re.compile(r'^\s*(/\*|\*\s)')
__regex_has_comment = re.compile(r'.*(/\*|\*\s)')
__regex_trailing_operator = re.compile(r'^[^ ]* [^ ]*[?:]$')
__regex_conditional_else_bracing = re.compile(r'^\s*else\s*{?$')
__regex_conditional_else_bracing2 = re.compile(r'^\s*}\selse\s*$')
__regex_has_xxx_mark = re.compile(r'.*xxx.*', re.IGNORECASE)

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

# Don't enforce a requirement that leading whitespace be all spaces on
# files that include these characters in their name, since these kinds
# of files need lines with leading tabs.
leading_whitespace_blacklist = ['.mk', '.am', '.at']


def is_subtracted_line(line):
    """Returns TRUE if the line in question has been removed."""
    return __regex_subtracted_line.search(line) is not None


def is_added_line(line):
    """Returns TRUE if the line in question is an added line.
    """
    global checking_file
    return __regex_added_line.search(line) is not None or checking_file


def added_line(line):
    """Returns the line formatted properly by removing diff syntax"""
    global checking_file
    if not checking_file:
        return line[1:]
    return line


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
            if letter == '(':
                balance += 1
            elif letter == ')':
                balance -= 1
        return balance == 0

    if __regex_is_for_if_single_line_bracket.search(line) is not None:
        if not balanced_parens(line):
            return True
        if __regex_ends_with_bracket.search(line) is None:
            return False
    if __regex_conditional_else_bracing.match(line) is not None:
        return False
    if __regex_conditional_else_bracing2.match(line) is not None:
        return False
    return True


def pointer_whitespace_check(line):
    """Return TRUE if there is no space between a pointer name and the
       asterisk that denotes this is a apionter type, ie: 'struct foo*'"""
    return __regex_ptr_declaration_missing_whitespace.search(line) is not None


def line_length_check(line):
    """Return TRUE if the line length is too long"""
    if len(line) > 79:
        return True
    return False


def is_comment_line(line):
    """Returns TRUE if the current line is part of a block comment."""
    return __regex_is_comment_line.match(line) is not None


def has_comment(line):
    """Returns TRUE if the current line contains a comment or is part of
       a block comment."""
    return __regex_has_comment.match(line) is not None


def trailing_operator(line):
    """Returns TRUE if the current line ends with an operatorsuch as ? or :"""
    return __regex_trailing_operator.match(line) is not None


def has_xxx_mark(line):
    """Returns TRUE if the current line contains 'xxx'."""
    return __regex_has_xxx_mark.match(line) is not None


checks = [
    {'regex': None,
     'match_name':
     lambda x: not any([fmt in x for fmt in line_length_blacklist]),
     'check': lambda x: line_length_check(x),
     'print': lambda: print_warning("Line length is >79-characters long")},

    {'regex': None,
     'match_name':
     lambda x: not any([fmt in x for fmt in leading_whitespace_blacklist]),
     'check': lambda x: not leading_whitespace_is_spaces(x),
     'print': lambda: print_warning("Line has non-spaces leading whitespace")},

    {'regex': None, 'match_name': None,
     'check': lambda x: trailing_whitespace_or_crlf(x),
     'print': lambda: print_warning("Line has trailing whitespace")},

    {'regex': '(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': lambda x: not if_and_for_whitespace_checks(x),
     'print': lambda: print_error("Improper whitespace around control block")},

    {'regex': '(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': lambda x: not if_and_for_end_with_bracket_check(x),
     'print': lambda: print_error("Inappropriate bracing around statement")},

    {'regex': '(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': lambda x: pointer_whitespace_check(x),
     'print':
     lambda: print_error("Inappropriate spacing in pointer declaration")},

    {'regex': '(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': lambda x: trailing_operator(x),
     'print':
     lambda: print_error("Line has '?' or ':' operator at end of line")},

    {'regex': '(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: has_comment(x),
     'check': lambda x: has_xxx_mark(x),
     'print': lambda: print_warning("Comment with 'xxx' marker")},
]


def regex_function_factory(func_name):
    regex = re.compile(r'\b%s\([^)]*\)' % func_name)
    return lambda x: regex.search(x) is not None


def regex_error_factory(description):
    return lambda: print_error(description)


std_functions = [
        ('malloc', 'Use xmalloc() in place of malloc()'),
        ('calloc', 'Use xcalloc() in place of calloc()'),
        ('realloc', 'Use xrealloc() in place of realloc()'),
        ('strdup', 'Use xstrdup() in place of strdup()'),
        ('asprintf', 'Use xasprintf() in place of asprintf()'),
        ('vasprintf', 'Use xvasprintf() in place of vasprintf()'),
        ('strcpy', 'Use ovs_strlcpy() in place of strcpy()'),
        ('strlcpy', 'Use ovs_strlcpy() in place of strlcpy()'),
        ('strncpy', 'Use ovs_strzcpy() in place of strncpy()'),
        ('strerror', 'Use ovs_strerror() in place of strerror()'),
        ('sleep', 'Use xsleep() in place of sleep()'),
        ('abort', 'Use ovs_abort() in place of abort()'),
        ('assert', 'Use ovs_assert() in place of assert()'),
        ('error', 'Use ovs_error() in place of error()'),
]
checks += [
    {'regex': '(\.c|\.h)(\.in)?$',
     'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': regex_function_factory(function_name),
     'print': regex_error_factory(description)}
    for (function_name, description) in std_functions]


def regex_operator_factory(operator):
    regex = re.compile(r'^[^#][^"\']*[^ "]%s[^ "\'][^"]*' % operator)
    return lambda x: regex.search(x) is not None


infix_operators = \
    [re.escape(op) for op in ['/', '%', '<<', '>>', '<=', '>=', '==', '!=',
            '^', '|', '&&', '||', '?:', '=', '+=', '-=', '*=', '/=', '%=',
            '&=', '^=', '|=', '<<=', '>>=']] \
    + ['[^<" ]<[^=" ]', '[^->" ]>[^=" ]', '[^ !()/"]\*[^/]', '[^ !&()"]&',
       '[^" +(]\+[^"+;]', '[^" -(]-[^"->;]', '[^" <>=!^|+\-*/%&]=[^"=]']
checks += [
    {'regex': '(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': regex_operator_factory(operator),
     'print': lambda: print_warning("Line lacks whitespace around operator")}
    for operator in infix_operators]


def get_file_type_checks(filename):
    """Returns the list of checks for a file based on matching the filename
       against regex."""
    global checks
    checkList = []
    for check in checks:
        if check['regex'] is None and check['match_name'] is None:
            checkList.append(check)
        if check['regex'] is not None and \
           re.compile(check['regex']).search(filename) is not None:
            checkList.append(check)
        elif check['match_name'] is not None and check['match_name'](filename):
            checkList.append(check)
    return checkList


def run_checks(current_file, line, lineno):
    """Runs the various checks for the particular line.  This will take
       filename into account."""
    global checking_file, total_line
    print_line = False
    for check in get_file_type_checks(current_file):
        if 'prereq' in check and not check['prereq'](line):
            continue
        if check['check'](line):
            check['print']()
            print_line = True

    if print_line:
        if checking_file:
            print("%s:%d:" % (current_file, lineno))
        else:
            print("#%d FILE: %s:%d:" % (total_line, current_file, lineno))
        print("%s\n" % line)


def ovs_checkpatch_parse(text, filename):
    global print_file_name, total_line, checking_file
    lineno = 0
    signatures = []
    co_authors = []
    parse = 0
    current_file = filename if checking_file else ''
    previous_file = ''
    scissors = re.compile(r'^[\w]*---[\w]*')
    hunks = re.compile('^(---|\+\+\+) (\S+)')
    hunk_differences = re.compile(
        r'^@@ ([0-9-+]+),([0-9-+]+) ([0-9-+]+),([0-9-+]+) @@')
    is_signature = re.compile(r'((\s*Signed-off-by: )(.*))$',
                              re.I | re.M | re.S)
    is_co_author = re.compile(r'(\s*(Co-authored-by: )(.*))$',
                              re.I | re.M | re.S)
    is_gerrit_change_id = re.compile(r'(\s*(change-id: )(.*))$',
                                     re.I | re.M | re.S)

    reset_counters()

    for line in text.split('\n'):
        if current_file != previous_file:
            previous_file = current_file

        lineno = lineno + 1
        total_line = total_line + 1
        if len(line) <= 0:
            continue

        if checking_file:
            parse = 2

        if parse == 1:
            match = hunks.match(line)
            if match:
                parse = parse + 1
                current_file = match.group(2)[2:]
                print_file_name = current_file
            continue
        elif parse == 0:
            if scissors.match(line):
                parse = parse + 1
                if not skip_signoff_check:
                    if len(signatures) == 0:
                        print_error("No signatures found.")
                    elif len(signatures) != 1 + len(co_authors):
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
            elif is_gerrit_change_id.match(line):
                print_error(
                    "Remove Gerrit Change-Id's before submitting upstream.")
                print("%d: %s\n" % (lineno, line))
        elif parse == 2:
            newfile = hunks.match(line)
            if newfile:
                current_file = newfile.group(2)[2:]
                print_file_name = current_file
                continue
            reset_line_number = hunk_differences.match(line)
            if reset_line_number:
                lineno = int(reset_line_number.group(3))
                if lineno < 0:
                    lineno = -1 * lineno
                lineno -= 1
            if is_subtracted_line(line):
                lineno -= 1
            if not is_added_line(line):
                continue

            cmp_line = added_line(line)

            # Skip files which have /datapath in them, since they are
            # linux or windows coding standards
            if current_file.startswith('datapath'):
                continue
            if current_file.startswith('include/linux'):
                continue
            run_checks(current_file, cmp_line, lineno)
    if __errors or __warnings:
        return -1
    return 0


def usage():
    print("""\
Open vSwitch checkpatch.py
Checks a patch for trivial mistakes.
usage:
%s [options] [PATCH1 [PATCH2 ...] | -f SOURCE1 [SOURCE2 ...] | -1 | -2 | ...]

Input options:
-f|--check-file                Arguments are source files, not patches.
-1, -2, ...                    Check recent commits in this repo.

Check options:
-h|--help                      This help message
-b|--skip-block-whitespace     Skips the if/while/for whitespace tests
-l|--skip-leading-whitespace   Skips the leading whitespace test
-s|--skip-signoff-lines        Tolerate missing Signed-off-by line
-t|--skip-trailing-whitespace  Skips the trailing whitespace test"""
          % sys.argv[0])


def ovs_checkpatch_print_result(result):
    global __warnings, __errors, total_line
    if result < 0:
        print("Lines checked: %d, Warnings: %d, Errors: %d\n" %
              (total_line, __warnings, __errors))
    else:
        print("Lines checked: %d, no obvious problems found\n" % (total_line))


def ovs_checkpatch_file(filename):
    try:
        mail = email.message_from_file(open(filename, 'r'))
    except:
        print_error("Unable to parse file '%s'. Is it a patch?" % filename)
        return -1

    for part in mail.walk():
        if part.get_content_maintype() == 'multipart':
            continue
    result = ovs_checkpatch_parse(part.get_payload(decode=False), filename)
    ovs_checkpatch_print_result(result)
    return result


def partition(pred, iterable):
    """Returns [[trues], [falses]], where [trues] is the items in
    'iterable' that satisfy 'pred' and [falses] is all the rest."""
    trues = []
    falses = []
    for item in iterable:
        if pred(item):
            trues.append(item)
        else:
            falses.append(item)
    return trues, falses


if __name__ == '__main__':
    try:
        numeric_options, args = partition(lambda s: re.match('-[0-9]+$', s),
                                          sys.argv[1:])
        n_patches = int(numeric_options[-1][1:]) if numeric_options else 0

        optlist, args = getopt.getopt(args, 'bhlstf',
                                      ["check-file",
                                       "help",
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
        elif o in ("-f", "--check-file"):
            checking_file = True
        else:
            print("Unknown option '%s'" % o)
            sys.exit(-1)

    if sys.stdout.isatty():
        colors = True

    if n_patches:
        status = 0

        git_log = 'git log --no-color --no-merges --pretty=format:"%H %s" '
        with os.popen(git_log + '-%d' % n_patches, 'r') as f:
            commits = f.read().split("\n")

        for i in reversed(range(0, n_patches)):
            revision, name = commits[i].split(" ", 1)
            f = os.popen('git format-patch -1 --stdout %s' % revision, 'r')
            patch = f.read()
            f.close()

            print('== Checking %s ("%s") ==' % (revision[0:12], name))
            result = ovs_checkpatch_parse(patch, revision)
            ovs_checkpatch_print_result(result)
            if result:
                status = -1
        sys.exit(status)

    if not args:
        if sys.stdin.isatty():
            usage()
            sys.exit(-1)
        result = ovs_checkpatch_parse(sys.stdin.read(), '-')
        ovs_checkpatch_print_result(result)
        sys.exit(result)

    status = 0
    for filename in args:
        print('== Checking "%s" ==' % filename)
        result = ovs_checkpatch_file(filename)
        if result:
            status = -1
    sys.exit(status)
