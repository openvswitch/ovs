# This file is part of Autoconf.                          -*- Autoconf -*-
# M4 sugar for common shell constructs.
# Requires GNU M4 and M4sugar.
#
# Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
# 2009, 2010 Free Software Foundation, Inc.

# This file is part of Autoconf.  This program is free
# software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Under Section 7 of GPL version 3, you are granted additional
# permissions described in the Autoconf Configure Script Exception,
# version 3.0, as published by the Free Software Foundation.
#
# You should have received a copy of the GNU General Public License
# and a copy of the Autoconf Configure Script Exception along with
# this program; see the files COPYINGv3 and COPYING.EXCEPTION
# respectively.  If not, see <http://www.gnu.org/licenses/>.

# Written by Akim Demaille, Pavel Roskin, Alexandre Oliva, Lars J. Aas
# and many other people.

# Define AS_ECHO for compatibility with Autoconf before version 2.62.
m4_ifndef([AS_ECHO], [

# AS_ECHO(WORD)
# -------------
# Output WORD followed by a newline.  WORD must be a single shell word
# (typically a quoted string).  The bytes of WORD are output as-is, even
# if it starts with "-" or contains "\".
m4_defun_init([AS_ECHO],
[AS_REQUIRE([_$0_PREPARE])],
[$as_echo $1])


# AS_ECHO_N(WORD)
# ---------------
# Like AS_ECHO(WORD), except do not output the trailing newline.
m4_defun_init([AS_ECHO_N],
[AS_REQUIRE([_AS_ECHO_PREPARE])],
[$as_echo_n $1])


# _AS_ECHO_PREPARE
# ----------------
# Arrange for $as_echo 'FOO' to echo FOO without escape-interpretation;
# and similarly for $as_echo_n, which omits the trailing newline.
# 'FOO' is an optional single argument; a missing FOO is treated as empty.
m4_defun([_AS_ECHO_PREPARE],
[[as_nl='
'
export as_nl
# Printing a long string crashes Solaris 7 /usr/bin/printf.
as_echo='\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\'
as_echo=$as_echo$as_echo$as_echo$as_echo$as_echo
as_echo=$as_echo$as_echo$as_echo$as_echo$as_echo$as_echo
# Prefer a ksh shell builtin over an external printf program on Solaris,
# but without wasting forks for bash or zsh.
if test -z "$BASH_VERSION$ZSH_VERSION" \
    && (test "X`print -r -- $as_echo`" = "X$as_echo") 2>/dev/null; then
  as_echo='print -r --'
  as_echo_n='print -rn --'
elif (test "X`printf %s $as_echo`" = "X$as_echo") 2>/dev/null; then
  as_echo='printf %s\n'
  as_echo_n='printf %s'
else
  if test "X`(/usr/ucb/echo -n -n $as_echo) 2>/dev/null`" = "X-n $as_echo"; then
    as_echo_body='eval /usr/ucb/echo -n "$][1$as_nl"'
    as_echo_n='/usr/ucb/echo -n'
  else
    as_echo_body='eval expr "X$][1" : "X\\(.*\\)"'
    as_echo_n_body='eval
      arg=$][1;
      case $arg in @%:@(
      *"$as_nl"*)
	expr "X$arg" : "X\\(.*\\)$as_nl";
	arg=`expr "X$arg" : ".*$as_nl\\(.*\\)"`;;
      esac;
      expr "X$arg" : "X\\(.*\\)" | tr -d "$as_nl"
    '
    export as_echo_n_body
    as_echo_n='sh -c $as_echo_n_body as_echo'
  fi
  export as_echo_body
  as_echo='sh -c $as_echo_body as_echo'
fi
]])# _AS_ECHO_PREPARE
])
