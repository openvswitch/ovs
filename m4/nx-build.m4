# -*- autoconf -*-

# Copyright (c) 2008 Nicira Networks.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

dnl NX_BUILDNR
dnl
dnl If --with-build-number=NUMBER is used, substitutes a Makefile
dnl variable BUILDNR with NUMBER, and sets a C preprocessor variable
dnl BUILDNR to "+buildNUMBER".
dnl
dnl Otherwise, if --with-build-number is not used, substitutes BUILDNR
dnl with 0 and sets C preprocessor variable BUILDNR to "".
AC_DEFUN([NX_BUILDNR],
  [AC_ARG_WITH(
     [build-number],
     [AS_HELP_STRING([--with-build-number=NUMBER],
                     [Official build number (default is none)])])
   AC_MSG_CHECKING([build number])
   case $with_build_number in # (
     [[0-9]] | \
     [[0-9]][[0-9]] | \
     [[0-9]][[0-9]][[0-9]] | \
     [[0-9]][[0-9]][[0-9]][[0-9]] | \
     [[0-9]][[0-9]][[0-9]][[0-9]][[0-9]])
       BUILDNR=$with_build_number
       buildnr='"+build'$BUILDNR'"'
       AC_MSG_RESULT([$with_build_number])
       ;; # (
     ''|no)
       BUILDNR=0
       buildnr='""'
       AC_MSG_RESULT([none])
       ;; # (
     *)
       AC_MSG_ERROR([invalid build number $with_build_number])
       ;;
   esac
   AC_SUBST([BUILDNR])
   AC_DEFINE_UNQUOTED([BUILDNR], [$buildnr],
     [Official build number as a VERSION suffix string, e.g. "+build123",
      or "" if this is not an official build.])])
