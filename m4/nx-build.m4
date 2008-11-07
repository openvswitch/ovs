# -*- autoconf -*-

# Copyright (c) 2008 The Board of Trustees of The Leland Stanford
# Junior University
#
# We are making the OpenFlow specification and associated documentation
# (Software) available for public use and benefit with the expectation
# that others will use, modify and enhance the Software and contribute
# those enhancements back to the community. However, since we would
# like to make the Software available for broadest use, with as few
# restrictions as possible permission is hereby granted, free of
# charge, to any person obtaining a copy of this Software to deal in
# the Software under the copyrights without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# The name and trademarks of copyright holder(s) may NOT be used in
# advertising or publicity pertaining to the Software or any
# derivatives without specific, written prior permission.

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
