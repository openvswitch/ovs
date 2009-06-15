# -*- autoconf -*-

# Copyright (c) 2008 Nicira Networks.
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
