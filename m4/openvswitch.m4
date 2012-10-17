# -*- autoconf -*-

# Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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

dnl Checks for --enable-coverage and updates CFLAGS and LDFLAGS appropriately.
AC_DEFUN([OVS_CHECK_COVERAGE],
  [AC_REQUIRE([AC_PROG_CC])
   AC_ARG_ENABLE(
     [coverage],
     [AC_HELP_STRING([--enable-coverage],
                     [Enable gcov coverage tool.])],
     [case "${enableval}" in
        (yes) coverage=true ;;
        (no)  coverage=false ;;
        (*) AC_MSG_ERROR([bad value ${enableval} for --enable-coverage]) ;;
      esac],
     [coverage=false])
   if $coverage; then
     CFLAGS="$CFLAGS -O0 --coverage"
     LDFLAGS="$LDFLAGS --coverage"
   fi])

dnl Checks for --enable-ndebug and defines NDEBUG if it is specified.
AC_DEFUN([OVS_CHECK_NDEBUG],
  [AC_ARG_ENABLE(
     [ndebug],
     [AC_HELP_STRING([--enable-ndebug],
                     [Disable debugging features for max performance])],
     [case "${enableval}" in
        (yes) ndebug=true ;;
        (no)  ndebug=false ;;
        (*) AC_MSG_ERROR([bad value ${enableval} for --enable-ndebug]) ;;
      esac],
     [ndebug=false])
   AM_CONDITIONAL([NDEBUG], [test x$ndebug = xtrue])])

dnl Checks for --enable-cache-time and defines CACHE_TIME if it is specified.
AC_DEFUN([OVS_CHECK_CACHE_TIME],
  [AC_ARG_ENABLE(
     [cache-time],
     [AC_HELP_STRING([--enable-cache-time],
                     [Override time caching default (for testing only)])],
     [case "${enableval}" in
        (yes) cache_time=1;;
        (no)  cache_time=0;;
        (*) AC_MSG_ERROR([bad value ${enableval} for --enable-cache-time]) ;;
      esac
      AC_DEFINE_UNQUOTED([CACHE_TIME], [$cache_time],
          [Define to 1 to enable time caching, to 0 to disable time caching, or
           leave undefined to use the default (as one should
           ordinarily do).])])])

dnl Checks for ESX.
AC_DEFUN([OVS_CHECK_ESX],
  [AC_CHECK_HEADER([vmware.h],
                   [ESX=yes],
                   [ESX=no])
   AM_CONDITIONAL([ESX], [test "$ESX" = yes])
   if test "$ESX" = yes; then
      AC_DEFINE([ESX], [1], [Define to 1 if building on ESX.])
   fi])

dnl Checks for Netlink support.
AC_DEFUN([OVS_CHECK_NETLINK],
  [AC_CHECK_HEADER([linux/netlink.h],
                   [HAVE_NETLINK=yes],
                   [HAVE_NETLINK=no],
                   [#include <sys/socket.h>
   #include <linux/types.h>
   ])
   AM_CONDITIONAL([HAVE_NETLINK], [test "$HAVE_NETLINK" = yes])
   if test "$HAVE_NETLINK" = yes; then
      AC_DEFINE([HAVE_NETLINK], [1],
                [Define to 1 if Netlink protocol is available.])
   fi])

dnl Checks for OpenSSL.
AC_DEFUN([OVS_CHECK_OPENSSL],
  [AC_ARG_ENABLE(
     [ssl],
     [AC_HELP_STRING([--disable-ssl], [Disable OpenSSL support])],
     [case "${enableval}" in
        (yes) ssl=true ;;
        (no)  ssl=false ;;
        (*) AC_MSG_ERROR([bad value ${enableval} for --enable-ssl]) ;;
      esac],
     [ssl=check])

   if test "$ssl" != false; then
       m4_ifndef([PKG_CHECK_MODULES], [m4_fatal([Please install pkg-config.])])
       PKG_CHECK_MODULES([SSL], [openssl],
         [HAVE_OPENSSL=yes],
         [HAVE_OPENSSL=no
          if test "$ssl" = check; then
            AC_MSG_WARN([Cannot find openssl:

$SSL_PKG_ERRORS

OpenFlow connections over SSL will not be supported.
(You may use --disable-ssl to suppress this warning.)])
          else
            AC_MSG_ERROR([Cannot find openssl (use --disable-ssl to configure without SSL support)])
          fi])
   else
       HAVE_OPENSSL=no
   fi
   AC_SUBST([HAVE_OPENSSL])
   AM_CONDITIONAL([HAVE_OPENSSL], [test "$HAVE_OPENSSL" = yes])
   if test "$HAVE_OPENSSL" = yes; then
      AC_DEFINE([HAVE_OPENSSL], [1], [Define to 1 if OpenSSL is installed.])
   fi])

dnl Checks for libraries needed by lib/socket-util.c.
AC_DEFUN([OVS_CHECK_SOCKET_LIBS],
  [AC_CHECK_LIB([socket], [connect])
   AC_SEARCH_LIBS([gethostbyname], [resolv], [RESOLVER_LIBS=-lresolv])])

dnl Checks for the directory in which to store the PKI.
AC_DEFUN([OVS_CHECK_PKIDIR],
  [AC_ARG_WITH(
     [pkidir],
     AC_HELP_STRING([--with-pkidir=DIR],
                    [PKI hierarchy directory [[LOCALSTATEDIR/lib/openvswitch/pki]]]),
     [PKIDIR=$withval],
     [PKIDIR='${localstatedir}/lib/openvswitch/pki'])
   AC_SUBST([PKIDIR])])

dnl Checks for the directory in which to store pidfiles.
AC_DEFUN([OVS_CHECK_RUNDIR],
  [AC_ARG_WITH(
     [rundir],
     AC_HELP_STRING([--with-rundir=DIR],
                    [directory used for pidfiles
                    [[LOCALSTATEDIR/run/openvswitch]]]),
     [RUNDIR=$withval],
     [RUNDIR='${localstatedir}/run/openvswitch'])
   AC_SUBST([RUNDIR])])

dnl Checks for the directory in which to store logs.
AC_DEFUN([OVS_CHECK_LOGDIR],
  [AC_ARG_WITH(
     [logdir],
     AC_HELP_STRING([--with-logdir=DIR],
                    [directory used for logs [[LOCALSTATEDIR/log/PACKAGE]]]),
     [LOGDIR=$withval],
     [LOGDIR='${localstatedir}/log/${PACKAGE}'])
   AC_SUBST([LOGDIR])])

dnl Checks for the directory in which to store the Open vSwitch database.
AC_DEFUN([OVS_CHECK_DBDIR],
  [AC_ARG_WITH(
     [dbdir],
     AC_HELP_STRING([--with-dbdir=DIR],
                    [directory used for conf.db [[SYSCONFDIR/PACKAGE]]]),
     [DBDIR=$withval],
     [DBDIR='${sysconfdir}/${PACKAGE}'])
   AC_SUBST([DBDIR])])

dnl Defines HAVE_BACKTRACE if backtrace() is declared in <execinfo.h>
dnl and exists in libc.
AC_DEFUN([OVS_CHECK_BACKTRACE],
  [AC_CHECK_HEADER([execinfo.h], [AC_CHECK_FUNCS([backtrace])])])

dnl Checks for __malloc_hook, etc., supported by glibc.
AC_DEFUN([OVS_CHECK_MALLOC_HOOKS],
  [AC_CACHE_CHECK(
    [whether libc supports hooks for malloc and related functions],
    [ovs_cv_malloc_hooks],
    [AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM(
         [#include <malloc.h>
         ],
         [(void) __malloc_hook;
          (void) __realloc_hook;
          (void) __free_hook;])],
      [ovs_cv_malloc_hooks=yes],
      [ovs_cv_malloc_hooks=no])])
   if test $ovs_cv_malloc_hooks = yes; then
     AC_DEFINE([HAVE_MALLOC_HOOKS], [1],
               [Define to 1 if you have __malloc_hook, __realloc_hook, and
                __free_hook in <malloc.h>.])
   fi])

dnl Checks for valgrind/valgrind.h.
AC_DEFUN([OVS_CHECK_VALGRIND],
  [AC_CHECK_HEADERS([valgrind/valgrind.h])])

dnl Checks for Python 2.x, x >= 4.
AC_DEFUN([OVS_CHECK_PYTHON],
  [AC_CACHE_CHECK(
     [for Python 2.x for x >= 4],
     [ovs_cv_python],
     [if test -n "$PYTHON"; then
        ovs_cv_python=$PYTHON
      else
        ovs_cv_python=no
        for binary in python python2.4 python2.5; do
          ovs_save_IFS=$IFS; IFS=$PATH_SEPARATOR
          for dir in $PATH; do
            IFS=$ovs_save_IFS
            test -z "$dir" && dir=.
            if test -x $dir/$binary && $dir/$binary -c 'import sys
if sys.hexversion >= 0x02040000 and sys.hexversion < 0x03000000:
    sys.exit(0)
else:
    sys.exit(1)'; then
              ovs_cv_python=$dir/$binary
              break 2
            fi
          done
        done
      fi])
   AC_SUBST([HAVE_PYTHON])
   AM_MISSING_PROG([PYTHON], [python])
   if test $ovs_cv_python != no; then
     PYTHON=$ovs_cv_python
     HAVE_PYTHON=yes
   else
     HAVE_PYTHON=no
   fi
   AM_CONDITIONAL([HAVE_PYTHON], [test "$HAVE_PYTHON" = yes])])

dnl Checks for dot.
AC_DEFUN([OVS_CHECK_DOT],
  [AC_CACHE_CHECK(
    [for dot],
    [ovs_cv_dot],
    [dnl "dot" writes -V output to stderr:
     if (dot -V) 2>&1 | grep '^dot - [[gG]]raphviz version' >/dev/null 2>&1; then
       ovs_cv_dot=yes
     else
       ovs_cv_dot=no
     fi])
   AM_CONDITIONAL([HAVE_DOT], [test "$ovs_cv_dot" = yes])])

dnl Checks for pyuic4.
AC_DEFUN([OVS_CHECK_PYUIC4],
  [AC_CACHE_CHECK(
    [for pyuic4],
    [ovs_cv_pyuic4],
    [if (pyuic4 --version) >/dev/null 2>&1; then
       ovs_cv_pyuic4=pyuic4
     else
       ovs_cv_pyuic4=no
     fi])
   AM_MISSING_PROG([PYUIC4], [pyuic4])
   if test $ovs_cv_pyuic4 != no; then
     PYUIC4=$ovs_cv_pyuic4
   fi])

dnl Checks whether $PYTHON supports the module given as $1
AC_DEFUN([OVS_CHECK_PYTHON_MODULE],
  [AC_REQUIRE([OVS_CHECK_PYTHON])
   AC_CACHE_CHECK(
     [for $1 Python module],
     [ovs_cv_py_[]AS_TR_SH([$1])],
     [ovs_cv_py_[]AS_TR_SH([$1])=no
      if test $HAVE_PYTHON = yes; then
        AS_ECHO(["running $PYTHON -c 'import $1
import sys
sys.exit(0)'..."]) >&AS_MESSAGE_LOG_FD 2>&1
        if $PYTHON -c 'import $1
import sys
sys.exit(0)' >&AS_MESSAGE_LOG_FD 2>&1; then
          ovs_cv_py_[]AS_TR_SH([$1])=yes
        fi
      fi])])

dnl Checks for Python modules needed by ovsdbmonitor.
AC_DEFUN([OVS_CHECK_OVSDBMONITOR],
  [OVS_CHECK_PYTHON_MODULE([PySide.QtCore])
   OVS_CHECK_PYTHON_MODULE([PyQt4.QtCore])
   OVS_CHECK_PYTHON_MODULE([twisted.conch.ssh])
   OVS_CHECK_PYTHON_MODULE([twisted.internet])
   OVS_CHECK_PYTHON_MODULE([twisted.application])
   OVS_CHECK_PYTHON_MODULE([json])
   OVS_CHECK_PYTHON_MODULE([zope.interface])
   if (test $ovs_cv_py_PySide_QtCore = yes \
       || test $ovs_cv_py_PyQt4_QtCore = yes) \
      && test $ovs_cv_py_twisted_conch_ssh = yes \
      && test $ovs_cv_py_twisted_internet = yes \
      && test $ovs_cv_py_twisted_application = yes \
      && test $ovs_cv_py_json = yes \
      && test $ovs_cv_py_zope_interface = yes; then
     BUILD_OVSDBMONITOR=yes
   else
     BUILD_OVSDBMONITOR=no
   fi
   AC_MSG_CHECKING([whether to build ovsdbmonitor])
   AC_MSG_RESULT([$BUILD_OVSDBMONITOR])
   AM_CONDITIONAL([BUILD_OVSDBMONITOR], [test $BUILD_OVSDBMONITOR = yes])])

# OVS_LINK2_IFELSE(SOURCE1, SOURCE2, [ACTION-IF-TRUE], [ACTION-IF-FALSE])
# -------------------------------------------------------------
# Based on AC_LINK_IFELSE, but tries to link both SOURCE1 and SOURCE2
# into a program.
#
# This macro is borrowed from acinclude.m4 in GNU PSPP, which has the
# following license:
#
#     Copyright (C) 2005, 2006, 2007, 2009 Free Software Foundation, Inc.
#     This file is free software; the Free Software Foundation
#     gives unlimited permission to copy and/or distribute it,
#     with or without modifications, as long as this notice is preserved.
#
m4_define([OVS_LINK2_IFELSE],
[m4_ifvaln([$1], [AC_LANG_CONFTEST([$1])])dnl
mv conftest.$ac_ext conftest1.$ac_ext
m4_ifvaln([$2], [AC_LANG_CONFTEST([$2])])dnl
mv conftest.$ac_ext conftest2.$ac_ext
rm -f conftest1.$ac_objext conftest2.$ac_objext conftest$ac_exeext
ovs_link2='$CC -o conftest$ac_exeext $CFLAGS $CPPFLAGS $LDFLAGS conftest1.$ac_ext conftest2.$ac_ext $LIBS >&5'
AS_IF([_AC_DO_STDERR($ovs_link2) && {
	 test -z "$ac_[]_AC_LANG_ABBREV[]_werror_flag" ||
	 test ! -s conftest.err
       } && test -s conftest$ac_exeext && {
	 test "$cross_compiling" = yes ||
	 AS_TEST_X([conftest$ac_exeext])
       }],
      [$3],
      [echo "$as_me: failed source file 1 of 2 was:" >&5
sed 's/^/| /' conftest1.$ac_ext >&5
echo "$as_me: failed source file 2 of 2 was:" >&5
sed 's/^/| /' conftest2.$ac_ext >&5
	$4])
dnl Delete also the IPA/IPO (Inter Procedural Analysis/Optimization)
dnl information created by the PGI compiler (conftest_ipa8_conftest.oo),
dnl as it would interfere with the next link command.
rm -rf conftest.dSYM conftest1.dSYM conftest2.dSYM
rm -f core conftest.err conftest1.err conftest2.err
rm -f conftest1.$ac_objext conftest2.$ac_objext conftest*_ipa8_conftest*.oo
rm -f conftest$ac_exeext
rm -f m4_ifval([$1], [conftest1.$ac_ext]) m4_ifval([$2], [conftest1.$ac_ext])[]dnl
])# OVS_LINK2_IFELSE

dnl Defines USE_LINKER_SECTIONS to 1 if the compiler supports putting
dnl variables in sections with user-defined names and the linker
dnl automatically defines __start_SECNAME and __stop_SECNAME symbols
dnl that designate the start and end of the sections.
AC_DEFUN([OVS_CHECK_LINKER_SECTIONS],
  [AC_CACHE_CHECK(
    [for user-defined linker section support],
    [ovs_cv_use_linker_sections],
    [OVS_LINK2_IFELSE(
      [AC_LANG_SOURCE(
        [int a __attribute__((__section__("mysection"))) = 1;
         int b __attribute__((__section__("mysection"))) = 2;
         int c __attribute__((__section__("mysection"))) = 3;])],
      [AC_LANG_PROGRAM(
        [#include <stdio.h>
         extern int __start_mysection;
         extern int __stop_mysection;],
        [int n_ints = &__stop_mysection - &__start_mysection;
         int *i;
         for (i = &__start_mysection; i < &__start_mysection + n_ints; i++) {
             printf("%d\n", *i);
         }])],
      [ovs_cv_use_linker_sections=yes],
      [ovs_cv_use_linker_sections=no])])
   if test $ovs_cv_use_linker_sections = yes; then
     AC_DEFINE([USE_LINKER_SECTIONS], [1],
               [Define to 1 if the compiler support putting variables
                into sections with user-defined names and the linker
                automatically defines __start_SECNAME and __stop_SECNAME
                symbols that designate the start and end of the section.])
   fi
   AM_CONDITIONAL(
     [USE_LINKER_SECTIONS], [test $ovs_cv_use_linker_sections = yes])])

dnl Checks for groff.
AC_DEFUN([OVS_CHECK_GROFF],
  [AC_CACHE_CHECK(
    [for groff],
    [ovs_cv_groff],
    [if (groff -v) >/dev/null 2>&1; then
       ovs_cv_groff=yes
     else
       ovs_cv_groff=no
     fi])
   AM_CONDITIONAL([HAVE_GROFF], [test "$ovs_cv_groff" = yes])])

dnl Checks for --disable-brcompat and undefines BUILD_BRCOMPAT if it is specified.
AC_DEFUN([OVS_CHECK_BRCOMPAT],
  [AC_ARG_ENABLE(
     [brcompat],
     [AC_HELP_STRING([--disable-brcompat],
                     [Disable building brcompat])],
     [case "${enableval}" in
        (yes) brcompat=true ;;
        (no)  brcompat=false ;;
        (*) AC_MSG_ERROR([bad value ${enableval} for --enable-brcompat]) ;;
      esac],
     [brcompat=true])
   if test x$brcompat = xtrue; then
      BUILD_BRCOMPAT=yes
   else
      BUILD_BRCOMPAT=""
   fi
   AC_SUBST([BUILD_BRCOMPAT])
   AM_CONDITIONAL([BUILD_BRCOMPAT], [test x$brcompat = xtrue])])
