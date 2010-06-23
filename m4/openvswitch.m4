# -*- autoconf -*-

# Copyright (c) 2008, 2009, 2010 Nicira Networks.
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
        (lcov|yes) coverage=true ;;
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

dnl Checks for OpenSSL, if --enable-ssl is passed in.
AC_DEFUN([OVS_CHECK_OPENSSL],
  [AC_ARG_ENABLE(
     [ssl],
     [AC_HELP_STRING([--enable-ssl], 
                     [Enable ssl support (requires libssl)])],
     [case "${enableval}" in
        (yes) ssl=true ;;
        (no)  ssl=false ;;
        (*) AC_MSG_ERROR([bad value ${enableval} for --enable-ssl]) ;;
      esac],
     [ssl=false])

   if test "$ssl" = true; then
       dnl Make sure that pkg-config is installed.
       m4_pattern_forbid([PKG_CHECK_MODULES])
       PKG_CHECK_MODULES([SSL], [libssl], 
         [HAVE_OPENSSL=yes],
         [HAVE_OPENSSL=no
          AC_MSG_WARN([Cannot find libssl:

$SSL_PKG_ERRORS

OpenFlow connections over SSL will not be supported.])])
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
                    [PKI hierarchy directory [[DATADIR/openvswitch/pki]]]),
     [PKIDIR=$withval],
     [PKIDIR='${pkgdatadir}/pki'])
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

dnl Searches for a directory to put lockfiles for tty devices.
dnl Defines C preprocessor variable TTY_LOCK_DIR to a quoted string
dnl for that directory.
AC_DEFUN([OVS_CHECK_TTY_LOCK_DIR],
  [AC_CACHE_CHECK([directory used for serial device lockfiles],
                  [ovs_cv_path_tty_locks],
  		  [# This list of candidate directories is from minicom.
		   ovs_cv_path_tty_locks=none
                   for dir in /etc/locks /var/lock /usr/spool/locks \
                              /var/spool/locks /var/spool/lock \
                              /usr/spool/uucp /var/spool/uucp /var/run; do
		     if test -d $dir; then
		       ovs_cv_path_tty_locks=$dir
		       break
		     fi
                   done])
   if test "$ovs_cv_path_tty_locks" = none; then
     AC_MSG_ERROR([cannot find a directory for tty locks])
   fi
   AC_DEFINE_UNQUOTED([TTY_LOCK_DIR], "$ovs_cv_path_tty_locks",
                      [Directory used for serial device lockfiles])])

dnl The following check is adapted from GNU PSPP.
dnl It searches for the ncurses library.  If it finds it, it sets
dnl HAVE_CURSES to yes and sets NCURSES_LIBS and NCURSES_CFLAGS
dnl appropriate.  Otherwise, it sets HAVE_CURSES to no. 
AC_DEFUN([OVS_CHECK_CURSES],
  [if test "$cross_compiling" != yes; then
     AC_CHECK_PROGS([NCURSES_CONFIG], [ncurses5-config ncurses8-config])
   fi
   if test "$NCURSES_CONFIG" = ""; then
     AC_SEARCH_LIBS([tgetent], [ncurses],
         [AC_CHECK_HEADERS([term.h curses.h], 
                           [HAVE_CURSES=yes],
                           [HAVE_CURSES=no])])
   else
     save_cflags=$CFLAGS
     CFLAGS="$CFLAGS $($NCURSES_CONFIG --cflags)"
     AC_CHECK_HEADERS([term.h curses.h], 
                      [HAVE_CURSES=yes],
                      [HAVE_CURSES=no])
     CFLAGS=$save_cflags
     if test "$HAVE_CURSES" = yes; then
       NCURSES_LIBS=$($NCURSES_CONFIG --libs)
       NCURSES_CFLAGS=$($NCURSES_CONFIG --cflags)
       AC_SUBST(NCURSES_CFLAGS)
       AC_SUBST(NCURSES_LIBS)
     fi
   fi
   AM_CONDITIONAL([HAVE_CURSES], [test "$HAVE_CURSES" = yes])])

dnl Checks for linux/vt.h.
AC_DEFUN([OVS_CHECK_LINUX_VT_H],
  [AC_CHECK_HEADER([linux/vt.h],
                   [HAVE_LINUX_VT_H=yes],
                   [HAVE_LINUX_VT_H=no])
   AM_CONDITIONAL([HAVE_LINUX_VT_H], [test "$HAVE_LINUX_VT_H" = yes])
   if test "$HAVE_LINUX_VT_H" = yes; then
      AC_DEFINE([HAVE_LINUX_VT_H], [1],
                [Define to 1 if linux/vt.h is available.])
   fi])

dnl Checks for libpcre.
dnl
dnl ezio-term wants libpcre that supports the PCRE_PARTIAL feature,
dnl which is libpcre 7.2 or later.
AC_DEFUN([OVS_CHECK_PCRE],
  [dnl Make sure that pkg-config is installed.
   m4_pattern_forbid([PKG_CHECK_MODULES])
   PKG_CHECK_MODULES([PCRE],
                     [libpcre >= 7.2], 
                     [HAVE_PCRE_PARTIAL=yes],
                     [HAVE_PCRE_PARTIAL=no])
   AM_CONDITIONAL([HAVE_PCRE_PARTIAL], [test "$HAVE_PCRE_PARTIAL" = yes])
   AC_SUBST([HAVE_PCRE_PARTIAL])
])

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
     if (dot -V) 2>&1 | grep '^dot - [gG]raphviz version' >/dev/null 2>&1; then
       ovs_cv_dot=yes
     else
       ovs_cv_dot=no
     fi])])

dnl Check whether to build E-R diagrams.
AC_DEFUN([OVS_CHECK_ER_DIAGRAMS],
  [AC_REQUIRE([OVS_CHECK_DOT])
   AC_REQUIRE([OVS_CHECK_PYTHON])
   AC_CACHE_CHECK(
    [whether to build E-R diagrams for database],
    [ovs_cv_er_diagrams],
    [if test $ovs_cv_dot != no && test $ovs_cv_python != no; then
       ovs_cv_er_diagrams=yes
     else
       ovs_cv_er_diagrams=no
     fi])
   AM_CONDITIONAL([BUILD_ER_DIAGRAMS], [test $ovs_cv_er_diagrams = yes])])

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
