# -*- autoconf -*-

# Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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
#
m4_include([m4/compat.at])

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
     # Autoconf by default puts "-g -O2" in CFLAGS.  We need to remove the -O2
     # option for coverage to be useful.  This does it without otherwise
     # interfering with anything that the user might have put there.
     old_CFLAGS=$CFLAGS
     CFLAGS=
     for option in $old_CFLAGS; do
        case $option in
            (-O2) ;;
            (*) CFLAGS="$CFLAGS $option" ;;
        esac
     done

     OVS_CFLAGS="$OVS_CFLAGS --coverage"
     OVS_LDFLAGS="$OVS_LDFLAGS --coverage"
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

dnl Checks for ESX.
AC_DEFUN([OVS_CHECK_ESX],
  [AC_CHECK_HEADER([vmware.h],
                   [ESX=yes],
                   [ESX=no])
   AM_CONDITIONAL([ESX], [test "$ESX" = yes])
   if test "$ESX" = yes; then
      AC_DEFINE([ESX], [1], [Define to 1 if building on ESX.])
   fi])

dnl Checks for WINDOWS.
AC_DEFUN([OVS_CHECK_WIN32],
  [AC_CHECK_HEADER([windows.h],
                   [WIN32=yes],
                   [WIN32=no])
   AM_CONDITIONAL([WIN32], [test "$WIN32" = yes])
   if test "$WIN32" = yes; then
      AC_ARG_WITH([pthread],
         [AS_HELP_STRING([--with-pthread=DIR],
            [root of the pthread-win32 directory])],
         [
            case "$withval" in
            "" | y | ye | yes | n | no)
            AC_MSG_ERROR([Invalid --with-pthread value])
              ;;
            *)
            PTHREAD_INCLUDES="-I$withval/include"
            PTHREAD_LDFLAGS="-L$withval/lib/x86"
            PTHREAD_LIBS="-lpthreadVC2"
            AC_SUBST([PTHREAD_INCLUDES])
            AC_SUBST([PTHREAD_LDFLAGS])
            AC_SUBST([PTHREAD_LIBS])
              ;;
            esac
         ], [
            AC_MSG_ERROR([pthread directory not specified])
         ]
      )
      AC_ARG_WITH([debug],
         [AS_HELP_STRING([--with-debug],
            [Build without compiler optimizations])],
         [
            MSVC_CFLAGS="-O0"
            AC_SUBST([MSVC_CFLAGS])
         ], [
            MSVC_CFLAGS="-O2"
            AC_SUBST([MSVC_CFLAGS])
         ]
      )

      AC_DEFINE([WIN32], [1], [Define to 1 if building on WIN32.])
      AH_BOTTOM([#ifdef WIN32
#include "include/windows/windefs.h"
#endif])
   fi])

dnl OVS_CHECK_WINDOWS
dnl
dnl Configure Visual Studio solution build
AC_DEFUN([OVS_CHECK_VISUAL_STUDIO_DDK], [
AC_ARG_WITH([vstudiotarget],
         [AS_HELP_STRING([--with-vstudiotarget=target_type],
            [Target type: Debug/Release])],
         [
            case "$withval" in
            "Release") ;;
            "Debug") ;;
            *) AC_MSG_ERROR([No valid Visual Studio configuration found]) ;;
            esac

            VSTUDIO_CONFIG=$withval
         ], [
            VSTUDIO_CONFIG=
         ]
      )

  AC_SUBST([VSTUDIO_CONFIG])
  AC_DEFINE([VSTUDIO_DDK], [1], [System uses the Visual Studio build target.])
  AM_CONDITIONAL([VSTUDIO_DDK], [test -n "$VSTUDIO_CONFIG"])
])

dnl Checks for Netlink support.
AC_DEFUN([OVS_CHECK_NETLINK],
  [AC_CHECK_HEADER([linux/netlink.h],
                   [HAVE_NETLINK=yes],
                   [HAVE_NETLINK=no],
                   [#include <sys/socket.h>
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
       AX_CHECK_OPENSSL(
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
   AC_SEARCH_LIBS([gethostbyname], [resolv])])

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

dnl Defines HAVE_BACKTRACE if backtrace() is found.
AC_DEFUN([OVS_CHECK_BACKTRACE],
  [AC_SEARCH_LIBS([backtrace], [execinfo ubacktrace],
                  [AC_DEFINE([HAVE_BACKTRACE], [1],
                             [Define to 1 if you have backtrace(3).])])])

dnl Defines HAVE_PERF_EVENT if linux/perf_event.h is found.
AC_DEFUN([OVS_CHECK_PERF_EVENT],
  [AC_CHECK_HEADERS([linux/perf_event.h])])

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
        for binary in python python2.4 python2.5 python2.7; do
          ovs_save_IFS=$IFS; IFS=$PATH_SEPARATOR
          for dir in $PATH; do
            IFS=$ovs_save_IFS
            test -z "$dir" && dir=.
            if test -x "$dir"/"$binary" && "$dir"/"$binary" -c 'import sys
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

dnl Checks for missing python modules at build time
AC_DEFUN([OVS_CHECK_PYTHON_COMPAT],
  [OVS_CHECK_PYTHON_MODULE([uuid])
   if test $ovs_cv_py_uuid = yes; then
     INCLUDE_PYTHON_COMPAT=no
   else
     INCLUDE_PYTHON_COMPAT=yes
   fi
   AC_MSG_CHECKING([whether to add python/compat to PYTHONPATH])
   AC_MSG_RESULT([$INCLUDE_PYTHON_COMPAT])
   AM_CONDITIONAL([INCLUDE_PYTHON_COMPAT], [test $INCLUDE_PYTHON_COMPAT = yes])])

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

dnl Checks for thread-local storage support.
dnl
dnl Checks whether the compiler and linker support the C11
dnl thread_local macro from <threads.h>, and if so defines
dnl HAVE_THREAD_LOCAL.  If not, checks whether the compiler and linker
dnl support the GCC __thread extension, and if so defines
dnl HAVE___THREAD.
AC_DEFUN([OVS_CHECK_TLS],
  [AC_CACHE_CHECK(
     [whether $CC has <threads.h> that supports thread_local],
     [ovs_cv_thread_local],
     [AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([#include <threads.h>
static thread_local int var;], [return var;])],
        [ovs_cv_thread_local=yes],
        [ovs_cv_thread_local=no])])
   if test $ovs_cv_thread_local = yes; then
     AC_DEFINE([HAVE_THREAD_LOCAL], [1],
               [Define to 1 if the C compiler and linker supports the C11
                thread_local matcro defined in <threads.h>.])
   else
     AC_CACHE_CHECK(
       [whether $CC supports __thread],
       [ovs_cv___thread],
       [AC_LINK_IFELSE(
          [AC_LANG_PROGRAM([static __thread int var;], [return var;])],
          [ovs_cv___thread=yes],
          [ovs_cv___thread=no])])
     if test $ovs_cv___thread = yes; then
       AC_DEFINE([HAVE___THREAD], [1],
                 [Define to 1 if the C compiler and linker supports the
                  GCC __thread extenions.])
     fi
   fi])

dnl OVS_CHECK_ATOMIC_LIBS
dnl
dnl Check to see if -latomic is need for GCC atomic built-ins.
AC_DEFUN([OVS_CHECK_ATOMIC_LIBS],
   [AC_SEARCH_LIBS([__atomic_load_8], [atomic])])

dnl OVS_CHECK_GCC4_ATOMICS
dnl
dnl Checks whether the compiler and linker support GCC 4.0+ atomic built-ins.
dnl A compile-time only check is not enough because the compiler defers
dnl unimplemented built-ins to libgcc, which sometimes also lacks
dnl implementations.
AC_DEFUN([OVS_CHECK_GCC4_ATOMICS],
  [AC_CACHE_CHECK(
     [whether $CC supports GCC 4.0+ atomic built-ins],
     [ovs_cv_gcc4_atomics],
     [AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([[#include <stdlib.h>

#define ovs_assert(expr) if (!(expr)) abort();
#define TEST_ATOMIC_TYPE(TYPE)                  \
    {                                           \
        TYPE x = 1;                             \
        TYPE orig;                              \
                                                \
        __sync_synchronize();                   \
        ovs_assert(x == 1);                     \
                                                \
        __sync_synchronize();                   \
        x = 3;                                  \
        __sync_synchronize();                   \
        ovs_assert(x == 3);                     \
                                                \
        orig = __sync_fetch_and_add(&x, 1);     \
        ovs_assert(orig == 3);                  \
        __sync_synchronize();                   \
        ovs_assert(x == 4);                     \
                                                \
        orig = __sync_fetch_and_sub(&x, 2);     \
        ovs_assert(orig == 4);                  \
        __sync_synchronize();                   \
        ovs_assert(x == 2);                     \
                                                \
        orig = __sync_fetch_and_or(&x, 6);      \
        ovs_assert(orig == 2);                  \
        __sync_synchronize();                   \
        ovs_assert(x == 6);                     \
                                                \
        orig = __sync_fetch_and_and(&x, 10);    \
        ovs_assert(orig == 6);                  \
        __sync_synchronize();                   \
        ovs_assert(x == 2);                     \
                                                \
        orig = __sync_fetch_and_xor(&x, 10);    \
        ovs_assert(orig == 2);                  \
        __sync_synchronize();                   \
        ovs_assert(x == 8);                     \
    }]], [dnl
TEST_ATOMIC_TYPE(char);
TEST_ATOMIC_TYPE(unsigned char);
TEST_ATOMIC_TYPE(signed char);
TEST_ATOMIC_TYPE(short);
TEST_ATOMIC_TYPE(unsigned short);
TEST_ATOMIC_TYPE(int);
TEST_ATOMIC_TYPE(unsigned int);
TEST_ATOMIC_TYPE(long int);
TEST_ATOMIC_TYPE(unsigned long int);
TEST_ATOMIC_TYPE(long long int);
TEST_ATOMIC_TYPE(unsigned long long int);
])],
        [ovs_cv_gcc4_atomics=yes],
        [ovs_cv_gcc4_atomics=no])])
   if test $ovs_cv_gcc4_atomics = yes; then
     AC_DEFINE([HAVE_GCC4_ATOMICS], [1],
               [Define to 1 if the C compiler and linker supports the GCC 4.0+
                atomic built-ins.])
   fi])

dnl OVS_CHECK_ATOMIC_ALWAYS_LOCK_FREE(SIZE)
dnl
dnl Checks __atomic_always_lock_free(SIZE, 0)
AC_DEFUN([OVS_CHECK_ATOMIC_ALWAYS_LOCK_FREE], 
  [AC_CACHE_CHECK(
    [value of __atomic_always_lock_free($1)],
    [ovs_cv_atomic_always_lock_free_$1],
    [AC_COMPUTE_INT(
        [ovs_cv_atomic_always_lock_free_$1],
        [__atomic_always_lock_free($1, 0)],
        [],
        [ovs_cv_atomic_always_lock_free_$1=unsupported])])
   if test ovs_cv_atomic_always_lock_free_$1 != unsupported; then
     AC_DEFINE_UNQUOTED(
       [ATOMIC_ALWAYS_LOCK_FREE_$1B],
       [$ovs_cv_atomic_always_lock_free_$1],
       [If the C compiler is GCC 4.7 or later, define to the return value of
        __atomic_always_lock_free($1, 0).  If the C compiler is not GCC or is
        an older version of GCC, the value does not matter.])
   fi])

dnl OVS_CHECK_POSIX_AIO
AC_DEFUN([OVS_CHECK_POSIX_AIO],
  [AC_SEARCH_LIBS([aio_write], [rt])
   AM_CONDITIONAL([HAVE_POSIX_AIO], [test "$ac_cv_search_aio_write" != no])])

dnl OVS_CHECK_INCLUDE_NEXT
AC_DEFUN([OVS_CHECK_INCLUDE_NEXT],
  [AC_REQUIRE([gl_CHECK_NEXT_HEADERS])
   gl_CHECK_NEXT_HEADERS([$1])])

dnl OVS_CHECK_PRAGMA_MESSAGE
AC_DEFUN([OVS_CHECK_PRAGMA_MESSAGE],
  [AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
   [[_Pragma("message(\"Checking for pragma message\")")
   ]])],
     [AC_DEFINE(HAVE_PRAGMA_MESSAGE,1,[Define if compiler supports #pragma
     message directive])])
  ])
