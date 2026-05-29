# -*- autoconf -*-

# Copyright (c) 2008-2016, 2019 Nicira, Inc.
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
m4_include([m4/compat.m4])

dnl Checks for --enable-coverage and updates CFLAGS and LDFLAGS appropriately.
AC_DEFUN([OVS_CHECK_COVERAGE],
  [AC_REQUIRE([AC_PROG_CC])
   AC_ARG_ENABLE(
     [coverage],
     [AS_HELP_STRING([--enable-coverage],
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
     [AS_HELP_STRING([--enable-ndebug],
                     [Disable debugging features for max performance])],
     [case "${enableval}" in
        (yes) ndebug=true ;;
        (no)  ndebug=false ;;
        (*) AC_MSG_ERROR([bad value ${enableval} for --enable-ndebug]) ;;
      esac],
     [ndebug=false])
   AM_CONDITIONAL([NDEBUG], [test x$ndebug = xtrue])])

dnl Checks for --enable-usdt-probes and defines HAVE_USDT if it is specified.
AC_DEFUN([OVS_CHECK_USDT], [
  AC_ARG_ENABLE(
    [usdt-probes],
    [AS_HELP_STRING([--enable-usdt-probes],
                    [Enable User Statically Defined Tracing (USDT) probes])],
    [case "${enableval}" in
       (yes) usdt=true ;;
       (no)  usdt=false ;;
       (*) AC_MSG_ERROR([bad value ${enableval} for --enable-usdt-probes]) ;;
     esac],
    [usdt=false])

  AC_MSG_CHECKING([whether USDT probes are enabled])
  if test "$usdt" != true; then
    AC_MSG_RESULT([no])
  else
    AC_MSG_RESULT([yes])

    AC_CHECK_HEADER([sys/sdt.h], [],
      [AC_MSG_ERROR([unable to find sys/sdt.h needed for USDT support])])

    AC_DEFINE([HAVE_USDT_PROBES], [1],
              [Define to 1 if USDT probes are enabled.])
  fi
  AM_CONDITIONAL([HAVE_USDT_PROBES], [test $usdt = true])
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

dnl Checks for libcap-ng.
AC_DEFUN([OVS_CHECK_LIBCAPNG],
  [AC_ARG_ENABLE(
     [libcapng],
     [AS_HELP_STRING([--disable-libcapng], [Disable Linux capability support])],
     [case "${enableval}" in
        (yes) libcapng=true ;;
        (no)  libcapng=false ;;
        (*) AC_MSG_ERROR([bad value ${enableval} for --enable-libcapng]) ;;
      esac],
     [libcapng=check])

   if test "$libcapng" != false; then
       AC_CHECK_LIB([cap-ng], [capng_clear], [HAVE_LIBCAPNG=yes])

       if test "$HAVE_LIBCAPNG" != yes; then
           if test "$libcapng" = true ; then
                AC_MSG_ERROR([libcap-ng support requested, but not found])
           fi
           if test "$libcapng" = check ; then
                 AC_MSG_WARN([cannot find libcap-ng.
--user option will not be supported on Linux.
(you may use --disable-libcapng to suppress this warning). ])
           fi
       fi
   fi

   AC_SUBST([HAVE_LIBCAPNG])
   AM_CONDITIONAL([HAVE_LIBCAPNG], [test "$HAVE_LIBCAPNG" = yes])
   if test "$HAVE_LIBCAPNG" = yes; then
      AC_DEFINE([HAVE_LIBCAPNG], [1],
                [Define to 1 if libcap-ng is available.])
      CAPNG_LDADD="-lcap-ng"
      AC_SUBST([CAPNG_LDADD])
   fi])

dnl Checks for OpenSSL.
AC_DEFUN([OVS_CHECK_OPENSSL],
  [AC_ARG_ENABLE(
     [ssl],
     [AS_HELP_STRING([--disable-ssl], [Disable OpenSSL support])],
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

OpenFlow connections over SSL/TLS will not be supported.
(You may use --disable-ssl to suppress this warning.)])
          else
            AC_MSG_ERROR([Cannot find openssl (use --disable-ssl to configure without SSL/TLS support)])
          fi])
   else
       HAVE_OPENSSL=no
   fi
   AC_SUBST([HAVE_OPENSSL])
   AM_CONDITIONAL([HAVE_OPENSSL], [test "$HAVE_OPENSSL" = yes])
   if test "$HAVE_OPENSSL" = yes; then
      AC_DEFINE([HAVE_OPENSSL], [1], [Define to 1 if OpenSSL is installed.])
   fi
])

dnl Checks for libraries needed by lib/socket-util.c.
AC_DEFUN([OVS_CHECK_SOCKET_LIBS],
  [AC_CHECK_LIB([socket], [connect])
   AC_SEARCH_LIBS([gethostbyname], [resolv])])

dnl Checks for the directory in which to store the PKI.
AC_DEFUN([OVS_CHECK_PKIDIR],
  [AC_ARG_WITH(
     [pkidir],
     AS_HELP_STRING([--with-pkidir=DIR],
                    [PKI hierarchy directory [[LOCALSTATEDIR/lib/openvswitch/pki]]]),
     [PKIDIR=$withval],
     [PKIDIR='${localstatedir}/lib/openvswitch/pki'])
   AC_SUBST([PKIDIR])])

dnl Checks for the directory in which to store pidfiles.
AC_DEFUN([OVS_CHECK_RUNDIR],
  [AC_ARG_WITH(
     [rundir],
     AS_HELP_STRING([--with-rundir=DIR],
                    [directory used for pidfiles
                    [[LOCALSTATEDIR/run/openvswitch]]]),
     [RUNDIR=$withval],
     [RUNDIR='${localstatedir}/run/openvswitch'])
   AC_SUBST([RUNDIR])])

dnl Checks for the directory in which to store logs.
AC_DEFUN([OVS_CHECK_LOGDIR],
  [AC_ARG_WITH(
     [logdir],
     AS_HELP_STRING([--with-logdir=DIR],
                    [directory used for logs [[LOCALSTATEDIR/log/PACKAGE]]]),
     [LOGDIR=$withval],
     [LOGDIR='${localstatedir}/log/${PACKAGE}'])
   AC_SUBST([LOGDIR])])

dnl Checks for the directory in which to store the Open vSwitch database.
AC_DEFUN([OVS_CHECK_DBDIR],
  [AC_ARG_WITH(
     [dbdir],
     AS_HELP_STRING([--with-dbdir=DIR],
                    [directory used for conf.db [[SYSCONFDIR/PACKAGE]]]),
     [DBDIR=$withval],
     [DBDIR='${sysconfdir}/${PACKAGE}'])
   AC_SUBST([DBDIR])])

dnl Defines HAVE_BACKTRACE if backtrace() is found.
AC_DEFUN([OVS_CHECK_BACKTRACE],
  [AC_SEARCH_LIBS([backtrace], [execinfo ubacktrace],
                  [HAVE_BACKTRACE=yes], [HAVE_BACKTRACE=no])
   if test "$HAVE_BACKTRACE" = "yes"; then
     AC_DEFINE([HAVE_BACKTRACE], [1], [Define to 1 if you have backtrace(3).])
   fi
   AM_CONDITIONAL([HAVE_BACKTRACE], [test "$HAVE_BACKTRACE" = "yes"])
   AC_SUBST([HAVE_BACKTRACE])])

dnl Defines HAVE_PERF_EVENT if linux/perf_event.h is found.
AC_DEFUN([OVS_CHECK_PERF_EVENT],
  [AC_CHECK_HEADERS([linux/perf_event.h])])

dnl Checks for valgrind/valgrind.h.
AC_DEFUN([OVS_CHECK_VALGRIND],
  [AC_CHECK_HEADERS([valgrind/valgrind.h])])

dnl Checks for Python 3.7 or later.
AC_DEFUN([OVS_CHECK_PYTHON3],
  [AC_CACHE_CHECK(
     [for Python 3 (version 3.7 or later)],
     [ovs_cv_python3],
     [if test -n "$PYTHON3"; then
        ovs_cv_python3=$PYTHON3
      else
        ovs_cv_python3=no
        for binary in python3 python3.7 python3.8 python3.9 python3.10 python3.11 python3.12 python3.13; do
          ovs_save_IFS=$IFS; IFS=$PATH_SEPARATOR
          for dir in $PATH; do
            IFS=$ovs_save_IFS
            test -z "$dir" && dir=.
            if test -x "$dir"/"$binary" && "$dir"/"$binary" -c 'import sys
if sys.hexversion >= 0x03070000 and sys.hexversion < 0x04000000:
    sys.exit(0)
else:
    sys.exit(1)'; then
              ovs_cv_python3=$dir/$binary
              break 2
            fi
          done
        done
      fi])
   if test "$ovs_cv_python3" = no; then
     AC_MSG_ERROR([Python 3.7 or later is required but not found in $PATH, please install it or set $PYTHON3 to point to it])
   fi
   AC_ARG_VAR([PYTHON3])
   PYTHON3=$ovs_cv_python3])

dnl Checks for flake8.
AC_DEFUN([OVS_CHECK_FLAKE8],
  [AC_CACHE_CHECK(
    [for flake8],
    [ovs_cv_flake8],
    [if flake8 --version >/dev/null 2>&1; then
       ovs_cv_flake8=yes
     else
       ovs_cv_flake8=no
     fi])
   AM_CONDITIONAL([HAVE_FLAKE8], [test "$ovs_cv_flake8" = yes])])

dnl Checks for sphinx.
AC_DEFUN([OVS_CHECK_SPHINX],
  [AC_CHECK_PROGS(
     [SPHINXBUILD], [sphinx-build-3 sphinx-build-2 sphinx-build], [none])
   AC_ARG_VAR([SPHINXBUILD])
   AM_CONDITIONAL([HAVE_SPHINX], [test "$SPHINXBUILD" != none])])

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
  [AC_ARG_ENABLE(
     [posix-aio],
     [AS_HELP_STRING([--disable-posix-aio],
                     [Disable POSIX asynchronous I/O for logging])],
     [case "${enableval}" in
        (yes) posix_aio=true ;;
        (no)  posix_aio=false ;;
        (*) AC_MSG_ERROR([bad value ${enableval} for --enable-posix-aio]) ;;
      esac],
     [posix_aio=check])

   if test "$posix_aio" != false; then
      AC_SEARCH_LIBS([aio_write], [rt])
   fi

   if test "$posix_aio" = true && test "$ac_cv_search_aio_write" = no; then
      AC_MSG_ERROR([POSIX AIO support requested, but aio_write not found])
   fi

   AM_CONDITIONAL([HAVE_POSIX_AIO],
     [test "$posix_aio" != false && test "$ac_cv_search_aio_write" != no])])

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

dnl OVS_LIBTOOL_VERSIONS sets the major, minor, micro version information for
dnl OVS_LTINFO variable.  This variable locks libtool information for shared
dnl objects, allowing multiple versions with different ABIs to coexist.
AC_DEFUN([OVS_LIBTOOL_VERSIONS],
    [AC_MSG_CHECKING(linker output version information)
  OVS_MAJOR=`echo "$PACKAGE_VERSION" | sed -e 's/[[.]].*//'`
  OVS_MINOR=`echo "$PACKAGE_VERSION" | sed -e "s/^$OVS_MAJOR//" -e 's/^.//' -e 's/[[.]].*//'`
  OVS_MICRO=`echo "$PACKAGE_VERSION" | sed -e "s/^$OVS_MAJOR.$OVS_MINOR//" -e 's/^.//' -e 's/[[^0-9]].*//'`
  OVS_LT_RELINFO="-release $OVS_MAJOR.$OVS_MINOR"
  OVS_LT_VERINFO="-version-info $LT_CURRENT:$OVS_MICRO"
  OVS_LTINFO="$OVS_LT_RELINFO $OVS_LT_VERINFO"
  AC_MSG_RESULT([libX-$OVS_MAJOR.$OVS_MINOR.so.$LT_CURRENT.0.$OVS_MICRO)])
  AC_SUBST(OVS_LTINFO)
    ])

dnl OVS does not use C++ itself, but it provides public header files
dnl that a C++ compiler should accept, so when --enable-Werror is in
dnl effect and a C++ compiler is available, we enable building a C++
dnl source file that #includes all the public headers, as a way to
dnl ensure that they are acceptable as C++.
AC_DEFUN([OVS_CHECK_CXX],
  [AC_REQUIRE([AC_PROG_CXX])
   AC_REQUIRE([OVS_ENABLE_WERROR])
   AX_CXX_COMPILE_STDCXX([11], [], [optional])
   if test $enable_Werror = yes && test $HAVE_CXX11 = 1; then
     enable_cxx=:
     AC_LANG_PUSH([C++])
     AC_CHECK_HEADERS([atomic])
     AC_LANG_POP([C++])
   else
     enable_cxx=false
   fi
   AM_CONDITIONAL([HAVE_CXX], [$enable_cxx])])

dnl Checks for unbound library.
AC_DEFUN([OVS_CHECK_UNBOUND],
  [AC_CHECK_LIB(unbound, ub_ctx_create, [HAVE_UNBOUND=yes], [HAVE_UNBOUND=no])
   if test "$HAVE_UNBOUND" = yes; then
     AC_DEFINE([HAVE_UNBOUND], [1], [Define to 1 if unbound is detected.])
     LIBS="$LIBS -lunbound"
   fi
   AM_CONDITIONAL([HAVE_UNBOUND], [test "$HAVE_UNBOUND" = yes])
   AC_SUBST([HAVE_UNBOUND])])

dnl Checks for libunwind.
AC_DEFUN([OVS_CHECK_UNWIND],
  [AC_CHECK_LIB([unwind], [unw_backtrace],
   [AC_CHECK_HEADERS([libunwind.h], [HAVE_UNWIND=yes], [HAVE_UNWIND=no])],
   [HAVE_UNWIND=no])
   if test "$HAVE_UNWIND" = yes; then
     AC_DEFINE([HAVE_UNWIND], [1], [Define to 1 if unwind is detected.])
     LIBS="$LIBS -lunwind"
   fi
   AM_CONDITIONAL([HAVE_UNWIND], [test "$HAVE_UNWIND" = yes])
   AC_SUBST([HAVE_UNWIND])])
