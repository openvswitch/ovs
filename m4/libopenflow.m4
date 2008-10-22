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

dnl Checks for --enable-ndebug and defines NDEBUG if it is specified.
AC_DEFUN([OFP_CHECK_NDEBUG],
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
AC_DEFUN([OFP_CHECK_NETLINK],
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
AC_DEFUN([OFP_CHECK_OPENSSL],
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

   OpenFlow will not support SSL connections.])])

   fi
   AM_CONDITIONAL([HAVE_OPENSSL], [test "$HAVE_OPENSSL" = yes])
   if test "$HAVE_OPENSSL" = yes; then
      AC_DEFINE([HAVE_OPENSSL], [1], [Define to 1 if OpenSSL is installed.])
   fi])

dnl Checks for --enable-snat and defines SUPPORT_SNAT if it is specified.
AC_DEFUN([OFP_CHECK_SNAT],
  [AC_ARG_ENABLE(
     [snat],
     [AC_HELP_STRING([--enable-snat], 
                     [Enable support for source-NAT action])],
     [case "${enableval}" in
        (yes) snat=true ;;
        (no)  snat=false ;;
        (*) AC_MSG_ERROR([bad value ${enableval} for --enable-snat]) ;;
      esac],
     [snat=false])
   AM_CONDITIONAL([SUPPORT_SNAT], [test x$snat = xtrue])
   if test x$snat = xtrue; then
      AC_DEFINE([SUPPORT_SNAT], [1], [Define to 1 if SNAT is desired.])
      SUPPORT_SNAT=-DSUPPORT_SNAT
      AC_SUBST([SUPPORT_SNAT])
   fi])

dnl Checks for libraries needed by lib/fault.c.
AC_DEFUN([OFP_CHECK_FAULT_LIBS],
  [AC_CHECK_LIB([dl], [dladdr], [FAULT_LIBS=-ldl])
   AC_SUBST([FAULT_LIBS])])

dnl Checks for libraries needed by lib/socket-util.c.
AC_DEFUN([OFP_CHECK_SOCKET_LIBS],
  [AC_CHECK_LIB([socket], [connect])
   AC_SEARCH_LIBS([gethostbyname], [resolv], [RESOLVER_LIBS=-lresolv])])

dnl Checks for the directory in which to store the PKI.
AC_DEFUN([OFP_CHECK_PKIDIR],
  [AC_ARG_WITH(
     [pkidir], 
     AC_HELP_STRING([--with-pkidir=DIR], 
                    [PKI hierarchy directory [[DATADIR/openflow/pki]]]),
     [PKIDIR=$withval],
     [PKIDIR='${pkgdatadir}/pki'])
   AC_SUBST([PKIDIR])])

dnl Checks for the directory in which to store pidfiles.
AC_DEFUN([OFP_CHECK_RUNDIR],
  [AC_ARG_WITH(
     [rundir], 
     AC_HELP_STRING([--with-rundir=DIR], 
                    [directory used for pidfiles [[LOCALSTATEDIR/run]]]),
     [RUNDIR=$withval],
     [RUNDIR='${localstatedir}/run'])
   AC_SUBST([RUNDIR])])

dnl Checks for the directory in which to store logs.
AC_DEFUN([OFP_CHECK_LOGDIR],
  [AC_ARG_WITH(
     [logdir], 
     AC_HELP_STRING([--with-logdir=DIR], 
                    [directory used for logs [[LOCALSTATEDIR/log/PACKAGE]]]),
     [LOGDIR=$withval],
     [LOGDIR='${localstatedir}/log/${PACKAGE}'])
   AC_SUBST([LOGDIR])])

dnl Runs the checks required to include the headers in include/ and
dnl link against lib/libopenflow.a.
AC_DEFUN([OFP_CHECK_LIBOPENFLOW],
  [AC_REQUIRE([AC_USE_SYSTEM_EXTENSIONS])
   AC_REQUIRE([OFP_CHECK_NDEBUG])
   AC_REQUIRE([OFP_CHECK_NETLINK])
   AC_REQUIRE([OFP_CHECK_OPENSSL])
   AC_REQUIRE([OFP_CHECK_SNAT])
   AC_REQUIRE([OFP_CHECK_FAULT_LIBS])
   AC_REQUIRE([OFP_CHECK_SOCKET_LIBS])
   AC_REQUIRE([OFP_CHECK_PKIDIR])
   AC_REQUIRE([OFP_CHECK_RUNDIR])
   AC_REQUIRE([OFP_CHECK_LOGDIR])
   AC_CHECK_FUNCS([strlcpy])])

