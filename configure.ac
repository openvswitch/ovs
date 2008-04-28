AC_PREREQ(2.59)
AC_INIT(openflow, v0.2.2a5, info@openflowswitch.org)
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_CPP
AC_PROG_LD

AC_USE_SYSTEM_EXTENSIONS

AC_PROG_LIBTOOL

AC_ARG_ENABLE(
  [ndebug],
  [AC_HELP_STRING([--enable-ndebug], 
                  [Disable debugging features for max performance])],
  [case "${enableval}" in # (
     yes) ndebug=true ;; # (
     no)  ndebug=false ;; # (
     *) AC_MSG_ERROR([bad value ${enableval} for --enable-ndebug]) ;;
   esac],
  [ndebug=false])
AM_CONDITIONAL([NDEBUG], [test x$ndebug = xtrue])

CHECK_LINUX(l26, 2.6, 2.6, KSRC26, L26_ENABLED)
CHECK_LINUX(l24, 2.4, 2.4, KSRC24, L24_ENABLED)

AC_CHECK_HEADER([linux/netlink.h],
                [HAVE_NETLINK=yes],
                [HAVE_NETLINK=no],
                [#include <sys/socket.h>
#include <linux/types.h>])
AM_CONDITIONAL([HAVE_NETLINK], [test "$HAVE_NETLINK" = yes])
if test "$HAVE_NETLINK" = yes; then
   AC_DEFINE([HAVE_NETLINK], [1],
             [Define to 1 if Netlink protocol is available.])
fi

AC_CHECK_HEADER([net/if_packet.h],
                [HAVE_IF_PACKET=yes],
                [HAVE_IF_PACKET=no])
AM_CONDITIONAL([HAVE_IF_PACKET], [test "$HAVE_IF_PACKET" = yes])
if test "$HAVE_IF_PACKET" = yes; then
   AC_DEFINE([HAVE_IF_PACKET], [1],
             [Define to 1 if net/if_packet.h is available.])
fi

AC_ARG_ENABLE(
  [ssl],
  [AC_HELP_STRING([--enable-ssl], 
                  [Enable ssl support (requires libssl)])],
  [case "${enableval}" in # (
     yes) ssl=true ;;  # (
     no)  ssl=false ;; # (
     *) AC_MSG_ERROR([bad value ${enableval} for --enable-ssl]) ;;
   esac],
  [ssl=false])

if test "$ssl" = true; then
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
fi

AC_CHECK_LIB([socket], [connect])
AC_CHECK_LIB([resolv], [gethostbyname])
AC_CHECK_LIB([dl], [dladdr])

CFLAGS="$CFLAGS -Wall -Wno-sign-compare"

AC_CONFIG_FILES([Makefile 
man/Makefile
man/man8/Makefile
datapath/Makefile 
lib/Makefile
include/Makefile
controller/Makefile
utilities/Makefile
secchan/Makefile
switch/Makefile
tests/Makefile
datapath/tests/Makefile
third-party/Makefile
datapath/linux-2.6/Kbuild
datapath/linux-2.6/Makefile
datapath/linux-2.6/Makefile.main
datapath/linux-2.4/Makefile])

AC_OUTPUT
