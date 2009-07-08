# Copyright (c) 2008, 2009 Nicira Networks
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

AC_PREREQ(2.60)
AC_INIT(openvswitch, 0.90.0, ovs-bugs@openvswitch.org)
NX_BUILDNR
AC_CONFIG_SRCDIR([datapath/datapath.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_RANLIB
AC_PROG_MKDIR_P

AC_ARG_VAR([PERL], [path to Perl interpreter])
AC_PATH_PROG([PERL], perl, no)
if test "$PERL" = no; then
   AC_MSG_ERROR([Perl interpreter not found in $PATH or $PERL.])
fi

AC_USE_SYSTEM_EXTENSIONS
AC_C_BIGENDIAN
AC_SYS_LARGEFILE

OVS_CHECK_USERSPACE
OVS_CHECK_NDEBUG
OVS_CHECK_NETLINK
OVS_CHECK_OPENSSL
OVS_CHECK_LOGDIR
OVS_CHECK_CURSES
OVS_CHECK_LINUX_VT_H
OVS_CHECK_PCRE
OVS_CHECK_IF_PACKET
OVS_CHECK_DPKG_BUILDPACKAGE

if $build_userspace; then
    OVS_CHECK_PKIDIR
    OVS_CHECK_RUNDIR
    OVS_CHECK_MALLOC_HOOKS
    OVS_CHECK_VALGRIND
    OVS_CHECK_TTY_LOCK_DIR
    OVS_CHECK_SOCKET_LIBS
    OVS_CHECK_FAULT_LIBS

    AC_CHECK_FUNCS([strsignal])

    OVS_ENABLE_OPTION([-Wall])
    OVS_ENABLE_OPTION([-Wno-sign-compare])
    OVS_ENABLE_OPTION([-Wpointer-arith])
    OVS_ENABLE_OPTION([-Wdeclaration-after-statement])
    OVS_ENABLE_OPTION([-Wformat-security])
    OVS_ENABLE_OPTION([-Wswitch-enum])
    OVS_ENABLE_OPTION([-Wunused-parameter])
    OVS_ENABLE_OPTION([-Wstrict-aliasing])
    OVS_ENABLE_OPTION([-Wbad-function-cast])
    OVS_ENABLE_OPTION([-Wcast-align])
    OVS_ENABLE_OPTION([-Wstrict-prototypes])
    OVS_ENABLE_OPTION([-Wold-style-definition])
    OVS_ENABLE_OPTION([-Wmissing-prototypes])
    OVS_ENABLE_OPTION([-Wmissing-field-initializers])
    OVS_ENABLE_OPTION([-Wno-override-init])
fi

AC_ARG_VAR(KARCH, [Kernel Architecture String])
AC_SUBST(KARCH)
OVS_CHECK_LINUX(l26, 2.6, KSRC26, L26_ENABLED)

AC_CONFIG_FILES([Makefile 
datapath/Makefile 
datapath/linux-2.6/Kbuild
datapath/linux-2.6/Makefile
datapath/linux-2.6/Makefile.main])

AC_OUTPUT
