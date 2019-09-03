# Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
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

AC_PREREQ(2.63)
AC_INIT(openvswitch, 2.12.1, bugs@openvswitch.org)
AC_CONFIG_SRCDIR([datapath/datapath.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_TESTDIR([tests])
AM_INIT_AUTOMAKE([tar-pax])

AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_MKDIR_P
AC_PROG_FGREP
AC_PROG_EGREP
PKG_PROG_PKG_CONFIG

AM_MISSING_PROG([AUTOM4TE], [autom4te])

AC_USE_SYSTEM_EXTENSIONS
AC_C_BIGENDIAN
AC_SYS_LARGEFILE

LT_INIT([disable-shared])
m4_pattern_forbid([LT_INIT]) dnl Make autoconf fail if libtool is missing.

# The following explanation may help to understand the use of the
# version number fields: current, revision, and age.
#
# Consider that there are three possible kinds of reactions from
# users of your library to changes in a shared library:
#
# 1. Programs using the previous version may use the new version as drop-in
#    replacement, and programs using the new version can also work with the
#    previous one. In other words, no recompiling nor relinking is needed.
#    In short, there are no changes to any symbols, no symbols removed,
#    and no symbols added. In this case, bump revision only, don't touch
#    current nor age.
#
# 2. Programs using the previous version may use the new version as drop-in
#    replacement, but programs using the new version may use APIs not
#    present in the previous one. In other words, new symbols have been
#    added and a program linking against the new version may fail with
#    "unresolved symbols." If linking against the old version at runtime:
#    set revision to 0, bump current and age.
#
# 3. Programs may need to be changed, recompiled, relinked in order to use
#    the new version. This is the case when symbols have been modified or
#    deleted. Bump current, set revision and age to 0.

m4_define([libopenvswitch_lt_current],    [0])
m4_define([libopenvswitch_lt_revision],   [0])
m4_define([libopenvswitch_lt_age],        [0])

LT_CURRENT=libopenvswitch_lt_current
AC_SUBST([LT_CURRENT])
LT_REVISION=libopenvswitch_lt_revision
AC_SUBST([LT_REVISION])
LT_AGE=libopenvswitch_lt_age
AC_SUBST([LT_AGE])

AC_SEARCH_LIBS([pow], [m])
AC_SEARCH_LIBS([clock_gettime], [rt])
AC_SEARCH_LIBS([timer_create], [rt])
AC_SEARCH_LIBS([pthread_rwlock_tryrdlock], [pthread])
AC_SEARCH_LIBS([pthread_rwlockattr_destroy], [pthread])
AC_SEARCH_LIBS([pthread_spin_lock], [pthread])
AC_CHECK_FUNCS([pthread_spin_lock])
AC_FUNC_STRERROR_R

OVS_CHECK_WIN64
OVS_CHECK_WIN32
OVS_CHECK_VISUAL_STUDIO_DDK
OVS_CHECK_COVERAGE
OVS_CHECK_NDEBUG
OVS_CHECK_NETLINK
OVS_CHECK_OPENSSL
OVS_CHECK_LIBCAPNG
OVS_CHECK_LOGDIR
OVS_CHECK_PYTHON2
OVS_CHECK_PYTHON3
OVS_CHECK_PYTHON
OVS_CHECK_FLAKE8
OVS_CHECK_SPHINX
OVS_CHECK_DOT
OVS_CHECK_IF_DL
OVS_CHECK_STRTOK_R
OVS_CHECK_LINUX_AF_XDP
AC_CHECK_DECLS([sys_siglist], [], [], [[#include <signal.h>]])
AC_CHECK_MEMBERS([struct stat.st_mtim.tv_nsec, struct stat.st_mtimensec],
  [], [], [[#include <sys/stat.h>]])
AC_CHECK_MEMBERS([struct ifreq.ifr_flagshigh], [], [], [[#include <net/if.h>]])
AC_CHECK_MEMBERS([struct mmsghdr.msg_len], [], [], [[#include <sys/socket.h>]])
AC_CHECK_MEMBERS([struct sockaddr_in6.sin6_scope_id], [], [],
  [[#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>]])
AC_CHECK_FUNCS([mlockall strnlen getloadavg statvfs getmntent_r sendmmsg clock_gettime])
AC_CHECK_HEADERS([mntent.h sys/statvfs.h linux/types.h linux/if_ether.h])
AC_CHECK_HEADERS([linux/net_namespace.h stdatomic.h bits/floatn-common.h])
AC_CHECK_HEADERS([net/if_mib.h], [], [], [[#include <sys/types.h>
#include <net/if.h>]])

OVS_CHECK_PKIDIR
OVS_CHECK_RUNDIR
OVS_CHECK_DBDIR
OVS_CHECK_BACKTRACE
OVS_CHECK_PERF_EVENT
OVS_CHECK_VALGRIND
OVS_CHECK_SOCKET_LIBS
OVS_CHECK_XENSERVER_VERSION
OVS_CHECK_GROFF
OVS_CHECK_TLS
OVS_CHECK_ATOMIC_LIBS
OVS_CHECK_GCC4_ATOMICS
OVS_CHECK_ATOMIC_ALWAYS_LOCK_FREE(1)
OVS_CHECK_ATOMIC_ALWAYS_LOCK_FREE(2)
OVS_CHECK_ATOMIC_ALWAYS_LOCK_FREE(4)
OVS_CHECK_ATOMIC_ALWAYS_LOCK_FREE(8)
OVS_CHECK_POSIX_AIO
OVS_CHECK_PTHREAD_SET_NAME
OVS_CHECK_LINUX_HOST
OVS_LIBTOOL_VERSIONS
OVS_CHECK_CXX
AX_FUNC_POSIX_MEMALIGN
OVS_CHECK_UNBOUND

OVS_CHECK_INCLUDE_NEXT([stdio.h string.h])
AC_CONFIG_FILES([
    lib/stdio.h
    lib/string.h
    ovsdb/libovsdb.sym
    ofproto/libofproto.sym
    lib/libsflow.sym
    lib/libopenvswitch.sym
    ovn/lib/libovn.sym
    vtep/libvtep.sym])

OVS_ENABLE_OPTION([-Wall])
OVS_ENABLE_OPTION([-Wextra])
OVS_ENABLE_OPTION([-Wno-sign-compare])
OVS_ENABLE_OPTION([-Wpointer-arith])
OVS_ENABLE_OPTION([-Wformat -Wformat-security])
OVS_ENABLE_OPTION([-Wswitch-enum])
OVS_ENABLE_OPTION([-Wunused-parameter])
OVS_ENABLE_OPTION([-Wbad-function-cast])
OVS_ENABLE_OPTION([-Wcast-align])
OVS_ENABLE_OPTION([-Wstrict-prototypes])
OVS_ENABLE_OPTION([-Wold-style-definition])
OVS_ENABLE_OPTION([-Wmissing-prototypes])
OVS_ENABLE_OPTION([-Wmissing-field-initializers])
OVS_ENABLE_OPTION([-Wthread-safety])
OVS_ENABLE_OPTION([-fno-strict-aliasing])
OVS_ENABLE_OPTION([-Wswitch-bool])
OVS_ENABLE_OPTION([-Wlogical-not-parentheses])
OVS_ENABLE_OPTION([-Wsizeof-array-argument])
OVS_ENABLE_OPTION([-Wbool-compare])
OVS_ENABLE_OPTION([-Wshift-negative-value])
OVS_ENABLE_OPTION([-Wduplicated-cond])
OVS_ENABLE_OPTION([-Qunused-arguments])
OVS_ENABLE_OPTION([-Wshadow])
OVS_ENABLE_OPTION([-Wmultistatement-macros])
OVS_ENABLE_OPTION([-Wcast-align=strict])
OVS_ENABLE_OPTION([-Wno-null-pointer-arithmetic])
OVS_ENABLE_OPTION([-Warray-bounds-pointer-arithmetic])
OVS_CONDITIONAL_CC_OPTION([-Wno-unused], [HAVE_WNO_UNUSED])
OVS_CONDITIONAL_CC_OPTION([-Wno-unused-parameter], [HAVE_WNO_UNUSED_PARAMETER])
OVS_ENABLE_WERROR
OVS_ENABLE_SPARSE
OVS_CTAGS_IDENTIFIERS

AC_ARG_VAR(KARCH, [Kernel Architecture String])
AC_SUBST(KARCH)
OVS_CHECK_LINUX
OVS_CHECK_LINUX_TC
OVS_CHECK_LINUX_SCTP_CT
OVS_CHECK_DPDK
OVS_CHECK_PRAGMA_MESSAGE
AC_SUBST([OVS_CFLAGS])
AC_SUBST([OVS_LDFLAGS])

AC_CONFIG_FILES(Makefile)
AC_CONFIG_FILES(datapath/Makefile)
AC_CONFIG_FILES(datapath/linux/Kbuild)
AC_CONFIG_FILES(datapath/linux/Makefile)
AC_CONFIG_FILES(datapath/linux/Makefile.main)
AC_CONFIG_FILES(tests/atlocal)
AC_CONFIG_FILES(lib/libopenvswitch.pc)
AC_CONFIG_FILES(lib/libsflow.pc)
AC_CONFIG_FILES(ofproto/libofproto.pc)
AC_CONFIG_FILES(ovsdb/libovsdb.pc)
AC_CONFIG_FILES(include/openvswitch/version.h)

dnl This makes sure that include/openflow gets created in the build directory.
AC_CONFIG_COMMANDS([include/openflow/openflow.h.stamp])

AC_CONFIG_COMMANDS([utilities/bugtool/dummy], [:])
AC_CONFIG_COMMANDS([ovn/dummy], [:])
AC_CONFIG_COMMANDS([ovn/utilities/dummy], [:])
AC_CONFIG_COMMANDS([ipsec/dummy], [:])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

AC_OUTPUT
