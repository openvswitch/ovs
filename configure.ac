# Copyright (c) 2008, 2009, 2010 Nicira Networks
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

AC_PREREQ(2.64)
AC_INIT(openvswitch, 1.1.0pre2, ovs-bugs@openvswitch.org)
NX_BUILDNR
AC_CONFIG_SRCDIR([datapath/datapath.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_TESTDIR([tests])
AM_INIT_AUTOMAKE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_RANLIB
AC_PROG_MKDIR_P
AC_PROG_FGREP

AC_ARG_VAR([PERL], [path to Perl interpreter])
AC_PATH_PROG([PERL], perl, no)
if test "$PERL" = no; then
   AC_MSG_ERROR([Perl interpreter not found in $PATH or $PERL.])
fi

AC_USE_SYSTEM_EXTENSIONS
AC_C_BIGENDIAN
AC_SYS_LARGEFILE

AC_SEARCH_LIBS([pow], [m])
AC_SEARCH_LIBS([clock_gettime], [rt])

OVS_CHECK_COVERAGE
OVS_CHECK_NDEBUG
OVS_CHECK_NETLINK
OVS_CHECK_OPENSSL
OVS_CHECK_LOGDIR
OVS_CHECK_PYTHON
OVS_CHECK_PYUIC4
OVS_CHECK_OVSDBMONITOR
OVS_CHECK_ER_DIAGRAMS
OVS_CHECK_IF_PACKET
OVS_CHECK_STRTOK_R
AC_CHECK_MEMBERS([struct stat.st_mtim.tv_nsec, struct stat.st_mtimensec],
  [], [], [[#include <sys/stat.h>]])
AC_CHECK_FUNCS([mlockall])

OVS_CHECK_PKIDIR
OVS_CHECK_RUNDIR
OVS_CHECK_MALLOC_HOOKS
OVS_CHECK_VALGRIND
OVS_CHECK_SOCKET_LIBS
OVS_CHECK_LINKER_SECTIONS

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
OVS_CONDITIONAL_CC_OPTION([-Wno-unused], [HAVE_WNO_UNUSED])
OVS_CONDITIONAL_CC_OPTION([-Wno-unused-parameter], [HAVE_WNO_UNUSED_PARAMETER])

AC_ARG_VAR(KARCH, [Kernel Architecture String])
AC_SUBST(KARCH)
OVS_CHECK_LINUX26

AC_CONFIG_FILES([Makefile 
datapath/Makefile 
datapath/linux-2.6/Kbuild
datapath/linux-2.6/Makefile
datapath/linux-2.6/Makefile.main
tests/atlocal])

dnl This makes sure that include/openflow gets created in the build directory.
AC_CONFIG_COMMANDS([include/openflow/openflow.h.stamp])

AC_CONFIG_COMMANDS([ovsdb/ovsdbmonitor/dummy], [:])

AC_OUTPUT
