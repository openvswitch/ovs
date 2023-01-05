# -*- autoconf -*-

# Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2019 Nicira, Inc.
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

dnl Set OVS Actions Autovalidator as the default action implementation
dnl at compile time. This enables automatically running all unit tests
dnl with all actions implementations.
AC_DEFUN([OVS_CHECK_ACTIONS_AUTOVALIDATOR], [
  AC_ARG_ENABLE([actions-default-autovalidator],
                [AS_HELP_STRING([--enable-actions-default-autovalidator],
                                [Enable actions autovalidator as default
                                 ovs actions implementation.])],
                [autovalidator=yes],[autovalidator=no])
  AC_MSG_CHECKING([whether actions Autovalidator is default implementation])
  if test "$autovalidator" != yes; then
    AC_MSG_RESULT([no])
  else
    AC_DEFINE([ACTIONS_AUTOVALIDATOR_DEFAULT], [1],
              [Autovalidator for actions is a default implementation.])
    AC_MSG_RESULT([yes])
  fi
])


dnl Set OVS MFEX Autovalidator as default miniflow extract at compile time?
dnl This enables automatically running all unit tests with all MFEX
dnl implementations.
AC_DEFUN([OVS_CHECK_MFEX_AUTOVALIDATOR], [
  AC_ARG_ENABLE([mfex-default-autovalidator],
                [AS_HELP_STRING([--enable-mfex-default-autovalidator],
                                [Enable MFEX autovalidator as default
                                 miniflow_extract implementation.])],
                [autovalidator=yes],[autovalidator=no])
  AC_MSG_CHECKING([whether MFEX Autovalidator is default implementation])
  if test "$autovalidator" != yes; then
    AC_MSG_RESULT([no])
  else
    AC_DEFINE([MFEX_AUTOVALIDATOR_DEFAULT], [1],
              [Autovalidator for miniflow_extract is a default implementation.])
    AC_MSG_RESULT([yes])
  fi
])

dnl Set OVS DPCLS Autovalidator as default subtable search at compile time?
dnl This enables automatically running all unit tests with all DPCLS
dnl implementations.
AC_DEFUN([OVS_CHECK_DPCLS_AUTOVALIDATOR], [
  AC_ARG_ENABLE([autovalidator],
                [AS_HELP_STRING([--enable-autovalidator],
                                [Enable DPCLS autovalidator as default subtable
                                 search implementation.])],
                [autovalidator=yes],[autovalidator=no])
  AC_MSG_CHECKING([whether DPCLS Autovalidator is default implementation])
  if test "$autovalidator" != yes; then
    AC_MSG_RESULT([no])
  else
    AC_DEFINE([DPCLS_AUTOVALIDATOR_DEFAULT], [1],
              [Autovalidator for the userspace datapath classifier is a
               default implementation.])
    AC_MSG_RESULT([yes])
  fi
])

dnl Set OVS DPIF default implementation at configure time for running the unit
dnl tests on the whole codebase without modifying tests per DPIF impl
AC_DEFUN([OVS_CHECK_DPIF_AVX512_DEFAULT], [
  AC_ARG_ENABLE([dpif-default-avx512],
                [AS_HELP_STRING([--enable-dpif-default-avx512],
                                [Enable DPIF AVX512 implementation as default.])],
                [dpifavx512=yes],[dpifavx512=no])
  AC_MSG_CHECKING([whether DPIF AVX512 is default implementation])
  if test "$dpifavx512" != yes; then
    AC_MSG_RESULT([no])
  else
    AC_DEFINE([DPIF_AVX512_DEFAULT], [1],
              [DPIF AVX512 is a default implementation of the userspace
               datapath interface.])
    AC_MSG_RESULT([yes])
  fi
])

dnl OVS_CHECK_AVX512
dnl
dnl Checks if compiler and binutils supports various AVX512 ISA.
AC_DEFUN([OVS_CHECK_AVX512], [
  OVS_CHECK_BINUTILS_AVX512
  OVS_CHECK_GCC_AVX512VL
  OVS_CONDITIONAL_CC_OPTION_DEFINE([-mavx512f], [HAVE_AVX512F])
  OVS_CONDITIONAL_CC_OPTION_DEFINE([-mavx512bw], [HAVE_AVX512BW])
  OVS_CONDITIONAL_CC_OPTION_DEFINE([-mavx512vl], [HAVE_AVX512VL])
  OVS_CONDITIONAL_CC_OPTION_DEFINE([-mavx512vbmi], [HAVE_AVX512VBMI])
  OVS_CHECK_AVX512VPOPCNTDQ
])

dnl OVS_ENABLE_WERROR
AC_DEFUN([OVS_ENABLE_WERROR],
  [AC_ARG_ENABLE(
     [Werror],
     [AS_HELP_STRING([--enable-Werror], [Add -Werror to CFLAGS])],
     [], [enable_Werror=no])
   AC_CONFIG_COMMANDS_PRE(
     [if test "X$enable_Werror" = Xyes; then
        OVS_CFLAGS="$OVS_CFLAGS -Werror"
      fi])

   # Unless --enable-Werror is specified, report but do not fail the build
   # for errors reported by flake8.
   if test "X$enable_Werror" = Xyes; then
     FLAKE8_WERROR=
   else
     FLAKE8_WERROR=-
   fi
   AC_SUBST([FLAKE8_WERROR])

   # If --enable-Werror is specified, fail the build on sparse warnings.
   if test "X$enable_Werror" = Xyes; then
     SPARSE_WERROR=-Wsparse-error
   else
     SPARSE_WERROR=
   fi
   AC_SUBST([SPARSE_WERROR])])

dnl Version for a top level invocation, since AC_REQUIRE can not be used
dnl outside of AC_DEFUN, but needed to protect against double expansion.
AC_DEFUN([OVS_ENABLE_WERROR_TOP], [AC_REQUIRE([OVS_ENABLE_WERROR])])

dnl OVS_CHECK_LINUX
dnl
dnl Configure linux kernel source tree
AC_DEFUN([OVS_CHECK_LINUX], [
  if test X"$with_linux" != X; then
    AC_MSG_WARN([--with-linux is no longer supported])
  fi
])

dnl OVS_CHECK_LINUX_NETLINK
dnl
dnl Configure Linux netlink compat.
AC_DEFUN([OVS_CHECK_LINUX_NETLINK], [
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/netlink.h>], [
        struct nla_bitfield32 x =  { 0 };
    ])],
    [AC_DEFINE([HAVE_NLA_BITFIELD32], [1],
    [Define to 1 if struct nla_bitfield32 is available.])])
])

dnl OVS_CHECK_LINUX_TC
dnl
dnl Configure Linux tc compat.
AC_DEFUN([OVS_CHECK_LINUX_TC], [
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/pkt_cls.h>], [
        int x = TCA_ACT_FLAGS_SKIP_HW;
    ])],
    [AC_DEFINE([HAVE_TCA_ACT_FLAGS_SKIP_HW], [1],
               [Define to 1 if TCA_ACT_FLAGS_SKIP_HW is available.])])

  AC_CHECK_MEMBERS([struct tcf_t.firstuse], [], [], [#include <linux/pkt_cls.h>])

  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/tc_act/tc_vlan.h>], [
        int x = TCA_VLAN_PUSH_VLAN_PRIORITY;
    ])],
    [AC_DEFINE([HAVE_TCA_VLAN_PUSH_VLAN_PRIORITY], [1],
               [Define to 1 if TCA_VLAN_PUSH_VLAN_PRIORITY is available.])])

  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/tc_act/tc_mpls.h>], [
        int x = TCA_MPLS_TTL;
    ])],
    [AC_DEFINE([HAVE_TCA_MPLS_TTL], [1],
               [Define to 1 if HAVE_TCA_MPLS_TTL is available.])])

  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/tc_act/tc_tunnel_key.h>], [
        int x = TCA_TUNNEL_KEY_ENC_TTL;
    ])],
    [AC_DEFINE([HAVE_TCA_TUNNEL_KEY_ENC_TTL], [1],
               [Define to 1 if TCA_TUNNEL_KEY_ENC_TTL is available.])])

  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/tc_act/tc_pedit.h>], [
        int x = TCA_PEDIT_KEY_EX_HDR_TYPE_UDP;
    ])],
    [AC_DEFINE([HAVE_TCA_PEDIT_KEY_EX_HDR_TYPE_UDP], [1],
               [Define to 1 if TCA_PEDIT_KEY_EX_HDR_TYPE_UDP is available.])])

  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/tc_act/tc_skbedit.h>], [
        int x = TCA_SKBEDIT_FLAGS;
    ])],
    [AC_DEFINE([HAVE_TCA_SKBEDIT_FLAGS], [1],
               [Define to 1 if TCA_SKBEDIT_FLAGS is available.])])

  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/gen_stats.h>], [
        int x = TCA_STATS_PKT64;
    ])],
    [AC_DEFINE([HAVE_TCA_STATS_PKT64], [1],
               [Define to 1 if TCA_STATS_PKT64 is available.])])
])

dnl OVS_CHECK_LINUX_SCTP_CT
dnl
dnl Checks for kernels which need additional SCTP state
AC_DEFUN([OVS_CHECK_LINUX_SCTP_CT], [
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_sctp.h>], [
        int x = SCTP_CONNTRACK_HEARTBEAT_SENT;
    ])],
    [AC_DEFINE([HAVE_SCTP_CONNTRACK_HEARTBEATS], [1],
               [Define to 1 if SCTP_CONNTRACK_HEARTBEAT_SENT is available.])])
])

dnl OVS_CHECK_LINUX_VIRTIO_TYPES
dnl
dnl Checks for kernels that need virtio_types definition.
AC_DEFUN([OVS_CHECK_LINUX_VIRTIO_TYPES], [
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/virtio_types.h>], [
        __virtio16 x =  0;
    ])],
    [AC_DEFINE([HAVE_VIRTIO_TYPES], [1],
    [Define to 1 if __virtio16 is available.])])
])

dnl OVS_FIND_DEPENDENCY(FUNCTION, SEARCH_LIBS, NAME_TO_PRINT)
dnl
dnl Check for a function in a library list.
AC_DEFUN([OVS_FIND_DEPENDENCY], [
  AC_SEARCH_LIBS([$1], [$2], [], [
    AC_MSG_ERROR([unable to find $3, install the dependency package])
  ])
])

dnl OVS_CHECK_LINUX_AF_XDP
dnl
dnl Check both Linux kernel AF_XDP and libbpf/libxdp support
AC_DEFUN([OVS_CHECK_LINUX_AF_XDP], [
  AC_ARG_ENABLE(
    [afxdp],
    [AS_HELP_STRING([--disable-afxdp], [Disable AF-XDP support])],
    [case "${enableval}" in
       (yes | no | auto) ;;
       (*) AC_MSG_ERROR([bad value ${enableval} for --enable-afxdp]) ;;
     esac],
    [enable_afxdp=auto])

  AC_MSG_CHECKING([whether AF_XDP is enabled])
  if test "$enable_afxdp" = no; then
    AC_MSG_RESULT([no])
    AF_XDP_ENABLE=false
  else
    AC_MSG_RESULT([$enable_afxdp])
    AF_XDP_ENABLE=true
    failed_dep=none
    dnl Saving libs to restore in case we will end up not building with AF_XDP.
    save_LIBS=$LIBS

    AC_CHECK_HEADER([bpf/libbpf.h], [], [failed_dep="bpf/libbpf.h"])

    if test "$failed_dep" = none; then
      AC_CHECK_HEADER([linux/if_xdp.h], [], [failed_dep="linux/if_xdp.h"])
    fi

    if test "$failed_dep" = none; then
      AC_SEARCH_LIBS([libbpf_strerror], [bpf], [], [failed_dep="libbpf"])
      AC_CHECK_FUNCS([bpf_xdp_query_id bpf_xdp_detach])
    fi

    if test "$failed_dep" = none -a "x$ac_cv_func_bpf_xdp_detach" = xyes; then
        dnl We have libbpf >= 0.7.  Look for libxdp as xsk functions
        dnl were moved into this library.
        AC_SEARCH_LIBS([libxdp_strerror], [xdp],
          AC_CHECK_HEADER([xdp/xsk.h],
            AC_DEFINE([HAVE_LIBXDP], [1], [xsk.h is supplied with libxdp]),
            [failed_dep="xdp/xsk.h"]),
          [failed_dep="libxdp"])
    elif test "$failed_dep" = none; then
        dnl libbpf < 0.7 contains all the necessary functionality.
        AC_CHECK_HEADER([bpf/xsk.h], [], [failed_dep="bpf/xsk.h"])
    fi

    if test "$failed_dep" = none; then
      AC_CHECK_FUNCS([pthread_spin_lock], [], [failed_dep="pthread_spin_lock"])
    fi

    if test "$failed_dep" = none; then
      AC_SEARCH_LIBS([numa_alloc_onnode], [numa], [], [failed_dep="libnuma"])
    fi

    if test "$failed_dep" = none; then
      AC_DEFINE([HAVE_AF_XDP], [1],
                [Define to 1 if AF_XDP support is available and enabled.])
    elif test "$enable_afxdp" = yes; then
      AC_MSG_ERROR([Missing $failed_dep dependency for AF_XDP support])
    else
      AC_MSG_WARN(m4_normalize(
          [Cannot find $failed_dep, netdev-afxdp will not be supported
           (use --disable-afxdp to suppress this warning).]))
      AF_XDP_ENABLE=false
      LIBS=$save_LIBS
    fi
  fi
  AM_CONDITIONAL([HAVE_AF_XDP], test "$AF_XDP_ENABLE" = true)
])

dnl OVS_CHECK_DPDK
dnl
dnl Configure DPDK source tree
AC_DEFUN([OVS_CHECK_DPDK], [
  AC_ARG_WITH([dpdk],
              [AS_HELP_STRING([--with-dpdk=static|shared|yes],
                              [Specify "static" or "shared" depending on the
                              DPDK libraries to use])],
              [have_dpdk=true])

  AC_MSG_CHECKING([whether dpdk is enabled])
  if test "$have_dpdk" != true || test "$with_dpdk" = no; then
    AC_MSG_RESULT([no])
    DPDKLIB_FOUND=false
  else
    AC_MSG_RESULT([yes])
    case "$with_dpdk" in
      "shared")
          PKG_CHECK_MODULES([DPDK], [libdpdk], [
              DPDK_INCLUDE="$DPDK_CFLAGS"
              DPDK_LIB="$DPDK_LIBS"])
              ;;
      "static" | "yes")
          PKG_CHECK_MODULES_STATIC([DPDK], [libdpdk], [
              DPDK_INCLUDE="$DPDK_CFLAGS"
              DPDK_LIB="$DPDK_LIBS"])

          dnl Statically linked private DPDK objects of form
          dnl -l:file.a must be positioned between
          dnl --whole-archive ... --no-whole-archive linker parameters.
          dnl Old pkg-config versions misplace --no-whole-archive parameter
          dnl and put it next to --whole-archive.
          AC_MSG_CHECKING([for faulty pkg-config version])
          echo "$DPDK_LIB" | grep -q 'whole-archive.*l:lib.*no-whole-archive'
          status=$?
          case $status in
            0)
              AC_MSG_RESULT([no])
              ;;
            1)
              AC_MSG_RESULT([yes])
              AC_MSG_ERROR([Please upgrade pkg-config])
              ;;
            *)
              AC_MSG_ERROR([grep exited with status $status])
              ;;
          esac
    esac

    ovs_save_CFLAGS="$CFLAGS"
    ovs_save_LDFLAGS="$LDFLAGS"
    CFLAGS="$CFLAGS $DPDK_INCLUDE"

    AC_CHECK_HEADERS([rte_config.h], [], [
      AC_MSG_ERROR([unable to find rte_config.h in $with_dpdk])
    ], [AC_INCLUDES_DEFAULT])

    AC_CHECK_DECLS([RTE_LIBRTE_VHOST_NUMA, RTE_EAL_NUMA_AWARE_HUGEPAGES], [
      OVS_FIND_DEPENDENCY([get_mempolicy], [numa], [libnuma])
    ], [], [[#include <rte_config.h>]])

    AC_CHECK_DECL([RTE_NET_PCAP], [
      OVS_FIND_DEPENDENCY([pcap_dump_close], [pcap], [libpcap])
    ], [], [[#include <rte_config.h>]])

    AC_CHECK_DECL([RTE_NET_AF_XDP], [
      OVS_FIND_DEPENDENCY([libbpf_strerror], [bpf], [libbpf])
    ], [], [[#include <rte_config.h>]])

    AC_CHECK_DECL([RTE_LIBRTE_VHOST_NUMA], [
      AC_DEFINE([VHOST_NUMA], [1], [NUMA Aware vHost support detected in DPDK.])
    ], [], [[#include <rte_config.h>]])

    AC_CHECK_DECL([RTE_NET_MLX5], [dnl found
      AC_CHECK_DECL([RTE_IBVERBS_LINK_DLOPEN], [], [dnl not found
        OVS_FIND_DEPENDENCY([mlx5dv_create_wq], [mlx5], [libmlx5])
        OVS_FIND_DEPENDENCY([verbs_init_cq], [ibverbs], [libibverbs])
      ], [[#include <rte_config.h>]])
    ], [], [[#include <rte_config.h>]])

    AC_CHECK_DECL([RTE_NET_MLX4], [dnl found
      AC_CHECK_DECL([RTE_IBVERBS_LINK_DLOPEN], [], [dnl not found
        OVS_FIND_DEPENDENCY([mlx4dv_init_obj], [mlx4], [libmlx4])
        OVS_FIND_DEPENDENCY([verbs_init_cq], [ibverbs], [libibverbs])
      ], [[#include <rte_config.h>]])
    ], [], [[#include <rte_config.h>]])

    AC_CHECK_DECL([MAP_HUGE_SHIFT], [
      AC_DEFINE([DPDK_IN_MEMORY_SUPPORTED], [1], [If MAP_HUGE_SHIFT is
                 defined, anonymous memory mapping is supported by the
                 kernel, and --in-memory can be used.])
    ], [], [[#include <sys/mman.h>]])

    # DPDK uses dlopen to load plugins.
    OVS_FIND_DEPENDENCY([dlopen], [dl], [libdl])

    AC_MSG_CHECKING([whether linking with dpdk works])
    LIBS="$DPDK_LIB $LIBS"
    AC_LINK_IFELSE(
      [AC_LANG_PROGRAM([#include <rte_config.h>
                        #include <rte_eal.h>],
                       [int rte_argc; char ** rte_argv;
                        rte_eal_init(rte_argc, rte_argv);])],
      [AC_MSG_RESULT([yes])
       DPDKLIB_FOUND=true],
      [AC_MSG_RESULT([no])
       AC_MSG_ERROR(m4_normalize([
          Failed to link with DPDK, check the config.log for more details.
          If a working DPDK library was not found in the default search path,
          update PKG_CONFIG_PATH for pkg-config to find the .pc file in a
          non-standard location.]))
      ])

    CFLAGS="$ovs_save_CFLAGS"
    LDFLAGS="$ovs_save_LDFLAGS"
    # Stripping out possible instruction set specific configuration that DPDK
    # forces in pkg-config since this could override user-specified options.
    # It's enough to have -mssse3 to build with DPDK headers.
    DPDK_INCLUDE=$(echo "$DPDK_INCLUDE" | sed 's/-march=[[^ ]]*//g')
    # Also stripping out '-mno-avx512f'.  Support for AVX512 will be disabled
    # if OVS will detect that it's broken.  OVS could be built with a
    # completely different toolchain that correctly supports AVX512, flags
    # forced by DPDK only breaks our feature detection mechanism and leads to
    # build failures: https://github.com/openvswitch/ovs-issues/issues/201
    DPDK_INCLUDE=$(echo "$DPDK_INCLUDE" | sed 's/-mno-avx512f//g')
    OVS_CFLAGS="$OVS_CFLAGS $DPDK_INCLUDE"
    OVS_ENABLE_OPTION([-mssse3])

    # DPDK pmd drivers are not linked unless --whole-archive is used.
    #
    # This happens because the rest of the DPDK code doesn't use any symbol in
    # the pmd driver objects, and the drivers register themselves using an
    # __attribute__((constructor)) function.
    # Wrap the DPDK libraries inside a single -Wl directive
    # after comma separation to prevent autotools from reordering them.
    DPDK_vswitchd_LDFLAGS=$(echo "$DPDK_LIB"| tr -s ' ' ',' | sed 's/-Wl,//g')
    # Replace -pthread with -lpthread for LD and remove the last extra comma.
    DPDK_vswitchd_LDFLAGS=$(echo "$DPDK_vswitchd_LDFLAGS"| sed 's/,$//' | \
                            sed 's/-pthread/-lpthread/g')
    # Prepend "-Wl,".
    DPDK_vswitchd_LDFLAGS="-Wl,$DPDK_vswitchd_LDFLAGS"

    AC_SUBST([DPDK_vswitchd_LDFLAGS])
    AC_DEFINE([DPDK_NETDEV], [1], [System uses the DPDK module.])
  fi

  AM_CONDITIONAL([DPDK_NETDEV], test "$DPDKLIB_FOUND" = true)
])

dnl Checks for net/if_dl.h.
dnl
dnl (We use this as a proxy for checking whether we're building on FreeBSD
dnl or NetBSD.)
AC_DEFUN([OVS_CHECK_IF_DL],
  [AC_CHECK_HEADER([net/if_dl.h],
                   [HAVE_IF_DL=yes],
                   [HAVE_IF_DL=no])
   AM_CONDITIONAL([HAVE_IF_DL], [test "$HAVE_IF_DL" = yes])
   if test "$HAVE_IF_DL" = yes; then
      AC_DEFINE([HAVE_IF_DL], [1],
                [Define to 1 if net/if_dl.h is available.])

      # On these platforms we use libpcap to access network devices.
      AC_SEARCH_LIBS([pcap_open_live], [pcap])
   fi])

dnl Checks for buggy strtok_r.
dnl
dnl Some versions of glibc 2.7 has a bug in strtok_r when compiling
dnl with optimization that can cause segfaults:
dnl
dnl http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614.
AC_DEFUN([OVS_CHECK_STRTOK_R],
  [AC_CACHE_CHECK(
     [whether strtok_r macro segfaults on some inputs],
     [ovs_cv_strtok_r_bug],
     [AC_RUN_IFELSE(
        [AC_LANG_PROGRAM([#include <stdio.h>
                          #include <string.h>
                         ],
                         [[#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 8
                           /* Assume bug is present, because relatively minor
                              changes in compiler settings (e.g. optimization
                              level) can make it crop up. */
                           return 1;
                           #else
                           char string[] = ":::";
                           char *save_ptr = (char *) 0xc0ffee;
                           char *token1, *token2;
                           token1 = strtok_r(string, ":", &save_ptr);
                           token2 = strtok_r(NULL, ":", &save_ptr);
                           freopen ("/dev/null", "w", stdout);
                           printf ("%s %s\n", token1, token2);
                           return 0;
                           #endif
                          ]])],
        [ovs_cv_strtok_r_bug=no],
        [ovs_cv_strtok_r_bug=yes],
        [ovs_cv_strtok_r_bug=yes])])
   if test $ovs_cv_strtok_r_bug = yes; then
     AC_DEFINE([HAVE_STRTOK_R_BUG], [1],
               [Define if strtok_r macro segfaults on some inputs])
   fi
])

dnl ----------------------------------------------------------------------
dnl These macros are from GNU PSPP, with the following original license:
dnl Copyright (C) 2005, 2006, 2007 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([_OVS_CHECK_CC_OPTION], [dnl
  m4_define([ovs_cv_name], [ovs_cv_[]m4_translit([$1], [-= ], [__])])dnl
  AC_CACHE_CHECK([whether $CC accepts $1], [ovs_cv_name], 
    [ovs_save_CFLAGS="$CFLAGS"
     dnl Include -Werror in the compiler options, because without -Werror
     dnl clang's GCC-compatible compiler driver does not return a failure
     dnl exit status even though it complains about options it does not
     dnl understand.
     dnl
     dnl Also, check stderr as gcc exits with status 0 for options
     dnl rejected at getopt level.
     dnl    % touch /tmp/a.c
     dnl    % gcc -g -c -Werror -Qunused-arguments /tmp/a.c; echo $?
     dnl    gcc: unrecognized option '-Qunused-arguments'
     dnl    0
     dnl    %
     dnl
     dnl In addition, GCC does not complain about a -Wno-<foo> option that
     dnl it does not understand, unless it has another error to report, so
     dnl instead of testing for -Wno-<foo>, test for the positive version.
     CFLAGS="$CFLAGS $WERROR m4_bpatsubst([$1], [-Wno-], [-W])"
     AC_COMPILE_IFELSE(
       [AC_LANG_SOURCE([int x;])],
       [if test -s conftest.err && grep "unrecognized option" conftest.err
        then
          ovs_cv_name[]=no
        else
          ovs_cv_name[]=yes
        fi],
       [ovs_cv_name[]=no])
     CFLAGS="$ovs_save_CFLAGS"])
  if test $ovs_cv_name = yes; then
    m4_if([$2], [], [:], [$2])
  else
    m4_if([$3], [], [:], [$3])
  fi
])

dnl OVS_CHECK_WERROR
dnl
dnl Check whether the C compiler accepts -Werror.
dnl Sets $WERROR to "-Werror", if so, and otherwise to the empty string.
AC_DEFUN([OVS_CHECK_WERROR],
  [WERROR=
   _OVS_CHECK_CC_OPTION([-Werror], [WERROR=-Werror])])

dnl OVS_CHECK_CC_OPTION([OPTION], [ACTION-IF-ACCEPTED], [ACTION-IF-REJECTED])
dnl Check whether the given C compiler OPTION is accepted.
dnl If so, execute ACTION-IF-ACCEPTED, otherwise ACTION-IF-REJECTED.
AC_DEFUN([OVS_CHECK_CC_OPTION],
  [AC_REQUIRE([OVS_CHECK_WERROR])
   _OVS_CHECK_CC_OPTION([$1], [$2], [$3])])

dnl OVS_ENABLE_OPTION([OPTION])
dnl Check whether the given C compiler OPTION is accepted.
dnl If so, add it to WARNING_FLAGS.
dnl Example: OVS_ENABLE_OPTION([-Wdeclaration-after-statement])
AC_DEFUN([OVS_ENABLE_OPTION], 
  [OVS_CHECK_CC_OPTION([$1], [WARNING_FLAGS="$WARNING_FLAGS $1"])
   AC_SUBST([WARNING_FLAGS])])

dnl OVS_CONDITIONAL_CC_OPTION([OPTION], [CONDITIONAL])
dnl Check whether the given C compiler OPTION is accepted.
dnl If so, enable the given Automake CONDITIONAL.

dnl Example: OVS_CONDITIONAL_CC_OPTION([-Wno-unused], [HAVE_WNO_UNUSED])
AC_DEFUN([OVS_CONDITIONAL_CC_OPTION],
  [OVS_CHECK_CC_OPTION(
    [$1], [ovs_have_cc_option=yes], [ovs_have_cc_option=no])
   AM_CONDITIONAL([$2], [test $ovs_have_cc_option = yes])])
dnl ----------------------------------------------------------------------

dnl OVS_CONDITIONAL_CC_OPTION_DEFINE([OPTION], [CONDITIONAL])
dnl Check whether the given C compiler OPTION is accepted.
dnl If so, enable the given Automake CONDITIONAL and define it.
dnl Example: OVS_CONDITIONAL_CC_OPTION_DEFINE([-mavx512f], [HAVE_AVX512F])
AC_DEFUN([OVS_CONDITIONAL_CC_OPTION_DEFINE],
  [OVS_CHECK_CC_OPTION(
    [$1], [ovs_have_cc_option=yes], [ovs_have_cc_option=no])
   AM_CONDITIONAL([$2], [test $ovs_have_cc_option = yes])
   if test "$ovs_have_cc_option" = yes; then
     AC_DEFINE([$2], [1],
               [Define to 1 if compiler supports the '$1' option.])
   fi])

dnl OVS_CHECK_SPARSE_TARGET
dnl
dnl The "cgcc" script from "sparse" isn't very good at detecting the
dnl target for which the code is being built.  This helps it out.
AC_DEFUN([OVS_CHECK_SPARSE_TARGET],
  [AC_CACHE_CHECK(
    [target hint for cgcc],
    [ac_cv_sparse_target],
    [AS_CASE([`$CC -dumpmachine 2>/dev/null`],
       [i?86-* | athlon-*], [ac_cv_sparse_target=x86],
       [x86_64-*], [ac_cv_sparse_target=x86_64],
       [ac_cv_sparse_target=other])])
   AS_CASE([$ac_cv_sparse_target],
     [x86], [SPARSEFLAGS= CGCCFLAGS="-target=i86 -target=host_os_specs"],
     [x86_64], [SPARSEFLAGS=-m64 CGCCFLAGS="-target=x86_64 -target=host_os_specs"],
     [SPARSEFLAGS= CGCCFLAGS=])

   dnl Get the default defines for vector instructions from compiler to
   dnl allow "sparse" correctly check the same code that will be built.
   dnl Required for checking DPDK headers.
   AC_MSG_CHECKING([vector options for cgcc])
   VECTOR=$($CC -dM -E - < /dev/null | grep -E "MMX|SSE|AVX" | \
            cut -c 9- | sed 's/ /=/' | sed 's/^/-D/' | tr '\n' ' ')
   AC_MSG_RESULT([$VECTOR])
   CGCCFLAGS="$CGCCFLAGS $VECTOR"

   AC_SUBST([SPARSEFLAGS])
   AC_SUBST([CGCCFLAGS])])

dnl OVS_SPARSE_EXTRA_INCLUDES
dnl
dnl The cgcc script from "sparse" does not search gcc's default
dnl search path. Get the default search path from GCC and pass
dnl them to sparse.
AC_DEFUN([OVS_SPARSE_EXTRA_INCLUDES],
    AC_SUBST([SPARSE_EXTRA_INCLUDES],
           [`$CC -v -E - </dev/null 2>&1 >/dev/null | sed -n -e '/^#include.*search.*starts.*here:/,/^End.*of.*search.*list\./s/^ \(.*\)/-I \1/p' |grep -v /usr/lib | grep -x -v '\-I /usr/include' | tr \\\n ' ' `] ))

dnl OVS_ENABLE_SPARSE
AC_DEFUN([OVS_ENABLE_SPARSE],
  [AC_REQUIRE([OVS_CHECK_SPARSE_TARGET])
   AC_REQUIRE([OVS_SPARSE_EXTRA_INCLUDES])
   : ${SPARSE=sparse}
   AC_SUBST([SPARSE])
   AC_CONFIG_COMMANDS_PRE(
     [CC='$(if $(C:0=),env REAL_CC="'"$CC"'" CHECK="$(SPARSE) $(SPARSE_WERROR) -I $(top_srcdir)/include/sparse -I $(top_srcdir)/include $(SPARSEFLAGS) $(SPARSE_EXTRA_INCLUDES) " cgcc $(CGCCFLAGS),'"$CC"')'])

   AC_ARG_ENABLE(
     [sparse],
     [AS_HELP_STRING([--enable-sparse], [Run "sparse" by default])],
     [], [enable_sparse=no])
   AM_CONDITIONAL([ENABLE_SPARSE_BY_DEFAULT], [test $enable_sparse = yes])])

dnl OVS_CTAGS_IDENTIFIERS
dnl
dnl ctags ignores symbols with extras identifiers. This is a list of
dnl specially handled identifiers to be ignored. [ctags(1) -I <list>].
AC_DEFUN([OVS_CTAGS_IDENTIFIERS],
    AC_SUBST([OVS_CTAGS_IDENTIFIERS_LIST],
           ["OVS_LOCKABLE OVS_NO_THREAD_SAFETY_ANALYSIS OVS_REQ_RDLOCK+ OVS_ACQ_RDLOCK+ OVS_REQ_WRLOCK+ OVS_ACQ_WRLOCK+ OVS_REQUIRES+ OVS_ACQUIRES+ OVS_TRY_WRLOCK+ OVS_TRY_RDLOCK+ OVS_TRY_LOCK+ OVS_GUARDED_BY+ OVS_EXCLUDED+ OVS_RELEASES+ OVS_ACQ_BEFORE+ OVS_ACQ_AFTER+"]))

dnl OVS_PTHREAD_SET_NAME
dnl
dnl This checks for three known variants of pthreads functions for setting
dnl the name of the current thread:
dnl
dnl   glibc: int pthread_setname_np(pthread_t, const char *name);
dnl   NetBSD: int pthread_setname_np(pthread_t, const char *format, void *arg);
dnl   FreeBSD: int pthread_set_name_np(pthread_t, const char *name);
dnl
dnl For glibc and FreeBSD, the arguments are just a thread and its name.  For
dnl NetBSD, 'format' is a printf() format string and 'arg' is an argument to
dnl provide to it.
dnl
dnl This macro defines:
dnl
dnl    glibc: HAVE_GLIBC_PTHREAD_SETNAME_NP
dnl    NetBSD: HAVE_NETBSD_PTHREAD_SETNAME_NP
dnl    FreeBSD: HAVE_PTHREAD_SET_NAME_NP
AC_DEFUN([OVS_CHECK_PTHREAD_SET_NAME],
  [AC_CHECK_FUNCS([pthread_set_name_np])
   if test $ac_cv_func_pthread_set_name_np != yes; then
     AC_CACHE_CHECK(
       [for pthread_setname_np() variant],
       [ovs_cv_pthread_setname_np],
       [AC_LINK_IFELSE(
         [AC_LANG_PROGRAM([#include <pthread.h>
  ], [pthread_setname_np(pthread_self(), "name");])],
         [ovs_cv_pthread_setname_np=glibc],
         [AC_LINK_IFELSE(
           [AC_LANG_PROGRAM([#include <pthread.h>
], [pthread_setname_np(pthread_self(), "%s", "name");])],
           [ovs_cv_pthread_setname_np=netbsd],
           [ovs_cv_pthread_setname_np=none])])])
     case $ovs_cv_pthread_setname_np in # (
       glibc)
          AC_DEFINE(
            [HAVE_GLIBC_PTHREAD_SETNAME_NP], [1],
            [Define to 1 if pthread_setname_np() is available and takes 2 parameters (like glibc).])
          ;; # (
       netbsd)
          AC_DEFINE(
            [HAVE_NETBSD_PTHREAD_SETNAME_NP], [1],
            [Define to 1 if pthread_setname_np() is available and takes 3 parameters (like NetBSD).])
          ;;
     esac
   fi])

dnl OVS_CHECK_LINUX_HOST.
dnl
dnl Checks whether we're building for a Linux host, based on the presence of
dnl the __linux__ preprocessor symbol, and sets up an Automake conditional
dnl LINUX based on the result.
AC_DEFUN([OVS_CHECK_LINUX_HOST],
  [AC_CACHE_CHECK(
     [whether __linux__ is defined],
     [ovs_cv_linux],
     [AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([enum { LINUX = __linux__};], [])],
        [ovs_cv_linux=true],
        [ovs_cv_linux=false])])
   AM_CONDITIONAL([LINUX], [$ovs_cv_linux])])
