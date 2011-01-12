# -*- autoconf -*-

# Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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

dnl OVS_CHECK_LINUX26
dnl
dnl Configure linux kernel source tree 
AC_DEFUN([OVS_CHECK_LINUX26], [
  AC_ARG_WITH([l26],
              [AC_HELP_STRING([--with-l26=/path/to/linux-2.6],
                              [Specify the linux 2.6 kernel build directory])],
              [KBUILD26="$withval"], [KBUILD26=])dnl
  AC_ARG_WITH([l26-source],
              [AC_HELP_STRING([--with-l26-source=/path/to/linux-2.6-source],
                              [Specify the linux 2.6 kernel source directory
			       (usually figured out automatically from build
			       directory)])],
              [KSRC26="$withval"], [KSRC26=])dnl
  if test -n "$KBUILD26"; then
    KBUILD26=`eval echo "$KBUILD26"`
    case $KBUILD26 in
        /*) ;;
        *) KBUILD26=`pwd`/$KBUILD26 ;;
    esac

    # The build directory is what the user provided.
    # Make sure that it exists.
    AC_MSG_CHECKING([for Linux 2.6 build directory])
    if test -d "$KBUILD26"; then
	AC_MSG_RESULT([$KBUILD26])
	AC_SUBST(KBUILD26)
    else
	AC_MSG_RESULT([no])
	AC_ERROR([source dir $KBUILD26 doesn't exist])
    fi

    # Debian breaks kernel headers into "source" header and "build" headers.
    # We want the source headers, but $KBUILD26 gives us the "build" headers.
    # Use heuristics to find the source headers.
    AC_MSG_CHECKING([for Linux 2.6 source directory])
    if test -n "$KSRC26"; then
      KSRC26=`eval echo "$KSRC26"`
      case $KSRC26 in
          /*) ;;
          *) KSRC26=`pwd`/$KSRC26 ;;
      esac
      if test ! -e $KSRC26/include/linux/kernel.h; then
        AC_MSG_ERROR([$KSRC26 is not a kernel source directory)])
      fi
    else
      KSRC26=$KBUILD26
      if test ! -e $KSRC26/include/linux/kernel.h; then
	case `echo "$KBUILD26" | sed 's,/*$,,'` in # (
	  */build)
	    KSRC26=`echo "$KBUILD26" | sed 's,/build/*$,/source,'`
	    ;; # (
	  *)
	    KSRC26=`(cd $KBUILD26 && pwd -P) | sed 's,-[[^-]]*$,-common,'`
	    ;;
	esac
      fi
      if test ! -e $KSRC26/include/linux/kernel.h; then
        AC_MSG_ERROR([cannot find source directory (please use --with-l26-source)])
      fi
    fi
    AC_MSG_RESULT([$KSRC26])

    AC_MSG_CHECKING([for kernel version])
    patchlevel=`sed -n 's/^PATCHLEVEL = //p' "$KSRC26/Makefile"`
    sublevel=`sed -n 's/^SUBLEVEL = //p' "$KSRC26/Makefile"`
    if test -z "$patchlevel" || test -z "$sublevel"; then
       AC_ERROR([cannot determine kernel version])
    fi
    AC_MSG_RESULT([2.$patchlevel.$sublevel])
    if test "2.$patchlevel" != '2.6'; then
       if test "$BUILD26" = "$KSRC26"; then
         AC_ERROR([Linux kernel in $KBUILD26 is not version 2.6])
       else
         AC_ERROR([Linux kernel in build tree $KBUILD26 (source tree $KSRC26) is not version 2.6])
       fi
    fi
    if test ! -e "$KBUILD26"/include/linux/version.h || \
       (test ! -e "$KBUILD26"/include/linux/autoconf.h && \
        test ! -e "$KBUILD26"/include/generated/autoconf.h); then
	AC_MSG_ERROR([Linux kernel source in $KBUILD26 is not configured])
    fi
    OVS_CHECK_LINUX26_COMPAT
  elif test -n "$KSRC26"; then
    AC_MSG_ERROR([--with-l26-source may not be specified without --with-l26])
  fi
  AM_CONDITIONAL(L26_ENABLED, test -n "$KBUILD26")
])

dnl OVS_GREP_IFELSE(FILE, REGEX, [IF-MATCH], [IF-NO-MATCH])
dnl
dnl Greps FILE for REGEX.  If it matches, runs IF-MATCH, otherwise IF-NO-MATCH.
dnl If IF-MATCH is empty then it defines to OVS_DEFINE(HAVE_<REGEX>), with
dnl <REGEX> translated to uppercase.
AC_DEFUN([OVS_GREP_IFELSE], [
  AC_MSG_CHECKING([whether $2 matches in $1])
  if test -f $1; then
    grep '$2' $1 >/dev/null 2>&1
    status=$?
    case $status in
      0) 
        AC_MSG_RESULT([yes])
        m4_if([$3], [], [OVS_DEFINE([HAVE_]m4_toupper([$2]))], [$3])
        ;;
      1) 
        AC_MSG_RESULT([no])
        $4
        ;;
      *) 
        AC_MSG_ERROR([grep exited with status $status])
        ;;
    esac
  else
    AC_MSG_RESULT([file not found])
    $4
  fi
])

dnl OVS_DEFINE(NAME)
dnl
dnl Defines NAME to 1 in kcompat.h.
AC_DEFUN([OVS_DEFINE], [
  echo '#define $1 1' >> datapath/linux-2.6/kcompat.h.new
])

AC_DEFUN([OVS_CHECK_LOG2_H], [
  AC_MSG_CHECKING([for $KSRC26/include/linux/log2.h])
  if test -e $KSRC26/include/linux/log2.h; then
    AC_MSG_RESULT([yes])
    OVS_DEFINE([HAVE_LOG2_H])
  else
    AC_MSG_RESULT([no])
  fi
])

dnl OVS_CHECK_LINUX26_COMPAT
dnl
dnl Runs various Autoconf checks on the Linux 2.6 kernel source in
dnl the directory in $KBUILD26.
AC_DEFUN([OVS_CHECK_LINUX26_COMPAT], [
  rm -f datapath/linux-2.6/kcompat.h.new
  mkdir -p datapath/linux-2.6
  : > datapath/linux-2.6/kcompat.h.new

  OVS_GREP_IFELSE([$KSRC26/arch/x86/include/asm/checksum_32.h], [src_err,],
                  [OVS_DEFINE([HAVE_CSUM_COPY_DBG])])

  OVS_GREP_IFELSE([$KSRC26/include/linux/err.h], [ERR_CAST])

  OVS_GREP_IFELSE([$KSRC26/include/linux/in.h], [ipv4_is_multicast])

  OVS_GREP_IFELSE([$KSRC26/include/linux/netdevice.h], [dev_disable_lro])
  OVS_GREP_IFELSE([$KSRC26/include/linux/netdevice.h], [dev_get_stats])

  # Check for the proto_data_valid member in struct sk_buff.  The [^@]
  # is necessary because some versions of this header remove the
  # member but retain the kerneldoc comment that describes it (which
  # starts with @).  The brackets must be doubled because of m4
  # quoting rules.
  OVS_GREP_IFELSE([$KSRC26/include/linux/skbuff.h], [[[^@]]proto_data_valid],
                  [OVS_DEFINE([HAVE_PROTO_DATA_VALID])])
  OVS_GREP_IFELSE([$KSRC26/include/linux/skbuff.h], [raw],
                  [OVS_DEFINE([HAVE_MAC_RAW])])
  OVS_GREP_IFELSE([$KSRC26/include/linux/skbuff.h], [skb_dst(],
                  [OVS_DEFINE([HAVE_SKB_DST_ACCESSOR_FUNCS])])
  OVS_GREP_IFELSE([$KSRC26/include/linux/skbuff.h], 
                  [skb_copy_from_linear_data_offset])
  OVS_GREP_IFELSE([$KSRC26/include/linux/skbuff.h], [skb_cow_head])
  OVS_GREP_IFELSE([$KSRC26/include/linux/skbuff.h], [skb_transport_header],
                  [OVS_DEFINE([HAVE_SKBUFF_HEADER_HELPERS])])
  OVS_GREP_IFELSE([$KSRC26/include/linux/skbuff.h], [skb_warn_if_lro],
                  [OVS_DEFINE([HAVE_SKB_WARN_LRO])])

  OVS_GREP_IFELSE([$KSRC26/include/linux/string.h], [kmemdup], [],
                  [OVS_GREP_IFELSE([$KSRC26/include/linux/slab.h], [kmemdup])])

  OVS_GREP_IFELSE([$KSRC26/include/linux/types.h], [bool],
                  [OVS_DEFINE([HAVE_BOOL_TYPE])])
  OVS_GREP_IFELSE([$KSRC26/include/linux/types.h], [__wsum],
                  [OVS_DEFINE([HAVE_CSUM_TYPES])])

  OVS_GREP_IFELSE([$KSRC26/include/net/checksum.h], [csum_replace4])
  OVS_GREP_IFELSE([$KSRC26/include/net/checksum.h], [csum_unfold])

  OVS_GREP_IFELSE([$KSRC26/include/net/netlink.h], [NLA_NUL_STRING])
  OVS_GREP_IFELSE([$KSRC26/include/net/netlink.h], [nla_get_be16])
  OVS_GREP_IFELSE([$KSRC26/include/net/netlink.h], [nla_find_nested])

  OVS_CHECK_LOG2_H

  if cmp -s datapath/linux-2.6/kcompat.h.new \
            datapath/linux-2.6/kcompat.h >/dev/null 2>&1; then
    rm datapath/linux-2.6/kcompat.h.new
  else
    mv datapath/linux-2.6/kcompat.h.new datapath/linux-2.6/kcompat.h
  fi
])

dnl Checks for net/if_packet.h.
AC_DEFUN([OVS_CHECK_IF_PACKET],
  [AC_CHECK_HEADER([net/if_packet.h],
                   [HAVE_IF_PACKET=yes],
                   [HAVE_IF_PACKET=no])
   AM_CONDITIONAL([HAVE_IF_PACKET], [test "$HAVE_IF_PACKET" = yes])
   if test "$HAVE_IF_PACKET" = yes; then
      AC_DEFINE([HAVE_IF_PACKET], [1],
                [Define to 1 if net/if_packet.h is available.])
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
                         [[char string[] = ":::";
                           char *save_ptr = (char *) 0xc0ffee;
                           char *token1, *token2;
                           token1 = strtok_r(string, ":", &save_ptr);
                           token2 = strtok_r(NULL, ":", &save_ptr);
                           freopen ("/dev/null", "w", stdout);
                           printf ("%s %s\n", token1, token2);
                           return 0;
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

dnl OVS_CHECK_CC_OPTION([OPTION], [ACTION-IF-ACCEPTED], [ACTION-IF-REJECTED])
dnl Check whether the given C compiler OPTION is accepted.
dnl If so, execute ACTION-IF-ACCEPTED, otherwise ACTION-IF-REJECTED.
AC_DEFUN([OVS_CHECK_CC_OPTION],
[
  m4_define([ovs_cv_name], [ovs_cv_[]m4_translit([$1], [-], [_])])dnl
  AC_CACHE_CHECK([whether $CC accepts $1], [ovs_cv_name], 
    [ovs_save_CFLAGS="$CFLAGS"
     CFLAGS="$CFLAGS $1"
     AC_COMPILE_IFELSE([AC_LANG_PROGRAM(,)], [ovs_cv_name[]=yes], [ovs_cv_name[]=no])
     CFLAGS="$ovs_save_CFLAGS"])
  if test $ovs_cv_name = yes; then
    m4_if([$2], [], [:], [$2])
  else
    m4_if([$3], [], [:], [$3])
  fi
])

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
