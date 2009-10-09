# -*- autoconf -*-

# Copyright (c) 2008, 2009 Nicira Networks.
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

dnl Checks for --disable-userspace.
AC_DEFUN([OVS_CHECK_USERSPACE],
  [AC_ARG_ENABLE(
     [userspace],
     [AC_HELP_STRING([--disable-userspace], 
                     [Disable building userspace components.])],
     [case "${enableval}" in
        (yes) build_userspace=true ;;
        (no)  build_userspace=false ;;
        (*) AC_MSG_ERROR([bad value ${enableval} for --enable-userspace]) ;;
      esac],
     [build_userspace=true])
   AM_CONDITIONAL([ENABLE_USERSPACE], [$build_userspace])])

dnl OVS_CHECK_LINUX(OPTION, VERSION, VARIABLE, CONDITIONAL)
dnl
dnl Configure linux kernel source tree 
AC_DEFUN([OVS_CHECK_LINUX], [
  AC_ARG_WITH([$1],
              [AC_HELP_STRING([--with-$1=/path/to/linux-$2],
                              [Specify the linux $2 kernel sources])],
              [path="$withval"], [path=])dnl
  if test -n "$path"; then
    path=`eval echo "$path"`

    AC_MSG_CHECKING([for $path directory])
    if test -d "$path"; then
	AC_MSG_RESULT([yes])
	$3=$path
	AC_SUBST($3)
    else
	AC_MSG_RESULT([no])
	AC_ERROR([source dir $path doesn't exist])
    fi

    AC_MSG_CHECKING([for $path kernel version])
    patchlevel=`sed -n 's/^PATCHLEVEL = //p' "$path/Makefile"`
    sublevel=`sed -n 's/^SUBLEVEL = //p' "$path/Makefile"`
    AC_MSG_RESULT([2.$patchlevel.$sublevel])
    if test "2.$patchlevel" != '$2'; then
       AC_ERROR([Linux kernel source in $path is not version $2])
    fi
    if ! test -e "$path"/include/linux/version.h || \
       ! test -e "$path"/include/linux/autoconf.h; then
	AC_MSG_ERROR([Linux kernel source in $path is not configured])
    fi
    m4_if($2, [2.6], [OVS_CHECK_LINUX26_COMPAT])
  fi
  AM_CONDITIONAL($4, test -n "$path")
])

dnl OVS_GREP_IFELSE(FILE, REGEX, IF-MATCH, IF-NO-MATCH)
dnl
dnl Greps FILE for REGEX.  If it matches, runs IF-MATCH, otherwise IF-NO-MATCH.
AC_DEFUN([OVS_GREP_IFELSE], [
  AC_MSG_CHECKING([whether $2 matches in $1])
  grep '$2' $1 >/dev/null 2>&1
  status=$?
  case $status in
    0) 
      AC_MSG_RESULT([yes])
      $3
      ;;
    1) 
      AC_MSG_RESULT([no])
      $4
      ;;
    *) 
      AC_MSG_ERROR([grep exited with status $status]) 
      ;;
  esac
])

dnl OVS_DEFINE(NAME)
dnl
dnl Defines NAME to 1 in kcompat.h.
AC_DEFUN([OVS_DEFINE], [
  echo '#define $1 1' >> datapath/linux-2.6/kcompat.h.new
])

AC_DEFUN([OVS_CHECK_VETH], [
  AC_MSG_CHECKING([whether to build veth module])
  if test "$sublevel" = 18; then
    AC_MSG_RESULT([yes])
    AC_SUBST([BUILD_VETH], 1)
  else
    AC_MSG_RESULT([no])
  fi
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
dnl the directory in $KSRC26.
AC_DEFUN([OVS_CHECK_LINUX26_COMPAT], [
  rm -f datapath/linux-2.6/kcompat.h.new
  mkdir -p datapath/linux-2.6
  : > datapath/linux-2.6/kcompat.h.new
  OVS_GREP_IFELSE([$KSRC26/include/linux/skbuff.h], [skb_transport_header],
                  [OVS_DEFINE([HAVE_SKBUFF_HEADER_HELPERS])])
  OVS_GREP_IFELSE([$KSRC26/include/linux/skbuff.h], [raw],
                  [OVS_DEFINE([HAVE_MAC_RAW])])
  OVS_GREP_IFELSE([$KSRC26/include/linux/skbuff.h], 
                  [skb_copy_from_linear_data_offset],
                  [OVS_DEFINE([HAVE_SKB_COPY_FROM_LINEAR_DATA_OFFSET])])
  OVS_GREP_IFELSE([$KSRC26/include/net/netlink.h], [NLA_NUL_STRING],
                  [OVS_DEFINE([HAVE_NLA_NUL_STRING])])
  OVS_GREP_IFELSE([$KSRC26/include/linux/err.h], [ERR_CAST],
                  [OVS_DEFINE([HAVE_ERR_CAST])])
  OVS_GREP_IFELSE([$KSRC26/include/net/checksum.h], [csum_unfold],
                  [OVS_DEFINE([HAVE_CSUM_UNFOLD])])
  OVS_GREP_IFELSE([$KSRC26/include/linux/skbuff.h], [skb_cow],
                  [OVS_DEFINE([HAVE_SKB_COW])])
  OVS_CHECK_LOG2_H
  OVS_CHECK_VETH
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
    m4_if([$2], [], [;], [$2])
  else
    m4_if([$3], [], [:], [$3])
  fi
])

dnl OVS_ENABLE_OPTION([OPTION])
dnl Check whether the given C compiler OPTION is accepted.
dnl If so, add it to CFLAGS.
dnl Example: OVS_ENABLE_OPTION([-Wdeclaration-after-statement])
AC_DEFUN([OVS_ENABLE_OPTION], 
  [OVS_CHECK_CC_OPTION([$1], [CFLAGS="$CFLAGS $1"])])
dnl ----------------------------------------------------------------------
