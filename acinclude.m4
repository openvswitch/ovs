dnl =================================================================================
dnl Distributed under the terms of the GNU GPL version 2.
dnl Copyright (c) 2007, 2008 The Board of Trustees of The Leland Stanford Junior University
dnl =================================================================================


dnl --
dnl CHECK_LINUX(OPTION, VERSION, VARIABLE, CONDITIONAL)
dnl
dnl Configure linux kernel source tree 
dnl --
AC_DEFUN([CHECK_LINUX], [
  AC_ARG_WITH([$1],
              [AC_HELP_STRING([--with-$1=/path/to/linux-$3],
                              [Specify the linux $3 kernel sources])],
              [path="$withval"], [path=])dnl
  if test -n "$path"; then
    path=`eval echo "$path"`

    AC_MSG_CHECKING([for $path directory])
    if test -d "$path"; then
	AC_MSG_RESULT([yes])
	$4=$path
	AC_SUBST($4)
    else
	AC_MSG_RESULT([no])
	AC_ERROR([source dir $path doesn't exist])
    fi

    AC_MSG_CHECKING([for $path kernel version])
    version=`grep '^PATCHLEVEL = ' "$path/Makefile" | sed 's/PATCHLEVEL = '//`
    AC_MSG_RESULT([2.$version])
    if test "2.$version" != '$3'; then
       AC_ERROR([Linux kernel source in $path is not version $3])
    fi
    if ! test -e "$path"/include/linux/version.h || \
       ! test -e "$path"/include/linux/autoconf.h; then
	AC_MSG_ERROR([Linux kernel source in $path is not configured])
    fi
  fi
  AM_CONDITIONAL($5, test -n "$path")
])
