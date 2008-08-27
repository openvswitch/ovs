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
