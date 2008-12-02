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

AC_PREREQ(2.59)
AC_INIT(openflow, 0.8.9~1, info@openflowswitch.org)
NX_BUILDNR
AC_CONFIG_SRCDIR([README.hwtables])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_RANLIB

AC_ARG_VAR([PERL], [path to Perl interpreter])
AC_PATH_PROG([PERL], perl, no)
if test "$PERL" = no; then
   AC_MSG_ERROR([Perl interpreter not found in $PATH or $PERL.])
fi

OFP_CHECK_LIBOPENFLOW
OFP_CHECK_IF_PACKET
OFP_CHECK_HWTABLES

AC_CHECK_FUNCS([strsignal])

AC_ARG_VAR(KARCH, [Kernel Architecture String])
AC_SUBST(KARCH)
OFP_CHECK_LINUX(l26, 2.6, 2.6, KSRC26, L26_ENABLED)
OFP_CHECK_LINUX(l24, 2.4, 2.4, KSRC24, L24_ENABLED)

OFP_CHECK_DPKG_BUILDPACKAGE

CFLAGS="$CFLAGS -Wall -Wno-sign-compare -Wpointer-arith -Wdeclaration-after-statement"

OFP_ENABLE_EXT
m4_include([ext.m4])

AC_CONFIG_FILES([Makefile 
datapath/Makefile 
datapath/linux-2.6/Kbuild
datapath/linux-2.6/Makefile
datapath/linux-2.6/Makefile.main
datapath/linux-2.4/Kbuild
datapath/linux-2.4/Makefile
datapath/linux-2.4/Makefile.main])

AC_OUTPUT
