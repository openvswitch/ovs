# The remainder of this file is from Intel's e1000 distribution,
# with the following license:

################################################################################
#
# Intel PRO/1000 Linux driver
# Copyright(c) 1999 - 2007 Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
#
# The full GNU General Public License is included in this distribution in
# the file called "COPYING".
#
# Contact Information:
# Linux NICS <linux.nics@intel.com>
# e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
# Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
#
################################################################################
ifeq (,$(BUILD_KERNEL))
BUILD_KERNEL=$(shell uname -r)
endif

###########################################################################
# Environment tests

CC := gcc cc
CFLAGS += $(CFLAGS_EXTRA)

ifeq (,$(KSRC))
  $(error Linux kernel source not found)
else
ifeq (/lib/modules/$(shell uname -r)/source, $(KSRC))
  KOBJ :=  /lib/modules/$(shell uname -r)/build
else
  KOBJ :=  $(KSRC)
endif
endif

# version 2.4 or 2.6? (we assume 2.2 isn't in use anymore
K_VERSION:=$(shell if grep -q 'PATCHLEVEL = 4' $(KSRC)/Makefile; then echo 2.4; else echo 2.6; fi)

ifneq ($(K_VERSION),2.6)
  $(error Linux kernel source not not 2.6)
endif

# check for version.h and autoconf.h for running kernel in /boot (SUSE)
ifneq (,$(wildcard /boot/vmlinuz.version.h))
  VERSION_FILE := /boot/vmlinuz.version.h
  CONFIG_FILE  := /boot/vmlinuz.autoconf.h
  KVER := $(shell $(CC) $(CFLAGS) -E -dM $(VERSION_FILE) | \
          grep UTS_RELEASE | awk '{ print $$3 }' | sed 's/\"//g')
  ifeq ($(KVER),$(shell uname -r))
    # set up include path to override headers from kernel source
    x:=$(shell rm -rf include)
    x:=$(shell mkdir -p include/linux)
    x:=$(shell cp /boot/vmlinuz.version.h include/linux/version.h)
    x:=$(shell cp /boot/vmlinuz.autoconf.h include/linux/autoconf.h)
    CFLAGS += -I./include
  else
    ifneq (,$(wildcard $(KOBJ)/include/linux/utsrelease.h))
      VERSION_FILE := $(KOBJ)/include/linux/utsrelease.h
    else
      VERSION_FILE := $(KOBJ)/include/linux/version.h
    endif
    CONFIG_FILE  := $(KSRC)/include/linux/autoconf.h
  endif
else
  ifneq (,$(wildcard $(KOBJ)/include/linux/utsrelease.h))
    VERSION_FILE := $(KOBJ)/include/linux/utsrelease.h
  else
    VERSION_FILE := $(KOBJ)/include/linux/version.h
  endif
  CONFIG_FILE  := $(KSRC)/include/linux/autoconf.h
endif

ifeq (,$(wildcard $(VERSION_FILE)))
  $(error Linux kernel source not configured - missing version.h)
endif

ifeq (,$(wildcard $(CONFIG_FILE)))
  $(error Linux kernel source not configured - missing autoconf.h)
endif


test_cc = $(shell $(cc) --version > /dev/null 2>&1 && echo $(cc))
CC := $(foreach cc, $(CC), $(test_cc))
CC := $(firstword $(CC))
ifeq (,$(CC))
  $(error Compiler not found)
endif

# we need to know what platform the driver is being built on
# some additional features are only built on Intel platforms
ARCH := $(shell uname -m | sed 's/i.86/i386/')
ifeq ($(ARCH),alpha)
  CFLAGS += -ffixed-8 -mno-fp-regs
endif
ifeq ($(ARCH),x86_64)
  CFLAGS += -mcmodel=kernel -mno-red-zone
endif
ifeq ($(ARCH),ppc)
  CFLAGS += -msoft-float
endif
ifeq ($(ARCH),ppc64)
  CFLAGS += -m64 -msoft-float
  LDFLAGS += -melf64ppc
endif

# standard flags for module builds
CFLAGS += -DLINUX -D__KERNEL__ -DMODULE -O2 -pipe -Wall
CFLAGS += -I$(KSRC)/include -I.
CFLAGS += $(shell [ -f $(KSRC)/include/linux/modversions.h ] && \
            echo "-DMODVERSIONS -DEXPORT_SYMTAB \
                  -include $(KSRC)/include/linux/modversions.h")

RHC := $(KSRC)/include/linux/rhconfig.h
ifneq (,$(wildcard $(RHC)))
  # 7.3 typo in rhconfig.h
  ifneq (,$(shell $(CC) $(CFLAGS) -E -dM $(RHC) | grep __module__bigmem))
	CFLAGS += -D__module_bigmem
  endif
endif

# get the kernel version - we use this to find the correct install path
KVER := $(shell $(CC) $(CFLAGS) -E -dM $(VERSION_FILE) | grep UTS_RELEASE | \
        awk '{ print $$3 }' | sed 's/\"//g')

# assume source symlink is the same as build, otherwise adjust KOBJ
ifneq (,$(wildcard /lib/modules/$(KVER)/build))
ifneq ($(KSRC),$(shell cd /lib/modules/$(KVER)/build ; pwd -P))
  KOBJ=/lib/modules/$(KVER)/build
endif
endif

KKVER := $(shell echo $(KVER) | \
         awk '{ if ($$0 ~ /2\.[6]\./) print "1"; else print "0"}')
ifeq ($(KKVER), 0)
  $(error *** Aborting the build. \
          *** This driver is not supported on kernel versions older than 2.6.0)
endif

# look for SMP in config.h
SMP := $(shell $(CC) $(CFLAGS) -E -dM $(CONFIG_FILE) | \
         grep -w CONFIG_SMP | awk '{ print $$3 }')
ifneq ($(SMP),1)
  SMP := 0
endif

#ifneq ($(SMP),$(shell uname -a | grep SMP > /dev/null 2>&1 && echo 1 || echo 0))
#  $(warning ***)
#  ifeq ($(SMP),1)
#    $(warning *** Warning: kernel source configuration (SMP))
#    $(warning *** does not match running kernel (UP))
#  else
#    $(warning *** Warning: kernel source configuration (UP))
#    $(warning *** does not match running kernel (SMP))
#  endif
#  $(warning *** Continuing with build,)
#  $(warning *** resulting driver may not be what you want)
#  $(warning ***)
#endif

ifeq ($(SMP),1)
  CFLAGS += -D__SMP__
endif

###########################################################################
# Makefile for 2.6.x kernel
all: $(TARGET)
TARGET = openflow_mod.ko unit_mod.ko

$(UNIT_CFILES): 
	$(foreach UNIT_CFILE, $(UNIT_CFILES), $(shell ln -s $(patsubst %,../t/%,$(UNIT_CFILE)) $(UNIT_CFILE)))

ifneq ($(PATCHLEVEL),)
EXTRA_CFLAGS += $(CFLAGS_EXTRA)
obj-m += openflow_mod.o unit_mod.o
openflow_mod-objs := $(CFILES:.c=.o)
unit_mod-objs := $(UNIT_CFILES:.c=.o)
else
default:
ifeq ($(KOBJ),$(KSRC))
	$(MAKE) -C $(KSRC) SUBDIRS=$(shell pwd) modules
else
	$(MAKE) -C $(KSRC) O=$(KOBJ) SUBDIRS=$(shell pwd) modules
endif
endif

# depmod version for rpm builds
DEPVER := $(shell /sbin/depmod -V 2>/dev/null | \
          awk 'BEGIN {FS="."} NR==1 {print $$2}')

.PHONY: clean

clean:
	rm -rf $(TARGET) $(TARGET:.ko=.o) $(TARGET:.ko=.mod.c) \
    $(TARGET:.ko=.mod.o) $(CFILES:.c=.o) $(MANFILE).gz .*cmd \
    .tmp_versions t/ tmp/
