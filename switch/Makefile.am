include ../Make.vars

bin_PROGRAMS = switch
dist_man_MANS = switch.8

switch_SOURCES = \
	chain.c \
	chain.h \
	crc32.c \
	crc32.h \
	datapath.c \
	datapath.h \
	switch.c \
	switch-flow.c \
	switch-flow.h \
	table.h \
	table-hash.c \
	table-linear.c

switch_LDADD = ../lib/libopenflow.la -ldl
