include ../Make.vars

bin_PROGRAMS = switch

switch_SOURCES = \
	chain.c \
	chain.h \
	controller.c \
	controller.h \
	crc32.c \
	crc32.h \
	datapath.c \
	datapath.h \
	forward.c \
	forward.h \
	netdev.c \
	netdev.h \
	switch.c \
	switch-flow.c \
	switch-flow.h \
	table.h \
	table-hash.c \
	table-linear.c \
	table-mac.c 

switch_LDADD = ../lib/libopenflow.la -ldl
