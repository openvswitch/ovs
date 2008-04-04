include ../Make.vars

if HAVE_NETLINK
bin_PROGRAMS = secchan
else
bin_PROGRAMS = 
endif

secchan_SOURCES = secchan.c
secchan_LDADD = ../lib/libopenflow.la -ldl
