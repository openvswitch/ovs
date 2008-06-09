include ../Make.vars

if HAVE_NETLINK
bin_PROGRAMS = secchan
dist_man_MANS = secchan.8
else
bin_PROGRAMS = 
dist_man_MANS =
endif

secchan_SOURCES = secchan.c
secchan_LDADD = ../lib/libopenflow.la -ldl
