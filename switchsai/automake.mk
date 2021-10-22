AM_CPPFLAGS += -I $(top_srcdir)/switchlink/submodules/SAI/inc
AM_CFLAGS += -I $(top_srcdir)/switchlink/submodules/SAI/inc

EXTRA_DIST += $(top_srcdir)/switchlink/submodules/SAI
EXTRA_DIST += switchapi

lib_LTLIBRARIES += switchsai/libswitchsai.la

switchsai_libswitchsai_la_LDFLAGS = \
        $(OVS_LTINFO) \
        -Wl,--version-script=$(top_builddir)/switchsai/libswitchsai.sym \
        $(AM_LDFLAGS)

switchsai_libswitchsai_la_SOURCES = \
   switchsai/sai.c \
   switchsai/saiinternal.h \
   switchsai/saiport.c

switchsai_libswitchsai_la_CPPFLAGS = $(AM_CPPFLAGS)
switchsai_libswitchsai_la_CPPFLAGS += -I ./switchapi

switchsai_libswitchsai_la_CFLAGS = $(AM_CFLAGS)
switchsai_libswitchsai_la_CFLAGS += -I ./switchapi

switchsai_libswitchsai_la_LIBADD = switchapi/libswitchapi.la

pkgconfig_DATA += \
    switchsai/libswitchsai.pc

CLEANFILES += switchsai/libswitchsai.sym
CLEANFILES += switchsai/libswitchsai.pc
