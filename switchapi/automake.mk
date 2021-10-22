AM_CPPFLAGS += -I $(top_srcdir)/switchlink/submodules/SAI/inc
AM_CFLAGS += -I $(top_srcdir)/switchlink/submodules/SAI/inc

EXTRA_DIST += $(top_srcdir)/switchlink/submodules/SAI

lib_LTLIBRARIES += switchapi/libswitchapi.la

switchapi_libswitchapi_la_LDFLAGS = \
        $(OVS_LTINFO) \
        -Wl,--version-script=$(top_builddir)/switchapi/libswitchapi.sym \
        $(AM_LDFLAGS)

switchapi_libswitchapi_la_SOURCES = \
    switchapi/switch_base_types.h \
    switchapi/switch_port.h \
    switchapi/switch_port.c \
    switchapi/switch_pd_port.c \
    switchapi/switch_handle.h \
    switchapi/switch_internal.h \
    switchapi/switch_id.h \
    switchapi/switch_interface.h \
    switchapi/switch_port_int.h \
    switchapi/switch_status.h \
    switchapi/switch_tunnel.h

switchapi_libswitchapi_la_CPPFLAGS = $(AM_CPPFLAGS)
switchapi_libswitchapi_la_CFLAGS = $(AM_CFLAGS)

pkgconfig_DATA += \
    switchapi/libswitchapi.pc

CLEANFILES += switchapi/libswitchapi.sym
CLEANFILES += switchapi/libswitchapi.pc
