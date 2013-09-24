lib_LTLIBRARIES = libcurve.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcurve.pc

include_HEADERS = \
    ../include/curve.h \
    ../include/curve_codec.h \
    ../include/curve_client.h \
    ../include/curve_server.h

libcurve_la_SOURCES = \
    curve_codec.c \
    curve_client.c \
    curve_server.c
    
INCLUDES = -I$(top_srcdir)/include
bin_PROGRAMS = curve_selftest
curve_selftest_LDADD = libcurve.la
curve_selftest_SOURCES = curve_selftest.c

if ON_MINGW
libcurve_la_LDFLAGS = -no-undefined -avoid-version -version-info @LTVER@
else
libcurve_la_LDFLAGS = -version-info @LTVER@
endif

TESTS = curve_selftest


