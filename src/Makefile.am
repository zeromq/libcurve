lib_LTLIBRARIES = libcurve.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcurve.pc

include_HEADERS = \
    ../include/libcurve.h \
    ../include/libcurve_codec.h \
    ../include/libcurve_keypair.h 

libcurve_la_SOURCES = \
    libcurve_codec.c \
    libcurve_keypair.c 

INCLUDES = -I$(top_srcdir)/include
bin_PROGRAMS = libcurve_selftest
libcurve_selftest_LDADD = libcurve.la
libcurve_selftest_SOURCES = libcurve_selftest.c

if ON_MINGW
libcurve_la_LDFLAGS = -no-undefined -avoid-version -version-info @LTVER@
else
libcurve_la_LDFLAGS = -version-info @LTVER@
endif

TESTS = libcurve_selftest


