lib_LTLIBRARIES = libcurvezmq.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcurvezmq.pc

include_HEADERS = \
    ../include/curvezmq.h \
    ../include/curvezmq_codec.h \
    ../include/curvezmq_keypair.h 

libcurvezmq_la_SOURCES = \
    curvezmq_codec.c \
    curvezmq_keypair.c 

INCLUDES = -I$(top_srcdir)/include
bin_PROGRAMS = curvezmq_selftest
curvezmq_selftest_LDADD = libcurvezmq.la
curvezmq_selftest_SOURCES = curvezmq_selftest.c

if ON_MINGW
libcurvezmq_la_LDFLAGS = -no-undefined -avoid-version -version-info @LTVER@
else
libcurvezmq_la_LDFLAGS = -version-info @LTVER@
endif

TESTS = curvezmq_selftest


