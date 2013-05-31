lib_LTLIBRARIES = libclab.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libclab.pc

include_HEADERS = \
    ../include/clab.h \
    ../include/cl_curve.h 

libclab_la_SOURCES = \
    cl_curve.c 

INCLUDES = -I$(top_srcdir)/include
bin_PROGRAMS = clab_selftest
clab_selftest_LDADD = libclab.la
clab_selftest_SOURCES = clab_selftest.c

if ON_MINGW
libclab_la_LDFLAGS = -no-undefined -avoid-version -version-info @LTVER@
else
libclab_la_LDFLAGS = -version-info @LTVER@
endif

TESTS = clab_selftest


