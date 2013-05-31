
<A name="toc1-3" title="CLAB - experimental C classes" />
# CLAB - experimental C classes

CLAB (libclab) is an experimental space that provides an incubator for CZMQ, the high-level C binding for ØMQ applications.  While CZMQ is generally "stable", CLAB is always "experimental". CLAB classes that prove useful may be moved into CZMQ. CLAB classes that prove useless may be deleted. The CLAB API is never considered stable and may change without notice.

<A name="toc2-8" title="Ownership and License" />
## Ownership and License

CLAB's contributors are listed in the AUTHORS file. It is held by the ZeroMQ organization at github.com. The authors of CLAB grant you use of this software under the terms of the GNU Lesser General Public License (LGPL). For details see the files `COPYING` and `COPYING.LESSER` in this directory.

<A name="toc2-13" title="Contributing" />
## Contributing

CLAB uses the [C4.1 (Collective Code Construction Contract)](http://rfc.zeromq.org/spec:22) process for contributions.

CLAB uses the [CLASS (C Language Style for Scalabilty)](http://rfc.zeromq.org/spec:21) guide for code style.

To report an issue, use the [CLAB issue tracker](https://github.com/imatix/clab/issues) at github.com.

<A name="toc2-22" title="Building and Installing" />
## Building and Installing

CLAB uses autotools for packaging. To build from git (all example commands are for Linux):

    git clone git://github.com/imatix/clab.git
    cd clab
    sh autogen.sh
    ./configure
    make all
    sudo make install
    sudo ldconfig

You will need the libtool and autotools packages. On FreeBSD, you may need to specify the default directories for configure:

    ./configure --with-libzmq=/usr/local

After building, you can run the CLAB selftests:

    make check

<A name="toc2-43" title="Linking with an Application" />
## Linking with an Application

Include `clab.h` in your application and link with libclab. Here is a typical gcc link command:

    gcc -lclab -lzmq myapp.c -o myapp

<A name="toc2-50" title="Documentation" />
## Documentation

All documentation is provided in the doc/ subdirectory.
