
<A name="toc1-3" title="CurveZMQ - authentication and encryption library" />
# CurveZMQ - authentication and encryption library

CurveZMQ implements the rfc.zeromq.org/spec:26 elliptic curve security mechanism and makes it easy to use in ZeroMQ applications. 

<A name="toc2-8" title="Ownership and License" />
## Ownership and License

CurveZMQ's contributors are listed in the AUTHORS file. It is held by the ZeroMQ organization at github.com. The authors of CurveZMQ grant you use of this software under the terms of the GNU Lesser General Public License (LGPL). For details see the files `COPYING` and `COPYING.LESSER` in this directory.

<A name="toc2-13" title="Contributing" />
## Contributing

This project uses the [C4.1 (Collective Code Construction Contract)](http://rfc.zeromq.org/spec:22) process for contributions.

This project uses the [CLASS (C Language Style for Scalabilty)](http://rfc.zeromq.org/spec:21) guide for code style.

To report an issue, use the [CurveZMQ issue tracker](https://github.com/zeromq/curvezmq/issues) at github.com.

<A name="toc2-22" title="Dependencies" />
## Dependencies

This project needs these projects:

* libzmq - git://github.com/zeromq/libzmq.git
* libczmq - git://github.com/zeromq/czmq.git
* libsodium - git://github.com/jedisct1/libsodium.git

<A name="toc2-31" title="Building and Installing" />
## Building and Installing

This project uses autotools for packaging. To build from git (all example commands are for Linux):

    #   libzmq
    git clone git://github.com/zeromq/libzmq.git
    cd libzmq
    ./autogen.sh
    ./configure && make check
    sudo make install
    sudo ldconfig
    cd ..

    #   CZMQ
    git clone git://github.com/zeromq/czmq.git
    cd czmq
    ./autogen.sh
    ./configure && make check
    sudo make install
    sudo ldconfig
    cd ..

    #   libsodium
    git clone git://github.com/jedisct1/libsodium.git
    cd libsodium
    ./autogen.sh
    ./configure && make check
    sudo make install
    sudo ldconfig
    cd ..

    git clone git://github.com/zeromq/curvezmq.git
    cd curvezmq
    sh autogen.sh
    ./autogen.sh
    ./configure && make check
    sudo make install
    sudo ldconfig
    cd ..

You will need the libtool and autotools packages. On FreeBSD, you may need to specify the default directories for configure:

    ./configure --with-libzmq=/usr/local

<A name="toc2-76" title="Linking with an Application" />
## Linking with an Application

Include `curvezmq.h` in your application and link with libcurvezmq. Here is a typical gcc link command:

    gcc -lcurvezmq -lzmq -lczmq myapp.c -o myapp

<A name="toc2-83" title="Documentation" />
## Documentation

All documentation is provided in the doc/ subdirectory.
