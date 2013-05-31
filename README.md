
<A name="toc1-3" title="CLab - experimental C classes" />
# CLab - experimental C classes

CLab (libclab) is an experimental space for classes that are interesting but not yet useful. Classes that prove themselves useful are moved into the CZMQ library for general use. While CZMQ is generally "stable", CLab is generally "experimental".

<A name="toc2-8" title="Ownership and License" />
## Ownership and License

CLab's contributors are listed in the AUTHORS file. It is held by the ZeroMQ organization at github.com. The authors of Clab grant you use of this software under the terms of the GNU Lesser General Public License (LGPL). For details see the files `COPYING` and `COPYING.LESSER` in this directory.

<A name="toc2-13" title="Contributing" />
## Contributing

Clab uses the [C4.1 (Collective Code Construction Contract)](http://rfc.zeromq.org/spec:22) process for contributions.

Clab uses the [CLASS (C Language Style for Scalabilty)](http://rfc.zeromq.org/spec:21) guide for code style.

To report an issue, use the [Clab issue tracker](https://github.com/imatix/clab/issues) at github.com.

<A name="toc2-22" title="Building and Installing" />
## Building and Installing

Clab uses autotools for packaging. To build from git (all example commands are for Linux):

    git clone git://github.com/imatix/clab.git
    cd clab
    sh autogen.sh
    ./configure
    make all
    sudo make install
    sudo ldconfig

You will need the libtool and autotools packages. On FreeBSD, you may need to specify the default directories for configure:

    ./configure --with-libzmq=/usr/local

After building, you can run the Clab selftests:

    make check

<A name="toc2-43" title="Linking with an Application" />
## Linking with an Application

Include `clab.h` in your application and link with libclab. Here is a typical gcc link command:

    gcc -lclab -lzmq myapp.c -o myapp

<A name="toc2-50" title="Documentation" />
## Documentation

All documentation is provided in the doc/ subdirectory.
