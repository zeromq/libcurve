/*  =========================================================================
    curvezmq_tests.c - run selftests

    -------------------------------------------------------------------------
    Copyright (c) 1991-2013 iMatix Corporation <www.imatix.com>
    Copyright other contributors as noted in the AUTHORS file.

    This file is part of the CurveZMQ authentication and encryption library.

    This is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or (at
    your option) any later version.

    This software is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this program. If not, see
    <http://www.gnu.org/licenses/>.
    =========================================================================
*/

#include "../include/curvezmq.h"

int main (int argc, char *argv [])
{
    bool verbose;
    if (argc == 2 && streq (argv [1], "-v"))
        verbose = true;
    else
        verbose = false;

	#if defined (HAVE_LIBSODIUM)
    printf ("Running CurveZMQ self tests with libsudium...\n");
	#else
    printf ("Running CurveZMQ self tests without libsodium...\n");
	#endif

    curvezmq_codec_test (verbose);
    curvezmq_keypair_test (verbose);
    printf ("Tests passed OK\n");
    return 0;
}
