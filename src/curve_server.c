/*  =========================================================================
    curve_socket - Curve-secured socket
        - secure socket API
        - extensible mechanisms, drivers
        - front-end / back-end model like VTX
        - use VTX framework as basis
        - API is like sockets:
            - new (type)
            - set ("property", value)
            - get ("property", value)
            - send (msg)
            - recv (msg)
            - handle - for polling

    -------------------------------------------------------------------------
    Copyright (c) 1991-2013 iMatix Corporation <www.imatix.com>
    Copyright other contributors as noted in the AUTHORS file.

    This file is part of the Curve authentication and encryption library.

    This is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by the 
    Free Software Foundation; either version 3 of the License, or (at your 
    option) any later version.

    This software is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABIL-
    ITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General 
    Public License for more details.

    You should have received a copy of the GNU Lesser General Public License 
    along with this program. If not, see <http://www.gnu.org/licenses/>.
    =========================================================================
*/

/*
@header
    Implements the client and server sockets. This class encodes and decodes
    zframes. All I/O is the responsibility of the caller. This is the 
    reference implementation of CurveZMQ. You will not normally want to use
    it directly in application code as the API is low-level and complex.
    TODO: authentication via ZAP - http://rfc.zeromq.org/spec:27/ZAP
@discuss
@end
*/

#include "../include/curve.h"

//  Structure of our class
struct _curve_socket_t {
    int filler;
};

//  --------------------------------------------------------------------------
//  Constructor
//  Create a new curve_socket instance

curve_socket_t *
curve_socket_new (void)
{
    curve_socket_t *self = (curve_socket_t *) zmalloc (sizeof (curve_socket_t));
    assert (self);
    return self;
}


//  --------------------------------------------------------------------------
//  Destructor

void
curve_socket_destroy (curve_socket_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        curve_socket_t *self = *self_p;
        free (self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Receive a message 

zmsg_t
*curve_socket_recv (curve_socket_t *self)
{
}

    _recv
    _send
    _handle

//  --------------------------------------------------------------------------
//  Selftest

void
curve_socket_test (bool verbose)
{
    printf (" * curve_socket: ");

    //  @selftest
    curve_socket_t *curve = curve_socket_new ();
    curve_socket_destroy (&curve);
    //  @end
    
    printf ("OK\n");
}
