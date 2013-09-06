/*  =========================================================================
    curve_client - Secure client socket

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

#ifndef __CURVE_CLIENT_H_INCLUDED__
#define __CURVE_CLIENT_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

//  Opaque class structure
typedef struct _curve_client_t curve_client_t;

//  @interface
//  Create a new curve_client instance
CZMQ_EXPORT curve_client_t *
    curve_client_new (void);

//  Destructor
CZMQ_EXPORT void
    curve_client_destroy (curve_client_t **self_p);
    
//  Create outgoing connection to server
CZMQ_EXPORT void
    curve_client_connect (curve_client_t *self, const char *endpoint, byte *server_key);

//  Send message to server, takes ownership of message
CZMQ_EXPORT int
    curve_client_send (curve_client_t *self, zmsg_t **msg_p);

//  Wait for message from server
CZMQ_EXPORT zmsg_t *
    curve_client_recv (curve_client_t *self);

//  Get socket handle, for polling
CZMQ_EXPORT void *
    curve_client_handle (curve_client_t *self);

//  Set metadata property, will be sent to servers at connection
CZMQ_EXPORT void
    curve_client_set_meta (curve_client_t *self, 
                           const char *name, const char *format, ...);
    
//  Self test of this class
void
    curve_client_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
