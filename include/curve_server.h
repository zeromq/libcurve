/*  =========================================================================
    curve_socket - Curve-secured socket

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

#ifndef __CURVE_SOCKET_H_INCLUDED__
#define __CURVE_SOCKET_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

//  Opaque class structure
typedef struct _curve_socket_t curve_socket_t;

//  @interface
//  Create a new curve_socket instance
CZMQ_EXPORT curve_socket_t *
    curve_socket_new (void);

//  Destructor
CZMQ_EXPORT void
    curve_socket_destroy (curve_socket_t **self_p);
    
//  Get socket handle, for polling
CZMQ_EXPORT void *
    curve_socket_handle (curve_socket_t *self);

//  Self test of this class
void
    curve_socket_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
