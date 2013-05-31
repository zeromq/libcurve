/*  =========================================================================
    cl_curve - CurveZMQ security engine (rfc.zeromq.org/spec:26)

    -------------------------------------------------------------------------
    Copyright (c) 1991-2013 iMatix Corporation <www.imatix.com>
    Copyright other contributors as noted in the AUTHORS file.

    This file is part of CLAB, the space for experimental C classes.

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

#ifndef __CL_CURVE_H_INCLUDED__
#define __CL_CURVE_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

//  Opaque class structure
typedef struct _cl_curve_t cl_curve_t;

//  @interface
//  Constructor; to create a client instance, pass the server public
//  key. If you pass null, you create a server instance.
CZMQ_EXPORT cl_curve_t *
    cl_curve_new (byte *server_key);
    
//  Destructor
CZMQ_EXPORT void
    cl_curve_destroy (cl_curve_t **self_p);

//  Long-term key management for servers; generate a new key pair
CZMQ_EXPORT void
    cl_curve_keypair_new (cl_curve_t *self);

//  Save long-term key pair to disk; not confidential
CZMQ_EXPORT int
    cl_curve_keypair_save (cl_curve_t *self);

//  Load long-term key pair from disk
CZMQ_EXPORT int
    cl_curve_keypair_load (cl_curve_t *self);

//  Return public part of key pair
CZMQ_EXPORT byte *
    cl_curve_keypair_public (cl_curve_t *self);
    
//  Set a metadata property; these are sent to the peer after the
//  security handshake. Property values are strings.
CZMQ_EXPORT void
    cl_curve_set_metadata (cl_curve_t *self, char *name, char *value);

//  Set tracing on cl_curve instance. Will report activity to stdout.
CZMQ_EXPORT void
    cl_curve_set_verbose (cl_curve_t *self, bool verbose);

//  Accept input command from peer. If the command is invalid, it is
//  discarded silently. May return a blob to send to the peer, or NULL
//  if there is nothing to send.
CZMQ_EXPORT zframe_t *
    cl_curve_execute (cl_curve_t *self, zframe_t *input);

//  Encode clear-text message to peer. Returns a blob ready to send
//  on the wire.
CZMQ_EXPORT zframe_t *
    cl_curve_encode (cl_curve_t *self, zframe_t **cleartext_p);

//  Decode blob into message from peer. Takes ownership of encrypted frame.

CZMQ_EXPORT zframe_t *
    cl_curve_decode (cl_curve_t *self, zframe_t **encrypted_p);

//  Indicate whether handshake is still in progress
CZMQ_EXPORT bool
    cl_curve_connected (cl_curve_t *self);

//  Self test of this class
void
    cl_curve_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
