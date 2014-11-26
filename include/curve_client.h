/*  =========================================================================
    curve_client - Secure client socket

    -------------------------------------------------------------------------
    Copyright (c) the Contributors as noted in the AUTHORS file.
    This file is part of the Curve authentication and encryption library.

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
    =========================================================================
*/

#ifndef __CURVE_CLIENT_H_INCLUDED__
#define __CURVE_CLIENT_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

//  @interface
//  Create a new curve_client instance.
//  We use a context per instance to keep the API as simple as possible.
//  Takes ownership of cert.
CZMQ_EXPORT curve_client_t *
    curve_client_new (zcert_t **cert_p);

//  Destructor
CZMQ_EXPORT void
    curve_client_destroy (curve_client_t **self_p);

//  Set metadata property, to be sent to server on connect
CZMQ_EXPORT void
    curve_client_set_metadata (curve_client_t *self, char *name, char *format, ...);

//  Enable verbose tracing of commands and activity
CZMQ_EXPORT void
    curve_client_set_verbose (curve_client_t *self, bool verbose);

//  Create outgoing connection to server, providing server permanent
//  public key
CZMQ_EXPORT void
    curve_client_connect (curve_client_t *self, char *endpoint, byte *server_key);

//  Close outgoing connection to server; idempotent
CZMQ_EXPORT void
    curve_client_disconnect (curve_client_t *self, char *endpoint);

//  Send message to server, takes ownership of message
CZMQ_EXPORT int
    curve_client_send (curve_client_t *self, zmsg_t **msg_p);

//  Wait for message from server
CZMQ_EXPORT zmsg_t *
    curve_client_recv (curve_client_t *self);

//  Send single-frame string message to server
CZMQ_EXPORT int
    curve_client_sendstr (curve_client_t *self, char *string);

//  Wait for single-frame string message from server
CZMQ_EXPORT char *
    curve_client_recvstr (curve_client_t *self);

//  Get socket handle, for polling
//  NOTE: do not call send/recv directly on handle since internal message
//  format is NOT A CONTRACT and is liable to change arbitrarily.
CZMQ_EXPORT void *
    curve_client_handle (curve_client_t *self);

//  Self test of this class
void
    curve_client_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
