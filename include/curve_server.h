/*  =========================================================================
    curve_server - Secure server socket

    -------------------------------------------------------------------------
    Copyright (c) the Contributors as noted in the AUTHORS file.
    This file is part of the Curve authentication and encryption library.

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
    =========================================================================
*/

#ifndef __CURVE_SERVER_H_INCLUDED__
#define __CURVE_SERVER_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

//  @interface
//  Create a new server instance, providing its permanent cert
//  The caller provides the ZeroMQ context so that it can also
//  attach an authenticator (zauth) to the same context.
CZMQ_EXPORT curve_server_t *
    curve_server_new (zctx_t *ctx, zcert_t **cert_p);

//  Destructor
CZMQ_EXPORT void
    curve_server_destroy (curve_server_t **self_p);

//  Set metadata property, will be sent to clients at connection
CZMQ_EXPORT void
    curve_server_set_metadata (curve_server_t *self, char *name, char *format, ...);

//  Enable verbose tracing of commands and activity
CZMQ_EXPORT void
    curve_server_set_verbose (curve_server_t *self, bool verbose);

//  Set maximum authenticated clients
CZMQ_EXPORT void
    curve_server_set_max_clients (curve_server_t *self, int limit);

//  Set maximum unauthenticated pending clients
CZMQ_EXPORT void
    curve_server_set_max_pending (curve_server_t *self, int limit);

//  Set time-to-live for authenticated clients
CZMQ_EXPORT void
    curve_server_set_client_ttl (curve_server_t *self, int limit);

//  Set time-to-live for unauthenticated pending clients
CZMQ_EXPORT void
    curve_server_set_pending_ttl (curve_server_t *self, int limit);

//  Bind server socket to local endpoint
CZMQ_EXPORT void
    curve_server_bind (curve_server_t *self, char *endpoint);

//  Unbind server socket from local endpoint, idempotent
CZMQ_EXPORT void
    curve_server_unbind (curve_server_t *self, char *endpoint);

//  Wait for message from server
CZMQ_EXPORT zmsg_t *
    curve_server_recv (curve_server_t *self);

//  Send message to server, takes ownership of message
CZMQ_EXPORT int
    curve_server_send (curve_server_t *self, zmsg_t **msg_p);

//  Get socket handle, for polling
CZMQ_EXPORT void *
    curve_server_handle (curve_server_t *self);

//  Self test of this class
void
    curve_server_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
