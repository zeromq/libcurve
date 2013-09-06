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

/*
@header
    Implements a secure client socket, doing I/O in the background. This is
    a high-level class intended for applications. It wraps the curve_codec
    class, and runs it across a DEALER socket to connect to a curve_server
    socket at the other end.
@discuss
    If you want to create a peer-to-peer architecture, use a server for all
    incoming connections, and use a client for each outgoing connection.
    Then send on the client socket, and receive on the server socket.
@end
*/

#include "../include/curve.h"

//  Structure of our class
struct _curve_client_t {
    void *pipe;                 //  Pipe through to agent
    zctx_t *ctx;                //  Private context
    bool connected;             //  Do we have an active connection?
};

//  This background thread does all the real work
static void
    s_agent_task (void *args, zctx_t *ctx, void *pipe);


//  --------------------------------------------------------------------------
//  Constructor
//  Create a new curve_client instance
//  We use a context per instance to keep the API as simple as possible.

curve_client_t *
curve_client_new (void)
{
    curve_client_t *self = (curve_client_t *) zmalloc (sizeof (curve_client_t));
    assert (self);
    self->ctx = zctx_new ();
    self->pipe = zthread_fork (self->ctx, s_agent_task, NULL);
    return self;
}


//  --------------------------------------------------------------------------
//  Destructor

void
curve_client_destroy (curve_client_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        curve_client_t *self = *self_p;
        zstr_send (self->pipe, "TERMINATE");
        free (zstr_recv (self->pipe));
        zctx_destroy (&self->ctx);
        free (self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Create outgoing connection to server
//  Currently allows a single connection only

void
curve_client_connect (curve_client_t *self, const char *endpoint, byte *server_key)
{
    assert (self);
    assert (endpoint);
    assert (server_key);
    assert (!self->connected);
    zstr_sendm (self->pipe, "CONNECT");
    zstr_sendm (self->pipe, endpoint);
    zmq_send (self->pipe, server_key, 32, 0);
    self->connected = true;
}


//  --------------------------------------------------------------------------
//  Close outgoing connection to server

void
curve_client_disconnect (curve_client_t *self)
{
    assert (self);
    self->connected = false;
    zstr_sendm (self->pipe, "DISCONNECT");
}


//  --------------------------------------------------------------------------
//  Send message to server, takes ownership of message

int
curve_client_send (curve_client_t *self, zmsg_t **msg_p)
{
    assert (self);
    zstr_sendm (self->pipe, "SEND");
    zmsg_send (msg_p, self->pipe);
    return 0;
}


//  --------------------------------------------------------------------------
//  Wait for message from server
//  Returns zmsg_t object, or NULL if interrupted

zmsg_t *
curve_client_recv (curve_client_t *self)
{
    assert (self);
    zmsg_t *msg = zmsg_recv (self->pipe);
    return msg;
}


//  --------------------------------------------------------------------------
//  Get socket handle, for polling

void *
curve_client_handle (curve_client_t *self)
{
    assert (self);    
    return self->pipe;
}


//  ---------------------------------------------------------------------
//  Set metadata property, will be sent to servers at connection

void
curve_client_set_meta (curve_client_t *self, const char *name, const char *format, ...)
{
    assert (self);
    va_list argptr;
    va_start (argptr, format);
    char *value = (char *) malloc (255 + 1);
    vsnprintf (value, 255, format, argptr);
    va_end (argptr);
    
    zstr_sendm (self->pipe, "SET");
    zstr_sendm (self->pipe, name);
    zstr_send  (self->pipe, value);
    free (value);
}


//  --------------------------------------------------------------------------
//  Selftest

void
curve_client_test (bool verbose)
{
    printf (" * curve_client: ");

    //  @selftest
    curve_client_t *curve = curve_client_new ();
    curve_client_destroy (&curve);
    //  @end
    
    printf ("OK\n");
}


//  *************************    BACK END AGENT    *************************

//  This structure holds the context for our agent, so we can
//  pass that around cleanly to methods which need it

typedef struct {
    zctx_t *ctx;                //  CZMQ context
    void *pipe;                 //  Pipe back to application
    zhash_t *metadata;          //  Metadata to be sent
    bool terminated;            //  API shut us down
} agent_t;

static agent_t *
s_agent_new (zctx_t *ctx, void *pipe)
{
    agent_t *self = (agent_t *) zmalloc (sizeof (agent_t));
    self->ctx = ctx;
    self->pipe = pipe;
    self->metadata = zhash_new ();
    zhash_autofree (self->metadata);
    return self;
}

static void
s_agent_destroy (agent_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        agent_t *self = *self_p;
        zhash_destroy (&self->metadata);
        free (self);
        *self_p = NULL;
    }
}


//  Handle a control message from front-end API

static int
s_agent_recv_from_api (agent_t *self)
{
    //  Get the whole message off the pipe in one go
    zmsg_t *request = zmsg_recv (self->pipe);
    char *command = zmsg_popstr (request);
    if (!command)
        return -1;                  //  Interrupted

    if (streq (command, "CONNECT")) {
    }
    else
    if (streq (command, "DISCONNECT")) {
    }
    else
    if (streq (command, "SEND")) {
    }
    else
    if (streq (command, "SET")) {
        char *name = zmsg_popstr (request);
        char *value = zmsg_popstr (request);
        zhash_update (self->metadata, name, value);
        free (name);
        free (value);
    }
    else
    if (streq (command, "TERMINATE")) {
        self->terminated = true;
        zstr_send (self->pipe, "OK");
    }
    free (command);
    zmsg_destroy (&request);
    return 0;
}

static void
s_agent_task (void *args, zctx_t *ctx, void *pipe)
{
    //  Create agent instance as we start this task
    agent_t *self = s_agent_new (ctx, pipe);
    if (!self)                  //  Interrupted
        return;
    
    zmq_pollitem_t pollitems [] = {
        { self->pipe, 0, ZMQ_POLLIN, 0 }
    };
    while (!zctx_interrupted) {
        if (zmq_poll (pollitems, 1, 1000) == -1)
            break;              //  Interrupted
        if (pollitems [0].revents & ZMQ_POLLIN)
            s_agent_recv_from_api (self);
        if (self->terminated)
            break;
    }
    //  Done, free all agent resources
    s_agent_destroy (&self);
}
