/*  =========================================================================
    curve_server - Secure server socket

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
    Implements a secure server socket, doing I/O in the background. This is
    a high-level class intended for applications. It wraps the curve_codec
    class, and runs it across a ROUTER socket to connect to a curve_server
    socket at the other end.
@discuss
@end
*/

#include "../include/curve.h"

//  Structure of our class
struct _curve_server_t {
    void *pipe;                 //  Pipe through to agent
    zctx_t *ctx;                //  Private context
};

//  This background thread does all the real work
static void
    s_agent_task (void *args, zctx_t *ctx, void *pipe);

//  --------------------------------------------------------------------------
//  Constructor
//  Create a new curve_server instance
//  We use a context per instance to keep the API as simple as possible.
//  Takes ownership of keypair.

curve_server_t *
curve_server_new (curve_keypair_t **keypair_p)
{
    curve_server_t *self = (curve_server_t *) zmalloc (sizeof (curve_server_t));
    assert (self);
    self->ctx = zctx_new ();
    self->pipe = zthread_fork (self->ctx, s_agent_task, NULL);
    curve_keypair_send (*keypair_p, self->pipe);
    curve_keypair_destroy (keypair_p);
    return self;
}


//  --------------------------------------------------------------------------
//  Destructor

void
curve_server_destroy (curve_server_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        curve_server_t *self = *self_p;
        zstr_send (self->pipe, "TERMINATE");
        free (zstr_recv (self->pipe));
        zctx_destroy (&self->ctx);
        free (self);
        *self_p = NULL;
    }
}


//  ---------------------------------------------------------------------
//  Set metadata property, will be sent to servers at connection

void
curve_server_set_metadata (curve_server_t *self, char *name, char *format, ...)
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
//  Enable verbose tracing of commands and activity

void
curve_server_set_verbose (curve_server_t *self, bool verbose)
{
    assert (self);
    zstr_sendm (self->pipe, "VERBOSE");
    zstr_send  (self->pipe, "%d", verbose);
}


//  --------------------------------------------------------------------------
//  Bind server socket to local endpoint

void
curve_server_bind (curve_server_t *self, char *endpoint)
{
    assert (self);
    zstr_sendm (self->pipe, "BIND");
    zstr_send  (self->pipe, endpoint);
}


//  --------------------------------------------------------------------------
//  Unbind server socket from local endpoint, idempotent

void
curve_server_unbind (curve_server_t *self, char *endpoint)
{
    assert (self);
    zstr_sendm (self->pipe, "UNBIND");
    zstr_send  (self->pipe, endpoint);
}


//  --------------------------------------------------------------------------
//  Wait for message from server
//  Returns zmsg_t object, or NULL if interrupted

zmsg_t *
curve_server_recv (curve_server_t *self)
{
    assert (self);
    zmsg_t *msg = zmsg_recv (self->pipe);
    return msg;
}


//  --------------------------------------------------------------------------
//  Send message to server, takes ownership of message

int
curve_server_send (curve_server_t *self, zmsg_t **msg_p)
{
    assert (self);
    assert (zmsg_size (*msg_p) > 0);
    zstr_sendm (self->pipe, "SEND");
    zmsg_send (msg_p, self->pipe);
    return 0;
}


//  --------------------------------------------------------------------------
//  Get socket handle, for polling

void *
curve_server_handle (curve_server_t *self)
{
    assert (self);
    return self->pipe;
}


//  *************************    BACK END AGENT    *************************

typedef enum {
    waiting,                    //  Waiting for connection
    connected,                  //  Ready for messages
    terminated                  //  Terminated by the API or error
} state_t;

//  This structure holds the context for our agent, so we can
//  pass that around cleanly to methods which need it

typedef struct {
    zctx_t *ctx;                //  CZMQ context
    void *pipe;                 //  Pipe back to application
    state_t state;              //  Current socket state
    curve_codec_t *codec;       //  Client CurveZMQ codec
    void *router;               //  ROUTER socket to server
    zframe_t *sender;           //  Client who sent us last message
} agent_t;

static agent_t *
s_agent_new (zctx_t *ctx, void *pipe)
{
    agent_t *self = (agent_t *) zmalloc (sizeof (agent_t));
    self->ctx = ctx;
    self->pipe = pipe;
    self->state = waiting;
    self->router = zsocket_new (ctx, ZMQ_ROUTER);
    return self;
}

static void
s_agent_destroy (agent_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        agent_t *self = *self_p;
        curve_codec_destroy (&self->codec);
        zframe_destroy (&self->sender);
        free (self);
        *self_p = NULL;
    }
}


//  Handle a control message from front-end API

static int
s_agent_handle_pipe (agent_t *self)
{
    //  Get the whole message off the pipe in one go
    zmsg_t *request = zmsg_recv (self->pipe);
    char *command = zmsg_popstr (request);
    if (!command)
        return -1;                  //  Interrupted

    if (streq (command, "SET")) {
        char *name = zmsg_popstr (request);
        char *value = zmsg_popstr (request);
        curve_codec_set_metadata (self->codec, name, value);
        free (name);
        free (value);
    }
    else
    if (streq (command, "BIND")) {
        char *endpoint = zmsg_popstr (request);
        int rc = zsocket_bind (self->router, endpoint);
        assert (rc != -1);
        free (endpoint);
    }
    else
    if (streq (command, "UNBIND")) {
        char *endpoint = zmsg_popstr (request);
        int rc = zsocket_unbind (self->router, endpoint);
        assert (rc != -1);
        free (endpoint);
    }
    else
    if (streq (command, "SEND")) {
        //  Encrypt and send all frames of request
        //  Each frame is a full ZMQ message with identity frame
        while (zmsg_size (request)) {
            zframe_t *cleartext = zmsg_pop (request);
            if (zmsg_size (request))
                zframe_set_more (cleartext, 1);
            zframe_t *encrypted = curve_codec_encode (self->codec, &cleartext);
            if (encrypted) {
                zframe_send (&self->sender, self->router, ZFRAME_MORE + ZFRAME_REUSE);
                zframe_send (&encrypted, self->router, 0);
            }
            else
                self->state = terminated;
        }
    }
    else
    if (streq (command, "VERBOSE")) {
        char *verbose = zmsg_popstr (request);
        curve_codec_set_verbose (self->codec, *verbose == '1'? true: false);
        free (verbose);
    }
    else
    if (streq (command, "TERMINATE")) {
        self->state = terminated;
        zstr_send (self->pipe, "OK");
    }
    free (command);
    zmsg_destroy (&request);
    return 0;
}

//  Handle a message from the server

static int
s_agent_handle_router (agent_t *self)
{
    zframe_destroy (&self->sender);
    self->sender = zframe_recv (self->router);

    //  If not yet connected, process one command frame
    //  We always read one request, and send one reply
    if (self->state == waiting) {
        zframe_t *input = zframe_recv (self->router);
        zframe_t *output = curve_codec_execute (self->codec, &input);
        if (output) {
            zframe_send (&self->sender, self->router, ZFRAME_MORE + ZFRAME_REUSE);
            zframe_send (&output, self->router, 0);
            if (curve_codec_connected (self->codec))
                self->state = connected;
        }
        else
            self->state = terminated;
    }
    else
    //  If connected, process one message
    if (self->state == connected) {
        zframe_t *encrypted = zframe_recv (self->router);
        zframe_t *cleartext = curve_codec_decode (self->codec, &encrypted);
        if (cleartext) {
            int flags = zframe_more (cleartext)? ZFRAME_MORE: 0;
            zframe_send (&cleartext, self->pipe, flags);
        }
        else
            self->state = terminated;
    }
    return 0;
}


static void
s_agent_task (void *args, zctx_t *ctx, void *pipe)
{
    //  Create agent instance as we start this task
    agent_t *self = s_agent_new (ctx, pipe);
    if (!self)                  //  Interrupted
        return;

    //  Create new server codec using keypair from API
    curve_keypair_t *server_key = curve_keypair_recv (self->pipe);
    self->codec = curve_codec_new_server (&server_key);
    curve_codec_set_verbose (self->codec, true);

    while (!zctx_interrupted) {
        //  Always handle messages on both sockets
        zmq_pollitem_t pollitems [] = {
            { self->pipe, 0, ZMQ_POLLIN, 0 },
            { self->router, 0, ZMQ_POLLIN, 0 },
        };
        if (zmq_poll (pollitems, 2, -1) == -1)
            break;              //  Interrupted

        if (pollitems [0].revents & ZMQ_POLLIN)
            s_agent_handle_pipe (self);
        if (pollitems [1].revents & ZMQ_POLLIN)
            s_agent_handle_router (self);

        if (self->state == terminated)
            break;
    }
    //  Done, free all agent resources
    s_agent_destroy (&self);
}


//  --------------------------------------------------------------------------
//  Selftest

static void *
client_task (void *args)
{
    bool verbose = *((bool *) args);

    //  This is the curve_codec client selftest, runs as background thread
    curve_keystore_t *keystore = curve_keystore_new ();
    int rc = curve_keystore_load (keystore, "test_keystore");
    assert (rc == 0);

    curve_keypair_t *client_keypair = curve_keystore_get (keystore, "client");
    curve_client_t *client = curve_client_new (&client_keypair);
    curve_client_set_metadata (client, "Client", "CURVEZMQ/curve_client");
    curve_client_set_metadata (client, "Identity", "E475DA11");
    curve_client_set_verbose (client, verbose);

    curve_keypair_t *server_keypair = curve_keystore_get (keystore, "server");
    curve_client_connect (client, "tcp://127.0.0.1:9000", curve_keypair_public (server_keypair));
    curve_keypair_destroy (&server_keypair);

    curve_client_sendstr (client, "Hello, World");
    char *reply = curve_client_recvstr (client);
    assert (streq (reply, "Hello, World"));
    free (reply);

    //  Try a multipart message
    zmsg_t *msg = zmsg_new ();
    zmsg_pushstr (msg, "Hello, World");
    zmsg_pushstr (msg, "Second frame");
    curve_client_send (client, &msg);
    msg = curve_client_recv (client);
    assert (zmsg_size (msg) == 2);
    zmsg_destroy (&msg);

    //  Now send messages of increasing size, check they work
    int count;
    int size = 0;
    for (count = 0; count < 18; count++) {
        if (verbose)
            printf ("Testing message of size=%d...\n", size);

        zframe_t *data = zframe_new (NULL, size);
        int byte_nbr;
        //  Set data to sequence 0...255 repeated
        for (byte_nbr = 0; byte_nbr < size; byte_nbr++)
            zframe_data (data)[byte_nbr] = (byte) byte_nbr;
        msg = zmsg_new ();
        zmsg_push (msg, data);
        curve_client_send (client, &msg);

        msg = curve_client_recv (client);
        data = zmsg_pop (msg);
        assert (data);
        assert (zframe_size (data) == size);
        for (byte_nbr = 0; byte_nbr < size; byte_nbr++) {
            assert (zframe_data (data)[byte_nbr] == (byte) byte_nbr);
        }
        zframe_destroy (&data);
        zmsg_destroy (&msg);
        size = size * 2 + 1;
    }
    //  Signal end of test
    curve_client_sendstr (client, "END");
    reply = curve_client_recvstr (client);
    free (reply);

    curve_keystore_destroy (&keystore);
    curve_client_destroy (&client);
    return NULL;
}

void
curve_server_test (bool verbose)
{
    printf (" * curve_server: ");

    //  We'll run the server as a background task, and the
    //  client in this foreground thread.
    zthread_new (client_task, &verbose);

    //  @selftest
    curve_keystore_t *keystore = curve_keystore_new ();
    int rc = curve_keystore_load (keystore, "test_keystore");
    assert (rc == 0);

    curve_keypair_t *server_keypair = curve_keystore_get (keystore, "server");
    curve_server_t *server = curve_server_new (&server_keypair);
    curve_server_set_metadata (server, "Server", "CURVEZMQ/curve_server");
    curve_server_set_verbose (server, verbose);
    curve_server_bind (server, "tcp://*:9000");
    curve_keystore_destroy (&keystore);

    bool finished = false;
    while (!finished) {
        zmsg_t *msg = curve_server_recv (server);
        if (memcmp (zframe_data (zmsg_first (msg)), "END", 3) == 0)
            finished = true;
        curve_server_send (server, &msg);
    }
    curve_server_destroy (&server);
    //  No other way to ensure client thread has exited before we do
    zclock_sleep (100);
    //  @end

    printf ("OK\n");
}
