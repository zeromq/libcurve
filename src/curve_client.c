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
@end
*/

#include "../include/curve.h"

//  Structure of our class
struct _curve_client_t {
    void *control;              //  Control to/from agent
    void *data;                 //  Data to/from agent
    zctx_t *ctx;                //  Private context
};

//  This background thread does all the real work
static void
    s_agent_task (void *args, zctx_t *ctx, void *control);


//  --------------------------------------------------------------------------
//  Constructor
//  Create a new curve_client instance.
//  We use a context per instance to keep the API as simple as possible.
//  Takes ownership of cert.

curve_client_t *
curve_client_new (zcert_t **cert_p)
{
    curve_client_t *self = (curve_client_t *) zmalloc (sizeof (curve_client_t));
    assert (self);
    self->ctx = zctx_new ();
    self->control = zthread_fork (self->ctx, s_agent_task, NULL);

    //  Create separate data socket, send address on control socket
    self->data = zsocket_new (self->ctx, ZMQ_PAIR);
    assert (self->data);
    int rc = zsocket_bind (self->data, "inproc://data-%p", self->data);
    assert (rc != -1);
    zstr_sendfm (self->control, "inproc://data-%p", self->data);
   
    //  Now send cert on control socket as well
    rc = zmq_send (self->control, zcert_public_key (*cert_p), 32, ZMQ_SNDMORE);
    assert (rc == 32);
    rc = zmq_send (self->control, zcert_secret_key (*cert_p), 32, 0);
    assert (rc == 32);
    
    zcert_destroy (cert_p);

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
        zstr_send (self->control, "TERMINATE");
        free (zstr_recv (self->control));
        zctx_destroy (&self->ctx);
        free (self);
        *self_p = NULL;
    }
}


//  ---------------------------------------------------------------------
//  Set metadata property, will be sent to servers at connection

void
curve_client_set_metadata (curve_client_t *self, char *name, char *format, ...)
{
    assert (self);
    va_list argptr;
    va_start (argptr, format);
    char *value = (char *) malloc (255 + 1);
    vsnprintf (value, 255, format, argptr);
    va_end (argptr);

    zstr_sendx (self->control, "SET", name, value, NULL);
    free (value);
}


//  --------------------------------------------------------------------------
//  Enable verbose tracing of commands and activity

void
curve_client_set_verbose (curve_client_t *self, bool verbose)
{
    assert (self);
    zstr_sendm (self->control, "VERBOSE");
    zstr_sendf (self->control, "%d", verbose);
}


//  --------------------------------------------------------------------------
//  Create outgoing connection to server
//  Currently allows a single connection only

void
curve_client_connect (curve_client_t *self, char *endpoint, byte *server_key)
{
    assert (self);
    assert (endpoint);
    assert (server_key);
    zstr_sendm (self->control, "CONNECT");
    zstr_sendm (self->control, endpoint);
    zmq_send (self->control, server_key, 32, 0);
}


//  --------------------------------------------------------------------------
//  Close outgoing connection to server; idempotent

void
curve_client_disconnect (curve_client_t *self, char *endpoint)
{
    assert (self);
    zstr_sendx (self->control, "DISCONNECT", endpoint, NULL);
}


//  --------------------------------------------------------------------------
//  Send message to server, takes ownership of message

int
curve_client_send (curve_client_t *self, zmsg_t **msg_p)
{
    assert (self);
    assert (zmsg_size (*msg_p) > 0);
    zmsg_send (msg_p, self->data);
    return 0;
}


//  --------------------------------------------------------------------------
//  Wait for message from server
//  Returns zmsg_t object, or NULL if interrupted

zmsg_t *
curve_client_recv (curve_client_t *self)
{
    assert (self);
    zmsg_t *msg = zmsg_recv (self->data);
    return msg;
}


//  --------------------------------------------------------------------------
//  Send single-frame string message to server

int
curve_client_sendstr (curve_client_t *self, char *string)
{
    zstr_send (self->data, string);
    return 0;
}


//  --------------------------------------------------------------------------
//  Wait for single-frame string message from server

char *
curve_client_recvstr (curve_client_t *self)
{
    assert (self);
    return zstr_recv (self->data);
}


//  --------------------------------------------------------------------------
//  Get data socket handle, for polling
//  NOTE: do not call send/recv directly on handle since internal message
//  format is NOT A CONTRACT and is liable to change arbitrarily.

void *
curve_client_handle (curve_client_t *self)
{
    assert (self);
    return self->data;
}


//  *************************    BACK END AGENT    *************************

typedef enum {
    waiting,                    //  Waiting for API to issue connect
    connecting,                 //  Connecting to server
    connected,                  //  Ready for messages
    exception,                  //  Failed due to some error
    terminated                  //  Terminated by the API
} state_t;

//  This structure holds the context for our agent, so we can
//  pass that around cleanly to methods which need it

typedef struct {
    zctx_t *ctx;                //  CZMQ context
    void *control;              //  Control socket back to application
    void *data;                 //  Data socket to application
    state_t state;              //  Current socket state
    curve_codec_t *codec;       //  Client CurveZMQ codec
    void *dealer;               //  DEALER socket to server
    char *endpoint;             //  Connected endpoint, if any
} agent_t;

static agent_t *
s_agent_new (zctx_t *ctx, void *control)
{
    agent_t *self = (agent_t *) zmalloc (sizeof (agent_t));
    self->ctx = ctx;
    self->control = control;
    self->state = waiting;
    self->dealer = zsocket_new (ctx, ZMQ_DEALER);

    //  Connect our data socket to caller's endpoint
    self->data = zsocket_new (ctx, ZMQ_PAIR);
    char *endpoint = zstr_recv (self->control);
    int rc = zsocket_connect (self->data, "%s", endpoint);
    assert (rc != -1);
    free (endpoint);

    //  Create new client codec using cert from API
    byte public_key [32];
    byte secret_key [32];
    rc = zmq_recv (self->control, public_key, 32, 0);
    assert (rc == 32);
    rc = zmq_recv (self->control, secret_key, 32, 0);
    assert (rc == 32);
    
    zcert_t *cert = zcert_new_from (public_key, secret_key);
    self->codec = curve_codec_new_client (cert);
    zcert_destroy (&cert);

    return self;
}

static void
s_agent_destroy (agent_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        agent_t *self = *self_p;
        free (self->endpoint);
        curve_codec_destroy (&self->codec);
        free (self);
        *self_p = NULL;
    }
}


//  Handle a control message from front-end API

static int
s_agent_handle_control (agent_t *self)
{
    //  Get the whole message off the control socket in one go
    zmsg_t *request = zmsg_recv (self->control);
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
    if (streq (command, "CONNECT")) {
        assert (!self->endpoint);
        self->endpoint = zmsg_popstr (request);
        int rc = zsocket_connect (self->dealer, "%s", self->endpoint);
        assert (rc != -1);
        zframe_t *server_key = zmsg_pop (request);
        zframe_t *output = curve_codec_execute (self->codec, &server_key);
        zframe_send (&output, self->dealer, 0);
        self->state = connecting;
    }
    else
    if (streq (command, "DISCONNECT")) {
        if (self->endpoint) {
            int rc = zsocket_disconnect (self->dealer, "%s", self->endpoint);
            assert (rc != -1);
            free (self->endpoint);
        }
    }
    else
    if (streq (command, "VERBOSE")) {
        char *verbose = zmsg_popstr (request);
        curve_codec_set_verbose (self->codec, *verbose == '1');
        free (verbose);
    }
    else
    if (streq (command, "TERMINATE")) {
        self->state = terminated;
        zstr_send (self->control, "OK");
    }
    else {
        puts ("E: invalid command from API");
        assert (false);
    }
    free (command);
    zmsg_destroy (&request);
    return 0;
}


static int
s_agent_handle_dealer (agent_t *self)
{
    if (self->state == connecting) {
        zframe_t *input = zframe_recv (self->dealer);
        zframe_t *output = curve_codec_execute (self->codec, &input);
        if (output)
            zframe_send (&output, self->dealer, 0);
        else
        if (curve_codec_connected (self->codec))
            self->state = connected;
        else
        if (curve_codec_exception (self->codec))
            self->state = exception;
    }
    else
    if (self->state == connected) {
        zframe_t *encrypted = zframe_recv (self->dealer);
        zframe_t *cleartext = curve_codec_decode (self->codec, &encrypted);
        if (cleartext) {
            int flags = zframe_more (cleartext)? ZFRAME_MORE: 0;
            zframe_send (&cleartext, self->data, flags);
        }
        else
            self->state = exception;
    }
    return 0;
}

//  Handle a data message from front-end API

static int
s_agent_handle_data (agent_t *self)
{
    //  Encrypt and send all frames of request
    zmsg_t *request = zmsg_recv (self->data);
    while (zmsg_size (request)) {
        zframe_t *cleartext = zmsg_pop (request);
        if (zmsg_size (request))
            zframe_set_more (cleartext, 1);
        zframe_t *encrypted = curve_codec_encode (self->codec, &cleartext);
        if (encrypted)
            zframe_send (&encrypted, self->dealer, 0);
        else
            self->state = exception;
    }
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

    //  We have three sockets, but poll third one only selectively
    zmq_pollitem_t pollitems [] = {
        { self->control, 0, ZMQ_POLLIN, 0 },
        { self->dealer, 0, ZMQ_POLLIN, 0 },
        { self->data, 0, ZMQ_POLLIN, 0 }
    };

    while (!zctx_interrupted) {
        int pollsize = self->state == connected? 3: 2;
        if (zmq_poll (pollitems, pollsize, -1) == -1)
            break;              //  Interrupted
        if (pollitems [0].revents & ZMQ_POLLIN)
            s_agent_handle_control (self);
        if (pollitems [1].revents & ZMQ_POLLIN)
            s_agent_handle_dealer (self);
        if (pollitems [2].revents & ZMQ_POLLIN)
            s_agent_handle_data (self);

        if (self->state == terminated
        ||  self->state == exception)
            break;
    }
    //  Done, free all agent resources
    s_agent_destroy (&self);
}


//  --------------------------------------------------------------------------
//  Selftest
//
//  For the test case, we'll put the client and server certs into the
//  the same keystore file. This is now how it would work in real life.
//
//  The test case consists of the client sending a series of messages to
//  the server, which the server has to echo back. The client will send
//  both single and multipart messages. A message "END" signals the end
//  of the test.

#define TESTDIR ".test_curve_client"

static void *
server_task (void *args)
{
    bool verbose = *((bool *) args);

    //  Install the authenticator
    zctx_t *ctx = zctx_new ();
    zauth_t *auth = zauth_new (ctx);
    assert (auth);
    zauth_set_verbose (auth, verbose);
    zauth_configure_curve (auth, "*", TESTDIR);

    void *router = zsocket_new (ctx, ZMQ_ROUTER);
    int rc = zsocket_bind (router, "tcp://127.0.0.1:9005");
    assert (rc != -1);

    zcert_t *server_cert = zcert_load (TESTDIR "/server.cert");
    assert (server_cert);
    curve_codec_t *server = curve_codec_new_server (server_cert, ctx);
    assert (server);
    zcert_destroy (&server_cert);
    curve_codec_set_verbose (server, verbose);

    //  Set some metadata properties
    curve_codec_set_metadata (server, "Server", "CURVEZMQ/curve_codec");

    //  Execute incoming frames until ready or exception
    //  In practice we'd want a server instance per unique client
    while (!curve_codec_connected (server)) {
        zframe_t *sender = zframe_recv (router);
        zframe_t *input = zframe_recv (router);
        assert (input);
        zframe_t *output = curve_codec_execute (server, &input);
        assert (output);
        zframe_send (&sender, router, ZFRAME_MORE);
        zframe_send (&output, router, 0);
    }
    //  Check client metadata
    char *client_name = zhash_lookup (curve_codec_metadata (server), "client");
    assert (client_name);
    assert (streq (client_name, "CURVEZMQ/curve_client"));

    bool finished = false;
    while (!finished) {
        //  Now act as echo service doing a full decode and encode
        zframe_t *sender = zframe_recv (router);
        zframe_t *encrypted = zframe_recv (router);
        assert (encrypted);
        zframe_t *cleartext = curve_codec_decode (server, &encrypted);
        assert (cleartext);
        if (memcmp (cleartext, "END", 3) == 0)
            finished = true;
        //  Echo message back
        encrypted = curve_codec_encode (server, &cleartext);
        assert (encrypted);
        zframe_send (&sender, router, ZFRAME_MORE);
        zframe_send (&encrypted, router, 0);
    }
    curve_codec_destroy (&server);
    zauth_destroy (&auth);
    zctx_destroy (&ctx);
    return NULL;
}


void
curve_client_test (bool verbose)
{
    printf (" * curve_client: ");
    //  @selftest
    //  Create temporary directory for test files
    zsys_dir_create (TESTDIR);
    
    //  We'll create two new certificates and save the client public 
    //  certificate on disk; in a real case we'd transfer this securely
    //  from the client machine to the server machine.
    zcert_t *server_cert = zcert_new ();
    zcert_save (server_cert, TESTDIR "/server.cert");

    //  We'll run the server as a background task, and the
    //  client in this foreground thread.
    zthread_new (server_task, &verbose);

    zcert_t *client_cert = zcert_new ();
    zcert_save_public (client_cert, TESTDIR "/client.cert");

    curve_client_t *client = curve_client_new (&client_cert);
    curve_client_set_metadata (client, "Client", "CURVEZMQ/curve_client");
    curve_client_set_metadata (client, "Identity", "E475DA11");
    curve_client_set_verbose (client, verbose);
    curve_client_connect (client, "tcp://127.0.0.1:9005", zcert_public_key (server_cert));

    curve_client_sendstr (client, "Hello, World");
    char *reply = curve_client_recvstr (client);
    assert (streq (reply, "Hello, World"));
    free (reply);

    //  Try a multipart message
    zmsg_t *msg = zmsg_new ();
    zmsg_addstr (msg, "Hello, World");
    zmsg_addstr (msg, "Second frame");
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
        zmsg_prepend (msg, &data);
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

    zcert_destroy (&server_cert);
    zcert_destroy (&client_cert);
    curve_client_destroy (&client);
    
    //  Delete all test files
    zdir_t *dir = zdir_new (TESTDIR, NULL);
    zdir_remove (dir, true);
    zdir_destroy (&dir);
    //  @end

    //  Ensure server thread has exited before we do
    zclock_sleep (100);
    printf ("OK\n");
}
