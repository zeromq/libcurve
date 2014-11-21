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
    zctx_t *ctx;                //  Our parent context
    void *control;              //  Control to/from agent
    void *data;                 //  Data to/from agent
};

//  This background thread does all the real work
static void
    s_agent_task (void *args, zctx_t *ctx, void *control);

//  --------------------------------------------------------------------------
//  Constructor
//  Create a new server instance, providing its permanent cert
//  The caller provides the ZeroMQ context so that it can also
//  attach an authenticator (zauth) to the same context.

curve_server_t *
curve_server_new (zctx_t *ctx, zcert_t **cert_p)
{
    curve_server_t *self = (curve_server_t *) zmalloc (sizeof (curve_server_t));
    assert (self);
    self->ctx = ctx;
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
curve_server_destroy (curve_server_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        curve_server_t *self = *self_p;
        zstr_send (self->control, "TERMINATE");
        free (zstr_recv (self->control));
        free (self);
        *self_p = NULL;
    }
}


//  ---------------------------------------------------------------------
//  Set metadata property, will be sent to clients at connection

void
curve_server_set_metadata (curve_server_t *self, char *name, char *format, ...)
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
curve_server_set_verbose (curve_server_t *self, bool verbose)
{
    assert (self);
    zstr_sendm (self->control, "VERBOSE");
    zstr_sendf (self->control, "%d", verbose);
}


//  --------------------------------------------------------------------------
//  Set maximum authenticated clients

void
curve_server_set_max_clients (curve_server_t *self, int limit)
{
    assert (self);
    zstr_sendm (self->control, "MAX CLIENTS");
    zstr_sendf (self->control, "%d", limit);
}


//  --------------------------------------------------------------------------
//  Set maximum unauthenticated pending clients

void
curve_server_set_max_pending (curve_server_t *self, int limit)
{
    assert (self);
    zstr_sendm (self->control, "MAX PENDING");
    zstr_sendf (self->control, "%d", limit);
}


//  --------------------------------------------------------------------------
//  Set time-to-live for authenticated clients

void
curve_server_set_client_ttl (curve_server_t *self, int limit)
{
    assert (self);
    zstr_sendm (self->control, "CLIENT TTL");
    zstr_sendf (self->control, "%d", limit);
}


//  --------------------------------------------------------------------------
//  Set time-to-live for unauthenticated pending clients

void
curve_server_set_pending_ttl (curve_server_t *self, int limit)
{
    assert (self);
    zstr_sendm (self->control, "PENDING TTL");
    zstr_sendf (self->control, "%d", limit);
}


//  --------------------------------------------------------------------------
//  Bind server socket to local endpoint

void
curve_server_bind (curve_server_t *self, char *endpoint)
{
    assert (self);
    zstr_sendx (self->control, "BIND", endpoint, NULL);
}


//  --------------------------------------------------------------------------
//  Unbind server socket from local endpoint, idempotent

void
curve_server_unbind (curve_server_t *self, char *endpoint)
{
    assert (self);
    zstr_sendx (self->control, "UNBIND", endpoint, NULL);
}


//  --------------------------------------------------------------------------
//  Wait for message from server
//  Returns zmsg_t object, or NULL if interrupted

zmsg_t *
curve_server_recv (curve_server_t *self)
{
    assert (self);
    zmsg_t *msg = zmsg_recv (self->data);
    return msg;
}


//  --------------------------------------------------------------------------
//  Send message to server, takes ownership of message

int
curve_server_send (curve_server_t *self, zmsg_t **msg_p)
{
    assert (self);
    assert (zmsg_size (*msg_p) > 0);
    zmsg_send (msg_p, self->data);
    return 0;
}


//  --------------------------------------------------------------------------
//  Get data socket handle, for polling
//  NOTE: do not call send/recv directly on handle since internal message
//  format is NOT A CONTRACT and is liable to change arbitrarily.

void *
curve_server_handle (curve_server_t *self)
{
    assert (self);
    return self->data;
}


//  *************************    BACK END AGENT    *************************

//  This structure holds the context for our agent, so we can
//  pass that around cleanly to methods which need it

typedef struct {
    zctx_t *ctx;                //  CZMQ context
    void *control;              //  Control socket back to application
    void *data;                 //  Data socket to application
    void *router;               //  ROUTER socket to server
    zcert_t *cert;   //  Server long term cert
    size_t nbr_clients;         //  Number of authenticated clients
    size_t nbr_pending;         //  Number of pending authentications
    size_t max_clients;         //  Max authenticated clients
    size_t max_pending;         //  Max pending authentications
    size_t client_ttl;          //  Time-out for authenticated clients
    size_t pending_ttl;         //  Time-out for pending authentications
    zhash_t *metadata;          //  Metadata for server
    zhash_t *clients;           //  Clients known so far
    bool terminated;            //  Agent terminated by API
    bool verbose;               //  Trace activity to stderr
} agent_t;

static agent_t *
s_agent_new (zctx_t *ctx, void *control)
{
    agent_t *self = (agent_t *) zmalloc (sizeof (agent_t));
    self->ctx = ctx;
    self->control = control;
    self->router = zsocket_new (ctx, ZMQ_ROUTER);

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
    self->cert = zcert_new_from (public_key, secret_key);
        
    self->metadata = zhash_new ();
    zhash_autofree (self->metadata);
    self->clients = zhash_new ();
    self->max_clients = 100;
    self->max_pending = 10;
    self->client_ttl = 3600;    //  60 minutes
    self->pending_ttl = 60;     //  60 seconds
    return self;
}

static void
s_agent_destroy (agent_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        agent_t *self = *self_p;
        zcert_destroy (&self->cert);
        zhash_destroy (&self->metadata);
        zhash_destroy (&self->clients);
        free (self);
        *self_p = NULL;
    }
}


//  This section covers a single client connection

typedef enum {
    pending = 0,                //  Waiting for connection
    connected = 1,              //  Ready for messages
    exception = 2               //  Failed due to some error
} state_t;

typedef struct {
    agent_t *agent;             //  Agent for this client
    curve_codec_t *codec;       //  Client CurveZMQ codec
    state_t state;              //  Current state
    zframe_t *address;          //  Client address identity
    zmsg_t *incoming;           //  Incoming message, if any
    char *hashkey;              //  Key into clients hash
} client_t;

static client_t *
client_new (agent_t *agent, zframe_t *address)
{
    client_t *self = (client_t *) zmalloc (sizeof (client_t));
    assert (self);
    self->agent = agent;
    self->codec = curve_codec_new_server (agent->cert, agent->ctx);
    self->address = zframe_dup (address);
    self->hashkey = zframe_strhex (address);
    return self;
}

static void
client_destroy (client_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        client_t *self = *self_p;
        curve_codec_destroy (&self->codec);
        zframe_destroy (&self->address);
        zmsg_destroy (&self->incoming);
        free (self->hashkey);
        free (self);
        *self_p = NULL;
    }
}

//  Callback when we remove client from 'clients' hash table
static void
client_free (void *argument)
{
    client_t *client = (client_t *) argument;
    client_destroy (&client);
}

static void
client_set_pending (client_t *self)
{
    self->state = pending;
    self->agent->nbr_pending++;
}

static void
client_set_connected (client_t *self)
{
    if (self->state == pending)
        self->agent->nbr_pending--;
    self->state = connected;
    self->agent->nbr_clients++;
}

static void
client_set_exception (client_t *self)
{
    if (self->state == pending)
        self->agent->nbr_pending--;
    else
    if (self->state == connected)
        self->agent->nbr_clients--;
    self->state = exception;
}

static int
client_set_metadata (const char *key, void *item, void *arg)
{
    client_t *self = (client_t *) arg;
    curve_codec_set_metadata (self->codec, (char *) key, (char *) item);
    return 0;
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
        zhash_insert (self->metadata, name, value);
        free (name);
        free (value);
    }
    else
    if (streq (command, "VERBOSE")) {
        char *verbose = zmsg_popstr (request);
        self->verbose = *verbose == '1';
        free (verbose);
    }
    else
    if (streq (command, "MAX CLIENTS")) {
        char *limit = zmsg_popstr (request);
        self->max_clients = atoi (limit);
        free (limit);
    }
    else
    if (streq (command, "MAX PENDING")) {
        char *limit = zmsg_popstr (request);
        self->max_pending = atoi (limit);
        free (limit);
    }
    else
    if (streq (command, "CLIENT TTL")) {
        char *limit = zmsg_popstr (request);
        self->client_ttl = atoi (limit);
        free (limit);
    }
    else
    if (streq (command, "PENDING TTL")) {
        char *limit = zmsg_popstr (request);
        self->pending_ttl = atoi (limit);
        free (limit);
    }
    else
    if (streq (command, "BIND")) {
        char *endpoint = zmsg_popstr (request);
puts (endpoint);
        int rc = zsocket_bind (self->router, "%s", endpoint);
        assert (rc != -1);
        free (endpoint);
    }
    else
    if (streq (command, "UNBIND")) {
        char *endpoint = zmsg_popstr (request);
        int rc = zsocket_unbind (self->router, "%s", endpoint);
        assert (rc != -1);
        free (endpoint);
    }
    else
    if (streq (command, "TERMINATE")) {
        self->terminated = true;
        zstr_send (self->control, "OK");
    }
    free (command);
    zmsg_destroy (&request);
    return 0;
}

//  Handle a message from the server

static int
s_agent_handle_router (agent_t *self)
{
    zframe_t *address = zframe_recv (self->router);
    char *hashkey = zframe_strhex (address);
    client_t *client = zhash_lookup (self->clients, hashkey);
    if (client == NULL
    && self->nbr_pending < self->max_pending) {
        client = client_new (self, address);
        client_set_pending (client);
        curve_codec_set_verbose (client->codec, self->verbose);
        zhash_foreach (self->metadata, client_set_metadata, client);
        zhash_insert (self->clients, hashkey, client);
        zhash_freefn (self->clients, hashkey, client_free);
    }
    free (hashkey);
    zframe_destroy (&address);

    //  If we're overloaded, discard client request without any further
    //  ado. The client will have to detect this and retry later.
    //  TODO: retry in client side to handle overloaded servers.
    if (client == NULL)
        return 0;

    //  If not yet connected, process one command frame
    //  We always read one request, and send one reply
    if (client->state == pending) {
        zframe_t *input = zframe_recv (self->router);
        zframe_t *output = curve_codec_execute (client->codec, &input);
        if (output) {
            zframe_send (&client->address, self->router, ZFRAME_MORE + ZFRAME_REUSE);
            zframe_send (&output, self->router, 0);
            if (curve_codec_connected (client->codec))
                client_set_connected (client);
        }
        else
            client_set_exception (client);
    }
    else
    //  If connected, process one message frame
    //  We will queue message frames in the client until we get a
    //  whole message ready to deliver up the data socket -- frames
    //  from different clients will be randomly intermixed.
    if (client->state == connected) {
        zframe_t *encrypted = zframe_recv (self->router);
        zframe_t *cleartext = curve_codec_decode (client->codec, &encrypted);
        if (cleartext) {
            if (client->incoming == NULL)
                client->incoming = zmsg_new ();
            zmsg_add (client->incoming, cleartext);
            if (!zframe_more (cleartext)) {
                zmsg_pushstr (client->incoming, client->hashkey);
                zmsg_send (&client->incoming, self->data);
            }
        }
        else
            client_set_exception (client);
    }
    //  If client is misbehaving, remove it
    if (client->state == exception)
        zhash_delete (self->clients, client->hashkey);

    return 0;
}

//  Handle a data message from front-end API

static int
s_agent_handle_data (agent_t *self)
{
    //  First frame is client address (hashkey)
    //  If caller sends unknown client address, we discard the message
    //  For testing, we'll abort in this case, since it cannot happen
    //  The assert disappears when we start to timeout clients...
    zmsg_t *request = zmsg_recv (self->data);
    char *hashkey = zmsg_popstr (request);
    client_t *client = zhash_lookup (self->clients, hashkey);
    free (hashkey);
    if (client) {
        //  Encrypt and send all frames of request
        //  Each frame is a full ZMQ message with identity frame
        while (zmsg_size (request)) {
            zframe_t *cleartext = zmsg_pop (request);
            if (zmsg_size (request))
                zframe_set_more (cleartext, 1);
            zframe_t *encrypted = curve_codec_encode (client->codec, &cleartext);
            if (encrypted) {
                zframe_send (&client->address, self->router, ZFRAME_MORE + ZFRAME_REUSE);
                zframe_send (&encrypted, self->router, 0);
            }
            else
                client_set_exception (client);
        }
    }
    zmsg_destroy (&request);
    return 0;
}


static void
s_agent_task (void *args, zctx_t *ctx, void *control)
{
    //  Create agent instance as we start this task
    agent_t *self = s_agent_new (ctx, control);
    if (!self)                  //  Interrupted
        return;

    //  We always poll all three sockets
    zmq_pollitem_t pollitems [] = {
        { self->control, 0, ZMQ_POLLIN, 0 },
        { self->router, 0, ZMQ_POLLIN, 0 },
        { self->data, 0, ZMQ_POLLIN, 0 }
    };
    while (!zctx_interrupted) {
        if (zmq_poll (pollitems, 3, -1) == -1)
            break;              //  Interrupted

        if (pollitems [0].revents & ZMQ_POLLIN)
            s_agent_handle_control (self);
        if (pollitems [1].revents & ZMQ_POLLIN)
            s_agent_handle_router (self);
        if (pollitems [2].revents & ZMQ_POLLIN)
            s_agent_handle_data (self);

        if (self->terminated)
            break;
    }
    //  Done, free all agent resources
    s_agent_destroy (&self);
}


//  --------------------------------------------------------------------------
//  Selftest

#define TESTDIR ".test_curve_server"

static void *
client_task (void *args)
{
    bool verbose = *((bool *) args);
    
    char filename [256];
    snprintf (filename, 255, TESTDIR "/client-%07d.cert", randof (10000000));
    zcert_t *client_cert = zcert_new ();
    zcert_save_public (client_cert, filename);
    curve_client_t *client = curve_client_new (&client_cert);
    curve_client_set_verbose (client, verbose);

    zcert_t *server_cert = zcert_load (TESTDIR "/server.cert");
    assert (server_cert);
    curve_client_connect (client, "tcp://127.0.0.1:9006", zcert_public_key (server_cert));
    zcert_destroy (&server_cert);

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

    curve_client_destroy (&client);
    return NULL;
}

void
curve_server_test (bool verbose)
{
    printf (" * curve_server: ");

    //  @selftest
    //  Create temporary directory for test files
    srand (time (NULL));
    zsys_dir_create (TESTDIR);
    
    zcert_t *server_cert = zcert_new ();
    zcert_save (server_cert, TESTDIR "/server.cert");

    //  Install the authenticator
    zctx_t *ctx = zctx_new ();
    zauth_t *auth = zauth_new (ctx);
    assert (auth);
    zauth_set_verbose (auth, verbose);
    zauth_configure_curve (auth, "*", TESTDIR);
    
    //  We'll run a set of clients as background tasks, and the
    //  server in this foreground thread. Don't pass verbose to
    //  the clients as the results are unreadable.
    int live_clients;
    for (live_clients = 0; live_clients < 5; live_clients++)
        zthread_new (client_task, &verbose);

    curve_server_t *server = curve_server_new (ctx, &server_cert);
    curve_server_set_verbose (server, verbose);
    curve_server_bind (server, "tcp://127.0.0.1:9006");
    
    while (live_clients > 0) {
        zmsg_t *msg = curve_server_recv (server);
        if (memcmp (zframe_data (zmsg_last (msg)), "END", 3) == 0)
            live_clients--;
        curve_server_send (server, &msg);
    }

    //  Try an invalid client/server combination
    byte bad_server_key [32] = { 0 };
    zcert_t *unknown = zcert_new ();
    curve_client_t *client = curve_client_new (&unknown);
    curve_client_set_verbose (client, true);
    curve_client_connect (client, "tcp://127.0.0.1:9006", bad_server_key);
    curve_client_sendstr (client, "Hello, World");

    //  Expect no reply after 250msec
    zmq_pollitem_t pollitems [] = {
        { curve_client_handle (client), 0, ZMQ_POLLIN, 0 }
    };
    assert (zmq_poll (pollitems, 1, 250) == 0);
    curve_client_destroy (&client);
 
    //  Delete all test files
    zdir_t *dir = zdir_new (TESTDIR, NULL);
    zdir_remove (dir, true);
    zdir_destroy (&dir);
    
    curve_server_destroy (&server);
    zauth_destroy (&auth);
    zctx_destroy (&ctx);
    //  @end
   
    //  Ensure client threads have exited before we do
    zclock_sleep (100);
    printf ("OK\n");
}
