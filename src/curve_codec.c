/*  =========================================================================
    curve_codec - core CurveZMQ engine (rfc.zeromq.org/spec:26)

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
    Implements the client and server codecs. This class encodes and decodes
    zframes. All I/O is the responsibility of the caller. This is the 
    reference implementation of CurveZMQ. You will not normally want to use
    it directly in application code as the API is low-level and complex.
    TODO: authentication via ZAP - http://rfc.zeromq.org/spec:27/ZAP
    TODO: clean exception handling
@discuss
@end
*/

#include "../include/curve.h"

#include <sodium.h>
#if crypto_box_PUBLICKEYBYTES != 32 \
 || crypto_box_SECRETKEYBYTES != 32 \
 || crypto_box_BEFORENMBYTES != 32 \
 || crypto_box_ZEROBYTES != 32 \
 || crypto_box_BOXZEROBYTES != 16 \
 || crypto_box_NONCEBYTES != 24
#   error "libsodium not built correctly"
#endif

typedef enum {
    send_hello,                 //  C: sends HELLO to server
    expect_hello,               //  S: accepts HELLO from client
    expect_welcome,             //  C: accepts WELCOME from server
    expect_initiate,            //  S: accepts INITIATE from client
    expect_ready,               //  C: accepts READY from server
    expect_message              //  C/S: accepts MESSAGE from server
} state_t;


//  Structure of our class
struct _curve_codec_t {
    curve_keypair_t
        *permanent;             //  Our permanent key
    curve_keypair_t
        *transient;             //  Our transient key
    byte precomputed [32];      //  Precomputed key
    
    byte peer_transient [32];   //  Peer transient public key

    bool verbose;               //  Trace activity to stdout
    state_t state;              //  Current codec state
    int64_t nonce_counter;      //  Counter for short nonces

    //  Metadata properties
    //  TODO: use a zhash dictionary here
    byte metadata [1000];       //  Encoded for the wire
    size_t metadata_size;       //  Actual size so far

    bool is_server;             //  True for server-side codec
    
    //  Server connection properties
    byte cookie_key [32];       //  Server cookie key
    byte client_key [32];       //  Client permanent public key
    
    //  Client connection properties
    byte cookie [96];           //  Cookie from server
    byte server_key [32];       //  Server permanent public key
};

//  Command structures

typedef struct {
    char id [sizeof ("HELLO")];
    byte version [2];           //  CurveZMQ major-minor version
    byte padding [72];          //  Anti-amplification padding
    byte client [32];           //  Client public connection key C'
    byte nonce [8];             //  Short nonce, prefixed by "CurveZMQHELLO---"
    byte box [80];              //  Signature, Box [64 * %x0](C'->S)
} hello_t;

typedef struct {
    char id [sizeof ("WELCOME")];
    byte nonce [16];            //  Long nonce, prefixed by "WELCOME-"
    byte box [144];             //  Box [S' + cookie](S->C')
} welcome_t;

typedef struct {
    char id [sizeof ("INITIATE")];
    byte cookie [96];           //  Server-provided cookie
    byte nonce [8];             //  Short nonce, prefixed by "CurveZMQINITIATE"
    byte box [112];             //  Box [C + vouch + metadata](C'->S')
} initiate_t;

typedef struct {
    char id [sizeof ("READY")];
    byte nonce [8];             //  Short nonce, prefixed by "CurveZMQREADY---"
    byte box [16];              //  Box [metadata](S'->C')
} ready_t;

typedef struct {
    char id [sizeof ("MESSAGE")];
    byte nonce [8];             //  Short nonce, prefixed by "CurveZMQMESSAGE-"
    byte box [16];              //  Box [payload](S'->C') or (C'->S')
} message_t;


//  --------------------------------------------------------------------------
//  Constructors
//  Create a new curve_codec instance for a client that talks to one
//  server identified by its public key.

curve_codec_t *
curve_codec_new_client (byte *server_key)
{
    curve_codec_t *self = (curve_codec_t *) zmalloc (sizeof (curve_codec_t));
    assert (self);
    memcpy (self->server_key, server_key, 32);
    self->is_server = false;
    self->state = send_hello;
    self->transient = curve_keypair_new ();
    return self;
}


//  --------------------------------------------------------------------------
//  Create a new curve_codec instance for a server that talks to a single
//  client peer.

curve_codec_t *
curve_codec_new_server (void)
{
    curve_codec_t *self = (curve_codec_t *) zmalloc (sizeof (curve_codec_t));
    assert (self);
    self->is_server = true;
    self->state = expect_hello;
    //  We don't generate transient keys yet because that uses up entropy 
    //  so would allow unauthenticated clients to do a Denial-of-Entropy
    //  attack.
    return self;
}


//  --------------------------------------------------------------------------
//  Destructor

void
curve_codec_destroy (curve_codec_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        curve_codec_t *self = *self_p;
        curve_keypair_destroy (&self->permanent);
        curve_keypair_destroy (&self->transient);
        free (self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Set permanent keys for this codec; takes ownership of keypair and
//  destroys when destroying the codec.

void
curve_codec_set_permanent_keys (curve_codec_t *self, curve_keypair_t *keypair)
{
    assert (self);
    self->permanent = keypair;
}


//  --------------------------------------------------------------------------
//  Set a metadata property; these are sent to the peer after the security 
//  handshake. Property values are strings.

void
curve_codec_set_metadata (curve_codec_t *self, char *name, char *value)
{
    assert (self);
    assert (name && value);
    size_t name_len = strlen (name);
    size_t value_len = strlen (value);
    assert (name_len > 0 && name_len < 256);
    byte *needle = self->metadata + self->metadata_size;

    //  Encode name
    *needle++ = (byte) name_len;
    memcpy (needle, name, name_len);
    needle += name_len;

    //  Encode value
    *needle++ = (byte) ((value_len >> 24) && 255);
    *needle++ = (byte) ((value_len >> 16) && 255);
    *needle++ = (byte) ((value_len >> 8)  && 255);
    *needle++ = (byte) ((value_len)       && 255);
    memcpy (needle, value, value_len);
    needle += value_len;

    //  Update size of metadata so far
    self->metadata_size = needle - self->metadata;
    //  This is a throwaway implementation; a proper metadata design would use
    //  a hash table and serialize to any size. TODO: rewrite this.
    assert (self->metadata_size < 1000);
}


//  --------------------------------------------------------------------------
//  Set tracing on curve_codec instance. Will report activity to stdout.

void
curve_codec_set_verbose (curve_codec_t *self, bool verbose)
{
    assert (self);
    self->verbose = verbose;
}


//  --------------------------------------------------------------------------
//  Internal functions for working with CurveZMQ commands

//  Encrypt a block of data using the connection nonce
//  If key_to/key_from are null, uses precomputed key
    
static void
s_encrypt (
    curve_codec_t *self,    //  Codec instance sending the data
    byte *target,           //  target must be nonce + box
    byte *data,             //  Clear text data to encrypt
    size_t size,            //  Size of clear text data
    char *prefix,           //  Nonce prefix to use, 8 or 16 chars
    byte *key_to,           //  Key to encrypt to, may be null
    byte *key_from)         //  Key to encrypt from, may be null
{
    //  Plain and encoded buffers are the same size; plain buffer starts
    //  with 32 (ZEROBYTES) zeros and box starts with 16 (BOXZEROBYTES)
    //  zeros. box_size is combined size, the same in both cases, and
    //  encrypted data is thus 16 bytes longer than plain data.
    size_t box_size = crypto_box_ZEROBYTES + size;
    byte *plain = malloc (box_size);
    byte *box = malloc (box_size);

    //  Prepare plain text with zero bytes at start for encryption
    memset (plain, 0, crypto_box_ZEROBYTES);
    memcpy (plain + crypto_box_ZEROBYTES, data, size);

    //  Prepare full nonce and store nonce into target
    //  Handle both short and long nonces
    byte nonce [24];
    if (strlen (prefix) == 16) {
        //  Long nonce is sequential integer
        memcpy (nonce, (byte *) prefix, 16);
        memcpy (nonce + 16, &self->nonce_counter, 8);
        memcpy (target, &self->nonce_counter, 8);
        self->nonce_counter++;
        target += 8;            //  Encrypted data comes after 8 byte nonce
    }
    else {
        //  Short nonce is random sequence
        randombytes (target, 16);
        memcpy (nonce, (byte *) prefix, 8);
        memcpy (nonce + 8, target, 16);
        target += 16;           //  Encrypted data comes after 16 byte nonce
    }
    //  Create box using either key pair, or precomputed key
    int rc;
    if (key_to)
        rc = crypto_box (box, plain, box_size, nonce, key_to, key_from);
    else
        rc = crypto_box_afternm (box, plain, box_size, nonce, self->precomputed);
    assert (rc == 0);

    //  Now copy encrypted data into target; it will be 16 bytes longer than
    //  plain data
    memcpy (target, box + crypto_box_BOXZEROBYTES, size + 16);
    free (plain);
    free (box);
}


//  Decrypt a block of data using the connection nonce and precomputed key
//  If key_to/key_from are null, uses precomputed key
    
static void
s_decrypt (
    curve_codec_t *self,    //  curve_codec instance sending the data
    byte *source,           //  source must be nonce + box
    byte *data,             //  Where to store decrypted clear text
    size_t size,            //  Size of clear text data
    char *prefix,           //  Nonce prefix to use, 8 or 16 chars
    byte *key_to,           //  Key to decrypt to, may be null
    byte *key_from)         //  Key to decrypt from, may be null
{
    size_t box_size = crypto_box_ZEROBYTES + size;
    byte *plain = malloc (box_size);
    byte *box = malloc (box_size);

    //  Prepare the full nonce from prefix and source
    //  Handle both short and long nonces
    byte nonce [24];
    if (strlen (prefix) == 16) {
        memcpy (nonce, (byte *) prefix, 16);
        memcpy (nonce + 16, source, 8);
        source += 8;
    }
    else {
        memcpy (nonce, (byte *) prefix, 8);
        memcpy (nonce + 8, source, 16);
        source += 16;
    }
    //  Get encrypted box from source
    memset (box, 0, crypto_box_BOXZEROBYTES);
    memcpy (box + crypto_box_BOXZEROBYTES, source, size + crypto_box_BOXZEROBYTES);
    
    //  Open box using either key pair, or precomputed key
    int rc;
    if (key_to)
        rc = crypto_box_open (plain, box, box_size, nonce, key_to, key_from);
    else
        rc = crypto_box_open_afternm (plain, box, box_size, nonce, self->precomputed);
    //  TODO: don't assert, but raise error on connection
    assert (rc == 0);
    
    memcpy (data, plain + crypto_box_ZEROBYTES, size);
    free (plain);
    free (box);
}

static zframe_t *
s_produce_hello (curve_codec_t *self)
{
    zframe_t *command = zframe_new (NULL, sizeof (hello_t));
    hello_t *hello = (hello_t *) zframe_data (command);
    strcpy (hello->id, "HELLO");

    memcpy (hello->client, curve_keypair_public (self->transient), 32);
    byte signature [64] = { 0 };
    s_encrypt (self, hello->nonce, 
               signature, 64,
               "CurveZMQHELLO---", 
               self->server_key, 
               curve_keypair_secret (self->transient));
    return command;
}

static void
s_process_hello (curve_codec_t *self, zframe_t *input)
{
    if (self->verbose)
        printf ("\nC:HELLO: ");
    hello_t *hello = (hello_t *) zframe_data (input);

    memcpy (self->peer_transient, hello->client, 32);
    byte signature_received [64];
    byte signature_expected [64] = { 0 };
    s_decrypt (self, hello->nonce, 
               signature_received, 64, 
               "CurveZMQHELLO---", 
               hello->client, 
               curve_keypair_secret (self->permanent));
    
    //  TODO: don't assert, but raise error on connection
    assert (memcmp (signature_received, signature_expected, 64) == 0);
    if (self->verbose)
        puts ("OK");
}

static zframe_t *
s_produce_welcome (curve_codec_t *self)
{
    zframe_t *command = zframe_new (NULL, sizeof (welcome_t));
    welcome_t *welcome = (welcome_t *) zframe_data (command);
    strcpy (welcome->id, "WELCOME");

    //  Working variables for libsodium calls
    byte nonce [24];            //  Full nonces are always 24 bytes
    byte plain [128];           //  Space for baking our cookies

    //  Client is authenticated, so it's safe to generate a transient keypair
    self->transient = curve_keypair_new ();

    //  Generate cookie = Box [C' + s'](t),
    memset (plain, 0, crypto_box_ZEROBYTES);
    memcpy (plain + crypto_box_ZEROBYTES, self->peer_transient, 32);
    memcpy (plain + crypto_box_ZEROBYTES + 32, 
            curve_keypair_secret (self->transient), 32);

    //  Create full nonce for encryption
    //  8-byte prefix plus 16-byte random nonce
    assert (crypto_box_BOXZEROBYTES == 16);
    byte cookie_nonce [16];
    randombytes (cookie_nonce, 16);
    memcpy (nonce, (byte *) "COOKIE--", 8);
    memcpy (nonce + 8, cookie_nonce, 16);

    //  Encrypt using one-time symmetric cookie key
    randombytes (self->cookie_key, 32);
    byte cookie_box [96];
    int rc = crypto_secretbox (cookie_box, plain, 96, nonce, self->cookie_key);
    assert (rc == 0);

    //  Create Box [S' + cookie](S->C')
    memcpy (plain, curve_keypair_public (self->transient), 32);
    memcpy (plain + 32, cookie_nonce, 16);
    memcpy (plain + 48, cookie_box + crypto_box_BOXZEROBYTES, 80);
    s_encrypt (self, welcome->nonce, 
               plain, 128, 
               "WELCOME-", 
               self->peer_transient, 
               curve_keypair_secret (self->permanent));

    return command;
}

static void
s_process_welcome (curve_codec_t *self, zframe_t *input)
{
    if (self->verbose)
        printf ("S:WELCOME: ");

    //  Open Box [S' + cookie](C'->S)
    byte plain [128];
    welcome_t *welcome = (welcome_t *) zframe_data (input);
    s_decrypt (self, welcome->nonce, 
               plain, 128, "WELCOME-", 
               self->server_key, 
               curve_keypair_secret (self->transient));
    memcpy (self->peer_transient, plain, 32);
    memcpy (self->cookie, plain + 32, 96);
    if (self->verbose)
        puts ("OK");
}

//  Pre-compute connection secret from peer's transient key
static void
s_precompute_key (curve_codec_t *self)
{
    int rc = crypto_box_beforenm (self->precomputed,
                                  self->peer_transient,
                                  curve_keypair_secret (self->transient));
    assert (rc == 0);
}

static zframe_t *
s_produce_initiate (curve_codec_t *self)
{
    zframe_t *command = zframe_new (NULL, sizeof (initiate_t) + self->metadata_size);
    initiate_t *initiate = (initiate_t *) zframe_data (command);
    strcpy (initiate->id, "INITIATE");
    memcpy (initiate->cookie, self->cookie, sizeof (initiate->cookie));

    //  Create vouch = Box [C'](C->S)
    byte vouch [64];
    s_encrypt (self, vouch, 
               curve_keypair_public (self->transient), 32, 
               "VOUCH---", 
               self->server_key, 
               curve_keypair_secret (self->permanent));
    
    //  Working variables for crypto calls
    size_t box_size = 96 + self->metadata_size;
    byte *plain = malloc (box_size);
    byte *box = malloc (box_size);

    //  Create Box [C + vouch + metadata](C'->S')
    memcpy (plain, curve_keypair_public (self->permanent), 32);
    memcpy (plain + 32, vouch, 64);
    memcpy (plain + 96, self->metadata, self->metadata_size);
    s_encrypt (self, initiate->nonce, 
               plain, 96 + self->metadata_size,
               "CurveZMQINITIATE", 
               NULL, NULL);
    free (plain);
    free (box);

    return command;
}

static void
s_process_initiate (curve_codec_t *self, zframe_t *input)
{
    if (self->verbose)
        printf ("C:INITIATE: ");

    //  Working variables for crypto calls
    byte nonce [24];
    
    initiate_t *initiate = (initiate_t *) zframe_data (input);
    size_t metadata_size = zframe_size (input) - sizeof (initiate_t);
    size_t box_size = crypto_box_ZEROBYTES + 96 + metadata_size;
    byte *plain = malloc (box_size);
    byte *box = malloc (box_size);

    //  Check cookie is valid
    //  We could but don't expire cookie key after 60 seconds
    //  Cookie nonce is first 16 bytes of cookie
    memcpy (nonce, (byte *) "COOKIE--", 8);
    memcpy (nonce + 8, initiate->cookie, 16);
    //  Cookie box is next 80 bytes of cookie
    memset (box, 0, crypto_box_BOXZEROBYTES);
    memcpy (box + crypto_box_BOXZEROBYTES, initiate->cookie + 16, 80);
    int rc = crypto_secretbox_open (plain, box,
                                    crypto_box_BOXZEROBYTES + 80,
                                    nonce, self->cookie_key);
    //  Throw away the cookie key
    memset (self->cookie_key, 0, 32);
    assert (rc == 0);

    //  Check cookie plain text is as expected [C' + s']
    //  TODO: don't assert, but raise error on connection
    assert (memcmp (plain + crypto_box_ZEROBYTES, 
                    self->peer_transient, 32) == 0);
    assert (memcmp (plain + crypto_box_ZEROBYTES + 32, 
                    curve_keypair_secret (self->transient), 32) == 0);

    //  Open Box [C + vouch + metadata](C'->S')
    s_decrypt (self, initiate->nonce, 
               plain, 96 + metadata_size, 
               "CurveZMQINITIATE", 
               NULL, NULL);
    
    //  This is where we'd check the decrypted client public key
    memcpy (self->client_key, plain, 32);
    //  Metadata is at plain + 96
    if (self->verbose)
        printf ("(received %zd bytes metadata) ", metadata_size);
    //  Vouch nonce + box is 64 bytes at plain + 32
    byte vouch [64];
    memcpy (vouch, plain + 32, 64);
    s_decrypt (self, vouch, 
               plain, 32, "VOUCH---",
               self->client_key, 
               curve_keypair_secret (self->permanent));
    
    //  What we decrypted must be the short term client public key
    //  TODO: don't assert, but raise error on connection
    assert (memcmp (plain, self->peer_transient, 32) == 0);

    free (plain);
    free (box);

    if (self->verbose)
        puts ("OK");
}

static zframe_t *
s_produce_ready (curve_codec_t *self)
{
    zframe_t *command = zframe_new (NULL, sizeof (ready_t) + self->metadata_size);
    ready_t *ready = (ready_t *) zframe_data (command);
    strcpy (ready->id, "READY");
    s_encrypt (self, ready->nonce, 
               self->metadata, self->metadata_size, 
               "CurveZMQREADY---", 
               NULL, NULL);
    return command;
}

static void
s_process_ready (curve_codec_t *self, zframe_t *input)
{
    ready_t *ready = (ready_t *) zframe_data (input);
    if (self->verbose)
        printf ("S:READY: ");
    self->metadata_size = zframe_size (input) - sizeof (ready_t);
    s_decrypt (self, ready->nonce, 
               self->metadata, self->metadata_size, 
               "CurveZMQREADY---", 
               NULL, NULL);
    if (self->verbose)
        printf ("(received %zd bytes metadata) OK\n", self->metadata_size);
}

static zframe_t *
s_produce_message (curve_codec_t *self, zframe_t *clear)
{
    //  Our clear text consists of flags + message data
    size_t clear_size = zframe_size (clear) + 1;
    byte  *clear_data = malloc (clear_size);
    clear_data [0] = zframe_more (clear);
    memcpy (clear_data + 1, zframe_data (clear), zframe_size (clear));
        
    zframe_t *command = zframe_new (NULL, sizeof (message_t) + clear_size);
    message_t *message = (message_t *) zframe_data (command);
    strcpy (message->id, "MESSAGE");
    s_encrypt (self, message->nonce, 
               clear_data, clear_size, 
               self->is_server? "CurveZMQMESSAGES": "CurveZMQMESSAGEC", 
               NULL, NULL);
    free (clear_data);
    return command;
}

static zframe_t *
s_process_message (curve_codec_t *self, zframe_t *input)
{
    message_t *message = (message_t *) zframe_data (input);
    if (self->verbose)
        printf ("%c:MESSAGE: ", self->is_server? 'C': 'S');

    size_t clear_size = zframe_size (input) - sizeof (message_t);
    byte  *clear_data = malloc (clear_size);
    s_decrypt (self, message->nonce, 
               clear_data, clear_size, 
               self->is_server? "CurveZMQMESSAGEC": "CurveZMQMESSAGES", 
               NULL, NULL);

    //  Create frame with clear text
    zframe_t *clear = zframe_new (clear_data + 1, clear_size - 1);
    zframe_set_more (clear, clear_data [0]);
    free (clear_data);
    
    if (self->verbose)
        printf ("(received %zd bytes data) OK\n", clear_size - 1);
    return clear;
}


static zframe_t *
s_execute_server (curve_codec_t *self, zframe_t *input)
{
    //  All server states require input
    assert (input);
    size_t size = zframe_size (input);
    byte *data = zframe_data (input);

    if (self->state == expect_hello
    &&  size == sizeof (hello_t)
    &&  streq ((char *) data, "HELLO")) {
        s_process_hello (self, input);
        self->state = expect_initiate;
        return s_produce_welcome (self);
    }
    else
    if (self->state == expect_initiate
    &&  size >= sizeof (initiate_t)
    &&  streq ((char *) data, "INITIATE")) {
        s_precompute_key (self);
        s_process_initiate (self, input);
        self->state = expect_message;
        return s_produce_ready (self);
    }
    if (self->verbose)
        puts ("E: invalid command");
    //  TODO: don't assert, but raise error on connection
    assert (false);
}

static zframe_t *
s_execute_client (curve_codec_t *self, zframe_t *input) 
{
    if (self->state == send_hello) {
        self->state = expect_welcome;
        return s_produce_hello (self);
    }
    //  All other states require input
    assert (input);
    size_t size = zframe_size (input);
    byte *data = zframe_data (input);

    if (self->state == expect_welcome
    &&  size == sizeof (welcome_t)
    &&  streq ((char *) data, "WELCOME")) {
        s_process_welcome (self, input);
        s_precompute_key (self);
        self->state = expect_ready;
        return s_produce_initiate (self);
    }
    else
    if (self->state == expect_ready
    &&  size >= sizeof (ready_t)
    &&  streq ((char *) data, "READY")) {
        s_process_ready (self, input);
        self->state = expect_message;
        return NULL;
    }
    if (self->verbose)
        puts ("E: invalid command");
    //  TODO: don't assert, but raise error on connection
    assert (false);
}


//  --------------------------------------------------------------------------
//  Accept input command from peer. If the command is invalid, it is
//  discarded silently. May return a frame to send to the peer, or NULL
//  if there is nothing to send.

zframe_t *
curve_codec_execute (curve_codec_t *self, zframe_t *input)
{
    assert (self);
    if (self->is_server)
        return s_execute_server (self, input);
    else
        return s_execute_client (self, input);
}


//  --------------------------------------------------------------------------
//  Encode clear-text message to peer. Returns a frame ready to send
//  on the wire. Takes ownership of clear-text frame.

zframe_t *
curve_codec_encode (curve_codec_t *self, zframe_t **cleartext_p)
{
    assert (self);
    assert (self->state == expect_message);
    assert (cleartext_p);
    assert (*cleartext_p);
    
    zframe_t *encrypted = s_produce_message (self, *cleartext_p);
    zframe_destroy (cleartext_p);
    return encrypted;
}


//  --------------------------------------------------------------------------
//  Decode blob into message from peer. Takes ownership of encrypted frame.

zframe_t *
curve_codec_decode (curve_codec_t *self, zframe_t **encrypted_p)
{
    assert (self);
    assert (self->state == expect_message);
    assert (encrypted_p);
    assert (*encrypted_p);
    
    zframe_t *cleartext = NULL;
    if (zframe_size (*encrypted_p) >= sizeof (message_t)
    &&  streq ((char *) zframe_data (*encrypted_p), "MESSAGE"))
        cleartext = s_process_message (self, *encrypted_p);
    else
    if (self->verbose)
        puts ("E: invalid command");
    
    zframe_destroy (encrypted_p);
    return cleartext;
}


//  --------------------------------------------------------------------------
//  Indicate whether handshake is still in progress

bool
curve_codec_connected (curve_codec_t *self)
{
    assert (self);
    return (self->state == expect_message);
}


//  --------------------------------------------------------------------------
//  Selftest

//  @selftest
void *
server_task (void *args)
{
    zctx_t *ctx = zctx_new ();
    assert (ctx);
    void *router = zsocket_new (ctx, ZMQ_ROUTER);
    int rc = zsocket_bind (router, "tcp://*:9000");
    assert (rc != -1);

    //  Create a new server instance and load its keys from the previously 
    //  generated keypair file
    curve_codec_t *server = curve_codec_new_server ();
    curve_codec_set_verbose (server, (bool *) args);
    curve_codec_set_permanent_keys (server, curve_keypair_load ());

    //  Set some metadata properties
    curve_codec_set_metadata (server, "Server", "CURVEZMQ/curve_codec");
    
    //  A hack to get the thread to timeout and exit so we can test
    //  under Valgrind. Do NOT do this on real servers!
    zsocket_set_rcvtimeo (router, 1000);

    //  Execute incoming frames until ready or exception
    //  In practice we'd want a server instance per unique client
    while (!curve_codec_connected (server)) {
        zframe_t *sender = zframe_recv (router);
        zframe_t *input = zframe_recv (router);
        assert (input);
        zframe_t *output = curve_codec_execute (server, input);
        assert (output);
        zframe_destroy (&input);
        zframe_send (&sender, router, ZFRAME_MORE);
        zframe_send (&output, router, 0);
    }
    while (true) {
        //  Now act as echo service doing a full decode and encode
        //  Finish when we get an END message
        zframe_t *sender = zframe_recv (router);
        if (!sender)
            break;          //  Timed-out, finished
        zframe_t *encrypted = zframe_recv (router);
        assert (encrypted);
        zframe_t *cleartext = curve_codec_decode (server, &encrypted);
        assert (cleartext);
        
        encrypted = curve_codec_encode (server, &cleartext);
        assert (encrypted);
        zframe_send (&sender, router, ZFRAME_MORE);
        zframe_send (&encrypted, router, 0);
    }
    curve_codec_destroy (&server);
    zctx_destroy (&ctx);
    return NULL;
}
//  @end

void
curve_codec_test (bool verbose)
{
    printf (" * curve_codec: ");

    //  Check compiler isn't padding our structures mysteriously
    assert (sizeof (hello_t) == 200);
    assert (sizeof (welcome_t) == 168);
    assert (sizeof (initiate_t) == 225);
    assert (sizeof (ready_t) == 30);
    assert (sizeof (message_t) == 32);

    //  @selftest
    //  Generate new permanent key pair for our test server
    //  The key pair will be stored in "secret.key"
    curve_keypair_t *keypair = curve_keypair_new ();
    int rc = curve_keypair_save (keypair);
    assert (rc == 0);
    assert (zfile_exists ("secret.key"));
    
    //  This is how we "share" the server key in our test
    byte server_key [32];
    memcpy (server_key, curve_keypair_public (keypair), 32);
    curve_keypair_destroy (&keypair);
    
    //  We'll run the server as a background task, and the
    //  client in this foreground thread.
    zthread_new (server_task, &verbose);

    zctx_t *ctx = zctx_new ();
    assert (ctx);
    void *dealer = zsocket_new (ctx, ZMQ_DEALER);
    rc = zsocket_connect (dealer, "tcp://127.0.0.1:9000");
    assert (rc != -1);
    
    //  Create a new client instance using shared server key
    curve_codec_t *client = curve_codec_new_client (server_key);
    curve_codec_set_verbose (client, verbose);
    curve_codec_set_permanent_keys (client, curve_keypair_new ());

    //  Set some metadata properties
    curve_codec_set_metadata (client, "Client", "CURVEZMQ/curve_codec");
    curve_codec_set_metadata (client, "Identity", "E475DA11");
    
    //  Execute null event on client to kick off handshake
    zframe_t *output = curve_codec_execute (client, NULL);
    while (!curve_codec_connected (client)) {
        assert (output);
        rc = zframe_send (&output, dealer, 0);
        assert (rc >= 0);
        zframe_t *input = zframe_recv (dealer);
        assert (input);
        output = curve_codec_execute (client, input);
        zframe_destroy (&input);
    }
    //  Handshake is done, now try Hello, World
    zframe_t *cleartext = zframe_new ((byte *) "Hello, World", 12);
    zframe_t *encrypted = curve_codec_encode (client, &cleartext);
    assert (encrypted);
    zframe_send (&encrypted, dealer, 0);

    encrypted = zframe_recv (dealer);
    assert (encrypted);
    
    cleartext = curve_codec_decode (client, &encrypted);
    assert (cleartext);
    assert (zframe_size (cleartext) == 12);
    assert (memcmp (zframe_data (cleartext), "Hello, World", 12) == 0);
    zframe_destroy (&cleartext);

    //  Try a multipart message
    cleartext = zframe_new ((byte *) "Hello, World", 12);
    zframe_set_more (cleartext, 1);
    encrypted = curve_codec_encode (client, &cleartext);
    assert (encrypted);
    zframe_send (&encrypted, dealer, 0);

    encrypted = zframe_recv (dealer);
    cleartext = curve_codec_decode (client, &encrypted);
    assert (cleartext);
    assert (zframe_more (cleartext) == 1);
    zframe_destroy (&cleartext);
    
    //  Now send messages of increasing size, check they work
    int count;
    int size = 0;
    for (count = 0; count < 18; count++) {
        if (verbose)
            printf ("Testing message of size=%d...\n", size);
        cleartext = zframe_new (NULL, size);
        int byte_nbr;
        //  Set data to sequence 0...255 repeated
        for (byte_nbr = 0; byte_nbr < size; byte_nbr++) 
            zframe_data (cleartext)[byte_nbr] = (byte) byte_nbr;

        encrypted = curve_codec_encode (client, &cleartext);
        assert (encrypted);
        zframe_send (&encrypted, dealer, 0);
        
        encrypted = zframe_recv (dealer);
        assert (encrypted);
        cleartext = curve_codec_decode (client, &encrypted);
        assert (cleartext);
        assert (zframe_size (cleartext) == size);
        for (byte_nbr = 0; byte_nbr < size; byte_nbr++) {
            assert (zframe_data (cleartext)[byte_nbr] == (byte) byte_nbr);
        }
        zframe_destroy (&cleartext);
        size = size * 2 + 1;
    }
    //  Give server thread a chance to time-out and exit
    zclock_sleep (1000);

    //  Done, clean-up
    curve_codec_destroy (&client);
    zfile_delete ("public.key");
    zfile_delete ("secret.key");
    zctx_destroy (&ctx);
    //  @end
    
    printf ("OK\n");
}
