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
    expect_message,             //  C/S: accepts MESSAGE from server
    exception                     //  Error condition, no work possible
} state_t;

//  For parsing incoming commands

typedef enum {
    no_command,
    hello_command,
    welcome_command,
    initiate_command,
    ready_command,
    message_command
} command_t;

//  Structure of our class
struct _curve_codec_t {
    curve_keypair_t
        *permakey;              //  Our permanent key
    curve_keypair_t
        *transkey;              //  Our transient key
    byte precomputed [32];      //  Precomputed key

    //  At some point we have to know the public keys for our peer
    byte peer_permakey [32];    //  Permanent public key for peer
    byte peer_transkey [32];    //  Transient public key for peer

    bool verbose;               //  Trace activity to stdout
    state_t state;              //  Current codec state
    int64_t nonce_counter;      //  Counter for short nonces

    //  Metadata properties
    //  TODO: use a zhash dictionary here
    byte metadata [1000];       //  Encoded for the wire
    size_t metadata_size;       //  Actual size so far

    bool is_server;             //  True for server-side codec
    char error_text [128];      //  In case of an error

    //  Server connection properties
    byte cookie_key [32];       //  Server cookie key

    //  Client connection properties
    byte cookie [96];           //  Cookie from server
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
//  Create a new curve_codec client instance, providing permanent keypair
//  for the client. Takes ownership of keypair.

curve_codec_t *
curve_codec_new_client (curve_keypair_t *keypair)
{
    curve_codec_t *self = (curve_codec_t *) zmalloc (sizeof (curve_codec_t));
    assert (self);
    assert (keypair);
    self->is_server = false;
    self->state = send_hello;
    self->permakey = curve_keypair_dup (keypair);
    self->transkey = curve_keypair_new ();
    return self;
}


//  --------------------------------------------------------------------------
//  Create a new curve_codec server instance, providing permanent keypair
//  for the server. Takes ownership of keypair.

curve_codec_t *
curve_codec_new_server (curve_keypair_t *keypair)
{
    curve_codec_t *self = (curve_codec_t *) zmalloc (sizeof (curve_codec_t));
    assert (self);
    assert (keypair);
    self->is_server = true;
    self->state = expect_hello;
    self->permakey = curve_keypair_dup (keypair);
    //  We don't generate a transient keypair yet because that uses
    //  up entropy so would allow unauthenticated clients to do a
    //  Denial-of-Entropy attack.
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
        curve_keypair_destroy (&self->permakey);
        curve_keypair_destroy (&self->transkey);
        free (self);
        *self_p = NULL;
    }
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

static void
s_raise_exception (curve_codec_t *self, char *error_text)
{
    strcpy (self->error_text, error_text);
    self->state = exception;
}

//  Encrypt a block of data using the connection nonce. If
//  key_to/key_from are null, uses precomputed key.

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
    //  These calls must always succeed
    assert (rc == 0);

    //  Now copy encrypted data into target; it will be 16 bytes longer than
    //  plain data
    memcpy (target, box + crypto_box_BOXZEROBYTES, size + 16);
    free (plain);
    free (box);
}


//  Decrypt a block of data using the connection nonce and precomputed key
//  If key_to/key_from are null, uses precomputed key. Returns 0 if OK,
//  -1 if there was an exception.

static int
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

    //  If we cannot open the box, it means it's been modified or is unauthentic
    if (rc == 0)
        memcpy (data, plain + crypto_box_ZEROBYTES, size);
    else
    if (self->verbose)
        puts ("E: invalid box received, cannot open it");

    free (plain);
    free (box);
    return rc;
}

static zframe_t *
s_produce_hello (curve_codec_t *self)
{
    zframe_t *command = zframe_new (NULL, sizeof (hello_t));
    hello_t *hello = (hello_t *) zframe_data (command);
    memcpy (hello->id, "\x05HELLO", 6);

    memcpy (hello->client, curve_keypair_public (self->transkey), 32);
    byte signature [64] = { 0 };
    s_encrypt (self, hello->nonce,
               signature, 64,
               "CurveZMQHELLO---",
               self->peer_permakey,     //  Server public key
               curve_keypair_secret (self->transkey));

    return command;
}

//  Returns 0 if OK, -1 if command or keys were invalid
static int
s_process_hello (curve_codec_t *self, zframe_t *input)
{
    hello_t *hello = (hello_t *) zframe_data (input);

    memcpy (self->peer_transkey, hello->client, 32);
    byte signature_received [64];
    int rc = s_decrypt (
        self, hello->nonce, signature_received, 64,
        "CurveZMQHELLO---",
        hello->client,
        curve_keypair_secret (self->permakey));

    return rc;
}

static zframe_t *
s_produce_welcome (curve_codec_t *self)
{
    zframe_t *command = zframe_new (NULL, sizeof (welcome_t));
    welcome_t *welcome = (welcome_t *) zframe_data (command);
    memcpy (welcome->id, "\x07WELCOME", 8);

    //  Working variables for libsodium calls
    byte nonce [24];            //  Full nonces are always 24 bytes
    byte plain [128];           //  Space for baking our cookies

    //  Client is authenticated, so it's safe to generate a transient keypair
    self->transkey = curve_keypair_new ();

    //  Generate cookie = Box [C' + s'](t),
    memset (plain, 0, crypto_box_ZEROBYTES);
    memcpy (plain + crypto_box_ZEROBYTES, self->peer_transkey, 32);
    memcpy (plain + crypto_box_ZEROBYTES + 32,
            curve_keypair_secret (self->transkey), 32);

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
    memcpy (plain, curve_keypair_public (self->transkey), 32);
    memcpy (plain + 32, cookie_nonce, 16);
    memcpy (plain + 48, cookie_box + crypto_box_BOXZEROBYTES, 80);
    s_encrypt (self, welcome->nonce,
               plain, 128,
               "WELCOME-",
               self->peer_transkey,
               curve_keypair_secret (self->permakey));

    return command;
}

//  Returns 0 if OK, -1 if command or keys were invalid
static int
s_process_welcome (curve_codec_t *self, zframe_t *input)
{
    //  Open Box [S' + cookie](C'->S)
    byte plain [128];
    welcome_t *welcome = (welcome_t *) zframe_data (input);
    int rc = s_decrypt (
        self, welcome->nonce, plain, 128, "WELCOME-",
        self->peer_permakey,    //  Server public key
        curve_keypair_secret (self->transkey));

    if (rc == 0) {
        memcpy (self->peer_transkey, plain, 32);
        memcpy (self->cookie, plain + 32, 96);
    }
    return rc;
}

//  Pre-compute connection secret from peer's transient key

static void
s_precompute_key (curve_codec_t *self)
{
    int rc = crypto_box_beforenm (self->precomputed,
                                  self->peer_transkey,
                                  curve_keypair_secret (self->transkey));
    assert (rc == 0);
}

static zframe_t *
s_produce_initiate (curve_codec_t *self)
{
    zframe_t *command = zframe_new (NULL, sizeof (initiate_t) + self->metadata_size);
    initiate_t *initiate = (initiate_t *) zframe_data (command);
    memcpy (initiate->id, "\x08INITIATE", 9);
    memcpy (initiate->cookie, self->cookie, sizeof (initiate->cookie));

    //  Create vouch = Box [C'](C->S)
    byte vouch [64];
    s_encrypt (self, vouch,
               curve_keypair_public (self->transkey), 32,
               "VOUCH---",
               self->peer_permakey,     //  Server public key
               curve_keypair_secret (self->permakey));

    //  Working variables for crypto calls
    size_t box_size = 96 + self->metadata_size;
    byte *plain = malloc (box_size);
    byte *box = malloc (box_size);

    //  Create Box [C + vouch + metadata](C'->S')
    memcpy (plain, curve_keypair_public (self->permakey), 32);
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

//  Returns 0 if OK, -1 if command or keys were invalid
static int
s_process_initiate (curve_codec_t *self, zframe_t *input)
{
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
    int rc = crypto_secretbox_open (
        plain, box, crypto_box_BOXZEROBYTES + 80,
        nonce, self->cookie_key);

    //  Throw away the cookie key
    memset (self->cookie_key, 0, 32);
    if (rc == 0) {
        //  Check cookie plain text is as expected [C' + s']
        byte *cookie = plain + crypto_box_ZEROBYTES;
        if (memcmp (cookie, self->peer_transkey, 32)
        ||  memcmp (cookie + 32, curve_keypair_secret (self->transkey), 32))
            rc = -1;
    }
    if (rc == 0)
        //  Open Box [C + vouch + metadata](C'->S')
        rc = s_decrypt (
            self, initiate->nonce, plain, 96 + metadata_size,
            "CurveZMQINITIATE", NULL, NULL);

    if (rc == 0) {
        memcpy (self->peer_permakey, plain, 32);
        //  TODO: call ZAP handler to authenticate client key
    }
    if (rc == 0) {
        //  Metadata is at plain + 96
        //  TODO: load metadata into zhash for caller to access
    }
    if (rc == 0) {
        //  Vouch nonce + box is 64 bytes at plain + 32
        byte vouch [64];
        memcpy (vouch, plain + 32, 64);
        int rc = s_decrypt (
            self, vouch, plain, 32, "VOUCH---",
            self->peer_permakey,    //  Client permanent key
            curve_keypair_secret (self->permakey));

        //  Check vouch is short term client public key
        if (rc == 0 && memcmp (plain, self->peer_transkey, 32))
            rc = -1;
    }
    free (plain);
    free (box);
    return rc;
}

static zframe_t *
s_produce_ready (curve_codec_t *self)
{
    zframe_t *command = zframe_new (NULL, sizeof (ready_t) + self->metadata_size);
    ready_t *ready = (ready_t *) zframe_data (command);
    memcpy (ready->id, "\x05READY", 6);
    s_encrypt (self, ready->nonce,
               self->metadata, self->metadata_size,
               "CurveZMQREADY---",
               NULL, NULL);
    return command;
}

//  Returns 0 if OK, -1 if command or keys were invalid
static int
s_process_ready (curve_codec_t *self, zframe_t *input)
{
    ready_t *ready = (ready_t *) zframe_data (input);
    self->metadata_size = zframe_size (input) - sizeof (ready_t);
    int rc = s_decrypt (
        self, ready->nonce, self->metadata, self->metadata_size,
        "CurveZMQREADY---", NULL, NULL);

    return rc;
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
    memcpy (message->id, "\x07MESSAGE", 8);
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
    size_t clear_size = zframe_size (input) - sizeof (message_t);
    byte *clear_data = malloc (clear_size);
    int rc = s_decrypt (
        self, message->nonce, clear_data, clear_size,
        self->is_server? "CurveZMQMESSAGEC": "CurveZMQMESSAGES",
        NULL, NULL);

    zframe_t *clear = NULL;
    if (rc == 0) {
        //  Create frame with clear text
        clear = zframe_new (clear_data + 1, clear_size - 1);
        zframe_set_more (clear, clear_data [0]);
    }
    free (clear_data);
    return clear;
}


//  Detect command type of frame
command_t
s_command (curve_codec_t *self, zframe_t *input)
{
    if (input) {
        size_t size = zframe_size (input);
        byte *data = zframe_data (input);
        if (size == sizeof (hello_t) && memcmp (data, "\x05HELLO", 6) == 0) {
            if (self->verbose)
                puts ("Received C:HELLO");
            return hello_command;
        }
        else
        if (size >= sizeof (initiate_t) && memcmp (data, "\x08INITIATE", 9) == 0) {
            if (self->verbose)
                puts ("Received C:INITIATE");
            return initiate_command;
        }
        else
        if (size == sizeof (welcome_t) && memcmp (data, "\x07WELCOME", 8) == 0) {
            if (self->verbose)
                puts ("Received S:WELCOME");
            return welcome_command;
        }
        else
        if (size >= sizeof (ready_t) && memcmp (data, "\x05READY", 6) == 0) {
            if (self->verbose)
                puts ("Received S:READY");
            return ready_command;
        }
        else
        if (size >= sizeof (message_t) && memcmp (data, "\x07MESSAGE", 8) == 0) {
            if (self->verbose)
                printf ("Received %c:MESSAGE\n", self->is_server? 'C': 'S');
            return message_command;
        }
    }
    return no_command;
}


static zframe_t *
s_execute_server (curve_codec_t *self, zframe_t *input)
{
    command_t command = s_command (self, input);
    if (self->state == expect_hello && command == hello_command) {
        if (s_process_hello (self, input) == 0) {
            self->state = expect_initiate;
            return s_produce_welcome (self);
        }
    }
    else
    if (self->state == expect_initiate && command == initiate_command) {
        s_precompute_key (self);
        if (s_process_initiate (self, input) == 0) {
            self->state = expect_message;
            return s_produce_ready (self);
        }
    }
    s_raise_exception (self, "Invalid command received from client");
    return NULL;
}

static zframe_t *
s_execute_client (curve_codec_t *self, zframe_t *input)
{
    command_t command = s_command (self, input);
    if (self->state == send_hello && command == no_command) {
        assert (zframe_size (input) == 32);
        memcpy (self->peer_permakey, zframe_data (input), 32);
        self->state = expect_welcome;
        return s_produce_hello (self);
    }
    else
    if (self->state == expect_welcome && command == welcome_command) {
        if (s_process_welcome (self, input) == 0) {
            self->state = expect_ready;
            s_precompute_key (self);
            return s_produce_initiate (self);
        }
    }
    else
    if (self->state == expect_ready && command == ready_command) {
        if (s_process_ready (self, input) == 0) {
            self->state = expect_message;
            return NULL;
        }
    }
    s_raise_exception (self, "Invalid command received from server");
    return NULL;
}


//  --------------------------------------------------------------------------
//  Accept input command from peer. May return a frame to send to the peer,
//  or NULL if there is nothing to send.

zframe_t *
curve_codec_execute (curve_codec_t *self, zframe_t **input_p)
{
    assert (self);
    zframe_t *output = NULL;
    if (self->is_server)
        output = s_execute_server (self, *input_p);
    else
        output = s_execute_client (self, *input_p);

    zframe_destroy (input_p);
    return output;
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
    assert (encrypted_p);
    assert (*encrypted_p);

    if (self->state == expect_message) {
        zframe_t *cleartext = NULL;
        if (s_command (self, *encrypted_p) == message_command)
            cleartext = s_process_message (self, *encrypted_p);
        else
            s_raise_exception (self, "Invalid command (expected MESSAGE)");
        zframe_destroy (encrypted_p);
        return cleartext;
    }
    else
    if (self->state == exception)
        return NULL;

    //  A bad state means the API is being misused
    assert (false);
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
//  Indicate whether codec hit a fatal error

bool
curve_codec_exception (curve_codec_t *self)
{
    assert (self);
    return (self->state == exception);
}


//  --------------------------------------------------------------------------
//  Selftest

//  @selftest
//  For the test case, we'll put the client and server keypairs into the
//  the same keystore file. This is now how it would work in real life.
//
//  The test case consists of the client sending a series of messages to
//  the server, which the server has to echo back. The client will send
//  both single and multipart messages. A message "END" signals the end
//  of the test.

static void *
server_task (void *args)
{
    bool verbose = *((bool *) args);

    zctx_t *ctx = zctx_new ();
    assert (ctx);
    void *router = zsocket_new (ctx, ZMQ_ROUTER);
    int rc = zsocket_bind (router, "tcp://*:9000");
    assert (rc != -1);

    //  Create a new server instance
    curve_keystore_t *keystore = curve_keystore_new ();
    rc = curve_keystore_load (keystore, "test_keystore");
    assert (rc == 0);
    curve_keypair_t *keypair = curve_keystore_get (keystore, "server");
    assert (keypair);
    curve_codec_t *server = curve_codec_new_server (keypair);
    assert (server);
    curve_keypair_destroy (&keypair);
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
    curve_keystore_destroy (&keystore);
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

    //  We'll run the server as a background task, and the
    //  client in this foreground thread.
    zthread_new (server_task, &verbose);

    //  @selftest
    curve_keystore_t *keystore = curve_keystore_new ();
    int rc = curve_keystore_load (keystore, "test_keystore");
    assert (rc == 0);

    zctx_t *ctx = zctx_new ();
    assert (ctx);
    void *dealer = zsocket_new (ctx, ZMQ_DEALER);
    rc = zsocket_connect (dealer, "tcp://127.0.0.1:9000");
    assert (rc != -1);

    //  Create a new client instance
    curve_keypair_t *keypair = curve_keystore_get (keystore, "client");
    assert (keypair);
    curve_codec_t *client = curve_codec_new_client (keypair);
    assert (client);
    curve_keypair_destroy (&keypair);
    curve_codec_set_verbose (client, verbose);

    //  Set some metadata properties
    curve_codec_set_metadata (client, "Client", "CURVEZMQ/curve_codec");
    curve_codec_set_metadata (client, "Identity", "E475DA11");

    //  Kick off client handshake
    //  First frame to new client is server's public key
    curve_keypair_t *server_keypair = curve_keystore_get (keystore, "server");
    zframe_t *input = zframe_new (curve_keypair_public (server_keypair), 32);
    zframe_t *output = curve_codec_execute (client, &input);
    curve_keypair_destroy (&server_keypair);

    while (!curve_codec_connected (client)) {
        assert (output);
        rc = zframe_send (&output, dealer, 0);
        assert (rc >= 0);
        zframe_t *input = zframe_recv (dealer);
        assert (input);
        output = curve_codec_execute (client, &input);
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
    cleartext = zframe_new ((byte *) "Second frame", 12);
    encrypted = curve_codec_encode (client, &cleartext);
    assert (encrypted);
    zframe_send (&encrypted, dealer, 0);

    encrypted = zframe_recv (dealer);
    assert (encrypted);
    cleartext = curve_codec_decode (client, &encrypted);
    assert (cleartext);
    assert (zframe_more (cleartext) == 1);
    zframe_destroy (&cleartext);

    encrypted = zframe_recv (dealer);
    assert (encrypted);
    cleartext = curve_codec_decode (client, &encrypted);
    assert (cleartext);
    assert (zframe_more (cleartext) == 0);
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
    //  Signal end of test
    cleartext = zframe_new ((byte *) "END", 3);
    encrypted = curve_codec_encode (client, &cleartext);
    assert (encrypted);
    zframe_send (&encrypted, dealer, 0);

    encrypted = zframe_recv (dealer);
    assert (encrypted);
    cleartext = curve_codec_decode (client, &encrypted);
    assert (cleartext);
    zframe_destroy (&cleartext);

    curve_keystore_destroy (&keystore);
    curve_codec_destroy (&client);

    //  Some invalid operations to test exception handling
    keypair = curve_keypair_new ();
    input = zframe_new (curve_keypair_public (keypair), 32);
    curve_codec_t *server = curve_codec_new_server (keypair);
    curve_keypair_destroy (&keypair);
    curve_codec_execute (server, &input);
    assert (curve_codec_exception (server));
    curve_codec_destroy (&server);

    zctx_destroy (&ctx);
    //  @end

    //  Ensure server thread has exited before we do
    zclock_sleep (100);
    printf ("OK\n");
}
