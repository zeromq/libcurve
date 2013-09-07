/*  =========================================================================
    curve_keypair - keypair management

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
    Works with a public-secret keypair.
@discuss
@end
*/

#include "../include/curve.h"

#include <sodium.h>
#if crypto_box_PUBLICKEYBYTES != 32 \
 || crypto_box_SECRETKEYBYTES != 32
#   error "libsodium not built correctly"
#endif

//  Structure of our class
struct _curve_keypair_t {
    byte public_key [32];       //  Our long-term public key
    byte secret_key [32];       //  Our long-term secret key
};


//  --------------------------------------------------------------------------
//  Constructor, creates a new public/secret key pair

curve_keypair_t *
curve_keypair_new (void)
{
    curve_keypair_t *self =
        (curve_keypair_t *) zmalloc (sizeof (curve_keypair_t));
    assert (self);
    int rc = crypto_box_keypair (self->public_key, self->secret_key);
    assert (rc == 0);
    return self;
}


//  --------------------------------------------------------------------------
//  Constructor, accepts public/secret key pair from caller

curve_keypair_t *
curve_keypair_new_from (byte *public_key, byte *secret_key)
{
    curve_keypair_t *self =
        (curve_keypair_t *) zmalloc (sizeof (curve_keypair_t));
    assert (self);
    assert (public_key);
    assert (secret_key);
    memcpy (self->public_key, public_key, 32);
    memcpy (self->secret_key, secret_key, 32);
    return self;
}


//  --------------------------------------------------------------------------
//  Destructor

void
curve_keypair_destroy (curve_keypair_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        curve_keypair_t *self = *self_p;
        free (self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Return public part of key pair

byte *
curve_keypair_public (curve_keypair_t *self)
{
    assert (self);
    return self->public_key;
}


//  --------------------------------------------------------------------------
//  Return secret part of key pair

byte *
curve_keypair_secret (curve_keypair_t *self)
{
    assert (self);
    return self->secret_key;
}


//  --------------------------------------------------------------------------
//  Return copy of keypair

curve_keypair_t *
curve_keypair_dup (curve_keypair_t *self)
{
    assert (self);
    return curve_keypair_new_from (self->public_key, self->secret_key);
}


//  --------------------------------------------------------------------------
//  Return true if two keypairs are identical

bool
curve_keypair_eq (curve_keypair_t *self, curve_keypair_t *compare)
{
    assert (self);
    assert (compare);

    if (memcmp (self->public_key, compare->public_key, 32) == 0
    &&  memcmp (self->secret_key, compare->secret_key, 32) == 0)
        return true;
    else
        return false;
}


//  --------------------------------------------------------------------------
//  Print contents of keypair to stderr for debugging

void
curve_keypair_dump (curve_keypair_t *self)
{
    assert (self);

    int byte_nbr;
    fprintf (stderr, "I: public key: ");
    for (byte_nbr = 0; byte_nbr < 32; byte_nbr++) {
        if (byte_nbr %4 == 4)
            fprintf (stderr, "-");
        fprintf (stderr, "%02x", self->public_key [byte_nbr]);
    }
    fprintf (stderr, "\n");
    fprintf (stderr, "I: secret key: ");
    for (byte_nbr = 0; byte_nbr < 32; byte_nbr++) {
        if (byte_nbr %4 == 4)
            fprintf (stderr, "-");
        fprintf (stderr, "%02x", self->secret_key [byte_nbr]);
    }
    fprintf (stderr, "\n");
}


//  --------------------------------------------------------------------------
//  Send keypair over socket as two-part message

int
curve_keypair_send (curve_keypair_t *self, void *pipe)
{
    assert (self);
    assert (pipe);
    int rc = zmq_send (pipe, self->public_key, 32, ZMQ_SNDMORE);
    assert (rc == 32);
    rc = zmq_send (pipe, self->secret_key, 32, 0);
    assert (rc == 32);
    return 0;
}


//  --------------------------------------------------------------------------
//  Receive keypair off socket, return new keypair or NULL if error

curve_keypair_t *
curve_keypair_recv (void *pipe)
{
    assert (pipe);
    byte public_key [32];
    byte secret_key [32];
    int rc = zmq_recv (pipe, public_key, 32, 0);
    if (rc != 32)
        return NULL;
    rc = zmq_recv (pipe, secret_key, 32, 0);
    if (rc != 32)
        return NULL;

    return curve_keypair_new_from (public_key, secret_key);
}


//  --------------------------------------------------------------------------
//  Selftest

void
curve_keypair_test (bool verbose)
{
    printf (" * curve_keypair: ");

    //  @selftest
    curve_keypair_t *keypair = curve_keypair_new ();
    assert (curve_keypair_public (keypair));
    assert (curve_keypair_secret (keypair));

    curve_keypair_t *shadow = curve_keypair_new_from (
        curve_keypair_public (keypair),
        curve_keypair_secret (keypair));
    assert (curve_keypair_eq (keypair, shadow));
    curve_keypair_destroy (&shadow);

    shadow = curve_keypair_dup (keypair);
    assert (curve_keypair_eq (keypair, shadow));
    curve_keypair_destroy (&shadow);

    curve_keypair_destroy (&keypair);

    //  @end

    printf ("OK\n");
}
