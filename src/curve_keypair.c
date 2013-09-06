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
//  Save key pair to disk

int
curve_keypair_save (curve_keypair_t *self)
{
    assert (self);

    //  Set process file create mask to owner access only
    zfile_mode_private ();

    //  The public key file contains just the public key
    char text_key [41];
    zconfig_t *root = zconfig_new ("root", NULL);
    zconfig_t *key = zconfig_new ("public-key", root);
    zconfig_set_value (key, "%s", curve_z85_encode (text_key, self->public_key, 32));
    zconfig_save (root, "public.key");

    //  The secret key file contains both secret and public keys
    key = zconfig_new ("secret-key", root);
    zconfig_set_value (key, "%s", curve_z85_encode (text_key, self->secret_key, 32));
    zconfig_save (root, "secret.key");
    zconfig_destroy (&root);

    //  Reset process file create mask
    zfile_mode_default ();
    return 0;
}


//  --------------------------------------------------------------------------
//  Constructor, load key pair from disk; returns NULL if the operation
//  failed for any reason.

curve_keypair_t *
curve_keypair_load (void)
{
    curve_keypair_t *self =
        (curve_keypair_t *) zmalloc (sizeof (curve_keypair_t));

    int matches = 0;            //  How many keys we parsed
    zconfig_t *root = zconfig_load ("secret.key");
    if (root) {
        char *secret_key = zconfig_resolve (root, "secret-key", NULL);
        if (secret_key && strlen (secret_key) == 40) {
            curve_z85_decode (self->secret_key, secret_key);
            matches++;
        }
        char *public_key = zconfig_resolve (root, "public-key", NULL);
        if (public_key && strlen (public_key) == 40) {
            curve_z85_decode (self->public_key, public_key);
            matches++;
        }
    }
    if (matches != 2)
        curve_keypair_destroy (&self);
    zconfig_destroy (&root);
    return self;
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
//  Selftest

void
curve_keypair_test (bool verbose)
{
    printf (" * curve_keypair: ");

    //  @selftest
    //  Generate new long-term key pair for our test server
    //  The key pair will be stored in "secret.key"
    curve_keypair_t *keypair = curve_keypair_new ();
    int rc = curve_keypair_save (keypair);
    assert (rc == 0);
    assert (zfile_exists ("secret.key"));
    assert (curve_keypair_secret (keypair));
    assert (curve_keypair_public (keypair));
    curve_keypair_destroy (&keypair);
    //  Done, clean-up
    zfile_delete ("public.key");
    zfile_delete ("secret.key");
    //  @end

    printf ("OK\n");
}
