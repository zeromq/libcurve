/*  =========================================================================
    curve_keystore - keystore management

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
    Manages a set of keys, held in a single text file. This is called a
    "keystore". The keystore is always private to the creating user, and
    since it contains secret keys, should never be shared.
@discuss
@end
*/

#include "../include/curve.h"

//  Structure of our class
struct _curve_keystore_t {
    zhash_t *hash;              //  Keys are stored by name
};


//  --------------------------------------------------------------------------
//  Constructor, creates a new, empty keystore in memory

curve_keystore_t *
curve_keystore_new (void)
{
    curve_keystore_t *self =
        (curve_keystore_t *) zmalloc (sizeof (curve_keystore_t));
    assert (self);
    self->hash = zhash_new ();
    zhash_autofree (self->hash);
    return self;
}


//  --------------------------------------------------------------------------
//  Destructor

void
curve_keystore_destroy (curve_keystore_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        curve_keystore_t *self = *self_p;
        zhash_destroy (&self->hash);
        free (self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Load keystore data from disk. Returns zero if OK, -1 on error.

int
curve_keystore_load (curve_keystore_t *self, char *filename)
{
    assert (self);
    return zhash_load (self->hash, filename);
}


//  --------------------------------------------------------------------------
//  Save keystore to disk, overwriting any file with the same name.
//  Returns zero if OK, -1 on error.
//  We format the keypair as a single value with the public key and secret
//  key separated by "|". This isn't intended to be human readable, just
//  easy to load and parse via zhash.

int
curve_keystore_save (curve_keystore_t *self, char *filename)
{
    assert (self);
    zfile_mode_private ();
    int rc = zhash_save (self->hash, filename);
    zfile_mode_default ();
    return rc;
}


//  --------------------------------------------------------------------------
//  Put a keypair into the keystore indexed by some chosen key name.

void
curve_keystore_put (curve_keystore_t *self, char *name, curve_keypair_t *keypair)
{
    assert (self);
    assert (name);
    assert (keypair);

    //  Encoded as secret|public
    char value [82];
    curve_z85_encode (value, curve_keypair_public (keypair), 32);
    curve_z85_encode (value + 41, curve_keypair_secret (keypair), 32);
    value [40] = '|';
    zhash_update (self->hash, name, value);
}


//  --------------------------------------------------------------------------
//  Get a keypair from the keystore; returns a new, valid keypair, or
//  NULL if the key name did not exist.

curve_keypair_t *
curve_keystore_get (curve_keystore_t *self, char *name)
{
    assert (self);
    assert (name);
    char *value = zhash_lookup (self->hash, name);
    if (value && strlen (value) == 81) {
        value = strdup (value);
        value [40] = 0;
        byte public_key [32];
        byte secret_key [32];
        curve_z85_decode (public_key, value);
        curve_z85_decode (secret_key, value + 41);
        free (value);
        curve_keypair_t *keypair = curve_keypair_new_from (public_key, secret_key);
        return keypair;
    }
    else
        return NULL;
}


//  --------------------------------------------------------------------------
//  Selftest

void
curve_keystore_test (bool verbose)
{
    printf (" * curve_keystore: ");

    //  @selftest
    curve_keystore_t *keystore = curve_keystore_new ();
    curve_keypair_t *client_keypair = curve_keypair_new ();
    assert (client_keypair);
    curve_keystore_put (keystore, "client", client_keypair);
    curve_keypair_t *server_keypair = curve_keypair_new ();
    assert (server_keypair);
    curve_keystore_put (keystore, "server", server_keypair);
    int rc = curve_keystore_save (keystore, ".keystore");
    assert (rc == 0);
    assert (zfile_exists (".keystore"));
    curve_keystore_destroy (&keystore);

    keystore = curve_keystore_new ();
    rc = curve_keystore_load (keystore, ".keystore");
    assert (rc == 0);
    curve_keypair_t *keypair = curve_keystore_get (keystore, "client");
    assert (keypair);
    assert (curve_keypair_eq (keypair, client_keypair));
    curve_keypair_destroy (&keypair);

    keypair = curve_keystore_get (keystore, "server");
    assert (keypair);
    assert (curve_keypair_eq (keypair, server_keypair));
    curve_keypair_destroy (&keypair);

    curve_keypair_destroy (&client_keypair);
    curve_keypair_destroy (&server_keypair);
    curve_keystore_destroy (&keystore);

    //  Done, clean-up
//     zfile_delete (".keystore");
    //  @end

    printf ("OK\n");
}
