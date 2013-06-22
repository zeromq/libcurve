/*  =========================================================================
    curvezmq_keypair - keypair management

    -------------------------------------------------------------------------
    Copyright (c) 1991-2013 iMatix Corporation <www.imatix.com>
    Copyright other contributors as noted in the AUTHORS file.

    This file is part of the CurveZMQ authentication and encryption library.

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

#include "../include/curvezmq.h"
#if !defined (__WINDOWS__)
#   include "platform.h"
#endif

#if defined (HAVE_LIBSODIUM)
#   include <sodium.h>
#   if crypto_box_PUBLICKEYBYTES != 32 \
    || crypto_box_SECRETKEYBYTES != 32
#   error "libsodium not built correctly"
#   endif
#endif


//  Structure of our class
struct _curvezmq_keypair_t {
    byte public_key [32];       //  Our long-term public key
    byte secret_key [32];       //  Our long-term secret key
};


//  --------------------------------------------------------------------------
//  Constructor, creates a new public/secret key pair

curvezmq_keypair_t *
curvezmq_keypair_new (void)
{
    curvezmq_keypair_t *self = 
        (curvezmq_keypair_t *) zmalloc (sizeof (curvezmq_keypair_t));
#if defined (HAVE_LIBSODIUM)
    if (self) {
        int rc = crypto_box_keypair (self->public_key, self->secret_key);
        assert (rc == 0);
    }
#endif
    return self;
}
    

//  --------------------------------------------------------------------------
//  Destructor

void
curvezmq_keypair_destroy (curvezmq_keypair_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        curvezmq_keypair_t *self = *self_p;
        free (self);
        *self_p = NULL;
    }
}


//  Return allocated string containing key in printable hex format

static char *
s_key_to_hex (byte *key)
{
    char *hex = zmalloc (65);
    int byte_nbr;
    for (byte_nbr = 0; byte_nbr < 32; byte_nbr++) 
        sprintf (hex + (byte_nbr * 2), "%02X", key [byte_nbr]);
    return hex;
}


//  --------------------------------------------------------------------------
//  Save key pair to disk

int
curvezmq_keypair_save (curvezmq_keypair_t *self)
{
    assert (self);

    //  Get printable key strings
    char *public_key = s_key_to_hex (self->public_key);
    char *secret_key = s_key_to_hex (self->secret_key);
    
    //  Set process file create mask to owner access only
    zfile_mode_private ();
    
    //  The public key file contains just the public key
    zconfig_t *root = zconfig_new ("root", NULL);
    zconfig_t *key = zconfig_new ("public-key", root);
    zconfig_set_value (key, public_key);
    zconfig_save (root, "public.key");
    
    //  The secret key file contains both secret and public keys
    key = zconfig_new ("secret-key", root);
    zconfig_set_value (key, secret_key);
    zconfig_save (root, "secret.key");
    zconfig_destroy (&root);
    
    //  Reset process file create mask
    zfile_mode_default ();
    
    free (public_key);
    free (secret_key);
    return 0;
}


//  --------------------------------------------------------------------------
//  Constructor, load key pair from disk; returns NULL if the operation
//  failed for any reason.

curvezmq_keypair_t *
curvezmq_keypair_load (void)
{
    curvezmq_keypair_t *self = 
        (curvezmq_keypair_t *) zmalloc (sizeof (curvezmq_keypair_t));
        
    int matches = 0;            //  How many key octets we parsed
    zconfig_t *root = zconfig_load ("secret.key");
    if (root) {
        char *secret_key = zconfig_resolve (root, "secret-key", NULL);
        if (secret_key) {
            int byte_nbr;
            for (byte_nbr = 0; byte_nbr < 32; byte_nbr++)
                matches += sscanf (secret_key + byte_nbr * 2, "%02hhX ", &self->secret_key [byte_nbr]);
        }
        char *public_key = zconfig_resolve (root, "public-key", NULL);
        if (public_key) {
            int byte_nbr;
            for (byte_nbr = 0; byte_nbr < 32; byte_nbr++)
                matches += sscanf (public_key + byte_nbr * 2, "%02hhX ", &self->public_key [byte_nbr]);
        }
    }
    if (matches != 64)
        curvezmq_keypair_destroy (&self);
    zconfig_destroy (&root);
    return self;
}


//  --------------------------------------------------------------------------
//  Return public part of key pair

byte *
curvezmq_keypair_public (curvezmq_keypair_t *self)
{
    assert (self);
    return self->public_key;
}
    

//  --------------------------------------------------------------------------
//  Return secret part of key pair

byte *
curvezmq_keypair_secret (curvezmq_keypair_t *self)
{
    assert (self);
    return self->secret_key;
}


//  --------------------------------------------------------------------------
//  Selftest

void
curvezmq_keypair_test (bool verbose)
{
    printf (" * curvezmq_keypair: ");

    //  @selftest
    //  Generate new long-term key pair for our test server
    //  The key pair will be stored in "secret.key"
    curvezmq_keypair_t *keypair = curvezmq_keypair_new ();
    int rc = curvezmq_keypair_save (keypair);
    assert (rc == 0);
    assert (zfile_exists ("secret.key"));
    assert (curvezmq_keypair_secret (keypair));
    assert (curvezmq_keypair_public (keypair));
    curvezmq_keypair_destroy (&keypair);
    //  Done, clean-up
    zfile_delete ("public.key");
    zfile_delete ("secret.key");
    //  @end
    
    printf ("OK\n");
}
