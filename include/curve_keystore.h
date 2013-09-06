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

#ifndef __CURVE_KEYSTORE_H_INCLUDED__
#define __CURVE_KEYSTORE_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

//  Opaque class structure
typedef struct _curve_keystore_t curve_keystore_t;

//  @interface
//  Constructor, creates a new, empty keystore in memory
CZMQ_EXPORT curve_keystore_t *
    curve_keystore_new (void);
    
//  Destructor
CZMQ_EXPORT void
    curve_keystore_destroy (curve_keystore_t **self_p);

//  Load keystore data from disk. Returns zero if OK, -1 on error.
CZMQ_EXPORT int
    curve_keystore_load (curve_keystore_t *self, char *filename);
    
//  Save keystore to disk, overwriting any file with the same name.
//  Returns zero if OK, -1 on error.
CZMQ_EXPORT int
    curve_keystore_save (curve_keystore_t *self, char *filename);

//  Put a keypair into the keystore indexed by some chosen key name.
CZMQ_EXPORT void
    curve_keystore_put (curve_keystore_t *self, char *name, 
                        curve_keypair_t *keypair);

//  Get a keypair from the keystore; returns a valid keypair, or
//  NULL if the key name did not exist.
CZMQ_EXPORT curve_keypair_t *
    curve_keystore_get (curve_keystore_t *self, char *name);

//  Self test of this class
void
    curve_keystore_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
