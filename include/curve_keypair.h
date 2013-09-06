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

#ifndef __CURVE_KEYPAIR_H_INCLUDED__
#define __CURVE_KEYPAIR_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

//  Opaque class structure
typedef struct _curve_keypair_t curve_keypair_t;

//  @interface
//  Constructor, creates a new public/secret key pair
CZMQ_EXPORT curve_keypair_t *
    curve_keypair_new (void);
//  Constructor, accepts public/secret key pair from caller
CZMQ_EXPORT curve_keypair_t *
    curve_keypair_new_from (byte *public_key, byte *secret_key);

//  Destructor
CZMQ_EXPORT void
    curve_keypair_destroy (curve_keypair_t **self_p);

//  Save key pair to disk
CZMQ_EXPORT int
    curve_keypair_save (curve_keypair_t *self);

//  Constructor, load key pair from disk
CZMQ_EXPORT curve_keypair_t *
    curve_keypair_load (void);

//  Return public part of key pair
CZMQ_EXPORT byte *
    curve_keypair_public (curve_keypair_t *self);

//  Return secret part of key pair
CZMQ_EXPORT byte *
    curve_keypair_secret (curve_keypair_t *self);

//  Self test of this class
void
    curve_keypair_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
