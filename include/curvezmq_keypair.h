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

#ifndef __CURVEZMQ_KEYPAIR_H_INCLUDED__
#define __CURVEZMQ_KEYPAIR_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

//  Opaque class structure
typedef struct _curvezmq_keypair_t curvezmq_keypair_t;

//  @interface
//  Constructor, creates a new public/secret key pair
CZMQ_EXPORT curvezmq_keypair_t *
    curvezmq_keypair_new (void);
    
//  Destructor
CZMQ_EXPORT void
    curvezmq_keypair_destroy (curvezmq_keypair_t **self_p);

//  Save key pair to disk
CZMQ_EXPORT int
    curvezmq_keypair_save (curvezmq_keypair_t *self);

//  Constructor, load key pair from disk
CZMQ_EXPORT curvezmq_keypair_t *
    curvezmq_keypair_load (void);

//  Return public part of key pair
CZMQ_EXPORT byte *
    curvezmq_keypair_public (curvezmq_keypair_t *self);
    
//  Return secret part of key pair
CZMQ_EXPORT byte *
    curvezmq_keypair_secret (curvezmq_keypair_t *self);
    
//  Self test of this class
void
    curvezmq_keypair_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
