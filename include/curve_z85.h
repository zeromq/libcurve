/*  =========================================================================
    curve_z85 - Z85 encoding and decoding, see 0MQ RFC 32

    -------------------------------------------------------------------------
    Copyright (c) the Contributors as noted in the AUTHORS file.
    This file is part of the Curve authentication and encryption library.

    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
    =========================================================================
*/

#ifndef __CURVE_Z85_H_INCLUDED__
#define __CURVE_Z85_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

//  @interface
//  Encode a binary frame as a string; destination string MUST be at least
//  size * 5 / 4 bytes long. Returns dest. Size must be a multiple of 4.
CZMQ_EXPORT char *
    curve_z85_encode (char *dest, uint8_t *data, size_t size);
    
//  Decode an encoded string into a binary frame; dest must be at least
//  strlen (string) * 4 / 5 bytes long. Returns dest. strlen (string) 
//  must be a multiple of 5.
CZMQ_EXPORT uint8_t *
    curve_z85_decode (uint8_t *dest, char *string);
    
//  Self test of this class
CZMQ_EXPORT void
    curve_z85_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
