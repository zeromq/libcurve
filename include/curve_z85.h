/*  =========================================================================
    curve_z85 - Z85 encoding and decoding, see 0MQ RFC 32

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

#ifndef __CURVE_Z85_H_INCLUDED__
#define __CURVE_Z85_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

//  Opaque class structure
typedef struct _curve_z85_t curve_z85_t;

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
void
    curve_z85_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
