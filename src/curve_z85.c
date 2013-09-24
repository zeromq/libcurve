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

/*
@header
    Provides an API to encode and decode CurveZMQ keys to/from Z85, 
    a text format designed for easier interchange.
@discuss
@end
*/

#include "../include/curve.h"

//  Maps base 256 to base 85
static char encoder [85 + 1] = {
    "0123456789" "abcdefghij" "klmnopqrst" "uvwxyzABCD"
    "EFGHIJKLMN" "OPQRSTUVWX" "YZ.-:+=^!/" "*?&<>()[]{" 
    "}@%$#"
};

//  Maps base 85 to base 256
//  We chop off lower 32 and higher 128 ranges
static uint8_t decoder [96] = {
    0x00, 0x44, 0x00, 0x54, 0x53, 0x52, 0x48, 0x00, 
    0x4B, 0x4C, 0x46, 0x41, 0x00, 0x3F, 0x3E, 0x45, 
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
    0x08, 0x09, 0x40, 0x00, 0x49, 0x42, 0x4A, 0x47, 
    0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 
    0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 
    0x3B, 0x3C, 0x3D, 0x4D, 0x00, 0x4E, 0x43, 0x00, 
    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 
    0x21, 0x22, 0x23, 0x4F, 0x00, 0x50, 0x00, 0x00
};

//  --------------------------------------------------------------------------
//  Encode a binary frame as a string; destination string MUST be at least
//  size * 5 / 4 bytes long plus 1 byte for the null terminator. Returns
//  dest. Size must be a multiple of 4.

char *
curve_z85_encode (char *dest, uint8_t *data, size_t size)
{
    assert (size % 4 == 0);
    unsigned int char_nbr = 0;
    unsigned int byte_nbr = 0;
    uint32_t value = 0;
    while (byte_nbr < size) {
        //  Accumulate value in base 256 (binary)
        value = value * 256 + data [byte_nbr++];
        if (byte_nbr % 4 == 0) {
            //  Output value in base 85
            unsigned int divisor = 85 * 85 * 85 * 85;
            while (divisor) {
                dest [char_nbr++] = encoder [value / divisor % 85];
                divisor /= 85;
            }
            value = 0;
        }
    }
    assert (char_nbr == size * 5 / 4);
    dest [char_nbr] = 0;
    return dest;
}

    
//  --------------------------------------------------------------------------
//  Decode an encoded string into a binary frame; dest must be at least
//  strlen (string) * 4 / 5 bytes long. Returns dest. strlen (string) 
//  must be a multiple of 5.

uint8_t *
curve_z85_decode (uint8_t *dest, char *string)
{
    assert (strlen (string) % 5 == 0);
    unsigned int byte_nbr = 0;
    unsigned int char_nbr = 0;
    uint32_t value = 0;
    while (char_nbr < strlen (string)) {
        //  Accumulate value in base 85
        value = value * 85 + decoder [(uint8_t) string [char_nbr++] - 32];
        if (char_nbr % 5 == 0) {
            //  Output value in base 256
            unsigned int divisor = 256 * 256 * 256;
            while (divisor) {
                dest [byte_nbr++] = value / divisor % 256;
                divisor /= 256;
            }
            value = 0;
        }
    }
    assert (byte_nbr == strlen (string) * 4 / 5);
    return dest;
}



//  --------------------------------------------------------------------------
//  Selftest

void
curve_z85_test (bool verbose)
{
    printf (" * curve_z85: ");

    //  @selftest
    byte test_data_1 [8] = {
        0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B
    };
    byte test_data_2 [32] = {
        0x8E, 0x0B, 0xDD, 0x69, 0x76, 0x28, 0xB9, 0x1D, 
        0x8F, 0x24, 0x55, 0x87, 0xEE, 0x95, 0xC5, 0xB0, 
        0x4D, 0x48, 0x96, 0x3F, 0x79, 0x25, 0x98, 0x77, 
        0xB4, 0x9C, 0xD9, 0x06, 0x3A, 0xEA, 0xD3, 0xB7  
    };
    char encoded [40];
    byte decoded [32];

    curve_z85_encode (encoded, NULL, 0);
    assert (streq (encoded, ""));
    curve_z85_decode (decoded, encoded);
    
    curve_z85_encode (encoded, test_data_1, 8);
    assert (strlen (encoded) == 10);
    assert (streq (encoded, "HelloWorld"));
    curve_z85_decode (decoded, encoded);
    assert (memcmp (test_data_1, decoded, 8) == 0);
    
    curve_z85_encode (encoded, test_data_2, 32);
    assert (strlen (encoded) == 40);
    assert (streq (encoded, "JTKVSB%%)wK0E.X)V>+}o?pNmC{O&4W4b!Ni{Lh6"));
    curve_z85_decode (decoded, encoded);
    assert (memcmp (test_data_2, decoded, 32) == 0);

    //  Standard test keys defined by zmq_curve man page
    byte client_public [32] = { 
        0xBB, 0x88, 0x47, 0x1D, 0x65, 0xE2, 0x65, 0x9B, 
        0x30, 0xC5, 0x5A, 0x53, 0x21, 0xCE, 0xBB, 0x5A, 
        0xAB, 0x2B, 0x70, 0xA3, 0x98, 0x64, 0x5C, 0x26, 
        0xDC, 0xA2, 0xB2, 0xFC, 0xB4, 0x3F, 0xC5, 0x18
    };
    byte client_secret [32] = { 
        0x7B, 0xB8, 0x64, 0xB4, 0x89, 0xAF, 0xA3, 0x67, 
        0x1F, 0xBE, 0x69, 0x10, 0x1F, 0x94, 0xB3, 0x89, 
        0x72, 0xF2, 0x48, 0x16, 0xDF, 0xB0, 0x1B, 0x51, 
        0x65, 0x6B, 0x3F, 0xEC, 0x8D, 0xFD, 0x08, 0x88
    };
    curve_z85_encode (encoded, client_public, 32);
    curve_z85_encode (encoded, client_secret, 32);

    byte server_public [32] = { 
        0x54, 0xFC, 0xBA, 0x24, 0xE9, 0x32, 0x49, 0x96, 
        0x93, 0x16, 0xFB, 0x61, 0x7C, 0x87, 0x2B, 0xB0, 
        0xC1, 0xD1, 0xFF, 0x14, 0x80, 0x04, 0x27, 0xC5, 
        0x94, 0xCB, 0xFA, 0xCF, 0x1B, 0xC2, 0xD6, 0x52
    };
    byte server_secret [32] = { 
        0x8E, 0x0B, 0xDD, 0x69, 0x76, 0x28, 0xB9, 0x1D, 
        0x8F, 0x24, 0x55, 0x87, 0xEE, 0x95, 0xC5, 0xB0, 
        0x4D, 0x48, 0x96, 0x3F, 0x79, 0x25, 0x98, 0x77, 
        0xB4, 0x9C, 0xD9, 0x06, 0x3A, 0xEA, 0xD3, 0xB7
    };
    curve_z85_encode (encoded, server_public, 32);
    curve_z85_encode (encoded, server_secret, 32);
    //  @end
    
    printf ("OK\n");
}
