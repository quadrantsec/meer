/*
** Copyright (C) 2018-2023 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2018-2023 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "util-base64.h"

#define ASCII_BLOCK         3
#define B64_BLOCK           4
#define BASE64_TABLE_MAX  122

static inline void DecodeBase64Block(uint8_t ascii[ASCII_BLOCK], uint8_t b64[B64_BLOCK]);
static inline int GetBase64Value(uint8_t c);


/* Base64 character to index conversion table */
/* Characters are mapped as "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" */

static const int b64table[] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                -1, -1, -1, 62, -1, -1, -1, 63, 52, 53,
                                54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
                                -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
                                5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                                15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
                                25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
                                29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
                                39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                                49, 50, 51
                                };


uint32_t DecodeBase64(uint8_t *dest, const uint8_t *src, uint32_t len,
                      int strict)
{
    int val;
    uint32_t padding = 0, numDecoded = 0, bbidx = 0, valid = 1, i;
    uint8_t *dptr = dest;
    uint8_t b64[B64_BLOCK] = { 0,0,0,0 };

    /* Traverse through each alpha-numeric letter in the source array */
    for(i = 0; i < len && src[i] != 0; i++)
        {

            /* Get decimal representation */
            val = GetBase64Value(src[i]);
            if (val < 0)
                {

                    /* Invalid character found, so decoding fails */
                    if (src[i] != '=')
                        {
                            valid = 0;
                            if (strict)
                                {
                                    numDecoded = 0;
                                }
                            break;
                        }
                    padding++;
                }

            /* For each alpha-numeric letter in the source array, find the numeric
             * value */
            b64[bbidx++] = (val > 0 ? val : 0);

            /* Decode every 4 base64 bytes into 3 ascii bytes */
            if (bbidx == B64_BLOCK)
                {

                    /* For every 4 bytes, add 3 bytes but deduct the '=' padded blocks */
                    numDecoded += ASCII_BLOCK - (padding < B64_BLOCK ?
                                                 padding : ASCII_BLOCK);

                    /* Decode base-64 block into ascii block and move pointer */
                    DecodeBase64Block(dptr, b64);
                    dptr += ASCII_BLOCK;

                    /* Reset base-64 block and index */
                    bbidx = 0;
                    padding = 0;
                }
        }

    /* Finish remaining b64 bytes by padding */
    if (valid && bbidx > 0)
        {

            /* Decode remaining */
            numDecoded += ASCII_BLOCK - (B64_BLOCK - bbidx);
            DecodeBase64Block(dptr, b64);
        }

//    if (numDecoded == 0) {
//        SCLogDebug("base64 decoding failed");
//    }

    return numDecoded;
}


static inline int GetBase64Value(uint8_t c)
{
    int val = -1;

    /* Pull from conversion table */
    if (c <= BASE64_TABLE_MAX)
        {
            val = b64table[(int) c];
        }

    return val;
}

static inline void DecodeBase64Block(uint8_t ascii[ASCII_BLOCK], uint8_t b64[B64_BLOCK])
{
    ascii[0] = (uint8_t) (b64[0] << 2) | (b64[1] >> 4);
    ascii[1] = (uint8_t) (b64[1] << 4) | (b64[2] >> 2);
    ascii[2] = (uint8_t) (b64[2] << 6) | (b64[3]);
}

