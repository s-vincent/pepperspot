/*
 * PepperSpot -- The Next Generation Captive Portal
 * Copyright (C) 2008,  Thibault Vançon and Sebastien Vincent
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Contact: thibault.vancon@pepperspot.info
 *          sebastien.vincent@pepperspot.info
 */

/**
 * \file md5.h
 * \brief MD5 algorithm.
 */

#ifndef MD5_H
#define MD5_H

#include <stdint.h>

/*
#ifdef __alpha
typedef unsigned int uint32_t;
#else
typedef unsigned long uint32_t;
#endif
*/

/* Documentation taken from RFC 1321 */

/**
 * \struct MD5Context
 * \brief MD5 context.
 *
 * Buffer used for MD5 operations.
 */
struct MD5Context
{
  uint32_t buf[4]; /**< state (ABCD) */
  uint32_t bits[2]; /**< number of bits, modulo 2^64 (lsb first) */
  unsigned char in[64]; /**< Input buffer */
};

/**
 * \brief Initialize MD5 context.
 *
 * Begins an MD5 operation, writing a new context
 * \param context MD5 context
 */
void MD5Init(struct MD5Context *context);

/**
 * \brief MD5 block update operation.
 *
 * Continues an MD5 message-digest operation, processing.
 * another message block, and updating the context.
 * \param context MD5 context
 * \param buf MD5 block
 * \param len length of MD5 block
 */
void MD5Update(struct MD5Context *context, unsigned char const *buf,
               unsigned len);

/**
 * \brief MD5 finalization.
 *
 * Ends an MD5 message-digest operation, writing the
 * the message digest and zeroizing the context.
 * \param digest MD5 digest that will be filled
 * \param context MD5 context
 */
void MD5Final(unsigned char digest[16], struct MD5Context *context);

/**
 * \brief MD5 basic transformation.
 *
 * Transforms state based on block.
 * \param buf state
 * \param in input buffer
 */
void MD5Transform(uint32_t buf[4], uint32_t const in[16]);

/**
 * \brief This is needed to make RSAREF happy on some MS-DOS compilers.
 */
typedef struct MD5Context MD5_CTX;

#endif /* !MD5_H */

