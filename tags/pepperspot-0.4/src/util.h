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

/* $Id: util.h 1.54 06/02/22 16:21:55+02:00 anttit@tcs.hut.fi $ */

/**
 * \file util.h
 * \brief "Util" functions.
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/uio.h>

/* For emission and reception distinction */
#ifndef IPV6_RECVHOPLIMIT
#define IPV6_RECVHOPLIMIT IPV6_HOPLIMIT /**< IPv6 socket option to get/set hop limit value */
#endif

#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO /**< IPv6 socket option to receive packet information */
#endif

/**
 * \def IN6ADDR_ALL_NODES_MC_INIT
 * \brief All nodes multicast address (FF02::1).
 */
#define IN6ADDR_ALL_NODES_MC_INIT \
  { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1 } } }

/**
 * \def IN6ADDR_ALL_ROUTERS_MC_INIT
 * \brief All routers multicast address (FF02::2).
 */
#define IN6ADDR_ALL_ROUTERS_MC_INIT \
  { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2 } } }

/* Following 4 routines are taken from include/net/ipv6.h */

/**
 * \brief Set an IPv6 address.
 * \param addr address will be build with four other parameters
 * \param w1 first 32 bit of IPv6 address
 * \param w2 second 32 bit of IPv6 address
 * \param w3 third 32 bit of IPv6 address
 * \param w4 last 32 bit of IPv6 address
 */
static inline void ipv6_addr_set(struct in6_addr *addr,
                                 uint32_t w1, uint32_t w2,
                                 uint32_t w3, uint32_t w4)
{
  ((uint32_t*)addr->s6_addr)[0] = w1;
  ((uint32_t*)addr->s6_addr)[1] = w2;
  ((uint32_t*)addr->s6_addr)[2] = w3;
  ((uint32_t*)addr->s6_addr)[3] = w4;
}

/**
 * \brief Build a IPv6 multicast solicited address.
 * \param addr IPv6 address
 * \param solicited Resulting solicited address built from addr
 */
static inline void ipv6_addr_solict_mult(const struct in6_addr *addr,
    struct in6_addr *solicited)
{
  ipv6_addr_set(solicited, htonl(0xFF020000), 0, htonl(0x1),
                htonl(0xFF000000) | ((uint32_t*)addr->s6_addr)[3]);
}

/**
 * \brief Build a link-local address from global address.
 * \param addr Global IPv6 address.
 * \param llocal result link-local address built from addr
 */
static inline void ipv6_addr_llocal(const struct in6_addr *addr,
                                    struct in6_addr *llocal)
{
  ipv6_addr_set(llocal, htonl(0xFE800000), 0,
                ((uint32_t*)addr->s6_addr)[2], ((uint32_t*)addr->s6_addr)[3]);
}

/**
 * \brief Free vector data.
 *
 * Frees an array of iovec data, specified by "iov" with "count"
 * elements.  Does not free actual array, only iov_base.
 * \param iov vector array
 * \param count number of elements in array
 */
static inline void free_iov_data(struct iovec *iov, int count)
{
  int len = count;

  if(iov == NULL) return;
  while(len--)
  {
    if(iov[len].iov_base)
      free(iov[len].iov_base);
  }
}

#endif /* __UTIL_H__ */

