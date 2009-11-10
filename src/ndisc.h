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

/* $Id: ndisc.h 1.13 04/09/20 12:47:39+03:00 vnuorval@tcs.hut.fi $ */

/**
 * \file ndisc.h
 * \brief IPv6 neighbor discovery.
 */

#ifndef __NDISC_H__
#define __NDISC_H__

#include <net/if_arp.h>

#ifndef ARPHRD_IEEE80211
#define ARPHRD_IEEE80211 801 /**< 802.11 type */
#endif

/**
 * \brief Get L2 address (MAC address) length of an address type.
 * \param iface_type type of an address
 * \return length of L2 address
 */
static inline short nd_get_l2addr_len(unsigned short iface_type)
{
  switch(iface_type)
  {
      /* supported physical devices */
    case ARPHRD_ETHER:
    case ARPHRD_IEEE802:
      /*  case ARPHRD_IEEE802_TR: */
    case ARPHRD_IEEE80211:
      /*  case ARPHRD_FDDI: */
      return 6;
#if 0
    case ARPHRD_ARCNET:
      return 1;
      /* supported virtual devices */
    case ARPHRD_SIT:
    case ARPHRD_TUNNEL6:
    case ARPHRD_PPP:
    case ARPHRD_IPGRE:
      return 0;
#endif
    default:
      /* unsupported */
      return -1;
  }
}

/**
 * \brief Send Neighbor Advertisement.
 * \param ifindex output interface index
 * \param src source address
 * \param dst destination address
 * \param target target IPv6 address
 * \param flags NA flags
 * \return 0 if success, -1 otherwise
 */
int ndisc_send_na(int ifindex, const struct in6_addr *src,
                  const struct in6_addr *dst,
                  const struct in6_addr *target, uint32_t flags);

#endif /* __NDISC_H__ */

