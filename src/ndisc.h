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
 * Contact: thibault.vancon@eturs.u-strasbg.fr
 *          vincent@lsiit.u-strasbg.fr
 *
 * You can find a Copy of this license in the LICENSE file
 */

/* $Id: ndisc.h 1.13 04/09/20 12:47:39+03:00 vnuorval@tcs.hut.fi $ */

#ifndef __NDISC_H__
#define __NDISC_H__ 1

#include <net/if_arp.h>

#define DAD_TIMEOUT 1 /* one second */

static inline short nd_get_l2addr_len(unsigned short iface_type)
{
	switch (iface_type) {
		/* supported physical devices */
	case ARPHRD_ETHER:
	case ARPHRD_IEEE802:
	case ARPHRD_IEEE802_TR:
	case ARPHRD_IEEE80211:
	case ARPHRD_FDDI:
		return 6;
	case ARPHRD_ARCNET:
		return 1;
		/* supported virtual devices */
	case ARPHRD_SIT:
	case ARPHRD_TUNNEL6:
	case ARPHRD_PPP:
	case ARPHRD_IPGRE:
		return 0;
	default:
		/* unsupported */
		return -1;
	}
}

int ndisc_do_dad(int ifi, struct in6_addr *addr, int ll);

int ndisc_send_rs(int ifindex, const struct in6_addr *src,
		  const struct in6_addr *dst);

int ndisc_send_ns(int ifindex, const struct in6_addr *src, 
		  const struct in6_addr *dst,
		  const struct in6_addr *target);

int ndisc_send_na(int ifindex, const struct in6_addr *src, 
		  const struct in6_addr *dst,
		  const struct in6_addr *target, uint32_t flags);

int proxy_nd_start(int ifindex, struct in6_addr *target, 
		   struct in6_addr *src, int bu_flags);

void proxy_nd_stop(int ifindex, struct in6_addr *target, int bu_flags);

int neigh_add(int ifindex, uint16_t state, uint8_t flags,
	      struct in6_addr *dst, uint8_t *hwa, int hwalen,
	      int override);

int neigh_del(int ifindex, struct in6_addr *dst);

int pneigh_add(int ifindex, uint8_t flags, struct in6_addr *dst);

int pneigh_del(int ifindex, struct in6_addr *dst);


#endif
