/*
 * PepperSpot -- The Next Generation Captive Portal
 * Copyright (C) 2008, Thibault VANCON and Sebastien VINCENT
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

/*
 * tun6.h - IPv6 tunnel interface declaration
 * $Id: tun6.h 1552 2006-07-04 15:38:38Z remi $
 */

/**
 * \file tun6.h
 * \brief IPv6 tunnel interface (tun).
 */

/***********************************************************************
 *  Copyright (c) 2004-2006 Remi DENIS-COURMONT.                       *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license.         *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               *
 *  See the GNU General Public License for more details.               *
 *                                                                     *
 *  You should have received a copy of the GNU General Public License  *
 *  along with this program; if not, you can get it from:              *
 *  http://www.gnu.org/copyleft/gpl.html                               *
 ***********************************************************************/

#ifndef _TUN6_H
#define _TUN6_H

// #include <stddef.h>                      /* NULL */
// #include <sys/types.h>
// #include <sys/select.h>
#include <net/if.h>                      /* IF_NAMESIZE */
#include <netinet/in.h>                  /* in_addr */

#ifndef IFNAMSIZ
#define IFNAMSIZ             IF_NAMESIZE /**< Maximum interface name size */
#endif

#define TUN6_PACKET_MAX_SIZE        8196 /**< Maximum packet size */

#if __STDC_VERSION__ < 199901L
#ifndef inline
#define inline                           /**< Fake definition of inline for old C version */
#endif

#ifndef restrict 
#define restrict                         /**< Fake definition of restrict for old C version */
#endif
#endif

/* [SV] : do similar struct as tun.h
 * in two word : makes wrapper for the libtun6
 * that match function name of tun.h.
 */

/**
 * \struct tun6_packet_t
 * \brief Describe an IPv6 packet.
 * \author Sebastien VINCENT
 */
struct tun6_packet_t
{
  uint32_t version:4;            /**< Version of IPv6 (always 6) */
  uint32_t traffic_class:8;      /**< Priority field */
  uint32_t flow_label:20;        /**< Flow label for QoS */
  uint16_t payload_length;       /**< Payload length */
  uint8_t  next_header;          /**< Next header (protocol or header extension) */
  uint8_t  hop_limit;            /**< Hop limit (ie TTL) */
  uint8_t  src_addr[16];         /**< IPv6 source address */
  uint8_t  dst_addr[16];         /**< IPv6 destination source address */
};

/**
 * \typedef tun6_t
 * \brief IPv6 tunnel interface information.
 * \struct tun6_t
 * \brief IPv6 tunnel interface information.
 * \author Sebastien VINCENT
 */
typedef struct tun6_t
{
  int fd6;                       /**< File descriptor to IPv6 tun interface */
  int ifindex;                   /**< Interface index */
  struct in6_addr addr6;         /**< Our IPv6 address */
  uint8_t prefixlen;             /**< Prefix length of the IPv6 address (64 by default) */
  int nb_addr6;                  /**< Number of allocated IP addresses */
  int routes6;                   /**< One if we allocated an automatic route */
  char devname6[IFNAMSIZ];       /**< Name of the IPv6 tun device */
  struct tun6 *device;           /**< The tun6 device */
  int (*cb_ind6)(struct tun6_t *this, void *pack, unsigned len); /**< Callback when receiving IPv6 packet */
} tun6_t;

/**
 * \brief Create a tun6_t instance
 * \param this a pointer on a pointer of tun6_t
 * \return 0 if success, -1 otherwise
 * \author Sebastien VINCENT
 */
int tun6_new(struct tun6_t **this);

/**
 * \brief Decapsulate a packet.
 * \param this the tun6_t instance
 * \return number of bytes readen or -1 if error
 * \author Sebastien VINCENT
 */
int tun6_decaps(struct tun6_t *this);

/**
 * \brief Encapsulate a packet.
 * \param this the tun6_t instance
 * \param pack the packet to encapsulate
 * \param len length of the packet
 * \return number of bytes written or -1 if error
 * \author Sebastien VINCENT
 */
int tun6_encaps(struct tun6_t *this, void *pack, unsigned int len);

/**
 * \brief Set an IPv6 address on the interface.
 * \param this the tun6_t instance
 * \param addr IPv6 address to set
 * \param prefixlen prefix length of the address
 * \return 0 if success, -1 otherwise
 * \author Sebastien VINCENT
 */
int tun6_setaddr(struct tun6_t *this, struct in6_addr *addr, uint8_t prefixlen);

/**
 * \brief Set an IPv6 route on the interface.
 * \param this the tun6_t instance
 * \param dst destnation IPv6 address
 * \param gateway gateway for IPv6 destination
 * \param prefixlen prefix length of the address
 * \return 0 if success, -1 otherwise
 * \author Sebastien VINCENT
 */
int tun6_addroute(struct tun6_t *this, struct in6_addr *dst,
                  struct in6_addr *gateway, uint8_t prefixlen);

/**
 * \brief Run script.
 * \param this the tun6_t instance
 * \param script path of the script
 * \return 0 if success, -1 otherwise
 * \author Sebastien VINCENT
 */
int tun6_runscript(struct tun6_t *this, char *script);

/**
 * \brief Free the ressource associated with the tun6_t instance
 * \param this the tun6_t instance
 * \return 0 if success, -1 otherwis
 * \author Sebastien VINCENT
 */
int tun6_free(struct tun6_t *this);

/**
 * \brief Set an IPv6 address on the interface.
 * \param this the tun6_t instance
 * \param cb_ind callbacl when receiving packet
 * \return 0 if success, -1 otherwise
 * \author Sebastien VINCENT
 */
int tun6_set_cb_ind(struct tun6_t *this,
                    int (*cb_ind)(struct tun6_t *this, void *pack, unsigned len));

#endif /* !_TUN6_H */

