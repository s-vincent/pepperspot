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

/*
 * TUN interface functions.
 *
 * Copyright (c) 2006, Jens Jakobsen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 *   Neither the names of copyright holders nor the names of its contributors
 *   may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Copyright (C) 2002, 2003, 2004, 2005 Mondru AB.
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

/**
 * \file tun.h
 * \brief IPv4 tunnel interface (tun).
 */

#ifndef _TUN_H
#define _TUN_H

#include <sys/types.h>
#include <net/if.h>
#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE /**< Interface name size */
#endif

#define PACKET_MAX      8196 /**< Maximum packet size we receive */
#define TUN_ADDRSIZE     128 /**< Maximum ascii address size */

#ifdef __linux__
#define TUN_NLBUFSIZE   1024 /**< maximum netlink message size */
#endif

/**
 * \struct tun_packet_t
 * \brief Describe an IPv4 packet.
 */
struct tun_packet_t
{
  unsigned int ver:4; /**< IPv4 version */
  unsigned int ihl:4; /**< Internet header length */
  unsigned int dscp:6; /**< DSCP field */
  unsigned int ecn:2; /**< ECN field */
  unsigned int length:16; /**< Total length */
  unsigned int id:16; /**< ID number */
  unsigned int flags:3; /**< IP flags */
  unsigned int fragment:13; /**< Fragmentation offset */
  unsigned int ttl:8; /**< Time to live */
  unsigned int protocol:8; /**< Up layer protocol number */
  unsigned int check:16; /**< Checksum */
  unsigned int src:32; /**< IPv4 source address */
  unsigned int dst:32; /**< IPv4 destination address */
};

/* ***********************************************************
 * Information storage for each tun_t instance
 *************************************************************/

/**
 * \struct tun_t
 * \brief IPv4 tunnel interface information.
 */
struct tun_t
{
  int fd;                /**< File descriptor to tun interface */
  struct in_addr addr;   /**< Main IPv4 address */
  struct in_addr dstaddr; /**< Destination address */
  struct in_addr netmask; /**< IPv4 Netmask */
  int addrs;             /**< Number of allocated IP addresses */
  int routes;            /**< One if we allocated an automatic route */
  char devname[IFNAMSIZ];/**< Name of the tun device */
  int (*cb_ind) (struct tun_t *tun, void *pack, unsigned len); /**< Callback when receiving packet */
};

/**
 * \brief Create an instance of tun.
 * \param tun resulting pointer will be filled in
 * \return 0 if success, -1 otherwise
 */
int tun_new(struct tun_t **tun);

/**
 * \brief Release a tun interface.
 * \param tun tun_t instance
 * \return 0 if success, -1 otherwise
 */
int tun_free(struct tun_t *tun);

/**
 * \brief Decapsulate packet coming from tun interface.
 * \param this tun_t instance
 * \return 0 if success, -1 otherwise
 */
int tun_decaps(struct tun_t *this);

/**
 * \brief Encapsulate packet coming from tun interface.
 * \param tun tun_t instance
 * \param pack packet
 * \param len packet length
 * \return 0 if success, -1 otherwise
 */
int tun_encaps(struct tun_t *tun, void *pack, unsigned len);

/**
 * \brief Add an address on tun interface.
 * \param this tun_t instance
 * \param addr IPv4 address
 * \param dstaddr IPv4 destination address
 * \param netmask IPv4 network mask
 * \return 0 if success, -1 otherwise
 */
int tun_addaddr(struct tun_t *this, struct in_addr *addr,
                struct in_addr *dstaddr, struct in_addr *netmask);

/**
 * \brief Set address on tun interface
 * \param this tun_t instance
 * \param our_adr our IPv4 address
 * \param his_adr IPv4 address
 * \param net_mask IPv4 network mask
 * \return 0 if success, -1 otherwise
 */
int tun_setaddr(struct tun_t *this, struct in_addr *our_adr,
                struct in_addr *his_adr, struct in_addr *net_mask);

/**
 * \brief Add a route for tun interface
 * \param this tun_t instance
 * \param dst IPv4 destination address
 * \param gateway IPv4 gateway
 * \param mask IPv4 network mask
 * \return 0 if success, -1 otherwise
 */
int tun_addroute(struct tun_t *this, struct in_addr *dst,
                 struct in_addr *gateway, struct in_addr *mask);

/**
 * \brief Set callback for receiving a packet from tun interface
 * \param this tun_t instance
 * \param cb_ind callback
 * \return 0
 */
int tun_set_cb_ind(struct tun_t *this,
                   int (*cb_ind) (struct tun_t *tun, void *pack, unsigned len));

/**
 * \brief Run script.
 * \param tun tun_t instance
 * \param script script pathname
 * \return 0
 */
int tun_runscript(struct tun_t *tun, char* script);

#endif  /* !_TUN_H */

