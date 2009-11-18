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
 * IP address pool functions.
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
 * Copyright (C) 2003, 2004 Mondru AB.
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

/**
 * \file ippool.h
 * \brief IPv4 and IPv6 address pool
 */

#ifndef _IPPOOL_H
#define _IPPOOL_H

/* Assuming that the address space is fragmented we need a hash table
   in order to return the addresses.

   The list pool should provide for both IPv4 and IPv6 addresses.

   When initialising a new address pool it should be possible to pass
   a string of CIDR format networks: "10.0.0.0/24 10.15.0.0/20" would
   translate to 256 addresses starting at 10.0.0.0 and 1024 addresses
   starting at 10.15.0.0.

   The above also applies to IPv6 which can be specified as described
   in RFC2373.
 */

#define IPPOOL_NONETWORK   0x01 /**< Flags for ippool_new() */
#define IPPOOL_NOBROADCAST 0x02 /**< Flags for ippool_new() */
#define IPPOOL_NOGATEWAY   0x04 /**< Flags for ippool_new() */

#define IPPOOL_STATSIZE 0x10000 /**< default pool's static addresses size */

struct ippoolm_t;                /* Forward declaration */

/**
 * \struct ippool_t
 * \brief Pool of IPv4/IPv6 addresses.
 */
struct ippool_t
{
  int listsize;                  /**< Total number of addresses */
  int allowdyn;                  /**< Allow dynamic IP address allocation */
  int allowstat;                 /**< Allow static IP address allocation */
  struct in_addr stataddr;       /**< Static address range network address */
  struct in_addr statmask;       /**< Static address range network mask */
  struct ippoolm_t *member;      /**< Listsize array of members */
  int hashsize;                  /**< Size of hash table */
  int hashlog;                   /**< Log2 size of hash table */
  int hashmask;                  /**< Bitmask for calculating hash */
  struct ippoolm_t **hash;       /**< Hashsize array of pointer to member */
  struct ippoolm_t *firstdyn;    /**< Pointer to first free dynamic member */
  struct ippoolm_t *lastdyn;     /**< Pointer to last free dynamic member */
  struct ippoolm_t *firststat;   /**< Pointer to first free static member */
  struct ippoolm_t *laststat;    /**< Pointer to last free static member */
  struct ippoolm_t *firstipv6;   /**< Pointer to the first IPv6 member */
  struct ippoolm_t *lastipv6;    /**< Pointer to the first IPv6 member */
};

/**
 * \struct ippoolm_t
 * \brief Member of poool.
 */
struct ippoolm_t
{
  struct in_addr addr;           /**< IP address of this member */
  struct in6_addr addrv6;        /**< IPv6 address of this member */
  int inuse;                     /**< 0=available; 1= dynamic; 2 = static */
  struct ippoolm_t *nexthash;    /**< Linked list part of hash table */
  struct ippoolm_t *prev;        /**< Previous member from linked list of free dynamic or static */
  struct ippoolm_t *next;        /**< Next member from linked list of free dynamic or static */
  void *peer;                    /**< Pointer to peer protocol handler */
};

/* The above structures require approximately 20 + 4 = 24 bytes for
   each address (IPv4). For IPv6 the corresponding value is 32 + 4 = 36
   bytes for each address. */

/**
 * \brief Hash an IP address using code based on Bob Jenkins lookup.
 * \param addr IPv4 address
 * \return hash
 */
unsigned long int ippool_hash4(struct in_addr *addr);

/**
 * \brief Create new address pool.
 * \param this resulting pool will be stored in this variable
 * \param dyn
 * \param stat
 * \param allowdyn allow or not dynamic distribution of IPv4
 * \param allowstat allow static IPv4 attribution
 * \param flags flags (IPPOOL_NONETWORK, IPPOOL_NOGATEWAY or IPPOOL_NOBROADCAST)
 * \return 0 if success, -1 otherwise
 */
int ippool_new(struct ippool_t **this, char *dyn,  char *stat,
               int allowdyn, int allowstat, int flags);

/**
 * \brief Delete existing address pool.
 * \param this ippool_t instance
 * \return 0
 */
int ippool_free(struct ippool_t *this);

/**
 * \brief Find an IPv4 address in the pool
 * \param this ippool_t instance
 * \param member if found its pointer will be put in this variable
 * \param addr IPv4 address to found
 * \return 0 if found, -1 otherwise
 */
int ippool_getip(struct ippool_t *this, struct ippoolm_t **member,
                 struct in_addr *addr);

/**
 * \brief Get an IP address. If addr = 0.0.0.0 get a dynamic IP address. Otherwise
 *  check to see if the given address is available
 * \param this ippool_t instance
 * \param member if found its pointer will be put in this variable
 * \param addr IPv4 address to found
 * \param statip static IPv4 or not
 * \return 0 if found, -1 otherwise
 */
int ippool_newip(struct ippool_t *this, struct ippoolm_t **member,
                 struct in_addr *addr, int statip);

/**
 * \brief Allocate a new IPv6 address.
 * \param this the ippool_t instance
 * \param member pointer that will receive the new allocated member
 * \param addr the IPv6 address
 * \return 0 if success, -1 otherwise
 */
int ippool_newip6(struct ippool_t* this, struct ippoolm_t** member, struct in6_addr* addr);

/**
 * Release a previously allocated IP address.
 * \param this ippool_t instance
 * \param member member to release
 * \return 0 if found and release, -1 otherwise
 */
int ippool_freeip(struct ippool_t *this, struct ippoolm_t *member);

/**
 * \brief Get network and mask based on ascii string (i.e 192.168.0.0/24).
 * \param addr IPv4 network address that will be filled in success
 * \param mask IPv4 network mask that will be filled in success
 * \param pool ascii IPv4 network address and mask (i.e. 192.168.0.0/24)
 * \param number not used
 * \return 0 if success, -1 otherwise
 */
int ippool_aton(struct in_addr *addr, struct in_addr *mask,
                char *pool, int number);

/**
 * \brief Get network and prefix based on ascii string (i.e 2001:db8::/64).
 * \param prefix IPv6 network address that will be filled in success
 * \param prefixlen IPv6 prefix length (in bit) will be filled in success
 * \param mask IPv6 network mask that will be filled in success
 * \param pool ascii IPv6 network address and mask (i.e. 2001:db8::/64)
 * \return 0 if success, -1 otherwise
 */
int ippool_atonv6(struct in6_addr *prefix, int *prefixlen,  int *mask,
                  char *pool);

/**
 * \brief Get IPv6 suffix from an IPv6 address.
 * \param suffix result will be put in this variable
 * \param addr IPv6 address
 * \param mask prefix length (in bit)
 */
void ippool_getv6suffix(struct in6_addr *suffix, struct in6_addr *addr, int mask);

/**
 * \brief Hash an IPv6 address using code based on Bob Jenkins lookup.
 * \param addr IPv6 address
 * \return hash
 */
unsigned long int ippool_hash6(struct in6_addr *addr);

/**
 * \brief Find an IPv6 address in the pool
 * \param this ippool_t instance
 * \param member if found its pointer will be put in this variable
 * \param addr IPv6 address to found
 * \return 0 if found, -1 otherwise
 */
int ippool_getip6(struct ippool_t *this, struct ippoolm_t **member, struct in6_addr *addr);

/**
 * \brief Hash and add an IPv6 member.
 * \param this ippool_t instance
 * \param member IPv6 member
 * \return 0
 */
int ippool_hashadd(struct ippool_t *this, struct ippoolm_t *member);

/**
 * \brief Hash and add an IPv4 member.
 * \param this ippool_t instance
 * \param member IPv4 member
 * \return 0
 */
int ippool_hashadd6(struct ippool_t *this, struct ippoolm_t *member);

/**
 * \brief Remove an IPv4 member.
 * \param this ippool_t instance
 * \param member IPv4 member
 * \return 0
 */
int ippool_hashdel(struct ippool_t *this, struct ippoolm_t *member);

/**
 * \brief Remove an IPv6 member.
 * \param this ippool_t instance
 * \param member IPv6 member
 * \return 0
 */
int ippool_hashdel6(struct ippool_t *this, struct ippoolm_t *member);

#endif  /* !_IPPOOL_H */

