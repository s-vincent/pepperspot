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
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

/**
 * \file ippool.c
 * \brief IPv4 and IPv6 address pool
 */

#include <sys/types.h>
#include <netinet/in.h> /* in_addr */
#include <stdlib.h>     /* calloc */
#include <stdio.h>      /* sscanf */
#include <syslog.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "syserr.h"
#include "ippool.h"
#include "lookup.h"

/**
 * \brief Print all addresses from the pool.
 * \param this ippool_t instance
 * \return 0
 */
static int ippool_printaddr(struct ippool_t *this)
{
  int n = 0;
  char buf[INET_ADDRSTRLEN];

  printf("Firstdyn %d\n", this->firstdyn - this->member);
  printf("Lastdyn %d\n",  this->lastdyn - this->member);
  printf("Firststat %d\n", this->firststat - this->member);
  printf("Laststat %d\n",  this->laststat - this->member);
  printf("Listsize %d\n",  this->listsize);

  for(n = 0; n < this->listsize; n++)
  {
    printf("Unit %d inuse %d prev %d next %d addr %s %x\n",
           n,
           this->member[n].inuse,
           this->member[n].prev - this->member,
           this->member[n].next - this->member,
           inet_ntop(AF_INET, &this->member[n].addr, buf, sizeof(buf)),
           this->member[n].addr.s_addr
          );
  }
  return 0;
}

int ippool_hashadd6(struct ippool_t *this, struct ippoolm_t *member)
{
  uint32_t hash = 0;
  struct ippoolm_t *p = NULL;
  struct ippoolm_t *p_prev = NULL;

  /* Insert into hash table */
  hash = ippool_hash6(&member->addrv6) & this->hashmask;
  for(p = this->hash[hash]; p; p = p->nexthash)
  {
    p_prev = p;
  }
  if(!p_prev)
  {
    this->hash[hash] = member;
  }
  else
  {
    p_prev->nexthash = member;
  }
  return 0; /* Always OK to insert */
}

int ippool_hashadd(struct ippool_t *this, struct ippoolm_t *member)
{
  uint32_t hash = 0;
  struct ippoolm_t *p = NULL;
  struct ippoolm_t *p_prev = NULL;

  /* Insert into hash table */
  hash = ippool_hash4(&member->addr) & this->hashmask;
  for(p = this->hash[hash]; p; p = p->nexthash)
    p_prev = p;
  if(!p_prev)
    this->hash[hash] = member;
  else
    p_prev->nexthash = member;
  return 0; /* Always OK to insert */
}

int ippool_hashdel6(struct ippool_t *this, struct ippoolm_t *member)
{
  uint32_t hash = 0;
  struct ippoolm_t *p = NULL;
  struct ippoolm_t *p_prev = NULL;

  /* Find in hash table */
  hash = ippool_hash6(&member->addrv6) & this->hashmask;
  for(p = this->hash[hash]; p; p = p->nexthash)
  {
    if(p == member)
    {
      break;
    }
    p_prev = p;
  }

  if(p!= member)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "ippool_hashdel: Tried to delete member not in hash table");
    return -1;
  }

  if(!p_prev)
    this->hash[hash] = p->nexthash;
  else
    p_prev->nexthash = p->nexthash;

  return 0;
}

int ippool_hashdel(struct ippool_t *this, struct ippoolm_t *member)
{
  uint32_t hash = 0;
  struct ippoolm_t *p = NULL;
  struct ippoolm_t *p_prev = NULL;

  /* Find in hash table */
  hash = ippool_hash4(&member->addr) & this->hashmask;
  for(p = this->hash[hash]; p; p = p->nexthash)
  {
    if(p == member)
    {
      break;
    }
    p_prev = p;
  }

  if(p!= member)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "ippool_hashdel: Tried to delete member not in hash table");
    return -1;
  }

  if(!p_prev)
    this->hash[hash] = p->nexthash;
  else
    p_prev->nexthash = p->nexthash;

  return 0;
}

unsigned long int ippool_hash4(struct in_addr *addr)
{
  return lookup((unsigned char*) &addr->s_addr, sizeof(addr->s_addr), 0);
}

unsigned long int ippool_hash6(struct in6_addr *addr)
{
  return lookup((unsigned char*) &addr->s6_addr, sizeof(addr->s6_addr), 0);
}

void ippool_getv6suffix(struct in6_addr *suffix, struct in6_addr *addr, int mask)
{
  uint32_t val[4];
  int i = 0;

  if(mask <= 32)
  {
    val[0] = 0xffffffff >> (32 - mask);
    val[1] = 0x00000000;
    val[2] = 0x00000000;
    val[3] = 0x00000000;
  }
  else if(mask <= 64)
  {
    val[0] = 0xffffffff;
    val[1] = 0xffffffff >> (64 - mask);
    val[2] = 0x00000000;
    val[3] = 0x00000000;
  }
  else if(mask <= 96)
  {
    val[0] = 0xffffffff;
    val[1] = 0xffffffff;
    val[2] = 0xffffffff >> (96 - mask);
    val[3] = 0x00000000;
  }
  else
  {
    val[0] = 0xffffffff;
    val[1] = 0xffffffff;
    val[2] = 0xffffffff;
    val[3] = 0xffffffff >> (128 - mask);
  }

  for(i = 0; i < 4; i++)
  {
    ((uint32_t*)suffix->s6_addr)[i] = ((uint32_t*)addr->s6_addr)[i] & ~val[i];
  }
}

/* Get IP address and mask */
int ippool_aton(struct in_addr *addr, struct in_addr *mask,
                char *pool, int number)
{
  /* Parse only first instance of network for now */
  /* Eventually "number" will indicate the token which we want to parse */

  unsigned int a1, a2, a3, a4;
  unsigned int m1, m2, m3, m4;
  int c = 0;
  int m = 0;
  int masklog = 0;

  /* To avoid unused parameter warning */
  number = 0;

  c = sscanf(pool, "%u.%u.%u.%u/%u.%u.%u.%u",
             &a1, &a2, &a3, &a4,
             &m1, &m2, &m3, &m4);
  switch(c)
  {
    case 4:
      mask->s_addr = 0xffffffff;
      break;
    case 5:
      if(m1 > 32)
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Invalid mask");
        return -1; /* Invalid mask */
      }
      mask->s_addr = htonl(0xffffffff << (32 - m1));
      break;
    case 8:
      if(m1 >= 256 ||  m2 >= 256 || m3 >= 256 || m4 >= 256)
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Invalid mask");
        return -1; /* Wrong mask format */
      }
      m = m1 * 0x1000000 + m2 * 0x10000 + m3 * 0x100 + m4;
      for(masklog = 0; ((1 << masklog) < ((~m) + 1)); masklog++);
      if(((~m) + 1) != (1 << masklog))
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Invalid mask");
        return -1; /* Wrong mask format (not all ones followed by all zeros)*/
      }
      mask->s_addr = htonl(m);
      break;
    default:
      sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Invalid mask");
      return -1; /* Invalid mask */
  }

  if(a1 >= 256 ||  a2 >= 256 || a3 >= 256 || a4 >= 256)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Wrong IP address format");
    return -1;
  }
  else
    addr->s_addr = htonl(a1 * 0x1000000 + a2 * 0x10000 + a3 * 0x100 + a4);

  return 0;
}

/* Get IPv6 prefix and mask */
int ippool_atonv6(struct in6_addr *prefix, int *prefixlen,  int *mask,
                  char *pool)
{
  char *addr = NULL;
  char *ptr = NULL;
  unsigned int m = 0;

  addr = strtok_r(pool, "/", &ptr);
  m = strtol(ptr, NULL, 10);

  if(addr == NULL || ptr == NULL)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Invalid format for prefix");
    return -1; /* Invalid Format */
  }

  if(inet_pton(AF_INET6, addr, prefix) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Invalid IPv6 prefix");
    return -1; /* Invalid Format */
  }

  *prefixlen = m / 8;
  *mask = m;

  return 0;
}

/* Create new address pool */
int ippool_new(struct ippool_t **this, char *dyn,  char *stat,
               int allowdyn, int allowstat, int flags)
{
  /* Parse only first instance of pool for now */

  int i = 0;
  struct in_addr addr;
  struct in_addr mask;
  struct in_addr stataddr;
  struct in_addr statmask;
  unsigned int m = 0;
  int listsize = 0;
  int dynsize = 0;
  int statsize = 0;
  /* [SV] */
  int ipv6size = 32;

  if(!allowdyn)
  {
    dynsize = 0;
  }
  else
  {
    if(ippool_aton(&addr, &mask, dyn, 0))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Failed to parse dynamic pool");
      return -1;
    }

    /* Set IPPOOL_NONETWORK if IPPOOL_NOGATEWAY is set */
    if(flags & IPPOOL_NOGATEWAY)
    {
      flags |= IPPOOL_NONETWORK;
    }

    m = ntohl(mask.s_addr);
    dynsize = ((~m) + 1);
    if(flags & IPPOOL_NONETWORK)   /* Exclude network address from pool */
      dynsize--;
    if(flags & IPPOOL_NOGATEWAY)   /* Exclude gateway address from pool */
      dynsize--;
    if(flags & IPPOOL_NOBROADCAST) /* Exclude broadcast address from pool */
      dynsize--;
  }

  if(!allowstat)
  {
    statsize = 0;
    stataddr.s_addr = 0;
    statmask.s_addr = 0;
  }
  else
  {
    if(ippool_aton(&stataddr, &statmask, stat, 0))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Failed to parse static range");
      return -1;
    }

    m = ntohl(statmask.s_addr);
    statsize = ((~m) + 1);
    if(statsize > IPPOOL_STATSIZE) statsize = IPPOOL_STATSIZE;
  }

  listsize = dynsize + statsize;  /* Allocate space for static IP addresses */
  listsize = dynsize + statsize + ipv6size; /* 32 IPv6 address */

  if(!(*this = calloc(sizeof(struct ippool_t), 1)))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Failed to allocate memory for ippool");
    return -1;
  }

  (*this)->allowdyn  = allowdyn;
  (*this)->allowstat = allowstat;
  (*this)->stataddr  = stataddr;
  (*this)->statmask  = statmask;

  (*this)->listsize += listsize;
  if(!((*this)->member = calloc(sizeof(struct ippoolm_t), listsize)))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Failed to allocate memory for members in ippool");
    return -1;
  }

  for((*this)->hashlog = 0;
       ((1 << (*this)->hashlog) < listsize);
       (*this)->hashlog++);

  printf("Hashlog %d %d %d\n", (*this)->hashlog, listsize, (1 << (*this)->hashlog));

  /* Determine hashsize */
  (*this)->hashsize = 1 << (*this)->hashlog; /* Fails if mask=0: All Internet*/
  (*this)->hashmask = (*this)->hashsize - 1;

  /* Allocate hash table */
  if(!((*this)->hash = calloc(sizeof(struct ippoolm_t), (*this)->hashsize)))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Failed to allocate memory for hash members in ippool");
    return -1;
  }

  (*this)->firstdyn = NULL;
  (*this)->lastdyn = NULL;

  for(i = 0; i < dynsize; i++)
  {
    if(flags & IPPOOL_NOGATEWAY)
      (*this)->member[i].addr.s_addr = htonl(ntohl(addr.s_addr) + i + 2);
    else if(flags & IPPOOL_NONETWORK)
      (*this)->member[i].addr.s_addr = htonl(ntohl(addr.s_addr) + i + 1);
    else
      (*this)->member[i].addr.s_addr = htonl(ntohl(addr.s_addr) + i);

    (*this)->member[i].inuse = 0;
    memset(&(*this)->member[i].addrv6, 0x00, sizeof(struct in6_addr));

    /* Insert into list of unused */
    (*this)->member[i].prev = (*this)->lastdyn;
    if((*this)->lastdyn)
    {
      (*this)->lastdyn->next = &((*this)->member[i]);
    }
    else
    {
      (*this)->firstdyn = &((*this)->member[i]);
    }
    (*this)->lastdyn = &((*this)->member[i]);
    (*this)->member[i].next = NULL; /* Redundant */

    ( void)ippool_hashadd(*this, &(*this)->member[i]);
  }

  (*this)->firststat = NULL;
  (*this)->laststat = NULL;
  for(i = dynsize; i < (listsize - ipv6size); i++)
  {
    (*this)->member[i].addr.s_addr = 0;
    (*this)->member[i].inuse = 0;
    memset(&(*this)->member[i].addrv6, 0x00, sizeof(struct in6_addr));

    /* Insert into list of unused */
    (*this)->member[i].prev = (*this)->laststat;
    if((*this)->laststat)
    {
      (*this)->laststat->next = &((*this)->member[i]);
    }
    else
    {
      (*this)->firststat = &((*this)->member[i]);
    }
    (*this)->laststat = &((*this)->member[i]);
    (*this)->member[i].next = NULL; /* Redundant */
  }

  (*this)->firstipv6 = NULL;
  (*this)->lastipv6 = NULL;
  for(i = (statsize + dynsize); i < listsize; i++)
  {
    (*this)->member[i].addr.s_addr = 0;
    (*this)->member[i].inuse = 0;
    memset(&(*this)->member[i].addrv6, 0x00, sizeof(struct in6_addr));

    /* Insert into list of unused */
    (*this)->member[i].prev = (*this)->lastipv6;
    if((*this)->lastipv6)
    {
      (*this)->lastipv6->next = &((*this)->member[i]);
    }
    else
    {
      (*this)->firstipv6 = &((*this)->member[i]);
    }
    (*this)->lastipv6 = &((*this)->member[i]);
    (*this)->member[i].next = NULL;
  }

  if(0) (void)ippool_printaddr(*this);
  return 0;
}

/* Delete existing address pool */
int ippool_free(struct ippool_t *this)
{
  free(this->hash);
  free(this->member);
  free(this);
  return 0; /* Always OK */
}

/* Find an IP address in the pool */
int ippool_getip6(struct ippool_t *this, struct ippoolm_t **member, struct in6_addr *addr)
{
  struct ippoolm_t *p = NULL;
  uint32_t hash = 0;

  /* Find in hash table */
  hash = ippool_hash6(addr) & this->hashmask;
  for(p = this->hash[hash]; p; p = p->nexthash)
  {
    char buf[INET6_ADDRSTRLEN];
    printf("compare with %s\n", inet_ntop(AF_INET6, &p->addrv6, buf, sizeof(buf)));
    if(IN6_ARE_ADDR_EQUAL(&p->addrv6, addr) && (p->inuse))
    {
      if(member) *member = p;
      return 0;
    }
  }
  if(member) *member = NULL;
  /*sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Address could not be found");*/
  return -1;
}

/* Find an IP address in the pool */
int ippool_getip(struct ippool_t *this, struct ippoolm_t **member,
                 struct in_addr *addr)
{
  struct ippoolm_t *p = NULL;
  uint32_t hash = 0;

  /* Find in hash table */
  hash = ippool_hash4(addr) & this->hashmask;
  for(p = this->hash[hash]; p; p = p->nexthash)
  {
    if((p->addr.s_addr == addr->s_addr) && (p->inuse))
    {
      if(member) *member = p;
      return 0;
    }
  }
  if(member) *member = NULL;
  /* sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Address could not be found"); */
  return -1;
}

int ippool_newip6(struct ippool_t* this, struct ippoolm_t** member, struct in6_addr* addr)
{
  struct ippoolm_t* p = NULL;
  struct ippoolm_t* p2 = NULL;
  uint32_t hash = 0;

  /* Find in hash table */
  if(addr && !IN6_IS_ADDR_UNSPECIFIED(addr))
  {
    hash = ippool_hash6(addr) & this->hashmask;
    for(p = this->hash[hash]; p; p = p->nexthash)
    {
      if(IN6_ARE_ADDR_EQUAL(&p->addrv6, addr))
      {
        p2 = p;
        break;
      }
    }

    if(p2 || !this->firstipv6)
    {
      printf("!this->firstipv6 || p2");
      return -1; /* address already owned by someone else */
    }

    p2 = this->firstipv6;

    /* Remove from linked list of free static addresses */
    if(p2->prev)
      p2->prev->next = p2->next;
    else
      this->firstipv6 = p2->next;
    if(p2->next)
      p2->next->prev = p2->prev;
    else
      this->lastipv6 = p2->prev;

    p2->next = NULL;
    p2->prev = NULL;
    p2->inuse = 3; /* IPv6 address in use */

    memcpy(&p2->addrv6, addr, sizeof(struct in6_addr));
    *member = p2;
    (void)ippool_hashadd6(this, *member);

    return 0; /* success */
  }
  printf("addrv6 unspec: %p\n", addr);
  return -1;
}

int ippool_newip(struct ippool_t *this, struct ippoolm_t **member,
                 struct in_addr *addr, int statip)
{
  struct ippoolm_t *p = NULL;
  struct ippoolm_t *p2 = NULL;
  uint32_t hash = 0;

  /* If static:
   *   Look in dynaddr.
   *     If found remove from firstdyn/lastdyn linked list.
   *   Else allocate from stataddr.
   *    Remove from firststat/laststat linked list.
   *    Insert into hash table.
   *
   * If dynamic
   *   Remove from firstdyn/lastdyn linked list.
   *
   */

  if(0) (void)ippool_printaddr(this);

  /* First check to see if this type of address is allowed */
  if((addr) && (addr->s_addr) && statip)   /* IP address given */
  {
    if(!this->allowstat)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Static IP address not allowed");
      return -1;
    }
    if((addr->s_addr & this->statmask.s_addr) != this->stataddr.s_addr)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Static out of range");
      return -1;
    }
  }
  else
  {
    if(!this->allowdyn)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Dynamic IP address not allowed");
      return -1;
    }
  }

  /* If IP address given try to find it in dynamic address pool */
  if((addr) && (addr->s_addr))   /* IP address given */
  {
    /* Find in hash table */
    hash = ippool_hash4(addr) & this->hashmask;
    for(p = this->hash[hash]; p; p = p->nexthash)
    {
      if((p->addr.s_addr == addr->s_addr))
      {
        p2 = p;
        break;
      }
    }
  }

  /* If IP was already allocated we can not use it */
  if((!statip) && (p2) && (p2->inuse))
  {
    p2 = NULL;
  }

  /* If not found yet and dynamic IP then allocate dynamic IP */
  if((!p2) && (!statip))
  {
    if(!this ->firstdyn)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "No more IP addresses available");
      return -1;
    }
    else
      p2 = this ->firstdyn;
  }

  if(p2) /* Was allocated from dynamic address pool */
  {
    if(p2->inuse)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "IP address allready in use");
      return -1; /* Allready in use / Should not happen */
    }

    /* Remove from linked list of free dynamic addresses */
    if(p2->prev)
      p2->prev->next = p2->next;
    else
      this->firstdyn = p2->next;
    if(p2->next)
      p2->next->prev = p2->prev;
    else
      this->lastdyn = p2->prev;
    p2->next = NULL;
    p2->prev = NULL;
    p2->inuse = 1; /* Dynamic address in use */

    *member = p2;
    if(0) (void)ippool_printaddr(this);
    return 0; /* Success */
  }

  /* It was not possible to allocate from dynamic address pool */
  /* Try to allocate from static address space */

  if((addr) && (addr->s_addr) && (statip))   /* IP address given */
  {
    if(!this->firststat)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "No more IP addresses available");
      return -1; /* No more available */
    }
    else
      p2 = this ->firststat;

    /* Remove from linked list of free static addresses */
    if(p2->prev)
      p2->prev->next = p2->next;
    else
      this->firststat = p2->next;
    if(p2->next)
      p2->next->prev = p2->prev;
    else
      this->laststat = p2->prev;
    p2->next = NULL;
    p2->prev = NULL;
    p2->inuse = 2; /* Static address in use */
    memcpy(&p2->addr, addr, sizeof(addr));
    *member = p2;
    (void)ippool_hashadd(this, *member);
    if(0) (void)ippool_printaddr(this);
    return 0; /* Success */
  }

  sys_err(LOG_ERR, __FILE__, __LINE__, 0,
          "Could not allocate IP address");
  return -1; /* Should never get here. TODO: Bad code */
}

int ippool_freeip(struct ippool_t *this, struct ippoolm_t *member)
{
  if(0) (void)ippool_printaddr(this);

  if(!member->inuse)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Address not in use");
    return -1; /* Not in use: Should not happen */
  }

  switch(member->inuse)
  {
    case 0: /* Not in use: Should not happen */
      sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Address not in use");
      return -1;
    case 1: /* Allocated from dynamic address space */
      /* Insert into list of unused */
      member->prev = this->lastdyn;
      if(this->lastdyn)
      {
        this->lastdyn->next = member;
      }
      else
      {
        this->firstdyn = member;
      }
      this->lastdyn = member;

      member->inuse = 0;
      member->peer = NULL;
      if(0) (void)ippool_printaddr(this);
      return 0;
    case 2: /* Allocated from static address space */
      if(ippool_hashdel(this, member))
        return -1;
      /* Insert into list of unused */
      member->prev = this->laststat;
      if(this->laststat)
      {
        this->laststat->next = member;
      }
      else
      {
        this->firststat = member;
      }
      this->laststat = member;

      member->inuse = 0;
      member->addr.s_addr = 0;
      member->peer = NULL;
      member->nexthash = NULL;
      if(0) (void)ippool_printaddr(this);
      return 0;
    case 3: /* allocated from IPv6 pool */
      if(ippool_hashdel6(this, member))
        return -1;
      /* Insert into list of unused */
      member->prev = this->lastipv6;
      if(this->lastipv6)
      {
        this->lastipv6->next = member;
      }
      else
      {
        this->firstipv6 = member;
      }
      this->lastipv6 = member;

      member->inuse = 0;
      member->addr.s_addr = 0;
      member->peer = NULL;
      member->nexthash = NULL;
      if(0) (void)ippool_printaddr(this);
      return 0;

    default: /* Should not happen */
      sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Could not free IP address");
      return -1;
  }
}

