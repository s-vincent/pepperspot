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
 * \file iphash.c
 * \brief Hash function for IPv4 and IPv6 addresses.
 */

#include <sys/types.h>
#include <netinet/in.h> /* in_addr */
#include <stdlib.h>     /* calloc */
#include <stdio.h>      /* sscanf */

#include "iphash.h"

/* Create new address pool hash */
int iphash_new(struct ippool_t **this, struct ippoolm_t *list, int listsize)
{
  int i = 0;

  if(!(*this = calloc(sizeof(struct ippool_t), 1)))
  {
    /* Failed to allocate memory for iphash */
    return -1;
  }

  (*this)->listsize = listsize;
  (*this)->member = list;

  /* Determine log2 of hashsize */
  for((*this)->hashlog = 0;
       ((1 << (*this)->hashlog) < listsize);
       (*this)->hashlog++);

  /* Determine hashsize */
  (*this)->hashsize = 1 << (*this)->hashlog; /* Fails if mask=0: All Internet */
  (*this)->hashmask = (*this)->hashsize -1;

  /* Allocate hash table */
  if(!((*this)->hash = calloc(sizeof(struct ippoolm_t), (*this)->hashsize)))
  {
    /* Failed to allocate memory for hash members in iphash */
    return -1;
  }

  for(i = 0; i < listsize; i++)
  {
    (*this)->member[i].inuse = 1; /* TODO */
    ippool_hash_add(*this, &(*this)->member[i]);
  }

  return 0;
}

/* Create new address pool hash */
int iphash_new6(struct ippool_t **this, struct ippoolm_t *list, int listsize)
{
  int i = 0;

  if(!(*this = calloc(sizeof(struct ippool_t), 1)))
  {
    /* Failed to allocate memory for iphash */
    return -1;
  }

  (*this)->listsize = listsize;
  (*this)->member = list;

  /* Determine log2 of hashsize */
  for((*this)->hashlog = 0;
       ((1 << (*this)->hashlog) < listsize);
       (*this)->hashlog++);

  /* Determine hashsize */
  (*this)->hashsize = 1 << (*this)->hashlog; /* Fails if mask=0: All Internet */
  (*this)->hashmask = (*this)->hashsize -1;

  /* Allocate hash table */
  if(!((*this)->hash = calloc(sizeof(struct ippoolm_t), (*this)->hashsize)))
  {
    /* Failed to allocate memory for hash members in iphash */
    return -1;
  }

  for(i = 0; i < listsize; i++)
  {
    (*this)->member[i].inuse = 1; /* TODO */
    ippool_hash_add6(*this, &(*this)->member[i]);
  }

  return 0;
}

/* Delete existing address pool */
int iphash_free(struct ippool_t *this)
{
  free(this->hash);
  free(this);
  return 0; /* Always OK */
}

