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
 * Radius client functions.
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
 * \file radius.c
 * \brief RADIUS client.
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h> /* in_addr */
#include <stdlib.h>     /* calloc */
#include <stdio.h>      /* sscanf */
#include <string.h>     /* memcpy */
#include <syslog.h>
#include <sys/time.h>

#include "syserr.h"
#include "radius.h"
#include "md5.h"

/**
 * \brief Print information about radius packet queue.
 * \param this radius_t instance
 * \return 0
 */
static int radius_printqueue(struct radius_t *this)
{
  int n = 0;
  printf("next %d, first %d, last %d\n",
         this->next, this->first, this ->last);

  for(n = 0; n < 256; n++)
  {
    if(this->queue[n].state)
    {
      printf("%3d %3d %3d %3d %8d %8d %d\n",
             n, this->queue[n].state,
             this->queue[n].next,
             this->queue[n].prev,
             (int) this->queue[n].timeout.tv_sec,
             (int) this->queue[n].timeout.tv_usec,
             (int) this->queue[n].retrans);
    }
  }
  return 0;
}

/**
 * \brief Calculate HMAC MD5 on a radius packet.
 * \param this radius_t instance
 * \param pack radius packet
 * \param dst destination buffer
 * \return 0
 */
static int radius_hmac_md5(struct radius_t *this, struct radius_packet_t *pack,
                    uint8_t *dst)
{
  unsigned char digest[RADIUS_MD5LEN];
  int length = 0;

  MD5_CTX context;

  uint8_t *key = NULL;
  int key_len = 0;

  unsigned char k_ipad[65];
  unsigned char k_opad[65];
  unsigned char tk[RADIUS_MD5LEN];
  int i = 0;

  if(this->secretlen > 64)   /* TODO: If Microsoft truncate to 64 instead */
  {
    MD5Init(&context);
    MD5Update(&context, (uint8_t*) this->secret, this->secretlen);
    MD5Final(tk, &context);
    key = tk;
    key_len = 16;
  }
  else
  {
    key = (uint8_t*) this->secret;
    key_len = this->secretlen;
  }

  length = ntohs(pack->length);

  memset(k_ipad, 0x36, sizeof k_ipad);
  memset(k_opad, 0x5c, sizeof k_opad);

  for(i = 0; i < key_len; i++)
  {
    k_ipad[i] ^= key[i];
    k_opad[i] ^= key[i];
  }

  /* Perform inner MD5 */
  MD5Init(&context);
  MD5Update(&context, k_ipad, 64);
  MD5Update(&context, (uint8_t*) pack, length);
  MD5Final(digest, &context);

  /* Perform outer MD5 */
  MD5Init(&context);
  MD5Update(&context, k_opad, 64);
  MD5Update(&context, digest, 16);
  MD5Final(digest, &context);

  memcpy(dst, digest, RADIUS_MD5LEN);

  return 0;
}

/**
 * \brief Update a packet with an accounting request authenticator.
 * \param this radius_t instance
 * \param pack radius packet
 * \return 0
 */
static int radius_acctreq_authenticator(struct radius_t *this,
                                 struct radius_packet_t *pack)
{
  /* From RFC 2866: Authenticator is the MD5 hash of:
     Code + Identifier + Length + 16 zero octets + request attributes +
     shared secret */

  MD5_CTX context;

  memset(pack->authenticator, 0, RADIUS_AUTHLEN);

  /* Get MD5 hash on secret + authenticator */
  MD5Init(&context);
  MD5Update(&context, (void*) pack, ntohs(pack->length));
  MD5Update(&context, (uint8_t*) this->secret, this->secretlen);
  MD5Final(pack->authenticator, &context);

  return 0;
}

/**
 * \brief Update a packet with an authentication response authenticator.
 * \param this radius_t instance
 * \param pack radius packet
 * \param req_auth authenticator
 * \param secret radius secret
 * \param secretlen length of secret
 * \return 0
 */
static int radius_authresp_authenticator(struct radius_t *this,
                                  struct radius_packet_t *pack,
                                  uint8_t *req_auth,
                                  char *secret, int secretlen)
{
  /* From RFC 2865: Authenticator is the MD5 hash of:
     Code + Identifier + Length + request authenticator + request attributes +
     shared secret */

  /* To avoid unused parameter warning */
  this = NULL;

  MD5_CTX context;

  memcpy(pack->authenticator, req_auth, RADIUS_AUTHLEN);

  /* Get MD5 hash on secret + authenticator */
  MD5Init(&context);
  MD5Update(&context, (void*) pack, ntohs(pack->length));
  MD5Update(&context, (uint8_t*) secret, secretlen);
  MD5Final(pack->authenticator, &context);

  return 0;
}

/**
 * \brief Place data in queue for later retransmission.
 * \param this radius_t instance
 * \param pack radius packet
 * \param cbp pointer used with callback
 * \return 0 if success, -1 otherwise
 */
static int radius_queue_in(struct radius_t *this, struct radius_packet_t *pack,
                    void *cbp)
{
  struct timeval *tv = NULL;
  struct radius_attr_t *ma = NULL; /* Message authenticator */

  if(this->debug) printf("radius_queue_in\n");

  if(this->debug)
  {
    printf("radius_queue_in\n");
    radius_printqueue(this);
  }

  if(this->queue[this->next].state == 1)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "radius queue is full!");
    /* Queue is not really full. It only means that the next space
       in queue is not available, but there might be space elsewhere */
    return -1;
  }

  pack->id = this->next;

  /* If packet contains message authenticator: Calculate it! */
  if(!radius_getattr(pack, &ma, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 0, 0, 0))
  {
    radius_hmac_md5(this, pack, ma->v.t);
  }

  /* If accounting request: Calculate authenticator */
  if(pack->code == RADIUS_CODE_ACCOUNTING_REQUEST)
    radius_acctreq_authenticator(this, pack);

  memcpy(&this->queue[this->next].p, pack, RADIUS_PACKSIZE);
  this->queue[this->next].state = 1;
  this->queue[this->next].cbp = cbp;
  this->queue[this->next].retrans = 0;
  tv = &this->queue[this->next].timeout;
  gettimeofday(tv, NULL);
  tv->tv_usec += RADIUS_TIMEOUT;
  tv->tv_sec  += tv->tv_usec / 1000000;
  tv->tv_usec = tv->tv_usec % 1000000;
  this->queue[this->next].lastsent = this->lastreply;

  /* Insert in linked list for handling timeouts */
  this->queue[this->next].next = -1;         /* Last in queue */
  this->queue[this->next].prev = this->last; /* Link to previous */

  if(this->last != -1)
    this->queue[this->last].next = this->next; /* Link previous to us */
  this->last = this->next;                   /* End of queue */

  if(this->first == -1)
    this->first = this->next; /* First and last */

  this->next++; /* next = next % RADIUS_QUEUESIZE */

  if(this->debug)
  {
    printf("radius_queue_in end\n");
    radius_printqueue(this);
  }

  return 0;
}

/**
 * \brief Remove data from queue.
 * \param this radius_t instance
 * \param pack radius packet
 * \param id ID
 * \param cbp pointer to use with callback
 * \return 0 if success, -1 otherwise
 */
static int radius_queue_out(struct radius_t *this, struct radius_packet_t *pack,
                     int id, void **cbp)
{
  if(this->debug) if(this->debug) printf("radius_queue_out\n");

  if(this->queue[id].state != 1)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "No such id in radius queue: %d!", id);
    return -1;
  }

  if(this->debug)
  {
    printf("radius_queue_out\n");
    radius_printqueue(this);
  }

  memcpy(pack, &this->queue[id].p, RADIUS_PACKSIZE);
  *cbp = this->queue[id].cbp;

  this->queue[id].state = 0;

  /* Remove from linked list */
  if(this->queue[id].next == -1) /* Are we the last in queue? */
    this->last = this->queue[id].prev;
  else
    this->queue[this->queue[id].next].prev = this->queue[id].prev;

  if(this->queue[id].prev == -1) /* Are we the first in queue? */
    this->first = this->queue[id].next;
  else
    this->queue[this->queue[id].prev].next = this->queue[id].next;

  if(this->debug)
  {
    printf("radius_queue_out end\n");
    radius_printqueue(this);
  }

  return 0;
}

/**
 * \brief Recalculate the timeout value of a packet in the queue.
 * \param this radius_t instance
 * \param id iD
 * \return 0 if success, -1 otherwise
 */
static int radius_queue_reschedule(struct radius_t *this, int id)
{
  struct timeval *tv = NULL;

  if(this->queue[id].state != 1)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "No such id in radius queue: %d!", id);
    return -1;
  }

  if(this->debug)
  {
    printf("radius_reschedule\n");
    radius_printqueue(this);
  }

  this->queue[id].retrans++;
  tv = &this->queue[id].timeout;
  gettimeofday(tv, NULL);
  tv->tv_usec += RADIUS_TIMEOUT;
  tv->tv_sec  += tv->tv_usec / 1000000;
  tv->tv_usec = tv->tv_usec % 1000000;

  /* Remove from linked list */
  if(this->queue[id].next == -1) /* Are we the last in queue? */
    this->last = this->queue[id].prev;
  else
    this->queue[this->queue[id].next].prev = this->queue[id].prev;

  if(this->queue[id].prev == -1) /* Are we the first in queue? */
    this->first = this->queue[id].next;
  else
    this->queue[this->queue[id].prev].next = this->queue[id].next;

  /* Insert in linked list for handling timeouts */
  this->queue[id].next = -1;         /* Last in queue */
  this->queue[id].prev = this->last; /* Link to previous (could be -1) */

  if(this->last != -1)
    this->queue[this->last].next = id; /* If not empty: link previous to us */
  this->last = id;                   /* End of queue */

  if(this->first == -1)
    this->first = id;                /* First and last */

  if(this->debug)
  {
    radius_printqueue(this);
  }

  return 0;
}

/**
 * \brief Returns an integer less than, equal to or greater than zero if tv1
 * is found, respectively, to be less than, to match or be greater than tv2.
 * \param tv1 first time
 * \param tv2 second time
 * \return an integer less than, equal to or greater than zero if tv1
 * is found, respectively, to be less than, to match or be greater than tv2
 */
static int radius_cmptv(struct timeval *tv1, struct timeval *tv2)
{
  struct timeval diff;

  if(0)
  {
    printf("tv1 %8d %8d tv2 %8d %8d\n",
           (int) tv1->tv_sec, (int) tv1->tv_usec,
           (int) tv2->tv_sec, (int) tv2->tv_usec);
  }

  /* First take the difference with |usec| < 1000000 */
  diff.tv_sec = (tv1->tv_usec  - tv2->tv_usec) / 1000000 +
                (tv1->tv_sec   - tv2->tv_sec);
  diff.tv_usec = (tv1->tv_usec - tv2->tv_usec) % 1000000;

  if(0)
  {
    printf("tv1 %8d %8d tv2 %8d %8d diff %8d %8d\n",
           (int) tv1->tv_sec, (int) tv1->tv_usec,
           (int) tv2->tv_sec, (int) tv2->tv_usec,
           (int) diff.tv_sec, (int) diff.tv_usec);
  }

  /* If sec and usec have different polarity add or subtract 1 second */
  if((diff.tv_sec > 0) & (diff.tv_usec < 0))
  {
    diff.tv_sec--;
    diff.tv_usec += 1000000;
  }
  if((diff.tv_sec < 0) & (diff.tv_usec > 0))
  {
    diff.tv_sec++;
    diff.tv_usec -= 1000000;
  }
  if(0)
  {
    printf("tv1 %8d %8d tv2 %8d %8d diff %8d %8d\n",
           (int) tv1->tv_sec, (int) tv1->tv_usec,
           (int) tv2->tv_sec, (int) tv2->tv_usec,
           (int) diff.tv_sec, (int) diff.tv_usec);
  }

  if(diff.tv_sec < 0)
  {
    if(0) printf("-1\n");
    return -1;
  }
  if(diff.tv_sec > 0)
  {
    if(0) printf("1\n");
    return  1;
  }

  if(diff.tv_usec < 0)
  {
    if(0) printf("-1\n");
    return -1;
  }
  if(diff.tv_usec > 0)
  {
    if(0) printf("1\n");
    return  1;
  }
  if(0) printf("0 \n");
  return 0;
}

int radius_timeleft(struct radius_t *this, struct timeval *timeout)
{
  struct timeval now, later, diff;

  if(this->first == -1) /* Queue is empty */
    return 0;

  gettimeofday(&now, NULL);
  later.tv_sec = this->queue[this->first].timeout.tv_sec;
  later.tv_usec = this->queue[this->first].timeout.tv_usec;

  /* First take the difference with |usec| < 1000000 */
  diff.tv_sec = (later.tv_usec  - now.tv_usec) / 1000000 +
                (later.tv_sec   - now.tv_sec);
  diff.tv_usec = (later.tv_usec - now.tv_usec) % 1000000;

  /* If sec and usec have different polarity add or subtract 1 second */
  if((diff.tv_sec > 0) & (diff.tv_usec < 0))
  {
    diff.tv_sec--;
    diff.tv_usec += 1000000;
  }
  if((diff.tv_sec < 0) & (diff.tv_usec > 0))
  {
    diff.tv_sec++;
    diff.tv_usec -= 1000000;
  }

  /* If negative set to zero */
  if((diff.tv_sec < 0) || (diff.tv_usec < 0))
  {
    diff.tv_sec = 0;
    diff.tv_usec = 0;
  }

  /* If original was smaller do nothing */
  if(radius_cmptv(timeout, &diff) <=0)
    return 0;

  timeout->tv_sec = diff.tv_sec;
  timeout->tv_usec = diff.tv_usec;
  return 0;
}

int radius_timeout(struct radius_t *this)
{
  /* Retransmit any outstanding packets */
  /* Remove from queue if maxretrans exceeded */
  struct timeval now;
  struct sockaddr_in addr;
  struct sockaddr_in6 addr6;
  struct radius_packet_t pack_req;
  void *cbp = NULL;
  int ipv6 = this->ouraddr.ss_family == AF_INET6 ? 1 : 0;

  /*printf("Retrans: New beginning %d\n", (int) now);*/

  gettimeofday(&now, NULL);

  if(this->debug)
  {
    printf("radius_timeout %8d %8d\n",
           (int) now.tv_sec, (int) now.tv_usec);
    radius_printqueue(this);
  }

  while((this->first != -1) &&
         (radius_cmptv(&now, &this->queue[this->first].timeout) >= 0))
  {
    if(this->queue[this->first].retrans < RADIUS_RETRY2)
    {
      if(ipv6)
      {
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
      }
      else
      {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
      }

      if(this->queue[this->first].retrans == (RADIUS_RETRY1 - 1))
      {
        /* Use the other server for next retransmission */
        if(this->queue[this->first].lastsent)
        {
          if(ipv6)
            addr6.sin6_addr = ((struct sockaddr_in6 *)&this->hisaddr0)->sin6_addr;
          else
            addr.sin_addr = ((struct sockaddr_in *)&this->hisaddr0)->sin_addr;
          this->queue[this->first].lastsent = 0;
        }
        else
        {
          if(ipv6)
            addr6.sin6_addr = ((struct sockaddr_in6 *)&this->hisaddr1)->sin6_addr;
          else
            addr.sin_addr = ((struct sockaddr_in *)&this->hisaddr1)->sin_addr;
          this->queue[this->first].lastsent = 1;
        }
      }
      else
      {
        /* Use the same server for next retransmission */
        if(this->queue[this->first].lastsent)
        {
          if(ipv6)
            addr6.sin6_addr = ((struct sockaddr_in6 *)&this->hisaddr1)->sin6_addr;
          else
            addr.sin_addr = ((struct sockaddr_in *)&this->hisaddr1)->sin_addr;
        }
        else
        {
          if(ipv6)
            addr6.sin6_addr = ((struct sockaddr_in6 *)&this->hisaddr0)->sin6_addr;
          else
            addr.sin_addr = ((struct sockaddr_in *)&this->hisaddr0)->sin_addr;
          this->queue[this->first].lastsent = 0;
        }
      }

      /* Use the correct port for accounting and authentication */
      if(this->queue[this->first].p.code == RADIUS_CODE_ACCOUNTING_REQUEST)
      {
        if(ipv6)
          addr6.sin6_port = htons(this->acctport);
        else
          addr.sin_port = htons(this->acctport);
      }
      else
      {
        if(ipv6)
          addr6.sin6_port = htons(this->authport);
        else
          addr.sin_port = htons(this->authport);
      }

      if(ipv6)
      {
        if(sendto(this->fd, &this->queue[this->first].p,
                   ntohs(this->queue[this->first].p.length), 0,
                   (struct sockaddr *) &addr6, sizeof(addr6)) < 0)
        {
          sys_err(LOG_ERR, __FILE__, __LINE__, errno,
                  "sendto() failed!");
          radius_queue_reschedule(this, this->first);
          return -1;
        }
      }
      else   /* IPv4 */
      {
        if(sendto(this->fd, &this->queue[this->first].p,
                   ntohs(this->queue[this->first].p.length), 0,
                   (struct sockaddr *) &addr, sizeof(addr)) < 0)
        {
          sys_err(LOG_ERR, __FILE__, __LINE__, errno,
                  "sendto() failed!");
          radius_queue_reschedule(this, this->first);
          return -1;
        }
      }
      radius_queue_reschedule(this, this->first);
    }
    else   /* Finished retrans */
    {
      if(radius_queue_out(this, &pack_req, this->first, &cbp))
      {
        sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
                "Matching request was not found in queue: %d!", this->first);
        return -1;
      }

      if((pack_req.code == RADIUS_CODE_ACCOUNTING_REQUEST) &&
          (this->cb_acct_conf))
        return this->cb_acct_conf(this, NULL, &pack_req, cbp);

      if((pack_req.code == RADIUS_CODE_ACCESS_REQUEST) &&
          (this->cb_auth_conf))
        return this->cb_auth_conf(this, NULL, &pack_req, cbp);
    }
  }

  if(this->debug)
  {
    printf("radius_timeout\n");
    if(this->first > 0)
    {
      printf("first %d, timeout %8d %8d\n", this->first,
             (int) this->queue[this->first].timeout.tv_sec,
             (int) this->queue[this->first].timeout.tv_usec);
    }
    radius_printqueue(this);
  }

  return 0;
}

int radius_addattr(struct radius_t *this, struct radius_packet_t *pack,
               uint8_t type, uint32_t vendor_id, uint8_t vendor_type,
               uint32_t value, uint8_t *data, uint16_t dlen)
{
  struct radius_attr_t *a = NULL;
  uint16_t length = ntohs(pack->length);
  uint8_t vlen = 0;
  char passwd[RADIUS_PWSIZE];
  int pwlen = 0;

  a = (struct radius_attr_t*) ((char *) pack + length); /* cast with (char *) to avoid use of void* in arithmetic warning */

  if(type == RADIUS_ATTR_USER_PASSWORD)
  {
    radius_pwencode(this, (uint8_t*) passwd, RADIUS_PWSIZE, &pwlen,
                    data, dlen, pack->authenticator,
                    this->secret, this->secretlen);
    data = (uint8_t*) passwd;
    dlen = pwlen;
  }

  if(type != RADIUS_ATTR_VENDOR_SPECIFIC)
  {
    if(dlen)   /* If dlen != 0 it is a text/string attribute */
    {
      vlen = dlen;
    }
    else
    {
      vlen = 4; /* address, integer or time */
    }

    if(vlen > RADIUS_ATTR_VLEN)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Data too long!");
      return -1;
    }

    if((length + vlen + 2) > RADIUS_PACKSIZE)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "No more space!");
      return -1;
    }

    length += vlen + 2;

    pack->length = htons(length);

    a->t = type;
    a->l = vlen + 2;
    if(data)
      memcpy(&a->v, data, dlen);
    else if(dlen)
      memset(&a->v, 0, dlen);
    else
      a->v.i = htonl(value);
  }
  else   /* Vendor specific */
  {
    if(dlen)   /* If dlen != 0 it is a text/string attribute */
    {
      vlen = dlen;
    }
    else
    {
      vlen = 4; /* address, integer or time */
    }

    if(vlen > RADIUS_ATTR_VLEN)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Data too long!");
      return -1;
    }

    if((length + vlen + 2) > RADIUS_PACKSIZE)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "No more space!");
      return -1;
    }

    length += vlen + 8;

    pack->length = htons(length);

    a->t = type;
    a->l = vlen + 8;

    a->v.vv.i = htonl(vendor_id);
    a->v.vv.t = vendor_type;
    a->v.vv.l = vlen + 2;

    if(data)
      memcpy(((char *) a) + 8, data, dlen); /* cast with (char *) to avoid use of void* in arithmetic warning */
    else if(dlen)
      memset(((char *) a) + 8, 0, dlen);
    else
      a->v.vv.i = htonl(value);
  }

  return 0;
}

int radius_addattrv6(struct radius_t *this, struct radius_packet_t *pack,
                 uint8_t type, uint32_t vendor_id, uint8_t vendor_type,
                 struct in6_addr value, uint8_t *data, uint16_t dlen)
{
  struct radius_attrv6_t *a = NULL;
  uint16_t length = ntohs(pack->length);
  uint8_t vlen = 0;

  /* To avoid unused parameter warning */
  this = NULL;

  a = (struct radius_attrv6_t*) ((char *) pack + length); /* cast with (char *) to avoid use of void* in arithmetic warning */

  if(type != RADIUS_ATTR_VENDOR_SPECIFIC)
  {
    if(dlen)   /* If dlen != 0 it is a text/string attribute */
    {
      vlen = dlen;
    }
    else
    {
      vlen = sizeof(value); /* address, integer or time */
    }

    if(vlen > RADIUS_ATTR_VLEN)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Data too long!");
      return -1;
    }

    if((length + vlen + 2) > RADIUS_PACKSIZE)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "No more space!");
      return -1;
    }

    if(type == RADIUS_ATTR_FRAMED_IPV6_PREFIX )   /* this attribute has a reserved and prefix-length field */
    {
      length += vlen + 2;
      pack->length = htons(length);
      a->t = type;
      a->l = vlen + 2;
    }
    else if(type == RADIUS_ATTR_FRAMED_INTERFACE_ID)
    {
      length += vlen + 2;
      pack->length = htons(length);
      a->t = type;
      a->l = vlen + 2;
    }
    else
    {
      length += vlen + 2;
      pack->length = htons(length);
      a->t = type;
      a->l = vlen + 2;
    }
    if(data)
      memcpy(&a->v, data, dlen);
    else
    {
      if(type == RADIUS_ATTR_FRAMED_IPV6_PREFIX)  /* this attribute has a reserved and prefix-length field */
      {
        vlen += 2;
        memset(&a->v.i, 0, vlen + 2);
        int val = (dlen - 2) * 8;
        memcpy(((char *)&a->v.i) + 1, &val, 1); /* cast with (char *) to avoid use of void* in arithmetic warning */
        memcpy(((char *)&a->v.i) + 2, &value.s6_addr, vlen);
      }
      else if(type == RADIUS_ATTR_FRAMED_INTERFACE_ID )
      {
        memcpy(((char *)&a->v.i), (uint64_t *)&value, vlen);
      }
      else
      {
        memcpy(&a->v.i, &value.s6_addr, vlen);
      }
    }
  }
  else   /* Vendor specific */
  {
    if(dlen)   /* If dlen != 0 it is a text/string attribute */
    {
      vlen = dlen;
    }
    else
    {
      vlen = 16; /* address, integer or time */
    }

    if(vlen > RADIUS_ATTR_VLEN)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Data too long!");
      return -1;
    }

    if((length + vlen + 2) > RADIUS_PACKSIZE)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "No more space!");
      return -1;
    }

    length += vlen + 8;

    pack->length = htons(length);

    a->t = type;
    a->l = vlen + 8;

    a->v.vv.i = htonl(vendor_id);
    a->v.vv.t = vendor_type;
    a->v.vv.l = vlen + 2;

    if(data)
      memcpy(((char *) a) + 8, data, dlen); /* cast with (char *) to avoid use of void* in arithmetic warning */
    else if(dlen)
      memset(((char *) a) + 8, 0, dlen);
    else
      memcpy(&a->v.vv.i, &value.s6_addr, sizeof(struct in6_addr));
  }

  return 0;
}

int radius_getattr(struct radius_packet_t *pack, struct radius_attr_t **attr,
               uint8_t type, uint32_t vendor_id, uint8_t vendor_type,
               int instance)
{
  struct radius_attr_t *t = NULL;
  /*  struct radius_attr_t *v = NULL;  TODO: Loop through vendor specific */
  int offset = 0;
  int count = 0;

  if(0)
  {
    printf("radius_getattr \n");
    printf("radius_getattr payload %.2x %.2x %.2x %.2x\n",
           pack->payload[0], pack->payload[1], pack->payload[2],
           pack->payload[3]);
  }

  if(type == RADIUS_ATTR_VENDOR_SPECIFIC)
  {
    do
    {
      t = (struct radius_attr_t*) (((char *) &(pack->payload)) + offset);  /* cast with (char *) to avoid use of void* in arithmetic warning */
      if(0)
      {
        printf("radius_getattr %d %d %d %.2x %.2x \n", t->t, t->l,
               ntohl(t->v.vv.i), (int) t->v.vv.t, (int) t->v.vv.l);
      }
      if((t->t == type) && (ntohl(t->v.vv.i) == vendor_id) && (t->v.vv.t == vendor_type))
      {
        if(count == instance)
        {
          *attr = (struct radius_attr_t *) &t->v.vv.t;
          if(0) printf("Found\n");
          return 0;
        }
        else
        {
          count++;
        }
      }
      offset +=  t->l;
    }
    while(offset < (ntohs(pack->length) - RADIUS_HDRSIZE)); /* TODO */
  }
  else       /* Need to check pack -> length */
  {
    do
    {
      t = (struct radius_attr_t*) (((char *) &(pack->payload)) + offset); /* cast with (char *) to avoid use of void* in arithmetic warning */
      if(t->t == type)
      {
        if(count == instance)
        {
          *attr = t;
          return 0;
        }
        else
        {
          count++;
        }
      }
      offset +=  t->l;
    }
    while(offset < (ntohs(pack->length) - RADIUS_HDRSIZE)); /* TODO */
  }

  return -1; /* Not found */
}

int radius_getattrv6(struct radius_packet_t *pack, struct radius_attrv6_t **attr,
                 uint8_t type, uint32_t vendor_id, uint8_t vendor_type,
                 int instance)
{
  struct radius_attrv6_t *t = NULL;
  /*  struct radius_attrv6_t *v = NULL;  TODO: Loop through vendor specific */
  int offset = 0;
  int count = 0;

  if(0)
  {
    printf("radius_getattrv6 \n");
    printf("radius_getattrv6 payload %.2x %.2x %.2x %.2x\n",
           pack->payload[0], pack->payload[1], pack->payload[2],
           pack->payload[3]);
  }

  if(type == RADIUS_ATTR_VENDOR_SPECIFIC)
  {
    do
    {
      t = (struct radius_attrv6_t*) (((char *) &(pack->payload)) + offset); /* cast with (char *) to avoid use of void* in arithmetic warning */
      if(0)
      {
        printf("radius_getattrv6 %d %d %d %.2x %.2x \n", t->t, t->l,
               ntohl(t->v.vv.i), (int) t->v.vv.t, (int) t->v.vv.l);
      }
      if((t->t == type) && (ntohl(t->v.vv.i) == vendor_id) && (t->v.vv.t == vendor_type))
      {
        if(count == instance)
        {
          *attr = (struct radius_attrv6_t *) &t->v.vv.t;
          if(0) printf("Found\n");
          return 0;
        }
        else
        {
          count++;
        }
      }
      offset +=  t->l;
    }
    while(offset < (ntohs(pack->length) - RADIUS_HDRSIZE)); /* TODO */
  }
  else       /* Need to check pack -> length */
  {
    do
    {
      t = (struct radius_attrv6_t*) (((char *) &(pack->payload)) + offset); /* cast with (char *) to avoid use of void* in arithmetic warning */
      if(t->t == type)
      {
        if(count == instance)
        {
          *attr = t;
          return 0;
        }
        else
        {
          count++;
        }
      }
      offset +=  t->l;
    }
    while(offset < (ntohs(pack->length) - RADIUS_HDRSIZE)); /* TODO */
  }

  return -1; /* Not found */
}

/**
 * \brief Count the number of instances of an attribute in a packet.
 * \param pack radius packet
 * \param type radius packet type to count
 * \return number of instances of attribute of the specified type
 */
/* static */ int radius_countattr(struct radius_packet_t *pack, uint8_t type)
{
  struct radius_attr_t *t = NULL;
  int offset = 0;
  int count = 0;

  /* Need to check pack -> length */

  do
  {
    t = (struct radius_attr_t*) (((char *) &(pack->payload)) + offset); /* cast with (char *) to avoid use of void* in arithmetic warning */
    if(t->t == type)
    {
      count++;
    }
    offset +=  2 + t->l;
  }
  while(offset < ntohs(pack->length));

  if(0) printf("Count %d\n", count);
  return count;
}

/**
 * \brief Compare two attributes to see if they are the same.
 * \param t1 first radius attribute
 * \param t2 second radius attribute
 * \return 0 if attributes are the same, -1 otherwise 
 */
/* static */ int radius_cmpattr(struct radius_attr_t *t1, struct radius_attr_t *t2)
{
  if(t1->t != t2->t  ) return -1;
  if(t1->l != t2->l) return -1;
  if(memcmp(t1->v.t, t2->v.t, t1->l)) return -1; /* Also int/time/addr */
  return 0;
}

/**
 * \brief Compare two attributes to see if they are the same.
 * \param t1 first radius attribute
 * \param t2 second radius attribute
 * \return 0 if attributes are the same, -1 otherwise 
 */
/* static */ int radius_cmpattrv6(struct radius_attrv6_t *t1, struct radius_attrv6_t *t2)
{
  if(t1->t != t2->t  ) return -1;
  if(t1->l != t2->l) return -1;
  if(memcmp(t1->v.t, t2->v.t, t1->l)) return -1; /* Also int/time/addr */
  return 0;
}

int radius_keydecode(struct radius_t *this, uint8_t *dst, int dstsize,
                     int *dstlen, uint8_t *src, int srclen,
                     uint8_t *authenticator, char *secret, int secretlen)
{
  int i = 0;
  int n = 0;
  MD5_CTX context;
  unsigned char b[RADIUS_MD5LEN];
  int blocks = 0;

  /* To avoid unused parameter warning */
  this = NULL;

  blocks = (srclen - 2) / RADIUS_MD5LEN;

  if((blocks * RADIUS_MD5LEN + 2) != srclen)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "radius_keydecode: srclen must be 2 plus n * 16");
    return -1;
  }

  if(blocks < 1)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "radius_keydecode srclen must be at least 18");
    return -1;
  }

  /* Get MD5 hash on secret + authenticator (First 16 octets) */
  MD5Init(&context);
  MD5Update(&context, (uint8_t*) secret, secretlen);
  MD5Update(&context, authenticator, RADIUS_AUTHLEN);
  MD5Update(&context, src, 2);
  MD5Final(b, &context);

  if((src[2] ^ b[0]) > dstsize)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "radius_keydecode dstsize too small");
    return -1;
  }

  if((src[2] ^ b[0]) > (srclen - 3))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "radius_keydecode dstlen > srclen -3");
    return -1;
  }

  *dstlen = src[2] ^ b[0];

  for(i = 1; i < RADIUS_MD5LEN; i++)
    if((i - 1) < *dstlen)
      dst[i - 1] = src[i + 2] ^ b[i];

  /* Next blocks of 16 octets */
  for(n = 1; n < blocks; n++)
  {
    MD5Init(&context);
    MD5Update(&context, (uint8_t*) secret, secretlen);
    MD5Update(&context, src + 2 + ((n - 1) * RADIUS_MD5LEN), RADIUS_MD5LEN);
    MD5Final(b, &context);
    for(i = 0; i < RADIUS_MD5LEN; i++)
      if((i - 1 + n * RADIUS_MD5LEN) < *dstlen)
        dst[i - 1 + n * RADIUS_MD5LEN] = src[i + 2 + n * RADIUS_MD5LEN] ^ b[i];
  }

  return 0;
}

int radius_keyencode(struct radius_t *this, uint8_t *dst, int dstsize,
                     int *dstlen, uint8_t *src, int srclen,
                     uint8_t *authenticator, char *secret, int secretlen)
{
  int i = 0;
  int n = 0;
  MD5_CTX context;
  unsigned char b[RADIUS_MD5LEN];
  int blocks = 0;

  blocks = (srclen + 1) / RADIUS_MD5LEN;
  if((blocks * RADIUS_MD5LEN) < (srclen + 1)) blocks++;

  if(((blocks * RADIUS_MD5LEN) + 2 ) > dstsize)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "radius_keyencode dstsize too small");
    return -1;
  }

  *dstlen = (blocks * RADIUS_MD5LEN) + 2;

  /* Read two salt octets */
  if(fread(dst, 1, 2, this->urandom_fp) != 2)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "fread() failed");
    return -1;
  }

  /* Get MD5 hash on secret + authenticator (First 16 octets) */
  MD5Init(&context);
  MD5Update(&context, (uint8_t*) secret, secretlen);
  MD5Update(&context, authenticator, RADIUS_AUTHLEN);
  MD5Update(&context, dst, 2);
  MD5Final(b, &context);
  dst[2] = (uint8_t) srclen ^ b[0]; /* Length of key */
  for(i = 1; i < RADIUS_MD5LEN; i++)
    if((i - 1) < srclen)
      dst[i + 2] = src[i - 1] ^ b[i];
    else
      dst[i + 2] = b[i];

  /* Get MD5 hash on secret + c(n - 1) (Next j 16 octets) */
  for(n = 1; n < blocks; n++)
  {
    MD5Init(&context);
    MD5Update(&context, (uint8_t*) secret, secretlen);
    MD5Update(&context, dst + 2 + ((n - 1) * RADIUS_MD5LEN), RADIUS_MD5LEN);
    MD5Final(b, &context);
    for(i = 0; i < RADIUS_MD5LEN; i++)
      if((i - 1) < srclen)
        dst[i + 2 + n * RADIUS_MD5LEN] = src[i - 1 + n * RADIUS_MD5LEN] ^ b[i];
      else
        dst[i + 2 + n * RADIUS_MD5LEN] = b[i];
  }

  return 0;
}

int radius_pwdecode(struct radius_t *this, uint8_t *dst, int dstsize,
                    int *dstlen, uint8_t *src, int srclen,
                    uint8_t *authenticator, char *secret, int secretlen)
{
  int i = 0;
  int n = 0;
  MD5_CTX context;
  unsigned char output[RADIUS_MD5LEN];

  if(srclen > dstsize)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "radius_pwdecode srclen larger than dstsize");
    return -1;
  }

  if(srclen % RADIUS_MD5LEN)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "radius_pwdecode srclen is not multiple of 16 octets");
    return -1;
  }

  *dstlen = srclen;

  if(this->debug)
  {
    printf("pwdecode srclen %d\n", srclen);
    for(n = 0; n < srclen; n++)
    {
      printf("%.2x ", src[n]);
      if((n % 16) == 15)
        printf("\n");
    }
    printf("\n");

    printf("pwdecode authenticator \n");
    for(n = 0; n < RADIUS_AUTHLEN; n++)
    {
      printf("%.2x ", authenticator[n]);
      if((n % 16) == 15)
        printf("\n");
    }
    printf("\n");

    printf("pwdecode secret \n");
    for(n = 0; n< secretlen; n++)
    {
      printf("%.2x ", secret[n]);
      if((n % 16) == 15)
        printf("\n");
    }
    printf("\n");
  }

  /* Get MD5 hash on secret + authenticator */
  MD5Init(&context);
  MD5Update(&context, (uint8_t*) secret, secretlen);
  MD5Update(&context, authenticator, RADIUS_AUTHLEN);
  MD5Final(output, &context);

  /* XOR first 16 octets of passwd with MD5 hash */
  for(i = 0; i < RADIUS_MD5LEN; i++)
    dst[i] = src[i] ^ output[i];

  /* Continue with the remaining octets of passwd if any */
  for(n = 0; n < 128 && n < (*dstlen - RADIUS_AUTHLEN); n += RADIUS_AUTHLEN)
  {
    MD5Init(&context);
    MD5Update(&context, (uint8_t*) secret, secretlen);
    MD5Update(&context, src + n, RADIUS_AUTHLEN);
    MD5Final(output, &context);
    for(i = 0; i < RADIUS_AUTHLEN; i++)
      dst[i + n + RADIUS_AUTHLEN] = src[i + n + RADIUS_AUTHLEN] ^ output[i];
  }

  if(this->debug)
  {
    printf("pwdecode dest \n");
    for(n = 0; n < 32; n++)
    {
      printf("%.2x ", dst[n]);
      if((n % 16) == 15)
        printf("\n");
    }
    printf("\n");
  }

  return 0;
}

int radius_pwencode(struct radius_t *this, uint8_t *dst, int dstsize,
                    int *dstlen, uint8_t *src, int srclen,
                    uint8_t *authenticator, char *secret, int secretlen)
{
  int i = 0;
  int n = 0;
  MD5_CTX context;
  unsigned char output[RADIUS_MD5LEN];

  /* To avoid unused parameter warning */
  this = NULL;

  memset(dst, 0, dstsize);

  /* Make dstlen multiple of 16 */
  if(srclen & 0x0f)
    *dstlen = (srclen & 0xf0) + 0x10; /* Padding 1 to 15 zeros */
  else
    *dstlen = srclen;                 /* No padding */

  /* Is dstsize too small ? */
  if(dstsize <= *dstlen)
  {
    *dstlen = 0;
    return -1;
  }

  /* Copy first 128 octets of src into dst */
  if(srclen <= 128)
    memcpy(dst, src, 128);
  else
    memcpy(dst, src, srclen);

  /* Get MD5 hash on secret + authenticator */
  MD5Init(&context);
  MD5Update(&context, (uint8_t*) secret, secretlen);
  MD5Update(&context, authenticator, RADIUS_AUTHLEN);
  MD5Final(output, &context);

  /* XOR first 16 octets of dst with MD5 hash */
  for(i = 0; i < RADIUS_MD5LEN; i++)
    dst[i] ^= output[i];

  /* if(*dstlen <= RADIUS_MD5LEN) return 0;  Finished */

  /* Continue with the remaining octets of dst if any */
  for(n = 0; n < 128 && n < (*dstlen - RADIUS_AUTHLEN); n += RADIUS_AUTHLEN)
  {
    MD5Init(&context);
    MD5Update(&context, (uint8_t*) secret, secretlen);
    MD5Update(&context, dst + n, RADIUS_AUTHLEN);
    MD5Final(output, &context);
    for(i = 0; i < RADIUS_AUTHLEN; i++)
      dst[i + n + RADIUS_AUTHLEN] ^= output[i];
  }
  return 0;
}

int radius_new(struct radius_t **this,
               struct sockaddr_storage *listen_addr, uint16_t port, int coanocheck,
               struct sockaddr_storage *proxylisten, uint16_t proxyport,
               struct sockaddr_storage *proxyaddr, struct sockaddr_storage *proxymask,
               char* proxysecret)
{
  int ipv6 = listen_addr->ss_family == AF_INET6 ? 1 : 0;

  struct sockaddr_in addr;
  struct sockaddr_in6 addr6;

  /* sys_err(LOG_INFO, __FILE__, __LINE__, 0,
     "Radius client started"); */

  /* Allocate storage for instance */
  if(!(*this = calloc(sizeof(struct radius_t), 1)))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "calloc() failed");
    return -1;
  }

  (*this)->coanocheck = coanocheck;

  /* Radius parameters */
  if(listen_addr->ss_family == AF_INET)
    memcpy(&(*this)->ouraddr, listen_addr, sizeof(struct sockaddr_in));
  else
    memcpy(&(*this)->ouraddr, listen_addr, sizeof(struct sockaddr_in6));
  (*this)->ourport = port;

  /* Proxy parameters */
  if(proxysecret)
  {
    if(proxylisten->ss_family == AF_INET)
      memcpy(&(*this)->proxylisten, proxylisten, sizeof(struct sockaddr_in));
    else
      memcpy(&(*this)->proxylisten, proxylisten, sizeof(struct sockaddr_in6));
    (*this)->proxyport = proxyport;

    if(proxyaddr)
      memcpy(&(*this)->proxyaddr, proxyaddr, sizeof(proxyaddr));
    else
      *((struct sockaddr_in6 *)&(*this)->proxyaddr)->sin6_addr.s6_addr = ~0;

    if(proxymask)
      memcpy(&(*this)->proxymask, proxymask, sizeof(proxymask));
    else
      *((struct sockaddr_in6 *)&(*this)->proxymask)->sin6_addr.s6_addr = ~0;

    if(((*this)->proxysecretlen = strlen(proxysecret)) > RADIUS_SECRETSIZE)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "proxysecret longer than %d", RADIUS_SECRETSIZE);
      free((*this));
      return -1;
    }

    if(((*this)->proxysecretlen = strlen(proxysecret)) > RADIUS_SECRETSIZE)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "proxy secret longer than %d", RADIUS_SECRETSIZE);
      free((*this));
      return -1;
    }
    memcpy((*this)->proxysecret, proxysecret, (*this)->proxysecretlen);
  }

  /* Initialise queue */
  (*this)->next = 0;
  (*this)->first = -1;
  (*this)->last = -1;

  if(((*this)->urandom_fp = fopen("/dev/urandom", "r")) == NULL)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "fopen(/dev/urandom, r) failed");
  }

  /* [SV]: => getnameinfo() */

  /* Initialise radius socket */
  if(((*this)->fd = socket(listen_addr->ss_family, SOCK_DGRAM, 0)) < 0 )
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "socket() failed!");
    fclose((*this)->urandom_fp);
    free((*this));
    return -1;
  }

  if(ipv6)
  {
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = listen_addr->ss_family;
    addr6.sin6_port = htons((*this)->ourport);
    addr6.sin6_addr = ((struct sockaddr_in6 *)&(*this)->ouraddr)->sin6_addr;
    addr6.sin6_flowinfo = htonl(0);
#ifdef SIN6_LEN
    addr6.sin6_len = sizeof(struct sockaddr_in6);
#endif
  }
  else
  {
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = listen_addr->ss_family;
    addr.sin_port = htons((*this)->ourport);
    addr.sin_addr = ((struct sockaddr_in *)&(*this)->ouraddr)->sin_addr;
  }

  if(bind((*this)->fd, ipv6 ? (struct sockaddr *) &addr6 : (struct sockaddr *)&addr, ipv6 ? sizeof(addr6) : sizeof(addr)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "bind() failed!");
    close(((int)(*this)->fd));
    fclose((*this)->urandom_fp);
    free((*this));
    return -1;
  }

  /* Initialise proxy socket */
  if(proxysecret)
  {
    if(ipv6)
    {
      memset(&addr, 0, sizeof(addr));
      addr6.sin6_family = AF_INET6;
      addr6.sin6_port = htons((*this)->proxyport);
      addr6.sin6_addr = ((struct sockaddr_in6 *)&(*this)->proxylisten)->sin6_addr;
    }
    else
    {
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons((*this)->proxyport);
      addr.sin_addr = ((struct sockaddr_in *)&(*this)->proxylisten)->sin_addr;
    }

    if(((*this)->proxyfd = socket(proxylisten->ss_family, SOCK_DGRAM, 0)) < 0 )
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "socket() failed!");
      close(((int)(*this)->fd));
      fclose((*this)->urandom_fp);
      free((*this));
      return -1;
    }

    if(bind((*this)->proxyfd, ipv6 ? (struct sockaddr *) &addr6 : (struct sockaddr *)&addr, ipv6 ? sizeof(addr6) : sizeof(addr)) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "bind() failed!");
      close(((int)(*this)->proxyfd));
      close(((int)(*this)->fd));
      fclose((*this)->urandom_fp);
      free((*this));
      return -1;
    }
  }
  else
  {
    (*this)->proxyfd = -1; /* Indicate that proxy is not used */
  }

  return 0;
}

int radius_free(struct radius_t *this)
{
  if(fclose(this->urandom_fp))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "fclose() failed!");
  }
  if(close(this->fd))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "close() failed!");
  }
  free(this);
  return 0;
}

void radius_set(struct radius_t *this, int debug,
                struct sockaddr_storage *server0, struct sockaddr_storage *server1,
                uint16_t authport, uint16_t acctport, char* secret)
{
  this->debug = debug;

  /* Remote radius server parameters */
  memcpy(&this->hisaddr0, server0, sizeof(struct sockaddr_storage));
  memcpy(&this->hisaddr1, server1, sizeof(struct sockaddr_storage));

  if(authport)
  {
    this->authport = authport;
  }
  else
  {
    this->authport = RADIUS_AUTHPORT;
  }

  if(acctport)
  {
    this->acctport = acctport;
  }
  else
  {
    this->acctport = RADIUS_ACCTPORT;
  }

  if((this->secretlen = strlen(secret)) > RADIUS_SECRETSIZE)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Radius secret too long. Truncating to %d characters",
            RADIUS_SECRETSIZE);
    this->secretlen = RADIUS_SECRETSIZE;
  }
  memcpy(this->secret, secret, this->secretlen);

  this->lastreply = 0; /* Start out using server 0 */
  return;
}

int radius_set_cb_ind(struct radius_t *this,
                      int (*cb_ind) (struct radius_t *radius, struct radius_packet_t *pack,
                                     struct sockaddr_storage *peer))
{
  this->cb_ind = cb_ind;
  return 0;
}

int radius_set_cb_auth_conf(struct radius_t *this,
                        int (*cb_auth_conf) (struct radius_t *radius, struct radius_packet_t *pack,
                                             struct radius_packet_t *pack_req, void *cbp))
{
  this->cb_auth_conf = cb_auth_conf;
  return 0;
}

int radius_set_cb_acct_conf(struct radius_t *this,
                        int (*cb_acct_conf) (struct radius_t *radius, struct radius_packet_t *pack,
                                             struct radius_packet_t *pack_req, void *cbp))
{
  this->cb_acct_conf = cb_acct_conf;
  return 0;
}

int radius_set_cb_coa_ind(struct radius_t *this,
                      int (*cb_coa_ind) (struct radius_t *radius, struct radius_packet_t *pack,
                                         struct sockaddr_storage *peer))
{
  this->cb_coa_ind = cb_coa_ind;
  return 0;
}

int radius_req(struct radius_t *this,
               struct radius_packet_t *pack,
               void *cbp)
{
  struct sockaddr_in addr;
  struct sockaddr_in6 addr6;
  int len = ntohs(pack->length);
  int ipv6 = this->ouraddr.ss_family == AF_INET6 ? 1 :0;

  /* Place packet in queue */
  if(radius_queue_in(this, pack, cbp))
  {
    return -1;
  }

  if(ipv6)
  {
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
  }
  else
  {
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
  }

  if(this->debug) printf("Lastreply: %d\n", this->lastreply);

  if(!this->lastreply)
  {
    if(ipv6)
      addr6.sin6_addr = ((struct sockaddr_in6 *)&this->hisaddr0)->sin6_addr;
    else
      addr.sin_addr = ((struct sockaddr_in *)&this->hisaddr0)->sin_addr;
  }
  else
  {
    if(ipv6)
      addr6.sin6_addr = ((struct sockaddr_in6 *)&this->hisaddr1)->sin6_addr;
    else
      addr.sin_addr = ((struct sockaddr_in *)&this->hisaddr1)->sin_addr;
  }

  if(pack->code == RADIUS_CODE_ACCOUNTING_REQUEST)
  {
    if(ipv6)
      addr6.sin6_port = htons(this->acctport);
    else
      addr.sin_port = htons(this->acctport);
  }
  else
  {
    if(ipv6)
      addr6.sin6_port = htons(this->authport);
    else
      addr.sin_port = htons(this->authport);
  }

  if(ipv6)
  {
    if(sendto(this->fd, pack, len, 0,
               (struct sockaddr *) &addr6, sizeof(addr6)) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "sendto() failed!");
      return -1;
    }
  }
  else
  {
    if(sendto(this->fd, pack, len, 0,
               (struct sockaddr *) &addr, sizeof(addr)) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "sendto() failed!");
      return -1;
    }
  }

  return 0;
}

int radius_resp(struct radius_t *this,
                struct radius_packet_t *pack,
                struct sockaddr_storage *peer, uint8_t *req_auth)
{
  int len = ntohs(pack->length);
  struct radius_attr_t *ma = NULL; /* Message authenticator */

  /* Prepare for message authenticator TODO */
  memset(pack->authenticator, 0, RADIUS_AUTHLEN);
  memcpy(pack->authenticator, req_auth, RADIUS_AUTHLEN);

  /* If packet contains message authenticator: Calculate it! */
  if(!radius_getattr(pack, &ma, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 0, 0, 0))
  {
    radius_hmac_md5(this, pack, ma->v.t);
  }

  radius_authresp_authenticator(this, pack, req_auth, this->proxysecret,
                                this->proxysecretlen);

  if(sendto(this->proxyfd, pack, len, 0,
             (struct sockaddr *) peer, sizeof(struct sockaddr_storage)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "sendto() failed!");
    return -1;
  }

  return 0;
}

int radius_coaresp(struct radius_t *this,
                   struct radius_packet_t *pack,
                   struct sockaddr_storage *peer, uint8_t *req_auth)
{
  /* Send of a packet (no retransmit queue) */
  int len = ntohs(pack->length);
  struct radius_attr_t *ma = NULL; /* Message authenticator */

  /* Prepare for message authenticator TODO */
  memset(pack->authenticator, 0, RADIUS_AUTHLEN);
  memcpy(pack->authenticator, req_auth, RADIUS_AUTHLEN);

  /* If packet contains message authenticator: Calculate it! */
  if(!radius_getattr(pack, &ma, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 0, 0, 0))
  {
    radius_hmac_md5(this, pack, ma->v.t);
  }

  radius_authresp_authenticator(this, pack, req_auth, this->secret,
                                this->secretlen);

  if(sendto(this->fd, pack, len, 0,
             (struct sockaddr *) peer, sizeof(struct sockaddr_storage)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "sendto() failed!");
    return -1;
  }

  return 0;
}

int radius_default_pack(struct radius_t *this,
                    struct radius_packet_t *pack,
                    int code)
{
  memset(pack, 0, RADIUS_PACKSIZE);
  pack->code = code;
  pack->id = 0; /* Let the send procedure queue the packet and assign id */
  pack->length = htons(RADIUS_HDRSIZE);

  if(fread(pack->authenticator, 1, RADIUS_AUTHLEN, this->urandom_fp)
      != RADIUS_AUTHLEN)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "fread() failed");
    return -1;
  }
  return 0;
}

/**
 * \brief Check that the authenticator on a reply is correct.
 * \param this radius_t instance
 * \param pack radius packet
 * \param pack_req packet which contains original request
 * \return 0 if authenticator is correct, other value otherwise
 */
static int radius_authcheck(struct radius_t *this, struct radius_packet_t *pack,
                     struct radius_packet_t *pack_req)
{
  uint8_t auth[RADIUS_AUTHLEN];
  MD5_CTX context;

  MD5Init(&context);
  MD5Update(&context, (void*) pack, RADIUS_HDRSIZE - RADIUS_AUTHLEN);
  MD5Update(&context, pack_req->authenticator, RADIUS_AUTHLEN);
  MD5Update(&context, ((unsigned char *) pack) + RADIUS_HDRSIZE,  /* cast with (unsigned char *) to avoid use of void* in arithmetic warning */
            ntohs(pack->length) - RADIUS_HDRSIZE);
  MD5Update(&context, (uint8_t*) this->secret, this->secretlen);
  MD5Final(auth, &context);

  return memcmp(pack->authenticator, auth, RADIUS_AUTHLEN);
}

/**
 * \brief Check that the authenticator on an accounting request is correct.
 * \param this radius_t instance
 * \param pack radius packet
 * \return 0 if authenticator is correct, other value otherwise
 */
int radius_acctcheck(struct radius_t *this, struct radius_packet_t *pack)
{
  uint8_t auth[RADIUS_AUTHLEN];
  uint8_t padd[RADIUS_AUTHLEN] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  MD5_CTX context;

  MD5Init(&context);
  MD5Update(&context, (void*) pack, RADIUS_HDRSIZE - RADIUS_AUTHLEN);
  MD5Update(&context, (uint8_t*) padd, RADIUS_AUTHLEN);
  MD5Update(&context, ((unsigned char *) pack) + RADIUS_HDRSIZE, /* cast with (unsigned char *) to avoid use of void* in arithmetic warning */
            ntohs(pack->length) - RADIUS_HDRSIZE);
  MD5Update(&context, (uint8_t*) this->secret, this->secretlen);
  MD5Final(auth, &context);

  return memcmp(pack->authenticator, auth, RADIUS_AUTHLEN);
}

int radius_decaps(struct radius_t *this)
{
  int status = 0;
  struct radius_packet_t pack;
  struct radius_packet_t pack_req;
  void *cbp = NULL;
  struct sockaddr_storage addr_ss;
  struct sockaddr_in addr;
  struct sockaddr_in6 addr6;
  socklen_t fromlen = sizeof(addr_ss);
  int coarequest = 0;
  int ipv6 = 0;

  if(this->debug) printf("Received radius packet\n");

  if((status = recvfrom(this->fd, &pack, sizeof(pack), 0,
                         (struct sockaddr *) &addr_ss, &fromlen)) <= 0)
  {
    if(errno != EINTR)
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "recvfrom() failed");
    return -1;
  }

  if(status < RADIUS_HDRSIZE)
  {
    sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
            "Received radius packet which is too short: %d < %d!",
            status, RADIUS_HDRSIZE);
    return -1;
  }

  if(ntohs(pack.length) != status)
  {
    sys_err(LOG_WARNING, __FILE__, __LINE__, errno,
            "Received radius packet with wrong length field %d != %d!",
            ntohs(pack.length), status);
    return -1;
  }

  ipv6 = addr_ss.ss_family == AF_INET6 ? 1 : 0;

  switch(pack.code)
  {
    case RADIUS_CODE_DISCONNECT_REQUEST:
    case RADIUS_CODE_COA_REQUEST:
      coarequest = 1;
      break;
    default:
      coarequest = 0;
  }

  addr6 = *(struct sockaddr_in6 *)&addr_ss;
  addr = *(struct sockaddr_in *)&addr_ss;

  if(!coarequest)
  {
    if(ipv6)
    {
      /* Check that reply is from correct address */
      if(!(IN6_ARE_ADDR_EQUAL(&addr6.sin6_addr, &((struct sockaddr_in6 *)&this->hisaddr0)->sin6_addr)) &&
         !(IN6_ARE_ADDR_EQUAL(&addr6.sin6_addr, &((struct sockaddr_in6 *)&this->hisaddr1)->sin6_addr)))
      {
        sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
                "Received radius reply from wrong address %.8x!",
                addr6.sin6_addr.s6_addr);
        return -1;
      }

      /* Check that UDP source port is correct */
      if((addr6.sin6_port != htons(this->authport)) &&
          (addr6.sin6_port != htons(this->acctport)))
      {
        sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
                "Received radius packet from wrong port %.4x!",
                addr6.sin6_port);
        return -1;
      }

    }
    else
    {
      /* Check that reply is from correct address */
      if((addr.sin_addr.s_addr != ((struct sockaddr_in *)&this->hisaddr0)->sin_addr.s_addr) &&
          (addr.sin_addr.s_addr != ((struct sockaddr_in *)&this->hisaddr1)->sin_addr.s_addr))
      {
        sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
                "Received radius reply from wrong address %.8x!\n",
                addr.sin_addr.s_addr);
        return -1;
      }

      /* Check that UDP source port is correct */
      if((addr.sin_port != htons(this->authport)) &&
          (addr.sin_port != htons(this->acctport)))
      {
        sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
                "Received radius packet from wrong port %.4x!",
                addr.sin_port);
        return -1;
      }
    }

    if(radius_queue_out(this, &pack_req, pack.id, &cbp))
    {
      sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
              "Matching request was not found in queue: %d!", pack.id);
      return -1;
    }

    if(radius_authcheck(this, &pack, &pack_req))
    {
      sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
              "Authenticator does not match request!");
      return -1;
    }

    if(ipv6)
    {
      /* Set which radius server to use next */
      if(addr6.sin6_addr.s6_addr == ((struct sockaddr_in6 *)&this->hisaddr0)->sin6_addr.s6_addr)
        this->lastreply = 0;
      else
        this->lastreply = 1;
    }
    else
    {
      /* Set which radius server to use next */
      if(addr.sin_addr.s_addr == ((struct sockaddr_in *)&this->hisaddr0)->sin_addr.s_addr)
        this->lastreply = 0;
      else
        this->lastreply = 1;
    }
  }
  else
  {
    if(!this->coanocheck)
    {
      if(ipv6)
      {
        /* Check that reply is from correct address */
        if((addr6.sin6_addr.s6_addr != ((struct sockaddr_in6 *)&this->hisaddr0)->sin6_addr.s6_addr) &&
            (addr6.sin6_addr.s6_addr != ((struct sockaddr_in6 *)&this->hisaddr1)->sin6_addr.s6_addr))
        {
          sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
                  "Received radius reply from wrong address %.8x!",
                  addr6.sin6_addr.s6_addr);
          return -1;
        }
      }
      else
      {
        if((addr.sin_addr.s_addr != ((struct sockaddr_in *)&this->hisaddr0)->sin_addr.s_addr) &&
            (addr.sin_addr.s_addr != ((struct sockaddr_in *)&this->hisaddr1)->sin_addr.s_addr))
        {
          sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
                  "Received radius reply from wrong address %.8x!",
                  addr.sin_addr.s_addr);
          return -1;
        }
      }
    }
    if(radius_acctcheck(this, &pack))
    {
      sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
              "Authenticator did not match MD5 of packet!");
      return -1;
    }
  }

  /* TODO: Check consistency of attributes vs packet length */

  switch(pack.code)
  {
    case RADIUS_CODE_ACCESS_ACCEPT:
    case RADIUS_CODE_ACCESS_REJECT:
    case RADIUS_CODE_ACCESS_CHALLENGE:
    case RADIUS_CODE_DISCONNECT_ACK:
    case RADIUS_CODE_DISCONNECT_NAK:
    case RADIUS_CODE_STATUS_ACCEPT:
    case RADIUS_CODE_STATUS_REJECT:
      if(this->cb_auth_conf)
        return this->cb_auth_conf(this, &pack, &pack_req, cbp);
      else
        return 0;
      break;
    case RADIUS_CODE_ACCOUNTING_RESPONSE:
      if(this->cb_acct_conf)
        return this->cb_acct_conf(this, &pack, &pack_req, cbp);
      else
        return 0;
      break;
    case RADIUS_CODE_DISCONNECT_REQUEST:
    case RADIUS_CODE_COA_REQUEST:
      if(this->cb_coa_ind)
        return this->cb_coa_ind(this, &pack, &addr_ss);
      else
        return 0;
      break;
    default:
      sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
              "Received unknown radius packet %d!", pack.code);
      return -1;
  }

  sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
          "Received unknown radius packet %d!", pack.code);
  return -1;
}

int radius_proxy_ind(struct radius_t *this)
{
  int status = 0;
  struct radius_packet_t pack;
  struct sockaddr_storage addr;
  socklen_t fromlen = sizeof(addr);

  if(this->debug) printf("Received radius packet\n");

  if((status = recvfrom(this->proxyfd, &pack, sizeof(pack), 0,
                         (struct sockaddr *) &addr, &fromlen)) <= 0)
  {
    if(errno != EINTR)
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "recvfrom() failed");
    return -1;
  }

  if(status < RADIUS_HDRSIZE)
  {
    sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
            "Received radius packet which is too short: %d < %d!",
            status, RADIUS_HDRSIZE);
    return -1;
  }

  if(ntohs(pack.length) != status)
  {
    sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
            "Received radius packet with wrong length field %d != %d!",
            ntohs(pack.length), status);
    return -1;
  }

  /* Is this a known request? */
  if((this->cb_ind) &&
      ((pack.code == RADIUS_CODE_ACCESS_REQUEST) ||
       (pack.code == RADIUS_CODE_ACCOUNTING_REQUEST) ||
       (pack.code == RADIUS_CODE_DISCONNECT_REQUEST) ||
       (pack.code == RADIUS_CODE_STATUS_REQUEST)))
  {
    /* Check that request is from a known client */
    /* Any of the two servers or from one of the clients */
    if(addr.ss_family == AF_INET)
    {
      if((((struct sockaddr_in *)&addr)->sin_addr.s_addr & ((struct sockaddr_in *)&this->proxymask)->sin_addr.s_addr)!=
          ((struct sockaddr_in *)&this->proxyaddr)->sin_addr.s_addr)
      {
        sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
                "Received radius request from wrong address %.8x!",
                ((struct sockaddr_in *)&addr)->sin_addr.s_addr);
        return -1;
      }
    }
    else   /* IPv6 */
    {
      /*if((((struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr & ((struct sockaddr_in6 *)&this->proxymask)->sin6_addr.s6_addr)!=
        ((struct sockaddr_in6 *)&this->proxyaddr)->sin6_addr.s6_addr) {
        sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
        "Received radius request from wrong address %.8x!",
        ((struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr);
        return -1;
        }*/
    }
    return this->cb_ind(this, &pack, &addr);
  }

  sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
          "Received unknown radius packet %d!", pack.code);
  return -1;
}

