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
 * $Id: icmp6.c 1.42 06/05/06 15:15:47+03:00 anttit@tcs.hut.fi $
 *
 * This file is part of the MIPL Mobile IPv6 for Linux.
 *
 * Authors: Antti Tuominen <anttit@tcs.hut.fi>
 *          Ville Nuorvala <vnuorval@tcs.hut.fi>
 *
 * Copyright 2003-2005 Go-Core Project
 * Copyright 2003-2006 Helsinki University of Technology
 *
 * MIPL Mobile IPv6 for Linux is free software; you can redistribute
 * it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; version 2 of
 * the License.
 *
 * MIPL Mobile IPv6 for Linux is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MIPL Mobile IPv6 for Linux; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA.
 */

/**
 * \file icmp6.c
 * \brief ICMPv6 related function (send/receive).
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <assert.h>

#include "icmp6.h"

#include "util.h"
/*
#include "debug.h"
#include "conf.h"
*/

/**
 * \var icmp6_sock
 * \brief ICMPv6 socket descriptor.
 */
struct icmpv6_socket icmp6_sock;

int if_mc_group(int sock, int ifindex, const struct in6_addr *mc_addr, int cmd)
{
  unsigned int val = 0;
  struct ipv6_mreq mreq;
  int ret = 0;

  if(sock == -1)
    sock = icmp6_sock.fd;

  memset(&mreq, 0, sizeof(mreq));
  mreq.ipv6mr_interface = ifindex;
  mreq.ipv6mr_multiaddr = *mc_addr;

  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                   &val, sizeof(int));

  if(ret < 0) return ret;

  return setsockopt(sock, IPPROTO_IPV6, cmd, &mreq, sizeof(mreq));
}

int icmp6_init(void)
{
  struct icmp6_filter filter;
  int val = 0;

  icmp6_sock.fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if(icmp6_sock.fd < 0)
  {
    syslog(LOG_ERR,
           "Unable to open ICMPv6 socket! "
           "Do you have root permissions?");
    return icmp6_sock.fd;
  }
  val = 1;
  if(setsockopt(icmp6_sock.fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                 &val, sizeof(val)) < 0)
    return -1;
  if(setsockopt(icmp6_sock.fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
                 &val, sizeof(val)) < 0)
    return -1;
  ICMP6_FILTER_SETBLOCKALL(&filter);
  ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filter);

  if(setsockopt(icmp6_sock.fd, IPPROTO_ICMPV6, ICMP6_FILTER,
                 &filter, sizeof(struct icmp6_filter)) < 0)
    return -1;
  val = 2;
  if(setsockopt(icmp6_sock.fd, IPPROTO_RAW, IPV6_CHECKSUM,
                 &val, sizeof(val)) < 0)
    return -1;

  return 0;
}

void *icmp6_create(struct iovec *iov, uint8_t type, uint8_t code)
{
  struct icmp6_hdr *hdr = NULL;
  int msglen = 0;

  switch(type)
  {
    case ICMP6_DST_UNREACH:
    case ICMP6_PACKET_TOO_BIG:
    case ICMP6_TIME_EXCEEDED:
    case ICMP6_PARAM_PROB:
      msglen = sizeof(struct icmp6_hdr);
      break;
    case ND_ROUTER_SOLICIT:
      msglen = sizeof(struct nd_router_solicit);
      break;
    case ND_ROUTER_ADVERT:
      msglen = sizeof(struct nd_router_advert);
      break;
    case ND_NEIGHBOR_SOLICIT:
      msglen = sizeof(struct nd_neighbor_solicit);
      break;
    case ND_NEIGHBOR_ADVERT:
      msglen = sizeof(struct nd_neighbor_advert);
      break;
    case ND_REDIRECT:
      msglen = sizeof(struct nd_redirect);
      break;
    default:
      msglen = sizeof(struct icmp6_hdr);
  }
  hdr = malloc(msglen);
  if(hdr == NULL)
    return NULL;

  memset(hdr, 0, msglen);
  hdr->icmp6_type = type;
  hdr->icmp6_code = code;
  iov->iov_base = hdr;
  iov->iov_len = msglen;

  return hdr;
}

int icmp6_send(int oif, uint8_t hoplimit,
               const struct in6_addr *src, const struct in6_addr *dst,
               struct iovec *datav, size_t iovlen)
{
  struct sockaddr_in6 daddr;
  struct msghdr msg;
  struct cmsghdr *cmsg = NULL;
  struct in6_pktinfo pinfo;
  int cmsglen, ret = 0, on = 1, hops;

  hops = (hoplimit == 0) ? 64 : hoplimit;

  memset(&daddr, 0, sizeof(struct sockaddr_in6));
  daddr.sin6_family = AF_INET6;
  daddr.sin6_addr = *dst;
  daddr.sin6_port = htons(IPPROTO_ICMPV6);

  memset(&pinfo, 0, sizeof(pinfo));
  pinfo.ipi6_addr = *src;
  if(oif > 0)
    pinfo.ipi6_ifindex = oif;

  cmsglen = CMSG_SPACE(sizeof(pinfo));
  cmsg = malloc(cmsglen);
  if(cmsg == NULL)
  {
    /* dbg("out of memory\n"); */
    return -ENOMEM;
  }
  cmsg->cmsg_len = CMSG_LEN(sizeof(pinfo));
  cmsg->cmsg_level = IPPROTO_IPV6;
  cmsg->cmsg_type = IPV6_PKTINFO;
  memcpy(CMSG_DATA(cmsg), &pinfo, sizeof(pinfo));

  msg.msg_control = cmsg;
  msg.msg_controllen = cmsglen;
  msg.msg_iov = datav;
  msg.msg_iovlen = iovlen;
  msg.msg_name = (void *)&daddr;
  msg.msg_namelen = CMSG_SPACE(sizeof(struct in6_pktinfo));

  setsockopt(icmp6_sock.fd, IPPROTO_IPV6, IPV6_PKTINFO,
             &on, sizeof(int));
  setsockopt(icmp6_sock.fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
             &hops, sizeof(hops));
  setsockopt(icmp6_sock.fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
             &hops, sizeof(hops));

  ret = sendmsg(icmp6_sock.fd, &msg, 0);
  if(ret < 0)
    printf("sendmsg: %s\n", strerror(errno));

  free(cmsg);

  return ret;
}

void icmp6_cleanup(void)
{
  close(icmp6_sock.fd);
}

