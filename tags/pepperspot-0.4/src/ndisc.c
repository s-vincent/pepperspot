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
 * $Id: ndisc.c 1.56 06/05/06 15:15:47+03:00 anttit@tcs.hut.fi $
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
 * \file ndisc.c
 * \brief IPv6 neighbor discovery.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "icmp6.h"
#include "util.h"
#include "ndisc.h"
/* #include "rtnl.h" */

#if defined (__FreeBSD__)   || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__APPLE__)
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <ifaddrs.h>
#endif

#if defined(__linux__)
/* #include <linux/if.h> */
#endif

/**
 * \var in6addr_all_nodes_mc
 * \brief Multicast address for all nodes (FF02::3).
 */
static const struct in6_addr in6addr_all_nodes_mc = IN6ADDR_ALL_NODES_MC_INIT;

/**
 * \var in6addr_all_routers_mc
 * \brief Multicast address for all routers (FF02::2).
 */
static const struct in6_addr in6addr_all_routers_mc = IN6ADDR_ALL_ROUTERS_MC_INIT;

/**
 * \brief Create an ICMPv6 option.
 * \param iov vector
 * \param type ICMPv6 type
 * \param len length
 * \param value data
 * \return header or NULL if failure
 */
static struct nd_opt_hdr *nd_opt_create(struct iovec *iov, uint8_t type,
                                        uint16_t len, uint8_t *value)
{
  struct nd_opt_hdr *opt = NULL;
  int hlen = sizeof(struct nd_opt_hdr);

  /* len must be lenght(value) in bytes */
  opt = malloc(len + hlen);
  if(opt == NULL)
    return NULL;

  opt->nd_opt_type = type;
  opt->nd_opt_len = (len + hlen) >> 3;
  memcpy(opt + 1, value, len);
  iov->iov_base = opt;
  iov->iov_len = len + hlen;

  return opt;
}

/**
 * \brief Get L2 address of an interface.
 * \param ifindex interface index
 * \param addr resulting address will be filled in
 * \return 0 if success, -1 otherwise
 */
static int nd_get_l2addr(int ifindex, uint8_t *addr)
{
  int res = 0;
#ifdef __linux__
  struct ifreq ifr;
  int fd = -1;

  fd = socket(PF_PACKET, SOCK_DGRAM, 0);
  if(fd < 0) return -1;

  memset(&ifr, 0, sizeof(ifr));
  if_indextoname(ifindex, ifr.ifr_name);
  if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
  {
    close(fd);
    return -1;
  }
  if((res = nd_get_l2addr_len(ifr.ifr_hwaddr.sa_family)) < 0)
    printf("Unsupported sa_family %d.\n", ifr.ifr_hwaddr.sa_family);
  else if(res > 0)
    memcpy(addr, ifr.ifr_hwaddr.sa_data, res);

  close(fd);

#elif defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__APPLE__)
  struct ifaddrs *ifap = NULL;
  struct ifaddrs *ifa = NULL;
  struct sockaddr_dl *sdl = NULL;
  char ifname[IFNAMSIZ];

  if_indextoname(ifindex, ifname);

  if(getifaddrs(&ifap))
  {
    return -1;
  }

  ifa = ifap;
  while(ifa)
  {
    if((strcmp(ifa->ifa_name, ifname) == 0) && (ifa->ifa_addr->sa_family == AF_LINK))
    {
      sdl = (struct sockaddr_dl *)ifa->ifa_addr;
      if((res = nd_get_l2addr_len(sdl->sdl_type)) < 0)
      {
        printf("Unsupported sa_family %d.\n", sdl->sdl_type);
      }
      else if(res > 0)
      {
        memcpy(addr, LLADDR(sdl), res);
      }

      freeifaddrs(ifap);
      return res;
    }
    ifa = ifa->ifa_next;
  }
  freeifaddrs(ifap);
  return -1;

#endif
  return res;
}

int ndisc_send_na(int ifindex, const struct in6_addr *src,
                  const struct in6_addr *dst,
                  const struct in6_addr *target, uint32_t flags)
{
  struct nd_neighbor_advert *na = NULL;
  struct iovec iov[2];
  uint8_t l2addr[32];
  int len = 0;

  memset(iov, 0, sizeof(iov));

  if((len = nd_get_l2addr(ifindex, l2addr)) < 0)
    return -EINVAL;

  na = icmp6_create(iov, ND_NEIGHBOR_ADVERT, 0);

  if(na == NULL) return -ENOMEM;

  if(len > 0 && nd_opt_create(&iov[1], ND_OPT_TARGET_LINKADDR, len, l2addr) == NULL)
  {
    free_iov_data(iov, 1);
    return -ENOMEM;
  }
  na->nd_na_target = *target;
  na->nd_na_flags_reserved = flags;

  icmp6_send(ifindex, 255, src, dst, iov, 2);
  free_iov_data(iov, 2);
  return 0;
}

