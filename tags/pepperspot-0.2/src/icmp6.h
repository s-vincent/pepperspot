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

/* $Id: icmp6.h 1.17 06/05/07 21:52:43+03:00 anttit@tcs.hut.fi $ */

#ifndef __ICMP6_H__
#define __ICMP6_H__ 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __APPLE__
#include <sys/socketvar.h>
#include <netinet/in_pcb.h>
#endif

#include <netinet/icmp6.h>
#include <netinet/ip6.h>

struct sock 
{
  int fd;
};

#define ICMP6_MAIN_SOCK -1

int if_mc_group(int sock, int ifindex, const struct in6_addr *mc_addr, int cmd);

int icmp6_init(void);

void icmp6_cleanup(void);

int icmp6_send(int oif, uint8_t hoplimit, const struct in6_addr *src,
    const struct in6_addr *dst, struct iovec *datav, size_t iovlen);

void *icmp6_create(struct iovec *iov, uint8_t type, uint8_t code);

struct ip6_hdr;

#endif

