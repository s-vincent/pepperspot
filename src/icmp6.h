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

/* $Id: icmp6.h 1.17 06/05/07 21:52:43+03:00 anttit@tcs.hut.fi $ */

#ifndef __ICMP6_H__
#define __ICMP6_H__ 1

#include <netinet/icmp6.h>

struct icmp6_handler {
	struct icmp6_handler *next;
	void (* recv)(const struct icmp6_hdr *ih, 
		      ssize_t len, 
		      const struct in6_addr *src,
		      const struct in6_addr *dst,
		      int iif,
		      int hoplimit);
};

struct sock 
{
/*   pthread_mutex_t send_mutex;  */
  int fd;
};

#define ICMP6_MAIN_SOCK -1

int if_mc_group(int sock, int ifindex, const struct in6_addr *mc_addr, int cmd);

/*
void icmp6_handler_reg(uint8_t type, struct icmp6_handler *handler);
void icmp6_handler_dereg(uint8_t type, struct icmp6_handler *handler);
*/

int icmp6_init(void);
void icmp6_cleanup(void);

int icmp6_send(int oif, uint8_t hoplimit, const struct in6_addr *src,
	       const struct in6_addr *dst, struct iovec *datav, size_t iovlen);

ssize_t icmp6_recv(int sock, unsigned char *msg, size_t msglen,
		   struct sockaddr_in6 *addr, struct in6_pktinfo *pkt_info,
		   int *hoplimit);

void *icmp6_create(struct iovec *iov, uint8_t type, uint8_t code);

struct ip6_hdr;

int icmp6_parse_data(struct ip6_hdr *ip6h, unsigned int len, 
		     struct in6_addr **lhoa, struct in6_addr **rhoa);

/* void* icmp6_listen(void* arg); */

#endif

