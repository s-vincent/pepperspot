/*
 * PepperSpot -- The Next Generation Captive Portal
 * Copyright (C) 2008,  Thibault Van�on and Sebastien Vincent
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <pthread.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include "icmp6.h"
#include "util.h"
#include <assert.h>
/*
#include "debug.h" 
#include "conf.h"
*/
enum {
	ICMP6_DU = 0,
	ICMP6_PP = 1,
	ICMP6_RA = 3,
	ICMP6_NA = 4,
	ICMP6_DRQ = 5,
	ICMP6_DRP = 6,
	ICMP6_MPS = 7,
	ICMP6_MPA = 8,
	__ICMP6_SENTINEL = 9
};


static pthread_rwlock_t handler_lock;
static struct icmp6_handler *handlers[__ICMP6_SENTINEL + 1];

struct sock icmp6_sock;
static pthread_t icmp6_listener;

static inline int icmp6_type_map(uint8_t type)
{
	switch (type) {
	case ICMP6_DST_UNREACH:
		return ICMP6_DU;
	case ICMP6_PARAM_PROB:
		return ICMP6_PP;	
	case ND_ROUTER_ADVERT:
		return ICMP6_RA;
	case ND_NEIGHBOR_ADVERT:
		return ICMP6_NA;
	/*case MIP_HA_DISCOVERY_REQUEST:
		return ICMP6_DRQ;
	case MIP_HA_DISCOVERY_REPLY:
		return ICMP6_DRP;
	case MIP_PREFIX_SOLICIT:
		return ICMP6_MPS;
	case MIP_PREFIX_ADVERT:
		return ICMP6_MPA;
        */
	default:
		return __ICMP6_SENTINEL;
	}
}

static inline struct icmp6_handler *icmp6_handler_get(uint8_t type)
{
	return handlers[icmp6_type_map(type)]; 
}

void icmp6_handler_reg(uint8_t type, struct icmp6_handler *handler)
{
	int i = icmp6_type_map(type);

	assert(handler->next == NULL);

	pthread_rwlock_wrlock(&handler_lock);
	handler->next = handlers[i];
	handlers[i] = handler;
	pthread_rwlock_unlock(&handler_lock);
        printf("recv_na reg!\n");
}

void icmp6_handler_dereg(uint8_t type, struct icmp6_handler *handler)
{
	struct icmp6_handler **h = NULL; 
	int i = icmp6_type_map(type);
	pthread_rwlock_wrlock(&handler_lock);
	h = &handlers[i];
	while (*h) {
		if (*h == handler) {
			*h = handler->next;
			handler->next = NULL;
			break;
		}
		h = &(*h)->next;
	}
	pthread_rwlock_unlock(&handler_lock);
}

/**
 * if_mc_group - join or leave multicast group
 * @sock: socket
 * @ifindex: interface to join/leave
 * @mc_addr: multicast address
 * @cmd: join/leave command
 *
 * Join/leave multicast group on interface.  cmd must be either
 * IPV6_JOIN_GROUP or IPV6_LEAVE_GROUP.  Also turns off local
 * multicast loopback. 
 **/
int if_mc_group(int sock, int ifindex, const struct in6_addr *mc_addr, int cmd)
{
	unsigned int val = 0;
	struct ipv6_mreq mreq;
	int ret = 0;

	if (sock == ICMP6_MAIN_SOCK)
		sock = icmp6_sock.fd;

	memset(&mreq, 0, sizeof(mreq));
	mreq.ipv6mr_interface = ifindex;
	mreq.ipv6mr_multiaddr = *mc_addr;

	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 
			 &val, sizeof(int));

	if (ret < 0) return ret;

	return setsockopt(sock, IPPROTO_IPV6, cmd, &mreq, sizeof(mreq));
}

void *icmp6_listen(void *arg)
{
	uint8_t msg[MAX_PKT_LEN];
	struct sockaddr_in6 addr;
	struct in6_addr *saddr, *daddr = NULL;
	struct in6_pktinfo pkt_info;
	struct icmp6_hdr *ih = NULL;
	int iif = 0;
	int hoplimit = 0;
	unsigned int len = 0;
	struct icmp6_handler *h = NULL;
	
	/* To avoid unused parameter warning */
	arg = NULL; 

	/*	pthread_dbg("thread started"); */

        printf("Thread started\n");
	while (1) { 
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		len = icmp6_recv(icmp6_sock.fd, msg, sizeof(msg),
				 &addr, &pkt_info, &hoplimit);
		/* check if socket has closed */
		if (-len == EBADF)
			return NULL;
		/* common validity check */
		if (len < sizeof(struct icmp6_hdr))
			return NULL;
		saddr = &addr.sin6_addr;
		daddr = &pkt_info.ipi6_addr;
		iif = pkt_info.ipi6_ifindex;

		ih = (struct icmp6_hdr *)msg;
		/* multiplex to right handler */
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		pthread_rwlock_rdlock(&handler_lock);


		if ((h = icmp6_handler_get(ih->icmp6_type)) != NULL)
			h->recv(ih, len, saddr, daddr, iif, hoplimit);


		pthread_rwlock_unlock(&handler_lock);
        } 
        pthread_exit(NULL); 
}

int icmp6_init(void)
{
	struct icmp6_filter filter;
	int val = 0;

	icmp6_sock.fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (icmp6_sock.fd < 0) {
		syslog(LOG_ERR,
		       "Unable to open ICMPv6 socket! "
		       "Do you have root permissions?");
		return icmp6_sock.fd;
	}
	val = 1;
	if (setsockopt(icmp6_sock.fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, 
		       &val, sizeof(val)) < 0)
		return -1;
	if (setsockopt(icmp6_sock.fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
		       &val, sizeof(val)) < 0)
		return -1;
	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filter); 

        /* [SV] : we allow just the NA to determine if wireless client
         * is IPv6 ready (if he responds to our NS) 
         */
        ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filter);
/*
	if (is_ha()) {
		ICMP6_FILTER_SETPASS(MIP_PREFIX_SOLICIT, &filter);
		ICMP6_FILTER_SETPASS(MIP_HA_DISCOVERY_REQUEST, &filter);
		ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);
	}

	if (is_mn()) {
		ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);
		ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filter);
		ICMP6_FILTER_SETPASS(MIP_PREFIX_ADVERT, &filter);
		ICMP6_FILTER_SETPASS(MIP_HA_DISCOVERY_REPLY, &filter);
		ICMP6_FILTER_SETPASS(ICMP6_PARAM_PROB, &filter);
	}
*/

	if (setsockopt(icmp6_sock.fd, IPPROTO_ICMPV6, ICMP6_FILTER, 
		       &filter, sizeof(struct icmp6_filter)) < 0)
		return -1;
	val = 2;
	if (setsockopt(icmp6_sock.fd, IPPROTO_RAW, IPV6_CHECKSUM, 
		       &val, sizeof(val)) < 0)
		return -1;
	/* create ICMP listener thread */
  /*      pthread_mutexattr_init(&mattrs); 
        pthread_mutexattr_settype(&mattrs, PTHREAD_MUTEX_FAST_NP); 
         
	if (pthread_mutex_init(&icmp6_sock.send_mutex, &mattrs) ||
	    pthread_rwlock_init(&handler_lock, NULL) ||
	    pthread_create(&icmp6_listener, NULL, icmp6_listen, NULL))
		return -1;
	*/
        pthread_create(&icmp6_listener, NULL, icmp6_listen, NULL);
	return 0;
}

void *icmp6_create(struct iovec *iov, uint8_t type, uint8_t code)
{
	struct icmp6_hdr *hdr = NULL;
	int msglen = 0;

	switch (type) {
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
	if (hdr == NULL)
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
	if (oif > 0)
		pinfo.ipi6_ifindex = oif;

	cmsglen = CMSG_SPACE(sizeof(pinfo));
	cmsg = malloc(cmsglen);
	if (cmsg == NULL) {
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

	// pthread_mutex_lock(&icmp6_sock.send_mutex); 
	setsockopt(icmp6_sock.fd, IPPROTO_IPV6, IPV6_PKTINFO,
		   &on, sizeof(int));
	setsockopt(icmp6_sock.fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 
		   &hops, sizeof(hops));
	setsockopt(icmp6_sock.fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 
		   &hops, sizeof(hops));

	ret = sendmsg(icmp6_sock.fd, &msg, 0);
	if (ret < 0)
		printf("sendmsg: %s\n", strerror(errno));

	//pthread_mutex_unlock(&icmp6_sock.send_mutex); 

	free(cmsg);

	return ret;
}

#define CMSG_BUF_LEN 128

ssize_t icmp6_recv(int sockfd, unsigned char *msg, size_t msglen,
		   struct sockaddr_in6 *addr, struct in6_pktinfo *pkt_info,
		   int *hoplimit)
{
	struct msghdr mhdr;
	struct cmsghdr *cmsg = NULL;
	struct iovec iov;
	static unsigned char chdr[CMSG_BUF_LEN];
	ssize_t len = 0;

	iov.iov_len = msglen;
	iov.iov_base = (unsigned char *) msg;

	mhdr.msg_name = (void *)addr;
	mhdr.msg_namelen = sizeof(struct sockaddr_in6);
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = (void *)chdr;
	mhdr.msg_controllen = CMSG_BUF_LEN;

	if ((len = recvmsg(sockfd, &mhdr, 0)) < 0)
		return -errno;

        for (cmsg = CMSG_FIRSTHDR(&mhdr); cmsg; 
	     cmsg = CMSG_NXTHDR(&mhdr, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6)
			continue;
		switch(cmsg->cmsg_type) {
		case IPV6_HOPLIMIT:
			*hoplimit = *(int *)CMSG_DATA(cmsg);
			break;
		case IPV6_PKTINFO:
			memcpy(pkt_info, CMSG_DATA(cmsg), sizeof(*pkt_info));
			break;
		}
	}
	return len;
}

struct ip6_subopt_hdr {
	u_int8_t	opttype;
	u_int8_t	optlen;
};

#if 0
int icmp6_parse_data(struct ip6_hdr *ip6h, unsigned int len, 
		     struct in6_addr **lhoa, struct in6_addr **rhoa)
{
	uint8_t *data = (uint8_t *)ip6h;
	unsigned int hoff = sizeof(struct ip6_hdr);
	uint8_t htype;

	if (len < hoff)
		return -1;

	htype = ip6h->ip6_nxt;

	/* The minumum length of an extension header is eight octets,
	   so check that we at least have room for that */
	while (hoff + 8 < len) {
		struct ip6_ext *h = (struct ip6_ext *) (data + hoff);
		unsigned int hlen = (h->ip6e_len + 1) << 3;

		if (htype != IPPROTO_DSTOPTS && 
		    htype != IPPROTO_ROUTING &&
		    htype != IPPROTO_HOPOPTS)
			return 0;

		if (len < hoff + hlen)
			return -1;

		if (htype == IPPROTO_DSTOPTS) {
			uint8_t *odata = (uint8_t *) h;
			uint32_t ooff = 2;
			while (ooff < hlen) {
				struct ip6_subopt_hdr *o;
				o = (struct ip6_subopt_hdr *) (odata + ooff);
				if (o->opttype == IP6OPT_PAD0) {
					ooff++;
					continue;
				}
				/* invalid TLV option length */
				if (hlen < ooff + 2 ||
				    hlen < ooff + 2 + o->optlen)
					break;
				if (o->opttype == IP6OPT_HOME_ADDRESS &&
				    o->optlen == sizeof(struct in6_addr)) {
					*lhoa = (struct in6_addr *) (o + 1);
					/*dbg("HAO %x:%x:%x:%x:%x:%x:%x:%x\n",
					    NIP6ADDR(*lhoa));*/
					break;
				}
				ooff += 2 + o->optlen;
			}
		} else if (htype == IPPROTO_ROUTING) {
			struct ip6_rthdr2 *rth = (struct ip6_rthdr2 *) h;
			if (rth->ip6r2_type == 2 && 
			rth->ip6r2_len == 2 && rth->ip6r2_segleft == 1)
				*rhoa = &rth->ip6r2_homeaddr;
			/*
                         * dbg("RTH2 %x:%x:%x:%x:%x:%x:%x:%x\n", NIP6ADDR(*rhoa));
                         */
		} else if (htype != IPPROTO_HOPOPTS) {
			return 0;
		}
		hoff += hlen;
		htype = h->ip6e_nxt;
	}
	return 0;
}
#endif

void icmp6_cleanup(void)
{
	close(icmp6_sock.fd);
	pthread_cancel(icmp6_listener);
	pthread_join(icmp6_listener, NULL);
        
}
