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
 * DHCP library functions.
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
 * Copyright (C) 2003, 2004, 2005, 2006 Mondru AB.
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

/**
 * \file dhcp.c
 * \brief Packet authenticator and DHCP module.
 */

/* Usage
 *
 * The library is initialised by calling dhcp_new(), which
 * initialises a dhcp_t struct that is used for all subsequent calls
 * to the library. Ressources are freed by calling dhcp_free().
 *
 */

/* TODO
 *
 * Port to FreeBSD.
 * - Mainly concerns Ethernet stuff.
 *
 * Move EAPOL stuff to separate files
 *
 * Change static memory allocation to malloc
 * - Mainly concerns newconn() and freeconn()
 * - Wait until code is bug free.
 */

#include <stdlib.h>
#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h> /* ISO C99 types */
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#include "util.h"
#include "ndisc.h"

#if defined(__linux__)
/* #include <linux/if.h> */
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#elif defined (__FreeBSD__)   || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__APPLE__)
#include <net/if.h>
#include <net/bpf.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <ifaddrs.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif

#include <net/if_arp.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "../config.h"
#include "syserr.h"
#include "ippool.h"
#include "iphash.h"
#include "dhcp.h"
#include "lookup.h"

#ifndef timercmp
/**
 * \def timercmp
 * \brief timercmp is BSD specific so it is
 * a replacement.
 */
#define timercmp(a, b, CMP) \
  (((a)->tv_sec == (b)->tv_sec) ?  \
   ((a)->tv_usec CMP(b)->tv_usec) :\
   ((a)->tv_sec CMP(b)->tv_sec))
#endif

#ifdef NAIVE
const static int paranoid = 0; /**< Trust that the program has no bugs */
#else
static const int paranoid = 1; /**< Check for errors which cannot happen */
#endif

/**
 * \brief Generate an IPv4 header checksum.
 * \param pack IPv4 packet
 * \return 0
 */
static int dhcp_ip_check(struct dhcp_ippacket_t *pack)
{
  int i = 0;
  uint32_t sum = 0;
  pack->iph.check = 0;

  for(i = 0; i < (pack->iph.ihl * 2); i++)
  {
    sum += ((uint16_t*) &pack->iph)[i];
  }
  while(sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  pack->iph.check = ~sum;
  return 0;
}

/**
 * \brief Generate an UDP header checksum.
 * \param pack Complete packet (IPv4 + transport protocol + data)
 * \return 0 if success, -1 otherwise (packet too long)
 */
static int dhcp_udp_check(struct dhcp_fullpacket_t *pack)
{
  int i = 0;
  uint32_t sum = 0;
  int udp_len = ntohs(pack->udph.len);

  pack->udph.check = 0;

  if(udp_len > DHCP_UDP_HLEN + DHCP_LEN)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Length of dhcp packet larger then %d: %d",
            DHCP_UDP_HLEN + DHCP_LEN, udp_len);
    return -1; /* Packet too long */
  }

  /* Sum UDP header and payload */
  for(i = 0; i < (udp_len / 2); i++)
  {
    sum += ((uint16_t*) &pack->udph)[i];
  }

  /* Sum any uneven payload octet */
  if(udp_len & 0x01)
  {
    sum += ((uint8_t*) &pack->udph)[udp_len - 1];
  }

  /* Sum both source and destination address */
  for(i = 0; i < 4; i++)
  {
    uint32_t* saddr = &pack->iph.saddr;
    sum += ((uint16_t*)saddr)[i];
  }

  /* Sum both protocol and udp_len (again) */
  sum = sum + pack->udph.len + ((pack->iph.protocol << 8) & 0xFF00);

  while(sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  pack->udph.check = ~sum;

  return 0;
}

/**
 * \brief Generate an TCP header checksum for IPv6 packet.
 * \param pack Complete packet (IPv6 + transport protocol + data)
 * \param length length of packet
 * \return 0 if success, -1 otherwise (packet too long)
 */
static int dhcp_tcp_checkv6(struct dhcp_ipv6packet_t *pack, int length)
{
  int i = 0;
  uint32_t sum = 0;
  struct dhcp_tcphdr_t *tcph = NULL;
  int tcp_len = 0;

  if(ntohs(pack->ip6h.payload_length) > (length - DHCP_ETH_HLEN))
    return -1; /* Wrong length of packet */

  tcp_len = ntohs(pack->ip6h.payload_length);

  if(tcp_len < 20) /* TODO */
    return -1; /* Packet too short */

  tcph = (struct dhcp_tcphdr_t*) pack->payload;
  tcph->check = 0;

  /* Sum TCP header and payload */
  for(i = 0 ; i < (tcp_len / 2) ; i++)
  {
    sum += ((uint16_t*) pack->payload)[i];
  }

  /* Sum any uneven payload octet */
  if(tcp_len & 0x01)
  {
    sum += ((uint8_t*) pack->payload)[tcp_len - 1];
  }

  /* Sum both source and destination address */
  for(i = 0 ; i < 16 ; i++)
  {
    sum += ((uint16_t*) &pack->ip6h.src_addr)[i];
  }

  /* Sum both protocol and tcp_len */
  sum = sum + htons(tcp_len) + ((pack->ip6h.next_header << 8) & 0xFF00);

  while(sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  tcph->check = ~sum;

  return 0;
}

#if 0

/**
 * \brief Generate UDP checksum for IPv6 packet.
 * \param pack IPv6 packet
 * \param length length of packet
 * \return 0 if success, -1 otherwise
 */
static int dhcp_udp_checkv6(struct dhcp_ipv6packet_t *pack, int length)
{
  int i = 0;
  uint32_t sum = 0;
  struct dhcp_udphdr_t *udph;
  int udp_len = 0;

  udph = (struct dhcp_udphdr_t*) pack->payload;
  udph->check = 0;

  if(ntohs(pack->ip6h.payload_length) > (length - DHCP_ETH_HLEN))
    return -1; /* Wrong length of packet */

  udp_len = ntohs(pack->ip6h.payload_length);

  /* Sum UDP header and payload */
  for(i = 0; i < (udp_len / 2); i++)
  {
    sum += ((uint16_t*) pack->payload)[i];
  }

  /* Sum any uneven payload octet */
  if(udp_len & 0x01)
  {
    sum += ((uint8_t*) pack->payload)[udp_len - 1];
  }

  /* Sum both source and destination address */
  for(i = 0; i < 4; i++)
  {
    sum += ((uint16_t*) &pack->ip6h.src_addr)[i];
  }

  /* Sum both protocol and udp_len (again) */
  sum = sum + udph->len + ((pack->ip6h.next_header << 8) & 0xFF00);

  while(sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  udph->check = ~sum;

  return 0;
}

#endif

/**
 * \brief Generate an TCP header checksum.
 * \param pack IPv4 packet
 * \param length length of packet
 * \return 0 if success, -1 otherwise (packet too long)
 */
static int dhcp_tcp_check(struct dhcp_ippacket_t *pack, int length)
{
  int i = 0;
  uint32_t sum = 0;
  struct dhcp_tcphdr_t *tcph;
  int tcp_len = 0;

  if(ntohs(pack->iph.tot_len) > (length - DHCP_ETH_HLEN))
    return -1; /* Wrong length of packet */

  tcp_len = ntohs(pack->iph.tot_len) - pack->iph.ihl * 4;

  if(tcp_len < 20) /* TODO */
    return -1; /* Packet too short */

  tcph = (struct dhcp_tcphdr_t*) pack->payload;
  tcph->check = 0;

  /* Sum TCP header and payload */
  for(i = 0; i < (tcp_len / 2); i++)
  {
    sum += ((uint16_t*) pack->payload)[i];
  }

  /* Sum any uneven payload octet */
  if(tcp_len & 0x01)
  {
    sum += ((uint8_t*) pack->payload)[tcp_len - 1];
  }

  /* Sum both source and destination address */
  for(i = 0; i < 4; i++)
  {
    uint32_t* saddr=&pack->iph.saddr;
    sum += ((uint16_t*) saddr)[i];
  }

  /* Sum both protocol and tcp_len */
  sum = sum + htons(tcp_len) + ((pack->iph.protocol << 8) & 0xFF00);

  while(sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  tcph->check = ~sum;

  return 0;
}

/**
 * \brief Set interface flags.
 * \param devname interface name
 * \param flags interface flags to set
 * \return 0 if success, - 1 otherwise
 */
static int dhcp_sifflags(char const *devname, int flags)
{
  struct ifreq ifr;
  int fd = -1;

  memset(&ifr, '\0', sizeof(ifr));
  ifr.ifr_flags = flags;
  strncpy(ifr.ifr_name, devname, IFNAMSIZ);
  ifr.ifr_name[IFNAMSIZ - 1] = 0; /* Make sure to terminate */
  if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "socket() failed");
  }
  if(ioctl(fd, SIOCSIFFLAGS, &ifr))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "ioctl(SIOCSIFFLAGS) failed");
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

/**
 * \brief Get interface flags.
 * \param devname interface name
 * \param flags interface flags will be set in it
 * \return 0 if success, - 1 otherwise
 */
static int dhcp_gifflags(char const *devname, int *flags)
{
  struct ifreq ifr;
  int fd = -1;

  memset(&ifr, '\0', sizeof(ifr));
  strncpy(ifr.ifr_name, devname, IFNAMSIZ);
  ifr.ifr_name[IFNAMSIZ - 1] = 0; /* Make sure to terminate */
  if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "socket() failed");
  }
  if(ioctl(fd, SIOCGIFFLAGS, &ifr))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "ioctl(SIOCSIFFLAGS) failed");
    close(fd);
    return -1;
  }
  close(fd);
  *flags = ifr.ifr_flags;

  return 0;
}

/**
 * \brief Set IPv4 paramters on interface.
 * \param devname interface name
 * \param addr IPv4 address
 * \param dstaddr IPv4 destination address
 * \param netmask IPv4 netmask
 * \return 0 if success, -1 otherwise
 */
static int dhcp_setaddr(char const *devname,
                        struct in_addr *addr,
                        struct in_addr *dstaddr,
                        struct in_addr *netmask)
{
  struct ifreq ifr;
  int fd = -1;

  memset(&ifr, '\0', sizeof(ifr));
  ifr.ifr_addr.sa_family = AF_INET;
  ifr.ifr_dstaddr.sa_family = AF_INET;

#if defined(__linux__)
  ifr.ifr_netmask.sa_family = AF_INET;

#elif defined(__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__APPLE__)
  ((struct sockaddr_in *) &ifr.ifr_addr)->sin_len =
    sizeof(struct sockaddr_in);
  ((struct sockaddr_in *) &ifr.ifr_dstaddr)->sin_len =
    sizeof(struct sockaddr_in);
#endif

  strncpy(ifr.ifr_name, devname, IFNAMSIZ);
  ifr.ifr_name[IFNAMSIZ - 1] = 0; /* Make sure to terminate */

  /* Create a channel to the NET kernel. */
  if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "socket() failed");
    return -1;
  }

  if(addr)   /* Set the interface address */
  {
    ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = addr->s_addr;
    if(ioctl(fd, SIOCSIFADDR, (void *) &ifr) < 0)
    {
      if(errno != EEXIST)
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, errno,
                "ioctl(SIOCSIFADDR) failed");
      }
      else
      {
        sys_err(LOG_WARNING, __FILE__, __LINE__, errno,
                "ioctl(SIOCSIFADDR): Address already exists");
      }
      close(fd);
      return -1;
    }
  }

  if(dstaddr)   /* Set the destination address */
  {
    ((struct sockaddr_in *) &ifr.ifr_dstaddr)->sin_addr.s_addr =
      dstaddr->s_addr;
    if(ioctl(fd, SIOCSIFDSTADDR, &ifr) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "ioctl(SIOCSIFDSTADDR) failed");
      close(fd);
      return -1;
    }
  }

  if(netmask)   /* Set the netmask */
  {
#if defined(__linux__)
    ((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr =
      netmask->s_addr;

#elif defined(__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__APPLE__)
    ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr =
      netmask->s_addr;

#elif defined(__sun__)
    ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr =
      netmask->s_addr;
#else
#error  "Unknown platform!" 
#endif

    if(ioctl(fd, SIOCSIFNETMASK, (void *) &ifr) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "ioctl(SIOCSIFNETMASK) failed");
      close(fd);
      return -1;
    }
  }

  close(fd);

  /* On linux the route to the interface is set automatically
     on FreeBSD we have to do this manually */

  /* TODO: How does it work on Solaris? */

#if defined(__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__APPLE__)
  return dhcp_sifflags(devname, IFF_UP | IFF_RUNNING);  /* TODO */
  /*return tun_addroute(this, addr, addr, netmask);*/
#else
  return dhcp_sifflags(devname, IFF_UP | IFF_RUNNING);
#endif
}

#if defined(__linux__)

int dhcp_getmac(const char *ifname, unsigned char *macaddr)
{
  int fd = -1;
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));

  /* Create socket */
  if((fd = socket(PF_PACKET, SOCK_RAW, htons(DHCP_ETH_IP))) < 0)
  {
    if(errno == EPERM)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "Cannot create raw socket. Must be root.");
      return -1;
    }
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "socket(domain=%d, protocol=%lx, protocol=%d) failed",
            PF_PACKET, SOCK_RAW, DHCP_ETH_IP);
    return -1;
  }

  /* Get the MAC address of our interface */
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
  if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "ioctl(d=%d, request=%d) failed",
            fd, SIOCGIFHWADDR);
    close(fd);
    return -1;
  }
  memcpy(macaddr, ifr.ifr_hwaddr.sa_data, DHCP_ETH_ALEN);
  if(ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Not Ethernet: %.16s", ifname);
    close(fd);
    return -1;
  }

  if(macaddr[0] & 0x01)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Ethernet has broadcast or multicast address: %.16s", ifname);
    close(fd);
    return -1;
  }

  close(fd);
  return 0;
}

/**
 * \brief Open an Ethernet interface.
 *
 * As an option the interface can be set in
 * promisc mode. If not null macaddr and ifindex are filled with the
 * interface mac address and index.
 * \param ifname interface name
 * \param protocol layer 3 protocol number
 * \param promisc set or not promiscuous mode
 * \param usemac use the macaddr instead of the interface own MAC address
 * \param ifindex interface index will be filled in it
 * \return socket descriptor if success, -1 otherwise
 */
static int dhcp_open_eth(char const *ifname, uint16_t protocol, int promisc,
                         int usemac, unsigned char *macaddr, int *ifindex)
{
  int fd = -1;
  int option = 1;
  struct ifreq ifr;
  struct packet_mreq mr;
  struct sockaddr_ll sa;
  memset(&ifr, 0, sizeof(ifr));

  printf("Open socket for protocol %x\n", protocol);

  /* Create socket */
  if((fd = socket(PF_PACKET, SOCK_RAW, htons(protocol))) < 0)
  {
    if(errno == EPERM)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "Cannot create raw socket. Must be root.");
    }
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "socket(domain=%d, protocol=%lx, protocol=%d) failed",
            PF_PACKET, SOCK_RAW, protocol);
  }

  /* Enable reception and transmission of broadcast frames */
  if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &option, sizeof(option)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "setsockopt(s=%d, level=%d, optname=%d, optlen=%d) failed",
            fd, SOL_SOCKET, SO_BROADCAST, sizeof(option));
  }

  /* Get the MAC address of our interface */
  if((!usemac) && (macaddr))
  {
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "ioctl(d=%d, request=%d) failed",
              fd, SIOCGIFHWADDR);
    }
    memcpy(macaddr, ifr.ifr_hwaddr.sa_data, DHCP_ETH_ALEN);
    if(ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Not Ethernet: %.16s", ifname);
    }

    if(macaddr[0] & 0x01)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Ethernet has broadcast or multicast address: %.16s", ifname);
    }
  }

  /* Verify that MTU = ETH_DATA_LEN */
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
  if(ioctl(fd, SIOCGIFMTU, &ifr) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "ioctl(d=%d, request=%d) failed",
            fd, SIOCGIFMTU);
  }
  if(ifr.ifr_mtu != ETH_DATA_LEN)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "MTU does not match EHT_DATA_LEN: %d %d",
            ifr.ifr_mtu, ETH_DATA_LEN);
  }

  /* Get ifindex */
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
  if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "ioctl(SIOCFIGINDEX) failed");
  }
  if(ifindex)
    *ifindex = ifr.ifr_ifindex;

  /* Set interface in promisc mode */
  if(promisc)
  {
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifr.ifr_ifindex;
    mr.mr_type =  PACKET_MR_PROMISC;
    if(setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                   (char *)&mr, sizeof(mr)) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "setsockopt(s=%d, level=%d, optname=%d, optlen=%d) failed",
              fd, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, sizeof(mr));
    }
  }

  /* Bind to particular interface */
  memset(&sa, 0, sizeof(sa));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(protocol);
  sa.sll_ifindex = ifr.ifr_ifindex;
  if(bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "bind(sockfd=%d) failed", fd);
  }
  return fd;
}

#elif defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__APPLE__)

/**
 * \brief Get MAC address for *BSD.
 * \param ifname interface name
 * \param macaddr MAC address will be filled in it
 * \return 0 if success, -1 otherwise
 */
int dhcp_getmac(const char *ifname, unsigned char *macaddr)
{
  struct ifaddrs *ifap = NULL;
  struct ifaddrs *ifa = NULL;
  struct sockaddr_dl *sdl = NULL;

  if(getifaddrs(&ifap))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno, "getifaddrs() failed!");
    return -1;
  }

  ifa = ifap;
  while(ifa)
  {
    if((strcmp(ifa->ifa_name, ifname) == 0) &&
        (ifa->ifa_addr->sa_family == AF_LINK))
    {
      sdl = (struct sockaddr_dl *)ifa->ifa_addr;
      switch(sdl->sdl_type)
      {
        case IFT_ETHER:
#ifdef IFT_IEEE80211
        case IFT_IEEE80211:
#endif
          break;
        default:
          continue;
      }
      if(sdl->sdl_alen != DHCP_ETH_ALEN)
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, errno, "Wrong sdl_alen!");
        freeifaddrs(ifap);
        return -1;
      }
      memcpy(macaddr, LLADDR(sdl), DHCP_ETH_ALEN);
      freeifaddrs(ifap);
      return 0;
    }
    ifa = ifa->ifa_next;
  }
  freeifaddrs(ifap);
  return -1;
}

/**
 * dhcp_open_eth()
 * Opens an Ethernet interface. As an option the interface can be set in
 * promisc mode. If not null macaddr and ifindex are filled with the
 * interface mac address and index
 **/

/* Relevant IOCTLs
   FIONREAD Get the number of bytes in input buffer
   SIOCGIFADDR Get interface address (IP)
   BIOCGBLEN, BIOCSBLEN Get and set required buffer length
   BIOCGDLT Type of underlying data interface
   BIOCPROMISC Set in promisc mode
   BIOCFLUSH Flushes the buffer of incoming packets
   BIOCGETIF, BIOCSETIF Set hardware interface. Uses ift_name
   BIOCSRTIMEOUT, BIOCGRTIMEOUT Set and get timeout for reads
   BIOCGSTATS Return stats for the interface
   BIOCIMMEDIATE Return immediately from reads as soon as packet arrives.
   BIOCSETF Set filter
   BIOCVERSION Return the version of BPF
   BIOCSHDRCMPLT BIOCGHDRCMPLT Set flag of wheather to fill in MAC address
   BIOCSSEESENT BIOCGSEESENT Return locally generated packets */

static int dhcp_open_eth(char const *ifname, uint16_t protocol, int promisc,
                         int usemac, unsigned char *macaddr, int *ifindex)
{
  char devname[IFNAMSIZ + 5]; /* "/dev/" + ifname */
  int devnum = 0;
  struct ifreq ifr;
  int fd = -1;
  struct bpf_version bv;
  unsigned int value = 0;

  /* to avoid warning at compilation */
  protocol = protocol;
  ifindex = ifindex;

  /* Find suitable device */
  for(devnum = 0; devnum < 255; devnum++)   /* TODO 255 */
  {
    snprintf(devname, sizeof(devname), "/dev/bpf%d", devnum);
    devname[sizeof(devname)] = 0;
    if((fd = open(devname, O_RDWR)) >= 0) break;
    if(errno != EBUSY) break;
  }
  if(fd < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno, "Can't find bpf device");
    return -1;
  }

  /* Set the interface */
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
  if(ioctl(fd, BIOCSETIF, &ifr) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,"ioctl() failed");
    return -1;
  }

  /* Get and validate BPF version */
  if(ioctl(fd, BIOCVERSION, &bv) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,"ioctl() failed!");
    return -1;
  }
  if(bv.bv_major != BPF_MAJOR_VERSION ||
      bv.bv_minor < BPF_MINOR_VERSION)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,"wrong BPF version!");
    return -1;
  }

  /* Get the MAC address of our interface */
  if((!usemac) && (macaddr))
  {
    if(dhcp_getmac(ifname, macaddr))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,"Did not find MAC address!");
      return -1;
    }

    if(0) printf("MAC Address %.2x %.2x %.2x %.2x %.2x %.2x\n",
                    macaddr[0], macaddr[1], macaddr[2],
                    macaddr[3], macaddr[4], macaddr[5]);

    if(macaddr[0] & 0x01)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Ethernet has broadcast or multicast address: %.16s", ifname);
      return -1;
    }
  }

  /* Set interface in promisc mode */
  if(promisc)
  {
    value = 1;
    if(ioctl(fd, BIOCPROMISC, NULL) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,"ioctl() failed!");
      return -1;
    }
    value = 1;
    if(ioctl(fd, BIOCSHDRCMPLT, &value) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,"ioctl() failed!");
      return -1;
    }
  }
  else
  {
    value = 0;
    if(ioctl(fd, BIOCSHDRCMPLT, &value) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,"ioctl() failed!");
      return -1;
    }
  }

  /* Make sure reads return as soon as packet has been received */
  value = 1;
  if(ioctl(fd, BIOCIMMEDIATE, &value) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,"ioctl() failed!");
    return -1;
  }

  return fd;
}

#endif

/**
 * \brief Send packet to interface.
 * \param this dhcp_t instance
 * \param fd descriptor of the layer 2 socket
 * \param protocol layer 3 protocol
 * \param hismac destination MAC address
 * \param ifindex interface index to send packet
 * \param packet packet data
 * \param length length of packet
 * \return 0 if success, -1 otherwise
 */
static int dhcp_send(struct dhcp_t *this,
                     int fd, uint16_t protocol, unsigned char *hismac, int ifindex,
                     void *packet, int length)
{
#if defined(__linux__)
  struct sockaddr_ll dest;

  memset(&dest, '\0', sizeof(dest));
  dest.sll_family = AF_PACKET;
  dest.sll_protocol = htons(protocol);
  dest.sll_ifindex = ifindex;
  dest.sll_halen = DHCP_ETH_ALEN;
  memcpy (dest.sll_addr, hismac, DHCP_ETH_ALEN);

  if(sendto(fd, packet, (length), 0,
             (struct sockaddr *)&dest, sizeof(dest)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "sendto(fd=%d, len=%d) failed",
            fd, length);
    return -1;
  }
#elif defined(__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__APPLE__)
  /* to avoid warning at compilation */
  protocol = protocol;
  ifindex = ifindex;
  hismac = hismac;

  if(write(fd, packet, length) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno, "write() failed");
    return -1;
  }
#endif

  if(this->debug)
  {
    switch(protocol)
    {
      case 0x800:
        printf("Sending IP packet\n");
        break;
      case 0x86dd:
        printf("Sending IPv6 packet\n");
        break;
      default:
        printf("Sending other packet: 0x%x\n", protocol);
        break;
    }
  }

  return 0;
}

/**
 * \brief Generate a 32 bit hash based on a mac address.
 * \param hwaddr MAC address
 * \return resulting hash
 */
static unsigned long int dhcp_hash(uint8_t *hwaddr)
{
  return lookup(hwaddr, DHCP_ETH_ALEN, 0);
}

/**
 * Initialise hash tables.
 * \param this dhcp_t instance
 * \param listsize size of hash tables
 * \return 0 if success, -1 otherwise
 */
static int dhcp_hashinit(struct dhcp_t *this, int listsize)
{
  /* Determine hashlog */
  for((this)->hashlog = 0;
       ((1 << (this)->hashlog) < listsize);
       (this)->hashlog++);

  /* Determine hashsize */
  (this)->hashsize = 1 << (this)->hashlog;
  (this)->hashmask = (this)->hashsize -1;

  /* Allocate hash table */
  if(!((this)->hash = calloc(sizeof(struct dhcp_conn_t), (this)->hashsize)))
  {
    /* Failed to allocate memory for hash members */
    return -1;
  }

  /* [SV] */
  if(!((this)->hashv6 = calloc(sizeof(struct dhcp_conn_t), (this)->hashsize)))
  {
    /* Failed to allocate memory for hash members */
    free(this->hash);
    return -1;
  }

  return 0;
}

/* [SV] */
/**
 * \brief Add a connection to the IPv6 hash table.
 * \param this dhcp_t instance
 * \param conn connection to add
 * \return 0 if success, -1 otherwise
 * \author Sebastien Vincent
 */
static int dhcp_hashaddv6(struct dhcp_t *this, struct dhcp_conn_t *conn)
{
  uint32_t hash = 0;
  struct dhcp_conn_t *p = NULL;
  struct dhcp_conn_t *p_prev = NULL;

  /* Insert into hash table */
  hash = dhcp_hash(conn->hismac) & this->hashmask;
  for(p = this->hashv6[hash]; p; p = p->nexthash)
    p_prev = p;
  if(!p_prev)
    this->hashv6[hash] = conn;
  else
    p_prev->nexthash = conn;
  return 0; /* Always OK to insert */
}

/**
 * \brief Add a connection to the IPv4 hash table.
 * \param this dhcp_t instance
 * \param conn connection to add
 * \return 0 if success, -1 otherwise
 */
static int dhcp_hashadd(struct dhcp_t *this, struct dhcp_conn_t *conn)
{
  uint32_t hash = 0;
  struct dhcp_conn_t *p = NULL;
  struct dhcp_conn_t *p_prev = NULL;

  /* Insert into hash table */
  hash = dhcp_hash(conn->hismac) & this->hashmask;
  for(p = this->hash[hash]; p; p = p->nexthash)
    p_prev = p;
  if(!p_prev)
    this->hash[hash] = conn;
  else
    p_prev->nexthash = conn;
  return 0; /* Always OK to insert */
}

/**
 * \brief Remove a connection from the IPv6 hash table.
 * \param this dhcp_t instance
 * \param conn connection to remove
 * \return 0 if success, -1 otherwise
 * \author Sebastien Vincent
 */
static int dhcp_hashdelv6(struct dhcp_t *this, struct dhcp_conn_t *conn)
{
  uint32_t hash = 0;
  struct dhcp_conn_t *p = NULL;
  struct dhcp_conn_t *p_prev = NULL;

  /* Find in hash table */
  hash = dhcp_hash(conn->hismac) & this->hashmask;
  for(p = this->hashv6[hash]; p; p = p->nexthash)
  {
    if(p == conn)
    {
      break;
    }
    p_prev = p;
  }

  if((paranoid) && (p!= conn))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Tried to delete connection not in hash table");
  }

  if(!p_prev)
    this->hashv6[hash] = p->nexthash;
  else
    p_prev->nexthash = p->nexthash;

  return 0;
}

/**
 * \brief Remove a connection from the IPv4 hash table.
 * \param this dhcp_t instance
 * \param conn connection to remove
 * \return 0 if success, -1 otherwise
 */
static int dhcp_hashdel(struct dhcp_t *this, struct dhcp_conn_t *conn)
{
  uint32_t hash = 0;
  struct dhcp_conn_t *p = NULL;
  struct dhcp_conn_t *p_prev = NULL;

  /* Find in hash table */
  hash = dhcp_hash(conn->hismac) & this->hashmask;
  for(p = this->hash[hash]; p; p = p->nexthash)
  {
    if(p == conn)
    {
      break;
    }
    p_prev = p;
  }

  if((paranoid) && (p!= conn))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Tried to delete connection not in hash table");
  }

  if(!p_prev)
    this->hash[hash] = p->nexthash;
  else
    p_prev->nexthash = p->nexthash;

  return 0;
}

int dhcp_hashgetv6(struct dhcp_t *this, struct dhcp_conn_t **conn,
                   uint8_t *hwaddr)
{
  struct dhcp_conn_t *p = NULL;
  uint32_t hash = 0;

  /* Find in hash table */
  hash = dhcp_hash(hwaddr) & this->hashmask;
  for(p = this->hashv6[hash]; p; p = p->nexthash)
  {
    if((!memcmp(p->hismac, hwaddr, DHCP_ETH_ALEN)) && (p->inuse))
    {
      *conn = p;
      return 0;
    }
  }
  *conn = NULL;
  return -1; /* Address could not be found */
}

int dhcp_hashget(struct dhcp_t *this, struct dhcp_conn_t **conn,
                 uint8_t *hwaddr)
{
  struct dhcp_conn_t *p = NULL;
  uint32_t hash = 0;

  /* Find in hash table */
  hash = dhcp_hash(hwaddr) & this->hashmask;
  for(p = this->hash[hash]; p; p = p->nexthash)
  {
    if((!memcmp(p->hismac, hwaddr, DHCP_ETH_ALEN)) && (p->inuse))
    {
      *conn = p;
      return 0;
    }
  }
  *conn = NULL;
  return -1; /* Address could not be found */
}

int dhcp_validate(struct dhcp_t *this)
{
  int used = 0;
  int unused = 0;
  struct dhcp_conn_t *conn = NULL;
  struct dhcp_conn_t *hash_conn = NULL;

  /* Count the number of used connections */
  conn = this->firstusedconn;
  while(conn)
  {
    if(!conn->inuse)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Connection with inuse == 0!");
    }
    (void)dhcp_hashget(this, &hash_conn, conn->hismac);
    if(conn != hash_conn)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Connection could not be found by hashget!");
    }
    used ++;
    conn = conn->next;
  }

  /* Count the number of unused connections */
  conn = this->firstfreeconn;
  while(conn)
  {
    if(conn->inuse)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Connection with inuse != 0!");
    }
    unused ++;
    conn = conn->next;
  }

  if(this->numconn != (used + unused))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "The number of free and unused IPv4 connections does not match!");
    if(this->debug)
    {
      printf("used %d unused %d\n", used, unused);
      conn = this->firstusedconn;
      while(conn)
      {
        printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
               conn->hismac[0], conn->hismac[1], conn->hismac[2],
               conn->hismac[3], conn->hismac[4], conn->hismac[5]);
        conn = conn->next;
      }
    }
  }

  return used;
}

/**
 * \brief Valides reference structures of IPv4 connections.
 * \param this dhcp_t instance
 * \return number of active IPv4 connections
 */
static int dhcp_validatev6(struct dhcp_t *this)
{
  int used = 0;
  int unused = 0;
  struct dhcp_conn_t *conn = NULL;
  struct dhcp_conn_t *hash_conn = NULL;

  /* Count the number of used connections */
  conn = this->firstusedconnv6;
  while(conn)
  {
    if(!conn->inuse)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Connection with inuse == 0!");
    }
    (void)dhcp_hashgetv6(this, &hash_conn, conn->hismac);
    if(conn != hash_conn)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Connection could not be found by hashget!");
    }
    used ++;
    conn = conn->next;
  }

  /* Count the number of unused connections */
  conn = this->firstfreeconnv6;
  while(conn)
  {
    if(conn->inuse)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Connection with inuse != 0!");
    }
    unused ++;
    conn = conn->next;
  }

  if(this->numconnv6 != (used + unused))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "The number of free and unused IPv6 connections does not match!");
    if(this->debug)
    {
      printf("used %d unused %d\n", used, unused);
      conn = this->firstusedconnv6;
      while(conn)
      {
        printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
               conn->hismac[0], conn->hismac[1], conn->hismac[2],
               conn->hismac[3], conn->hismac[4], conn->hismac[5]);
        conn = conn->next;
      }
    }
  }

  return used;
}

/**
 * \brief Initialise IPv4 connection references.
 * \param this dhcp_t instance
 * \return 0 if success, -1 otherwise
 */
static int dhcp_initconn(struct dhcp_t *this)
{
  int n = 0;
  this->firstusedconn = NULL; /* Redundant */
  this->lastusedconn  = NULL; /* Redundant */

  for(n = 0; n < this->numconn; n++)
  {
    this->conn[n].inuse = 0; /* Redundant */
    if(n == 0)
    {
      this->conn[n].prev = NULL; /* Redundant */
      this->firstfreeconn = &this->conn[n];
    }
    else
    {
      this->conn[n].prev = &this->conn[n - 1];
      this->conn[n - 1].next = &this->conn[n];
    }
    if(n == (this->numconn - 1))
    {
      this->conn[n].next = NULL; /* Redundant */
      this->lastfreeconn  = &this->conn[n];
    }
  }

  if(paranoid) dhcp_validate(this);

  return 0;
}

/**
 * \brief Initialise IPv6 connection references.
 * \param this dhcp_t instance
 * \return 0 if success, -1 otherwise
 */
static int dhcp_initconnv6(struct dhcp_t *this)
{
  int n = 0;

  /* [SV] */
  this->firstusedconnv6= NULL;
  this->lastusedconnv6 = NULL;

  for(n = 0; n < this->numconnv6; n++)
  {
    this->connv6[n].inuse = 0;
    if(n == 0)
    {
      /* [SV] */
      this->connv6[n].prev = NULL;
      this->firstfreeconnv6=&this->connv6[n];
    }
    else
    {
      /* [SV] */
      this->connv6[n].prev=&this->connv6[n - 1];
      this->connv6[n - 1].next=&this->connv6[n];
    }
    if(n == (this->numconnv6 - 1))
    {
      /* [SV] */
      this->connv6[n].next = NULL;
      this->lastfreeconnv6=&this->connv6[n];
    }
  }

  if(paranoid) dhcp_validatev6(this);

  return 0;
}

int dhcp_newconn6(struct dhcp_t* this, struct dhcp_conn_t** conn, uint8_t* hwaddr)
{
  if(this->debug || 1)
  {
    printf("IPv6 newconn: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
  }

  if(!this->firstfreeconnv6)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Out of free connections");
    return -1;
  }

  *conn = this->firstfreeconnv6;

  /* Remove from link of free */
  if(this->firstfreeconnv6->next)
  {
    this->firstfreeconnv6->next->prev = NULL;
    this->firstfreeconnv6 = this->firstfreeconnv6->next;
  }
  else   /* Took the last one */
  {
    this->firstfreeconnv6 = NULL;
    this->lastfreeconnv6 = NULL;
  }

  /* Initialise structures */
  memset(*conn, 0, sizeof(**conn));

  /* Insert into link of used */
  if(this->firstusedconnv6)
  {
    this->firstusedconnv6->prev = *conn;
    (*conn)->next = this->firstusedconnv6;
  }
  else   /* First insert */
  {
    this->lastusedconnv6 = *conn;
  }

  this->firstusedconnv6 = *conn;

  (*conn)->inuse = 1;
  (*conn)->ipv6 = 1;
  (*conn)->parent = this;

  /* Application specific initialisations */
  memcpy((*conn)->hismac, hwaddr, DHCP_ETH_ALEN);
  memcpy((*conn)->ourmac, this->hwaddr, DHCP_ETH_ALEN);
  gettimeofday(&(*conn)->lasttime, NULL);

  (void)dhcp_hashaddv6(this, *conn);

  /* Inform application that connection was created */
  if(this ->cb_connectv6)
    this->cb_connectv6(*conn);
  return 0; /* Success */
}

int dhcp_newconn(struct dhcp_t *this, struct dhcp_conn_t **conn,
                 uint8_t *hwaddr)
{
  if(this->debug || 1)
    printf("DHCP newconn: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
           hwaddr[0], hwaddr[1], hwaddr[2],
           hwaddr[3], hwaddr[4], hwaddr[5]);

  if(!this->firstfreeconn)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Out of free connections");
    return -1;
  }

  *conn = this->firstfreeconn;

  /* Remove from link of free */
  if(this->firstfreeconn->next)
  {
    this->firstfreeconn->next->prev = NULL;
    this->firstfreeconn = this->firstfreeconn->next;
  }
  else   /* Took the last one */
  {
    this->firstfreeconn = NULL;
    this->lastfreeconn = NULL;
  }

  /* Initialise structures */
  memset(*conn, 0, sizeof(**conn));

  /* Insert into link of used */
  if(this->firstusedconn)
  {
    this->firstusedconn->prev = *conn;
    (*conn)->next = this->firstusedconn;
  }
  else   /* First insert */
  {
    this->lastusedconn = *conn;
  }

  this->firstusedconn = *conn;

  (*conn)->inuse = 1;
  (*conn)->ipv6 = 0;
  (*conn)->parent = this;

  /* Application specific initialisations */
  memcpy((*conn)->hismac, hwaddr, DHCP_ETH_ALEN);
  memcpy((*conn)->ourmac, this->hwaddr, DHCP_ETH_ALEN);
  gettimeofday(&(*conn)->lasttime, NULL);
  (void)dhcp_hashadd(this, *conn);

  if(paranoid) dhcp_validate(this);

  /* Inform application that connection was created */
  if(this ->cb_connect)
    this ->cb_connect(*conn);

  return 0; /* Success */
}

int dhcp_freeconnv6(struct dhcp_conn_t *conn)
{
  /* TODO: Always returns success? */

  struct dhcp_t *this = conn->parent;

  /* Tell application that we disconnected */
  if(this->cb_disconnect)
    this->cb_disconnectv6(conn);

  if(this->debug || 1)
    printf("IPv6 freeconn: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
           conn->hismac[0], conn->hismac[1], conn->hismac[2],
           conn->hismac[3], conn->hismac[4], conn->hismac[5]);

  /* Application specific code */
  /* First remove from hash table */
  (void)dhcp_hashdelv6(this, conn);

  /* Remove from link of used */
  if((conn->next) && (conn->prev))
  {
    conn->next->prev = conn->prev;
    conn->prev->next = conn->next;
  }
  else if(conn->next)   /* && prev == 0 */
  {
    conn->next->prev = NULL;
    this->firstusedconnv6 = conn->next;
  }
  else if(conn->prev)   /* && next == 0 */
  {
    conn->prev->next = NULL;
    this->lastusedconnv6 = conn->prev;
  }
  else   /* if((next == 0) && (prev == 0)) */
  {
    this->firstusedconnv6 = NULL;
    this->lastusedconnv6 = NULL;
  }

  /* Initialise structures */
  memset(conn, 0, sizeof(*conn));

  /* Insert into link of free */
  if(this->firstfreeconnv6)
  {
    this->firstfreeconnv6->prev = conn;
  }
  else   /* First insert */
  {
    this->lastfreeconnv6 = conn;
  }

  conn->next = this->firstfreeconnv6;
  this->firstfreeconnv6 = conn;

  if(paranoid) dhcp_validatev6(this);

  return 0;
}

int dhcp_freeconn(struct dhcp_conn_t *conn)
{
  /* TODO: Always returns success? */

  struct dhcp_t *this = conn->parent;

  /* Tell application that we disconnected */
  if(this->cb_disconnect)
    this->cb_disconnect(conn);

  if(this->debug || 1)
    printf("DHCP freeconn: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
           conn->hismac[0], conn->hismac[1], conn->hismac[2],
           conn->hismac[3], conn->hismac[4], conn->hismac[5]);

  /* Application specific code */
  /* First remove from hash table */
  (void)dhcp_hashdel(this, conn);

  /* Remove from link of used */
  if((conn->next) && (conn->prev))
  {
    conn->next->prev = conn->prev;
    conn->prev->next = conn->next;
  }
  else if(conn->next)   /* && prev == 0 */
  {
    conn->next->prev = NULL;
    this->firstusedconn = conn->next;
  }
  else if(conn->prev)   /* && next == 0 */
  {
    conn->prev->next = NULL;
    this->lastusedconn = conn->prev;
  }
  else   /* if((next == 0) && (prev == 0)) */
  {
    this->firstusedconn = NULL;
    this->lastusedconn = NULL;
  }

  /* Initialise structures */
  memset(conn, 0, sizeof(*conn));

  /* Insert into link of free */
  if(this->firstfreeconn)
  {
    this->firstfreeconn->prev = conn;
  }
  else   /* First insert */
  {
    this->lastfreeconn = conn;
  }

  conn->next = this->firstfreeconn;
  this->firstfreeconn = conn;

  if(paranoid) dhcp_validate(this);

  return 0;
}

/**
 * \brief Check IPv4 client connections to see if the lease has expired.
 * \param this dhcp_t instance
 * \return 0
 */
static int dhcp_checkconn(struct dhcp_t *this)
{
  struct dhcp_conn_t *conn = NULL;
  struct timeval now;

  gettimeofday(&now, NULL);
  now.tv_sec -= this->lease;
  conn = this->firstusedconn;
  while(conn)
  {
    if(timercmp(&now, &conn->lasttime, >))
    {
      if(this->debug) printf("DHCP timeout: Removing connection\n");
      dhcp_freeconn(conn);
      return 0; /* Returning after first deletion */
    }
    conn = conn->next;
  }

  return 0;
}

/**
 * \brief Check IPv6 client connections to see if the lease has expired.
 * \param this dhcp_t instance
 * \return 0
 */
static int dhcp_checkconnv6(struct dhcp_t *this)
{
  struct dhcp_conn_t *conn = NULL;
  struct timeval now;

  gettimeofday(&now, NULL);
  now.tv_sec -= this->lease;
  conn = this->firstusedconnv6;
  while(conn)
  {
    if(timercmp(&now, &conn->lasttime, >))
    {
      if(this->debug) printf("IPv6 timeout: Removing connection\n");
      dhcp_freeconnv6(conn);
      return 0; /* Returning after first deletion */
    }
    conn = conn->next;
  }

  return 0;
}

/* API Functions */

const char* dhcp_version()
{
  return VERSION;
}

int dhcp_new(struct dhcp_t **dhcp, int numconn, char *interface,
             int usemac, uint8_t *mac, int promisc,
             struct in_addr *listen_addr, struct in6_addr *listenv6, int lease, int allowdyn,
             struct in_addr *uamlisten, struct in6_addr *uamlisten6, uint16_t uamport, int useeapol, char *ipversion)
{
  struct in_addr noaddr;

  if(!(*dhcp = calloc(sizeof(struct dhcp_t), 1)))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "calloc() failed");
    return -1;
  }

  if(!strncmp(ipversion, "ipv4", 4) || !strncmp(ipversion, "dual", 4))
  {
    (*dhcp)->numconn = numconn;

    if(!((*dhcp)->conn = calloc(sizeof(struct dhcp_conn_t), numconn)))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "calloc() failed");
      free(*dhcp);
      return -1;
    }
  }

  /* [SV] IPv6 table */
  if(strncmp(ipversion, "ipv4", 4))
  {
    (*dhcp)->numconnv6 = numconn;
    if(!((*dhcp)->connv6 = calloc(sizeof(struct dhcp_conn_t), numconn)))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0, "calloc() failed");
      if((*dhcp)->conn) free((*dhcp)->conn);
      free(*dhcp);
      return -1;
    }
  }

  if(!strncmp(ipversion, "ipv4", 4))
    dhcp_initconn(*dhcp);
  else if(!strncmp(ipversion, "ipv6", 4))
    dhcp_initconnv6(*dhcp);
  else
  {
    dhcp_initconn(*dhcp);
    dhcp_initconnv6(*dhcp);
  }

  strncpy((*dhcp)->devname, interface, IFNAMSIZ - 1);
  (*dhcp)->devname[IFNAMSIZ - 1] = 0; /* make sure to terminate */

  /* Bring network interface UP and RUNNING if currently down */
  (void)dhcp_gifflags((*dhcp)->devname, &(*dhcp)->devflags);
  if(!((*dhcp)->devflags & IFF_UP) || !((*dhcp)->devflags & IFF_RUNNING))
  {
    (void)dhcp_sifflags((*dhcp)->devname, (*dhcp)->devflags | IFF_NOARP);
    memset(&noaddr, 0, sizeof(noaddr));
    if(!strncmp(ipversion, "ipv4", 4) || !strncmp(ipversion, "dual", 4))
      (void)dhcp_setaddr((*dhcp)->devname, &noaddr, NULL, NULL);
  }

  if(!strncmp(ipversion, "ipv4", 4) || !strncmp(ipversion, "dual", 4))
  {
    if(usemac) memcpy(((*dhcp)->hwaddr), mac, DHCP_ETH_ALEN);
    if(((*dhcp)->fd =
           dhcp_open_eth(interface, DHCP_ETH_IP, promisc, usemac,
                         ((*dhcp)->hwaddr),
                         &((*dhcp)->ifindex))) < 0)
    {
      if((*dhcp)->connv6) free((*dhcp)->connv6);
      free((*dhcp)->conn);
      free(*dhcp);
      return -1; /* Error reporting done in dhcp_open_eth */
    }

#if defined(__FreeBSD__) || defined (__OpenBSD__) || defined (__APPLE__)
    {
      int blen = 0;
      if(ioctl((*dhcp)->fd, BIOCGBLEN, &blen) < 0)
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, errno,"ioctl() failed!");
      }
      (*dhcp)->rbuf_max = (unsigned int)blen;
      if(!((*dhcp)->rbuf = malloc((*dhcp)->rbuf_max)))
      {
        /* TODO: Free malloc */
        sys_err(LOG_ERR, __FILE__, __LINE__, errno, "malloc() failed");
      }
      (*dhcp)->rbuf_offset = 0;
      (*dhcp)->rbuf_len = 0;
    }
#endif

    if(usemac) memcpy(((*dhcp)->arp_hwaddr), mac, DHCP_ETH_ALEN);
    if(((*dhcp)->arp_fd =
           dhcp_open_eth(interface, DHCP_ETH_ARP, promisc, usemac,
                         ((*dhcp)->arp_hwaddr),
                         &((*dhcp)->arp_ifindex))) < 0)
    {
      if((*dhcp)->connv6) free((*dhcp)->connv6);
      close((*dhcp)->fd);
      free((*dhcp)->conn);
      free(*dhcp);
      return -1; /* Error reporting done in dhcp_open_eth */
    }
  }

  if(!useeapol)
  {
    (*dhcp)->eapol_fd = 0;
  }
  else
  {
    if(usemac) memcpy(((*dhcp)->eapol_hwaddr), mac, DHCP_ETH_ALEN);
    if(((*dhcp)->eapol_fd =
           dhcp_open_eth(interface, DHCP_ETH_EAPOL, promisc, usemac,
                         ((*dhcp)->eapol_hwaddr), &((*dhcp)->eapol_ifindex))) < 0)
    {
      close((*dhcp)->fd);
      close((*dhcp)->arp_fd);
      if((*dhcp)->connv6) free((*dhcp)->connv6);
      free((*dhcp)->conn);
      free(*dhcp);
      return -1; /* Error reporting done in eapol_open_eth */
    }
  }

  if(strncmp(ipversion, "ipv4", 4))
  {
    /* [SV] */
    if(usemac) memcpy(((*dhcp)->ipv6_hwaddr), mac, DHCP_ETH_ALEN);
    if(((*dhcp)->ipv6_fd = dhcp_open_eth(interface, DHCP_ETH_IPV6, promisc, usemac, ((*dhcp)->ipv6_hwaddr), &((*dhcp)->ipv6_ifindex))) < 0)
    {
      if(!strncmp(ipversion, "dual", 4))
      {
        close((*dhcp)->fd);
        close((*dhcp)->arp_fd);
        free((*dhcp)->conn);
      }
      if((*dhcp)->eapol_fd) close((*dhcp)->eapol_fd);
      free((*dhcp)->connv6);
      free(*dhcp);
      return -1; /* Error reporting done in ipv6_open_eth */
    }
  }

  if(strncmp(ipversion, "ipv4", 4))
  {
    if(dhcp_hashinit(*dhcp, (*dhcp)->numconnv6))
    {
      if(!strncmp(ipversion, "dual", 4))
      {
        close((*dhcp)->fd);
        close((*dhcp)->arp_fd);
        free((*dhcp)->conn);
      }
      if((*dhcp)->eapol_fd) close((*dhcp)->eapol_fd);
      free((*dhcp)->connv6);
      free(*dhcp);
      return -1; /* Failed to allocate hash tables */
    }
  }
  else if(dhcp_hashinit(*dhcp, (*dhcp)->numconn))
  {
    close((*dhcp)->fd);
    close((*dhcp)->arp_fd);
    free((*dhcp)->conn);
    free((*dhcp));
    return -1; /* Failed to allocate hash tables */
  }

  /* Initialise various variables */
  if(!strncmp(ipversion, "ipv4", 4) || !strncmp(ipversion, "dual", 4))
    (*dhcp)->ourip.s_addr = listen_addr->s_addr;
  if(strncmp(ipversion, "ipv4", 4))
    memcpy(&(*dhcp)->ouripv6, listenv6, sizeof(struct in6_addr));
  (*dhcp)->lease = lease;
  (*dhcp)->promisc = promisc;
  (*dhcp)->usemac = usemac;
  (*dhcp)->allowdyn = allowdyn;
  if(strncmp(ipversion, "ipv4", 4))
    memcpy(&(*dhcp)->uamlisten6, uamlisten6, sizeof(struct in6_addr));
  if(!strncmp(ipversion, "ipv4", 4) || !strncmp(ipversion, "dual", 4))
    (*dhcp)->uamlisten.s_addr = uamlisten->s_addr;
  (*dhcp)->uamport = uamport;

  /* Initialise call back functions */
  if(!strncmp(ipversion, "ipv4", 4) || !strncmp(ipversion, "dual", 4))
  {
    (*dhcp)->cb_data_ind = 0;
    (*dhcp)->cb_eap_ind = 0;
    (*dhcp)->cb_request = 0;
    (*dhcp)->cb_disconnect = 0;
    (*dhcp)->cb_connect = 0;
  }
  if(strncmp(ipversion, "ipv4", 4))
  {
    /* [SV] */
    (*dhcp)->cb_ipv6_ind= 0;
    (*dhcp)->cb_connectv6 = 0;
    (*dhcp)->cb_disconnectv6 = 0;
    (*dhcp)->cb_connectv6 = 0;
  }
  /* [SG] */
  (*dhcp)->cb_unauth_dnat = 0;

  return 0;
}

int dhcp_setv6(struct dhcp_t *dhcp, int debug,
               struct in6_addr *authip, int authiplen, int anydns,
               struct in6_addr *uamokip, int uamokiplen,
               struct in6_addr *uamokaddr,
               struct in6_addr *uamokmask, int uamoknetlen)
{
  int i = 0;

  dhcp->debug = debug;
  dhcp->anydns = anydns;

  /* Copy list of uamserver IP addresses */
  if((dhcp)->authip6) free((dhcp)->authip6);
  dhcp->authiplen6 = authiplen;
  if(!(dhcp->authip6 = calloc(sizeof(struct in6_addr), authiplen)))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "calloc() failed");
    dhcp->authip6 = 0;
    return -1;
  }
  memcpy(dhcp->authip6, authip, sizeof(struct in6_addr) * authiplen);

  /* Make hash table for allowed domains */
  if(dhcp->iphash6) iphash_free(dhcp->iphash6);
  if((!uamokip) || (uamokiplen == 0))
  {
    dhcp->iphashm6 = NULL;
    dhcp->iphash6 = NULL;
  }
  else
  {
    if(!(dhcp->iphashm6 = calloc(uamokiplen, sizeof(struct ippoolm_t))))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "calloc() failed");
      return -1;
    }
    for(i = 0; i < uamokiplen; i++)
    {
      memcpy(&(dhcp)->iphashm6[i].addrv6, &uamokip[i], sizeof(struct in6_addr));
    }
    (void)iphash_new6(&dhcp->iphash6, dhcp->iphashm6, uamokiplen);
  }

  /* Copy allowed networks */
  if(dhcp->uamokaddr6) free(dhcp->uamokaddr6);
  if(dhcp->uamokmask6) free(dhcp->uamokmask6);
  if((!uamokaddr) || (!uamokmask) || (uamoknetlen == 0))
  {
    dhcp->uamokaddr6 = NULL;
    dhcp->uamokmask6 = NULL;
    dhcp->uamoknetlen6 = 0;
  }
  else
  {
    dhcp->uamoknetlen6 = uamoknetlen;
    if(!(dhcp->uamokaddr6 = calloc(uamoknetlen, sizeof(struct in6_addr))))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "calloc() failed");
      return -1;
    }
    if(!(dhcp->uamokmask6 = calloc(uamoknetlen, sizeof(struct in6_addr))))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "calloc() failed");
      return -1;
    }
    memcpy(dhcp->uamokaddr6, uamokaddr, uamoknetlen * sizeof(struct in6_addr));
    memcpy(dhcp->uamokmask6, uamokmask, uamoknetlen * sizeof(struct in6_addr));
  }
  return 0;
}

int dhcp_set(struct dhcp_t *dhcp, int debug,
             struct in_addr *authip, int authiplen, int anydns,
             struct in_addr *uamokip, int uamokiplen,
             struct in_addr *uamokaddr,
             struct in_addr *uamokmask, int uamoknetlen)
{
  int i = 0;

  dhcp->debug = debug;
  dhcp->anydns = anydns;

  /* Copy list of uamserver IP addresses */
  if((dhcp)->authip) free((dhcp)->authip);
  dhcp->authiplen = authiplen;
  if(!(dhcp->authip = calloc(sizeof(struct in_addr), authiplen)))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "calloc() failed");
    dhcp->authip = 0;
    return -1;
  }
  memcpy(dhcp->authip, authip, sizeof(struct in_addr) * authiplen);

  /* Make hash table for allowed domains */
  if(dhcp->iphash) iphash_free(dhcp->iphash);
  if((!uamokip) || (uamokiplen == 0))
  {
    dhcp->iphashm = NULL;
    dhcp->iphash = NULL;
  }
  else
  {
    if(!(dhcp->iphashm = calloc(uamokiplen, sizeof(struct ippoolm_t))))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "calloc() failed");
      return -1;
    }
    for(i = 0; i < uamokiplen; i++)
    {
      dhcp->iphashm[i].addr = uamokip[i];
    }
    (void)iphash_new(&dhcp->iphash, dhcp->iphashm, uamokiplen);
  }

  /* Copy allowed networks */
  if(dhcp->uamokaddr) free(dhcp->uamokaddr);
  if(dhcp->uamokmask) free(dhcp->uamokmask);
  if((!uamokaddr) || (!uamokmask) || (uamoknetlen == 0))
  {
    dhcp->uamokaddr = NULL;
    dhcp->uamokmask = NULL;
    dhcp->uamoknetlen = 0;
  }
  else
  {
    dhcp->uamoknetlen = uamoknetlen;
    if(!(dhcp->uamokaddr = calloc(uamoknetlen, sizeof(struct in_addr))))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "calloc() failed");
      return -1;
    }
    if(!(dhcp->uamokmask = calloc(uamoknetlen, sizeof(struct in_addr))))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "calloc() failed");
      return -1;
    }
    memcpy(dhcp->uamokaddr, uamokaddr, uamoknetlen * sizeof(struct in_addr));
    memcpy(dhcp->uamokmask, uamokmask, uamoknetlen * sizeof(struct in_addr));
  }
  return 0;
}

int dhcp_free(struct dhcp_t *dhcp)
{
  if(dhcp->hash) free(dhcp->hash);
  if(dhcp->hashv6) free(dhcp->hashv6);
  if(dhcp->iphash) iphash_free(dhcp->iphash);
  if(dhcp->iphashm) free(dhcp->iphashm);
  if(dhcp->authip) free(dhcp->authip);
  if(dhcp->authip6) free(dhcp->authip6);
  if(dhcp->uamokaddr6) free(dhcp->uamokaddr6);
  if(dhcp->uamokmask6) free(dhcp->uamokmask6);
  (void)dhcp_sifflags(dhcp->devname, dhcp->devflags);
  close(dhcp->fd);
  close(dhcp->arp_fd);
  close(dhcp->ipv6_fd);
  if(dhcp->eapol_fd) close(dhcp->eapol_fd);
  free(dhcp->conn);
  free(dhcp->connv6);
  free(dhcp);
  return 0;
}

int dhcp_timeout(struct dhcp_t *this)
{
  if(paranoid)
  {
    dhcp_validate(this);
    dhcp_validatev6(this);
  }

  dhcp_checkconn(this);
  dhcp_checkconnv6(this);

  return 0;
}

struct timeval* dhcp_timeleft(struct dhcp_t *this, struct timeval *tvp)
{
  /* To avoid unused parameter warning */
  this = NULL;
  return tvp;
}

/**
 * \brief DNAT the packet to the UAM server.
 * \param conn the dhcp_conn_t instance
 * \param pack the packet
 * \param len length of the packet
 * \return 0 if success, -1 otherwise
 */
static int dhcp_doDNATv6(struct dhcp_conn_t* conn, struct dhcp_ipv6packet_t* pack, int len)
{
  struct dhcp_t* this = conn->parent;
  struct dhcp_tcphdr_t* tcph = (struct dhcp_tcphdr_t*)pack->payload;
  struct dhcp_udphdr_t* udph = (struct dhcp_udphdr_t*)pack->payload;
  char buf[INET6_ADDRSTRLEN];
  char buf2[INET6_ADDRSTRLEN];

  /* was it a DNS request */
  if(this->anydns || ((pack->ip6h.next_header == DHCP_IP_UDP) &&
                       (udph->dst == htons(DHCP_DNS))))
    return 0;

  printf("dnat: src %s | dst: %s len=%d\n", inet_ntop(AF_INET6, &pack->ip6h.src_addr, buf, sizeof(buf)), inet_ntop(AF_INET6, &pack->ip6h.dst_addr, buf2, sizeof(buf2)), ntohs(pack->ip6h.payload_length));

  /* was it an ICMPv6 request for us ?
   * if packet is a NS for us, the NA have been already sent
   */
  if(pack->ip6h.next_header == DHCP_IPV6_ICMPV6)
  {
    return 0;
  }

  /* was it a request for local redirection server */
  if(IN6_ARE_ADDR_EQUAL((struct in6_addr*)&pack->ip6h.dst_addr, &this->ouripv6) && pack->ip6h.next_header == DHCP_IPV6_TCP && tcph->dst == htons(this->uamport))
  {
    printf("IPv6 request for local redirection server!\n");
    return 0;
  }

  /* was it a http / https request for authentification server */
  /* default us! */
  if(IN6_ARE_ADDR_EQUAL((struct in6_addr*)&pack->ip6h.dst_addr, &this->ouripv6))
  {
    printf("HTTP / HTTPS for us\n");
    return 0;
  }

  /* Was it a request from an IPv6 allowed domain? */
  if(this->iphash6 &&
      (!ippool_getip6(this->iphash6, NULL, (struct in6_addr*) &pack->ip6h.dst_addr)))
    return 0;

  /* was it a http request for another server */
  /* DNAT the port! */
  if(pack->ip6h.next_header == DHCP_IPV6_TCP && tcph->dst == htons(DHCP_HTTP))
  {
    int n = 0;
    int pos = -1;

    for(n = 0 ; n < DHCP_DNATV6_MAX ; n++)
    {
      if(IN6_ARE_ADDR_EQUAL(&conn->dnatipv6[n], (struct in6_addr*) &pack->ip6h.dst_addr) && conn->dnatportv6[n] == tcph->src)
      {
        pos = n;
        break;
      }
    }

    if(pos == -1) /* save for undoing */
    {
      printf("save dnat for dst: %s port: %d\n", inet_ntop(AF_INET6, &pack->ip6h.dst_addr, buf, sizeof(buf)), tcph->src);
      memcpy(&conn->dnatipv6[conn->nextdnatv6], pack->ip6h.dst_addr, sizeof(struct in6_addr));
      conn->dnatportv6[conn->nextdnatv6] = tcph->src;
      conn->nextdnatv6 = (conn->nextdnatv6 + 1) % DHCP_DNATV6_MAX;
    }

    memcpy(&pack->ip6h.dst_addr, &this->ouripv6.s6_addr, sizeof(struct in6_addr));
    tcph->dst = htons(this->uamport);
    dhcp_tcp_checkv6(pack, len);
    return 0;
  }

  return -1;
}

/**
 * \brief Change IPv4 destination address to authentication server.
 * \param conn client connection
 * \param pack IPv4 packet
 * \param len length of packet
 * \return 0 or -1 if error
 */
static int dhcp_doDNAT(struct dhcp_conn_t *conn,
                       struct dhcp_ippacket_t *pack, int len)
{
  struct dhcp_t *this = conn->parent;
  struct dhcp_tcphdr_t *tcph = (struct dhcp_tcphdr_t*) pack->payload;
  struct dhcp_udphdr_t *udph = (struct dhcp_udphdr_t*) pack->payload;
  int i = 0;

  /* Was it a DNS request? */
  if(((this->anydns) ||
       (pack->iph.daddr == conn->dns1.s_addr) ||
       (pack->iph.daddr == conn->dns2.s_addr)) &&
      (pack->iph.protocol == DHCP_IP_UDP) &&
      (udph->dst == htons(DHCP_DNS)))
    return 0;

  /* Was it an ICMP request for us? */
  if((pack->iph.daddr == conn->ourip.s_addr) &&
      (pack->iph.protocol == DHCP_IP_ICMP))
    return 0;

  /* Was it a http or https request for authentication server? */
  /* Was it a request for authentication server? */
  for(i = 0; i < this->authiplen; i++)
  {
    if((pack->iph.daddr == this->authip[i].s_addr)  &&
        (pack->iph.protocol == DHCP_IP_TCP) &&
        ((tcph->dst == htons(DHCP_HTTP)) ||
         (tcph->dst == htons(DHCP_HTTPS))))
      return 0; /* Destination was authentication server */
  }

  /* Was it a request for local redirection server? */
  if((pack->iph.daddr == this->uamlisten.s_addr) &&
      (pack->iph.protocol == DHCP_IP_TCP) &&
      (tcph->dst == htons(this->uamport)))
    return 0; /* Destination was local redir server */

  /* Was it a request for an allowed domain? */
  if(this->iphash &&
      (!ippool_getip(this->iphash, NULL, (struct in_addr*) &pack->iph.daddr)))
    return 0;

  /* Was it a request for an allowed network? */
  for(i = 0; i < this->uamoknetlen; i++)
  {
    if(this->uamokaddr[i].s_addr ==
        (pack->iph.daddr & this->uamokmask[i].s_addr))
      return 0;
  }

  /* Was it a http request for another server? */
  /* We are changing dest IP and dest port to local UAM server */
  if((pack->iph.protocol == DHCP_IP_TCP) &&
      (tcph->dst == htons(DHCP_HTTP)))
  {
    int n = 0;
    int pos = -1;
    for(n = 0; n < DHCP_DNAT_MAX; n++)
    {
      if((conn->dnatip[n] == pack->iph.daddr) &&
          (conn->dnatport[n] == tcph->src))
      {
        pos = n;
        break;
      }
    }
    if(pos == -1)   /* Save for undoing */
    {
      conn->dnatip[conn->nextdnat] = pack->iph.daddr;
      conn->dnatport[conn->nextdnat] = tcph->src;
      conn->nextdnat = (conn->nextdnat + 1) % DHCP_DNAT_MAX;
    }
    pack->iph.daddr = this->uamlisten.s_addr;
    tcph->dst  = htons(this->uamport);
    (void)dhcp_tcp_check(pack, len);
    (void)dhcp_ip_check((struct dhcp_ippacket_t*) pack);
    return 0;
  }

  return -1; /* Something else */
}

/**
 * \brief Change IPv6 source address back to original server.
 * \param conn client connection
 * \param pack IPv6 packet
 * \param len length of packet
 * \return 0 or -1 if error
 */
static int dhcp_undoDNATv6(struct dhcp_conn_t *conn, struct dhcp_ipv6packet_t *pack, int len)
{
  struct dhcp_t* this = conn->parent;
  struct dhcp_tcphdr_t* tcph = (struct dhcp_tcphdr_t*)pack->payload;
  struct dhcp_udphdr_t* udph = (struct dhcp_udphdr_t*) pack->payload;

  if(this->anydns ||
      ((pack->ip6h.next_header == DHCP_IP_UDP) &&
       (udph->src == htons(DHCP_DNS))))
    return 0;

  /* icmpv6 */
  if(IN6_ARE_ADDR_EQUAL((struct in6_addr*)&pack->ip6h.src_addr, &conn->ouripv6) && pack->ip6h.next_header == DHCP_IPV6_ICMPV6)
  {
    return 0;
  }

  /* reply from redir server */
  if(IN6_ARE_ADDR_EQUAL((struct in6_addr*)&pack->ip6h.src_addr, &this->ouripv6) && pack->ip6h.next_header == DHCP_IPV6_TCP && tcph->src == htons(this->uamport))
  {
    int n = 0;

    for(n = 0 ; n < DHCP_DNATV6_MAX ; n++)
    {
      if(tcph->dst == conn->dnatportv6[n])
      {
        char buf[64];
        printf("modify packet src: %s: port: %d\n", inet_ntop(AF_INET6, &conn->dnatipv6[n], buf, sizeof(buf)), DHCP_HTTP);
        memcpy(&pack->ip6h.src_addr, &conn->dnatipv6[n], sizeof(struct in6_addr));
        tcph->src = htons(DHCP_HTTP);
        dhcp_tcp_checkv6(pack, len);
        return 0;
      }
    }
    return 0;
  }

  /* Was it a reply from an IPv6 allowed domain? */
  if(this->iphash6 &&
      (!ippool_getip6(this->iphash6, NULL, (struct in6_addr*) &pack->ip6h.src_addr)))
    return 0;

  /* Was it a normal http or https reply from authentication server? */
  /* Was it a normal reply from authentication server? */
  if(IN6_ARE_ADDR_EQUAL((struct in6_addr*)&pack->ip6h.src_addr, &this->ouripv6))
  {
    return 0; /* Destination was authentication server */
  }

  return -1;
}

/**
 * \brief Change IPv4 source address back to original server.
 * \param conn client connection
 * \param pack IPv4 packet
 * \param len length of packet
 * \return 0 or -1 if error
 */
static int dhcp_undoDNAT(struct dhcp_conn_t *conn,
                         struct dhcp_ippacket_t *pack, int len)
{
  struct dhcp_t *this = conn->parent;
  struct dhcp_tcphdr_t *tcph = (struct dhcp_tcphdr_t*) pack->payload;
  struct dhcp_udphdr_t *udph = (struct dhcp_udphdr_t*) pack->payload;
  char buf[INET_ADDRSTRLEN];
  int i = 0;
  struct in_addr in1;
  struct in_addr in2;

  in1.s_addr = pack->iph.saddr;
  in2.s_addr = pack->iph.daddr;
  printf("dhcp_undoDNAT\nsource:%s\n", inet_ntop(AF_INET, &in1, buf, sizeof(buf)));
  printf("dest:%s\n", inet_ntop(AF_INET, &in2, buf, sizeof(buf)));
  printf("portsrc:%d\n", ntohs(tcph->src));
  printf("portdest:%d\n", ntohs(tcph->dst));
  /* Was it a DNS reply? */
  if(((this->anydns) ||
       (pack->iph.saddr == conn->dns1.s_addr) ||
       (pack->iph.saddr == conn->dns2.s_addr)) &&
      (pack->iph.protocol == DHCP_IP_UDP) &&
      (udph->src == htons(DHCP_DNS)))
    return 0;

  /* Was it an ICMP reply from us? */
  if((pack->iph.saddr == conn->ourip.s_addr) &&
      (pack->iph.protocol == DHCP_IP_ICMP))
    return 0;

  /* Was it a reply from redir server? */
  if((pack->iph.saddr == this->uamlisten.s_addr) &&
      (pack->iph.protocol == DHCP_IP_TCP) &&
      (tcph->src == htons(this->uamport)))
  {
    int n = 0;
    for(n = 0; n < DHCP_DNAT_MAX; n++)
    {
      if(tcph->dst == conn->dnatport[n])
      {
        pack->iph.saddr = conn->dnatip[n];
        tcph->src = htons(DHCP_HTTP);
        (void)dhcp_tcp_check(pack, len);
        (void)dhcp_ip_check((struct dhcp_ippacket_t*) pack);
        return 0; /* It was a DNAT reply */
      }
    }
    return 0; /* It was a normal reply from redir server */
  }

  /* Was it a normal http or https reply from authentication server? */
  /* Was it a normal reply from authentication server? */
  for(i = 0; i < this->authiplen; i++)
  {
    if((pack->iph.saddr == this->authip[i].s_addr)  &&
        (pack->iph.protocol == DHCP_IP_TCP) &&
        ((tcph->src == htons(DHCP_HTTP)) ||
         (tcph->src == htons(DHCP_HTTPS))))
      return 0; /* Destination was authentication server */
  }

  /* Was it a reply from an IPv4 allowed domain? */
  if(this->iphash &&
      (!ippool_getip(this->iphash, NULL, (struct in_addr*) &pack->iph.saddr)))
    return 0;

  /* Was it a reply from for an allowed network? */
  for(i = 0; i < this->uamoknetlen; i++)
  {
    if(this->uamokaddr[i].s_addr ==
        (pack->iph.saddr & this->uamokmask[i].s_addr))
      return 0;
  }

  return -1; /* Something else */
}

#ifdef DHCP_CHECKDNS
/**
 * \brief Check if it was request for known domain name.
 *
 * In case it was a request for a known keyword then
 * redirect to the login/logout page
 * 2005-09-19: This stuff is highly experimental.
 * \param conn low-level connection
 * \param pack IPv4 packet
 * \param len length of packet
 * \return 0 or -1 if failure
 */
static int dhcp_checkDNS(struct dhcp_conn_t *conn,
                         struct dhcp_ippacket_t *pack, int len)
{
  struct dhcp_t *this = conn->parent;
  struct dhcp_udphdr_t *udph = (struct dhcp_udphdr_t*) pack->payload;
  struct dhcp_dns_packet_t *dnsp = (struct dhcp_dns_packet_t*)
                                   (pack->payload + sizeof(struct dhcp_udphdr_t));
  int i = 0;
  uint8_t *p1 = NULL;
  uint8_t *p2 = NULL;
  struct dhcp_dns_fullpacket_t answer;
  int length = 0;
  int udp_len = 0;
  uint8_t query[256];
  int query_len = 0;
  int n = 0;

  printf("DNS ID: \n");

  printf("DNS ID:    %d\n", ntohs(dnsp->id));
  printf("DNS flags: %d\n", ntohs(dnsp->flags));

  if((ntohs(dnsp->flags)   == 0x0100) &&
      (ntohs(dnsp->qdcount) == 0x0001) &&
      (ntohs(dnsp->ancount) == 0x0000) &&
      (ntohs(dnsp->nscount) == 0x0000) &&
      (ntohs(dnsp->arcount) == 0x0000))
  {
    printf("It was a query %s: \n", dnsp->records);
    p1 = dnsp->records + 1 + dnsp->records[0];
    p2 = dnsp->records;
    do
    {
      if(query_len < 256)
        query[query_len++] = *p2;
    }
    while(*p2++ != 0); /* TODO */
    for(n = 0; n < 4; n++)
    {
      if(query_len < 256)
        query[query_len++] = *p2++;
    }

    query[query_len++] = 0xc0;
    query[query_len++] = 0x0c;
    query[query_len++] = 0x00;
    query[query_len++] = 0x01;
    query[query_len++] = 0x00;
    query[query_len++] = 0x01;
    query[query_len++] = 0x00;
    query[query_len++] = 0x00;
    query[query_len++] = 0x01;
    query[query_len++] = 0x2c;
    query[query_len++] = 0x00;
    query[query_len++] = 0x04;
    memcpy(&query[query_len], &conn->ourip.s_addr, 4);
    query_len += 4;

    if(!memcmp(p1,
                "\3key\12pepperspot\3org",
                sizeof("\3key\12pepperspot\3org")))
    {
      printf("It was a matching query %s: \n", dnsp->records);
      memcpy(&answer, pack, len); /* TODO */

      /* DNS Header */
      answer.dns.id      = dnsp->id;
      answer.dns.flags   = htons(0x8000);
      answer.dns.qdcount = htons(0x0001);
      answer.dns.ancount = htons(0x0001);
      answer.dns.nscount = htons(0x0000);
      answer.dns.arcount = htons(0x0000);
      memcpy(answer.dns.records, query, query_len);

      /* UDP header */
      udp_len = query_len + DHCP_DNS_HLEN + DHCP_UDP_HLEN;
      answer.udph.len = htons(udp_len);
      answer.udph.src = udph->dst;
      answer.udph.dst = udph->src;

      /* IP header */
      answer.iph.ihl = 5;
      answer.iph.version = 4;
      answer.iph.tos = 0;
      answer.iph.tot_len = htons(udp_len + DHCP_IP_HLEN);
      answer.iph.id = 0;
      answer.iph.frag_off = 0;
      answer.iph.ttl = 0x10;
      answer.iph.protocol = 0x11;
      answer.iph.check = 0; /* Calculate at end of packet */
      memcpy(&answer.iph.daddr, &pack->iph.saddr, DHCP_IP_ALEN);
      memcpy(&answer.iph.saddr, &pack->iph.saddr, DHCP_IP_ALEN);

      /* Ethernet header */
      memcpy(&answer.ethh.dst, &pack->ethh.src, DHCP_ETH_ALEN);
      memcpy(&answer.ethh.src, &pack->ethh.dst, DHCP_ETH_ALEN);
      answer.ethh.prot = htons(DHCP_ETH_IP);

      /* Work out checksums */
      (void)dhcp_udp_check((struct dhcp_fullpacket_t*) &answer);
      (void)dhcp_ip_check((struct dhcp_ippacket_t*) &answer);

      /* Calculate total length */
      length = udp_len + DHCP_IP_HLEN + DHCP_ETH_HLEN;

      return dhcp_send(this, this->ipv6_fd, DHCP_ETH_IP, conn->hismac,
                       this->ifindex, &answer, length);
    }
  }
  return -0; /* Something else */
}

#endif

/**
 * \brief Fill in a DHCP packet with most essential values.
 * \param pack DHCP packet
 * \return 0
 */
static int dhcp_getdefault(struct dhcp_fullpacket_t *pack)
{
  /* Initialise reply packet with request */
  memset(pack, 0, sizeof(struct dhcp_fullpacket_t));

  /* DHCP Payload */
  pack->dhcp.op     = DHCP_BOOTREPLY;
  pack->dhcp.htype  = DHCP_HTYPE_ETH;
  pack->dhcp.hlen   = DHCP_ETH_ALEN;

  /* UDP header */
  pack->udph.src = htons(DHCP_BOOTPS);
  pack->udph.dst = htons(DHCP_BOOTPC);

  /* IP header */
  pack->iph.ihl = 5;
  pack->iph.version = 4;
  pack->iph.tos = 0;
  pack->iph.tot_len = 0; /* Calculate at end of packet */
  pack->iph.id = 0;
  pack->iph.frag_off = 0;
  pack->iph.ttl = 0x10;
  pack->iph.protocol = 0x11;
  pack->iph.check = 0; /* Calculate at end of packet */

  /* Ethernet header */
  pack->ethh.prot = htons(DHCP_ETH_IP);

  return 0;
}

/**
 * \brief Search a DHCP packet for a particular tag.
 * \param pack DHCP packet
 * \param length length of DHCP packet
 * \param tag if found tag will be filled in this variable
 * \param tagtype type of tag to search
 * \return -1 if not found.
 */
static int dhcp_gettag(struct dhcp_packet_t *pack, int length,
                       struct dhcp_tag_t **tag, uint8_t tagtype)
{
  struct dhcp_tag_t *t = NULL;
  int offset = DHCP_MIN_LEN + DHCP_OPTION_MAGIC_LEN;

  /* if(length > DHCP_LEN) {
     sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
     "Length of dhcp packet larger then %d: %d", DHCP_LEN, length);
     length = DHCP_LEN;
     } */

  while((offset + 2) < length)
  {
    t = (struct dhcp_tag_t*) (((char*) pack) + offset); /* cast with (char *) to avoid use of void* in arithmetic warning */
    if(t->t == tagtype)
    {
      if((offset +  2 + t->l) > length)
        return -1; /* Tag length too long */
      *tag = t;
      return 0;
    }
    offset +=  2 + t->l;
  }

  return -1; /* Not found  */
}

/**
 * \brief Send of a DHCP offer message to a peer.
 * \param conn DHCP connectino
 * \param pack packet
 * \param len length of packet
 * \return 0 if success, -1 otherwise4
 */
static int dhcp_sendOFFER(struct dhcp_conn_t *conn,
                          struct dhcp_fullpacket_t *pack, int len)
{
  struct dhcp_t *this = conn->parent;
  struct dhcp_fullpacket_t packet;
  uint16_t length = 576 + 4; /* Maximum length */
  uint16_t udp_len = 576 - 20; /* Maximum length */
  int pos = 0;

  /* To avoid unused parameter warning */
  len = 0;

  /* Get packet default values */
  dhcp_getdefault(&packet);

  /* DHCP Payload */
  packet.dhcp.xid    = pack->dhcp.xid;
  packet.dhcp.yiaddr = conn->hisip.s_addr;
  packet.dhcp.flags  = pack->dhcp.flags;
  packet.dhcp.giaddr = pack->dhcp.giaddr;
  memcpy(&packet.dhcp.chaddr, &pack->dhcp.chaddr, DHCP_CHADDR_LEN);

  /* Magic cookie */
  packet.dhcp.options[pos++] = 0x63;
  packet.dhcp.options[pos++] = 0x82;
  packet.dhcp.options[pos++] = 0x53;
  packet.dhcp.options[pos++] = 0x63;

  packet.dhcp.options[pos++] = DHCP_OPTION_MESSAGE_TYPE;
  packet.dhcp.options[pos++] = 1;
  packet.dhcp.options[pos++] = DHCPOFFER;

  packet.dhcp.options[pos++] = DHCP_OPTION_SUBNET_MASK;
  packet.dhcp.options[pos++] = 4;
  memcpy(&packet.dhcp.options[pos], &conn->hismask.s_addr, 4);
  pos += 4;

  packet.dhcp.options[pos++] = DHCP_OPTION_ROUTER_OPTION;
  packet.dhcp.options[pos++] = 4;
  memcpy(&packet.dhcp.options[pos], &conn->ourip.s_addr, 4);
  pos += 4;

  /* Insert DNS Servers if given */
  if(conn->dns1.s_addr && conn->dns2.s_addr)
  {
    packet.dhcp.options[pos++] = DHCP_OPTION_DNS;
    packet.dhcp.options[pos++] = 8;
    memcpy(&packet.dhcp.options[pos], &conn->dns1.s_addr, 4);
    pos += 4;
    memcpy(&packet.dhcp.options[pos], &conn->dns2.s_addr, 4);
    pos += 4;
  }
  else if(conn->dns1.s_addr)
  {
    packet.dhcp.options[pos++] = DHCP_OPTION_DNS;
    packet.dhcp.options[pos++] = 4;
    memcpy(&packet.dhcp.options[pos], &conn->dns1.s_addr, 4);
    pos += 4;
  }
  else if(conn->dns2.s_addr)
  {
    packet.dhcp.options[pos++] = DHCP_OPTION_DNS;
    packet.dhcp.options[pos++] = 4;
    memcpy(&packet.dhcp.options[pos], &conn->dns2.s_addr, 4);
    pos += 4;
  }

  /* Insert Domain Name if present */
  if(strlen(conn->domain))
  {
    packet.dhcp.options[pos++] = DHCP_OPTION_DOMAIN_NAME;
    packet.dhcp.options[pos++] = strlen(conn->domain);
    memcpy(&packet.dhcp.options[pos], &conn->domain, strlen(conn->domain));
    pos += strlen(conn->domain);
  }

  packet.dhcp.options[pos++] = DHCP_OPTION_LEASE_TIME;
  packet.dhcp.options[pos++] = 4;
  packet.dhcp.options[pos++] = (this->lease >> 24) & 0xFF;
  packet.dhcp.options[pos++] = (this->lease >> 16) & 0xFF;
  packet.dhcp.options[pos++] = (this->lease >>  8) & 0xFF;
  packet.dhcp.options[pos++] = (this->lease >>  0) & 0xFF;

  /* Must be listening address */
  packet.dhcp.options[pos++] = DHCP_OPTION_SERVER_ID;
  packet.dhcp.options[pos++] = 4;
  memcpy(&packet.dhcp.options[pos], &conn->ourip.s_addr, 4);
  pos += 4;

  packet.dhcp.options[pos++] = DHCP_OPTION_END;

  /* UDP header */
  udp_len = pos + DHCP_MIN_LEN + DHCP_UDP_HLEN;
  packet.udph.len = htons(udp_len);

  /* IP header */
  packet.iph.tot_len = htons(udp_len + DHCP_IP_HLEN);
  packet.iph.daddr = ~0; /* TODO: Always sending to broadcast address */
  packet.iph.saddr = conn->ourip.s_addr;

  /* Work out checksums */
  (void)dhcp_udp_check(&packet);
  (void)dhcp_ip_check((struct dhcp_ippacket_t*) &packet);

  /* Ethernet header */
  memcpy(packet.ethh.dst, conn->hismac, DHCP_ETH_ALEN);
  memcpy(packet.ethh.src, this->hwaddr, DHCP_ETH_ALEN);

  /* Calculate total length */
  length = udp_len + DHCP_IP_HLEN + DHCP_ETH_HLEN;

  return dhcp_send(this, this->fd, DHCP_ETH_IP, conn->hismac, this->ifindex,
                   &packet, length);
}

/**
 * \brief Send of a DHCP acknowledge message to a peer.
 * \param conn low-level connection
 * \param pack packet
 * \param len length of packet
 * \return 0 if success, -1 otherwise
 */
static int dhcp_sendACK(struct dhcp_conn_t *conn,
                        struct dhcp_fullpacket_t *pack, int len)
{
  struct dhcp_t *this = conn->parent;
  struct dhcp_fullpacket_t packet;
  uint16_t length = 576 + 4; /* Maximum length */
  uint16_t udp_len = 576 - 20; /* Maximum length */
  int pos = 0;

  /* To avoid unused parameter warning */
  len = 0;

  /* Get packet default values */
  dhcp_getdefault(&packet);

  /* DHCP Payload */
  packet.dhcp.xid    = pack->dhcp.xid;
  packet.dhcp.ciaddr = pack->dhcp.ciaddr;
  packet.dhcp.yiaddr = conn->hisip.s_addr;
  packet.dhcp.flags  = pack->dhcp.flags;
  packet.dhcp.giaddr = pack->dhcp.giaddr;
  memcpy(&packet.dhcp.chaddr, &pack->dhcp.chaddr, DHCP_CHADDR_LEN);

  /* Magic cookie */
  packet.dhcp.options[pos++] = 0x63;
  packet.dhcp.options[pos++] = 0x82;
  packet.dhcp.options[pos++] = 0x53;
  packet.dhcp.options[pos++] = 0x63;

  packet.dhcp.options[pos++] = DHCP_OPTION_MESSAGE_TYPE;
  packet.dhcp.options[pos++] = 1;
  packet.dhcp.options[pos++] = DHCPACK;

  packet.dhcp.options[pos++] = DHCP_OPTION_SUBNET_MASK;
  packet.dhcp.options[pos++] = 4;
  memcpy(&packet.dhcp.options[pos], &conn->hismask.s_addr, 4);
  pos += 4;

  packet.dhcp.options[pos++] = DHCP_OPTION_ROUTER_OPTION;
  packet.dhcp.options[pos++] = 4;
  memcpy(&packet.dhcp.options[pos], &conn->ourip.s_addr, 4);
  pos += 4;

  /* Insert DNS Servers if given */
  if(conn->dns1.s_addr && conn->dns2.s_addr)
  {
    packet.dhcp.options[pos++] = DHCP_OPTION_DNS;
    packet.dhcp.options[pos++] = 8;
    memcpy(&packet.dhcp.options[pos], &conn->dns1.s_addr, 4);
    pos += 4;
    memcpy(&packet.dhcp.options[pos], &conn->dns2.s_addr, 4);
    pos += 4;
  }
  else if(conn->dns1.s_addr)
  {
    packet.dhcp.options[pos++] = DHCP_OPTION_DNS;
    packet.dhcp.options[pos++] = 4;
    memcpy(&packet.dhcp.options[pos], &conn->dns1.s_addr, 4);
    pos += 4;
  }
  else if(conn->dns2.s_addr)
  {
    packet.dhcp.options[pos++] = DHCP_OPTION_DNS;
    packet.dhcp.options[pos++] = 4;
    memcpy(&packet.dhcp.options[pos], &conn->dns2.s_addr, 4);
    pos += 4;
  }

  /* Insert Domain Name if present */
  if(strlen(conn->domain))
  {
    packet.dhcp.options[pos++] = DHCP_OPTION_DOMAIN_NAME;
    packet.dhcp.options[pos++] = strlen(conn->domain);
    memcpy(&packet.dhcp.options[pos], &conn->domain, strlen(conn->domain));
    pos += strlen(conn->domain);
  }

  packet.dhcp.options[pos++] = DHCP_OPTION_LEASE_TIME;
  packet.dhcp.options[pos++] = 4;
  packet.dhcp.options[pos++] = (this->lease >> 24) & 0xFF;
  packet.dhcp.options[pos++] = (this->lease >> 16) & 0xFF;
  packet.dhcp.options[pos++] = (this->lease >>  8) & 0xFF;
  packet.dhcp.options[pos++] = (this->lease >>  0) & 0xFF;

  /*
     packet.dhcp.options[pos++] = DHCP_OPTION_INTERFACE_MTU;
     packet.dhcp.options[pos++] = 2;
     packet.dhcp.options[pos++] = (conn->mtu >> 8) & 0xFF;
     packet.dhcp.options[pos++] = (conn->mtu >> 0) & 0xFF;
     */

  /* Must be listening address */
  packet.dhcp.options[pos++] = DHCP_OPTION_SERVER_ID;
  packet.dhcp.options[pos++] = 4;
  memcpy(&packet.dhcp.options[pos], &conn->ourip.s_addr, 4);
  pos += 4;

  packet.dhcp.options[pos++] = DHCP_OPTION_END;

  /* UDP header */
  udp_len = pos + DHCP_MIN_LEN + DHCP_UDP_HLEN;
  packet.udph.len = htons(udp_len);

  /* IP header */
  packet.iph.tot_len = htons(udp_len + DHCP_IP_HLEN);
  packet.iph.daddr = ~0; /* TODO: Always sending to broadcast address */
  packet.iph.saddr = conn->ourip.s_addr;

  /* Work out checksums */
  (void)dhcp_udp_check(&packet);
  (void)dhcp_ip_check((struct dhcp_ippacket_t*) &packet);

  /* Ethernet header */
  memcpy(packet.ethh.dst, conn->hismac, DHCP_ETH_ALEN);
  memcpy(packet.ethh.src, this->hwaddr, DHCP_ETH_ALEN);

  /* Calculate total length */
  length = udp_len + DHCP_IP_HLEN + DHCP_ETH_HLEN;

  return dhcp_send(this, this->fd, DHCP_ETH_IP, conn->hismac, this->ifindex,
                   &packet, length);
}

/**
 * \brief Send of a DHCP negative acknowledge message to a peer.
 *
 * NAK messages are always sent to broadcast IP address (
 * except when using a DHCP relay server)
 * \param conn low-level connection
 * \param pack DHCP packet
 * \param len length of packet
 * \return 0 if success, -1 otherwise
 */
static int dhcp_sendNAK(struct dhcp_conn_t *conn,
                        struct dhcp_fullpacket_t *pack, int len)
{
  struct dhcp_t *this = conn->parent;
  struct dhcp_fullpacket_t packet;
  uint16_t length = 576 + 4; /* Maximum length */
  uint16_t udp_len = 576 - 20; /* Maximum length */
  int pos = 0;

  /* To avoid unused parameter warning */
  len = 0;

  /* Get packet default values */
  dhcp_getdefault(&packet);

  /* DHCP Payload */
  packet.dhcp.xid    = pack->dhcp.xid;
  packet.dhcp.flags  = pack->dhcp.flags;
  packet.dhcp.giaddr = pack->dhcp.giaddr;
  memcpy(&packet.dhcp.chaddr, &pack->dhcp.chaddr, DHCP_CHADDR_LEN);

  /* Magic cookie */
  packet.dhcp.options[pos++] = 0x63;
  packet.dhcp.options[pos++] = 0x82;
  packet.dhcp.options[pos++] = 0x53;
  packet.dhcp.options[pos++] = 0x63;

  packet.dhcp.options[pos++] = DHCP_OPTION_MESSAGE_TYPE;
  packet.dhcp.options[pos++] = 1;
  packet.dhcp.options[pos++] = DHCPNAK;

  /* Must be listening address */
  packet.dhcp.options[pos++] = DHCP_OPTION_SERVER_ID;
  packet.dhcp.options[pos++] = 4;
  memcpy(&packet.dhcp.options[pos], &conn->ourip.s_addr, 4);
  pos += 4;

  packet.dhcp.options[pos++] = DHCP_OPTION_END;

  /* UDP header */
  udp_len = pos + DHCP_MIN_LEN + DHCP_UDP_HLEN;
  packet.udph.len = htons(udp_len);

  /* IP header */
  packet.iph.tot_len = htons(udp_len + DHCP_IP_HLEN);
  packet.iph.daddr = ~0; /* TODO: Always sending to broadcast address */
  packet.iph.saddr = conn->ourip.s_addr;

  /* Work out checksums */
  (void)dhcp_udp_check(&packet);
  (void)dhcp_ip_check((struct dhcp_ippacket_t*) &packet);

  /* Ethernet header */
  memcpy(packet.ethh.dst, conn->hismac, DHCP_ETH_ALEN);
  memcpy(packet.ethh.src, this->hwaddr, DHCP_ETH_ALEN);

  /* Calculate total length */
  length = udp_len + DHCP_IP_HLEN + DHCP_ETH_HLEN;

  return dhcp_send(this, this->fd, DHCP_ETH_IP, conn->hismac, this->ifindex,
                   &packet, length);
}

/**
 * \brief Process a received DHCP request MESSAGE.
 * \param this dhcp_t instance
 * \param pack DHCP packet
 * \param len length of packet
 * \return 0 if success, -1 otherwise
 */
static int dhcp_getreq(struct dhcp_t *this,
                       struct dhcp_fullpacket_t *pack, int len)
{
  struct dhcp_conn_t *conn = NULL;

  struct dhcp_tag_t *message_type = 0;
  struct dhcp_tag_t *requested_ip = 0;
  struct in_addr addr;

  /* To avoid unused parameter warning */
  len = 0;

  if(pack->udph.dst != htons(DHCP_BOOTPS))
    return 0; /* Not a DHCP packet */

  if(dhcp_gettag(&pack->dhcp, ntohs(pack->udph.len) - DHCP_UDP_HLEN,
                  &message_type, DHCP_OPTION_MESSAGE_TYPE))
  {
    return -1;
  }

  if(message_type->l != 1)
    return -1; /* Wrong length of message type */

  if((message_type->v[0] != DHCPDISCOVER) &&
      (message_type->v[0] != DHCPREQUEST) &&
      (message_type->v[0] != DHCPRELEASE))
  {
    return 0; /* Unsupported message type */
  }

  /* Release message */
  /* If connection exists: Release it. No Reply to client is sent */
  if(message_type->v[0] == DHCPRELEASE)
  {
    if(!dhcp_hashget(this, &conn, pack->ethh.src))
    {
      dhcp_freeconn(conn);
    }
    return 0;
  }

  /* Check to see if we know MAC address. If not allocate new conn */
  if(dhcp_hashget(this, &conn, pack->ethh.src))
  {
    /* Do we allow dynamic allocation of IP addresses? */
    if(!this->allowdyn) /* TODO: Should be deleted! */
      return 0;

    /* Allocate new connection */
    if(dhcp_newconn(this, &conn, pack->ethh.src)) /* TODO: Delete! */
      return 0; /* Out of connections */
  }

  /* Request an IP address */
  if(conn->authstate == DHCP_AUTH_NONE)
  {
    addr.s_addr = pack->dhcp.ciaddr;
    if(this ->cb_request)
      if(this->cb_request(conn, &addr))
      {
        return 0; /* Ignore request if IP address was not allocated */
      }
  }

  gettimeofday(&conn->lasttime, NULL);

  /* Discover message */
  /* If an IP address was assigned offer it to the client */
  /* Otherwise ignore the request */
  if(message_type->v[0] == DHCPDISCOVER)
  {
    if(conn->hisip.s_addr) (void)dhcp_sendOFFER(conn, pack, len);
    return 0;
  }

  /* Request message */
  if(message_type->v[0] == DHCPREQUEST)
  {
    if(!conn->hisip.s_addr)
    {
      if(this->debug) printf("hisip not set\n");
      return dhcp_sendNAK(conn, pack, len);
    }

    if(!memcmp(&conn->hisip.s_addr, &pack->dhcp.ciaddr, 4))
    {
      if(this->debug) printf("hisip match ciaddr\n");
      return dhcp_sendACK(conn, pack, len);
    }

    if(!dhcp_gettag(&pack->dhcp, ntohs(pack->udph.len) - DHCP_UDP_HLEN,
                     &requested_ip, DHCP_OPTION_REQUESTED_IP))
    {
      if(!memcmp(&conn->hisip.s_addr, requested_ip->v, 4))
        return dhcp_sendACK(conn, pack, len);
    }

    if(this->debug) printf("Sending NAK to client\n");
    return dhcp_sendNAK(conn, pack, len);
  }

  /* Unsupported DHCP message: Ignore */
  return 0;
}

int dhcp_set_addrs(struct dhcp_conn_t *conn,
                   struct in_addr *hisip,
                   struct in_addr *hismask,
                   struct in_addr *ourip,
                   struct in_addr *dns1,
                   struct in_addr *dns2,
                   char *domain)
{
  conn->ipv6 = 0;
  conn->hisip.s_addr = hisip->s_addr;
  conn->hismask.s_addr = hismask->s_addr;
  conn->ourip.s_addr = ourip->s_addr;
  conn->dns1.s_addr = dns1->s_addr;
  conn->dns2.s_addr = dns2->s_addr;

  if(domain)
  {
    strncpy(conn->domain, domain, DHCP_DOMAIN_LEN);
    conn->domain[DHCP_DOMAIN_LEN - 1] = 0;
  }
  else
  {
    conn->domain[0] = 0;
  }

  return 0;
}

int dhcp_set_addrsv6(struct dhcp_conn_t *conn,
                     struct in6_addr *hisip,
                     struct in6_addr *ourip,
                     char *domain)
{
  conn->ipv6 = 1;
  memcpy(conn->hisipv6.s6_addr, hisip->s6_addr, sizeof(struct in6_addr));
  memcpy(conn->ouripv6.s6_addr, ourip->s6_addr, sizeof(struct in6_addr));
  if(domain)
  {
    strncpy(conn->domain, domain, DHCP_DOMAIN_LEN);
    conn->domain[DHCP_DOMAIN_LEN - 1] = 0;
  }
  else
  {
    conn->domain[0] = 0;
  }

  return 0;
}

/**
 * \brief Process IPv6 packet.
 * \param this the dhcp_t instance
 * \param pack the packet
 * \param len length of the packet
 * \return 0 if success, -1 otherwise
 * \author Sebastien Vincent
 */
static int dhcp_receive_ipv6(struct dhcp_t* this, struct dhcp_ipv6packet_t* pack, int len)
{
  struct dhcp_conn_t* conn = NULL;
  struct in6_addr ouripv6;

  /* Check to see if we know MAC address. */
  if(!dhcp_hashgetv6(this, &conn, pack->ethh.src))
  {
    if(this->debug) printf("IPv6 Address found\n");

    memcpy(&ouripv6, &conn->ouripv6, sizeof(struct in6_addr));

    /* protect from spoofing */
    if(!IN6_IS_ADDR_UNSPECIFIED(&conn->hisipv6) && !IN6_IS_ADDR_LINKLOCAL((struct in6_addr*)&pack->ip6h.src_addr) && !IN6_IS_ADDR_UNSPECIFIED((struct in6_addr*)&pack->ip6h.src_addr))
    {
      memcpy(&conn->hisipv6, pack->ip6h.src_addr, sizeof(struct in6_addr));
    }
  }
  else
  {
    /*if(this->debug)*/
    printf("Address not found\n");
    memcpy(&ouripv6, &this->ouripv6, sizeof(struct in6_addr));

    if(IN6_IS_ADDR_LINKLOCAL((struct in6_addr*)&pack->ip6h.src_addr) || IN6_IS_ADDR_UNSPECIFIED((struct in6_addr*)&pack->ip6h.src_addr))
    {
      /* we don't care about link-local address */
      printf("dont'care about link-local\n");
      return 0;
    }

    /* Allocate new connection */
    if(dhcp_newconn6(this, &conn, pack->ethh.src))
    {
      return 0; /* Out of connections */
    }

    memcpy(&conn->hisipv6, &pack->ip6h.src_addr, sizeof(struct in6_addr));
    memcpy(&conn->ouripv6, &this->ouripv6, sizeof(struct in6_addr));
  }

  /* Return if we do not know peer */
  if(!conn)
  {
    return 0;
  }

  if((conn->authstate == DHCP_AUTH_NONE))
  {
    /* [SV]: inform application about the IPv6 address */
    if(this->cb_requestv6(conn, &conn->hisipv6))
    {
      printf("cb_requestv6 error!\n");
      return -1;
    }
  }

  gettimeofday(&conn->lasttime, NULL);

  printf("IPv6 conn->authstate: %d\n", conn->authstate);

  /* check if there are NS for us.
   * We do it there because in all state PepperSpot have
   * to respond to NS.
   */
  if(pack->ip6h.next_header == DHCP_IPV6_ICMPV6)
  {
    struct in6_addr solict_addr;

    ipv6_addr_solict_mult(&this->ouripv6, &solict_addr);
    if(IN6_ARE_ADDR_EQUAL((struct in6_addr*)&pack->ip6h.dst_addr, &solict_addr) || IN6_ARE_ADDR_EQUAL((struct in6_addr*)&pack->ip6h.dst_addr, &this->ouripv6))
    {
      struct in6_addr src;
      struct dhcp_icmpv6packet_t* icmpv6 = (struct dhcp_icmpv6packet_t*)pack->payload;
      memcpy(&src, pack->ip6h.src_addr, 16);

      printf("icmpv6 for us!\n");
      /* send a NA */
      if(icmpv6->type == 135 /* NS */)
      {
        char buf[INET6_ADDRSTRLEN];
        printf("NS received\nouripv6:%s\n", inet_ntop(AF_INET6, this->ouripv6.s6_addr, buf, sizeof(buf)));
        if(ndisc_send_na(this->ipv6_ifindex, &this->ouripv6, &src, &this->ouripv6, 0x40000000 | 0x20000000) /* OVERRIDE +  SOLICITATION */ == -1)
        {
          printf("NA failed\n");
        }
      }
    }
  }

  /* [SG] If user is alerady logged in IPv4, we log him in IPv6. */
  if(conn->authstate == DHCP_AUTH_DNAT && this->cb_unauth_dnat)
  {
    this->cb_unauth_dnat(conn);
  }

  switch(conn->authstate)
  {
    case DHCP_AUTH_PASS:
      /* Pass packets unmodified */
      break;
    case DHCP_AUTH_UNAUTH_TOS:
      /* Set TOS to specified value (unauthenticated)
         pack->iph.tos = conn->unauth_cp;
         (void)dhcp_ip_check(pack);
         */
      break;
    case DHCP_AUTH_AUTH_TOS:
      /* [SV] SEE IT */
      /* Set TOS to specified value (authenticated)
         pack->iph.tos = conn->auth_cp;
         (void)dhcp_ip_check(pack);
         */
      break;
    case DHCP_AUTH_DNAT:
      /* Destination NAT if request to unknown web server */
      printf("auth_dnat ipv6\n");
      if(dhcp_doDNATv6(conn, pack, len))
        return 0; /* Drop is not http or dns */
      break;
    case DHCP_AUTH_DROP:
    default:
      return 0;
  }

  if(!IN6_IS_ADDR_UNSPECIFIED(&conn->hisipv6) && (this->cb_ipv6_ind))
  {
    this->cb_ipv6_ind(conn, &pack->ip6h, len - DHCP_ETH_HLEN);
  }

  return 0;
}

/**
 * \brief Process an newly IPv4 packet received, it can block packets,
 * request IPv4 address via DHCP, ...
 * \param this dhcp_t instance
 * \param pack IPv4 packet
 * \param len length of packet
 * \return 0 if success, -1 otherwise
 */
static int dhcp_receive_ip(struct dhcp_t *this, struct dhcp_ippacket_t *pack,
                           int len)
{
  struct dhcp_conn_t *conn = NULL;
  struct in_addr ourip;
  unsigned char const bmac[DHCP_ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  struct in_addr addr;

  if(this->debug) printf("DHCP packet received\n");
  printf("dhcp_receive_ip\n");

  /* Check that MAC address is our MAC or Broadcast */
  if((memcmp(pack->ethh.dst, this->hwaddr, DHCP_ETH_ALEN)) && (memcmp(pack->ethh.dst, bmac, DHCP_ETH_ALEN)))
    return 0;

  /* Check to see if we know MAC address. */
  if(!dhcp_hashget(this, &conn, pack->ethh.src))
  {
    if(this->debug) printf("Address found\n");
    ourip.s_addr = conn->ourip.s_addr;
  }
  else
  {
    if(this->debug) printf("Address not found\n");
    ourip.s_addr = this->ourip.s_addr;

    /* Do we allow dynamic allocation of IP addresses? */
    if(!this->allowdyn)
      return 0;

    /* Allocate new connection */
    if(dhcp_newconn(this, &conn, pack->ethh.src))
      return 0; /* Out of connections */
  }

  /* Request an IP address */
  if((conn->authstate == DHCP_AUTH_NONE) &&
      (pack->iph.daddr != 0) && (pack->iph.daddr != 0xffffffff))
  {
    addr.s_addr = pack->iph.saddr;
    if(this ->cb_request)
      if(this->cb_request(conn, &addr))
      {
        return 0; /* Ignore request if IP address was not allocated */
      }
  }

  /* Check to see if it is a packet for us */
  /* TODO: Handle IP packets with options. Currently these are just ignored */
  if(((pack->iph.daddr == 0) ||
       (pack->iph.daddr == 0xffffffff) ||
       (pack->iph.daddr == ourip.s_addr)) &&
      ((pack->iph.ihl == 5) && (pack->iph.protocol == DHCP_IP_UDP) &&
       (((struct dhcp_fullpacket_t*)pack)->udph.dst == htons(DHCP_BOOTPS))))
  {
    (void)dhcp_getreq(this, (struct dhcp_fullpacket_t*) pack, len);
  }

  /* Return if we do not know peer */
  if(!conn)
    return 0;

  /* [SG] If user is alerady logged in IPv6, we log him in IPv4. */
  if(conn->authstate == DHCP_AUTH_DNAT && this->cb_unauth_dnat)
  {
    this->cb_unauth_dnat(conn);
  }

  gettimeofday(&conn->lasttime, NULL);

  /* Was it a DNS request? */
  /*if(((pack->iph.daddr == conn->dns1.s_addr) ||
    (pack->iph.daddr == conn->dns2.s_addr)) &&
    (pack->iph.protocol == DHCP_IP_UDP) &&
    (udph->dst == htons(DHCP_DNS))) {
    if(dhcp_checkDNS(conn, pack, len)) return 0;
    } */

  switch(conn->authstate)
  {
    case DHCP_AUTH_PASS:
      /* Pass packets unmodified */
      break;
    case DHCP_AUTH_UNAUTH_TOS:
      /* Set TOS to specified value (unauthenticated) */
      pack->iph.tos = conn->unauth_cp;
      (void)dhcp_ip_check(pack);
      break;
    case DHCP_AUTH_AUTH_TOS:
      /* Set TOS to specified value (authenticated) */
      pack->iph.tos = conn->auth_cp;
      (void)dhcp_ip_check(pack);
      break;
    case DHCP_AUTH_DNAT:
      /* Destination NAT if request to unknown web server */
      if(dhcp_doDNAT(conn, pack, len))
        return 0; /* Drop is not http or dns */
      break;
    case DHCP_AUTH_DROP:
    default:
      return 0;
  }

  if((conn->hisip.s_addr) && (this ->cb_data_ind))
  {
    this ->cb_data_ind(conn, &pack->iph, len - DHCP_ETH_HLEN);
  }

  return 0;
}

int dhcp_decaps(struct dhcp_t *this)  /* DHCP Indication */
{
  struct dhcp_ippacket_t packet;
  int length = 0;

  /*if(this->debug)*/
  printf("DHCP packet received\n");

  if((length = recv(this->fd, &packet, sizeof(packet), 0)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "recv(fd=%d, len=%d) failed",
            this->fd, sizeof(packet));
    return -1;
  }

  return dhcp_receive_ip(this, &packet, length);
}

int dhcp_ipv6_ind(struct dhcp_t* this)
{
  struct dhcp_ipv6packet_t packet;
  ssize_t length = 0;

  if((length = recv(this->ipv6_fd, &packet, sizeof(packet), 0)) < 0)
  {
    if(errno != EINTR)
      sys_err(LOG_ERR, __FILE__, __LINE__, errno,
              "recv(fd=%d, len=%d) failed",
              this->ipv6_fd, sizeof(packet));
    return -1;
  }

  return dhcp_receive_ipv6(this, &packet, length);
}

int dhcp_ipv6_req(struct dhcp_conn_t* conn, void* pack, unsigned len)
{
  struct dhcp_t *this = conn->parent;
  int length = len + DHCP_ETH_HLEN;
  struct dhcp_ipv6packet_t packet;

  printf("Attempt to send IPv6 packet!!\n");

  /* Ethernet header */
  memcpy(packet.ethh.dst, conn->hismac, DHCP_ETH_ALEN);
  memcpy(packet.ethh.src, this->hwaddr, DHCP_ETH_ALEN);
  packet.ethh.prot = htons(DHCP_ETH_IPV6);

  /* IPv6 Packet */
  memcpy(&packet.ip6h, pack, len);

  switch(conn->authstate)
  {
    case DHCP_AUTH_PASS:
    case DHCP_AUTH_UNAUTH_TOS:
    case DHCP_AUTH_AUTH_TOS:
      /* Pass packets unmodified */
      break;
    case DHCP_AUTH_DNAT:
      /* Undo destination NAT */
      if(dhcp_undoDNATv6(conn, &packet, length))
        return 0;
      break;
    case DHCP_AUTH_DROP:
    default:
      return 0;
  }

  return dhcp_send(this, this->ipv6_fd, DHCP_ETH_IPV6, conn->hismac, this->ipv6_ifindex, &packet, length);
}

int dhcp_data_req(struct dhcp_conn_t *conn, void *pack, unsigned len)
{
  struct dhcp_t *this = conn->parent;
  int length = len + DHCP_ETH_HLEN;

  struct dhcp_ippacket_t packet;

  if(this->debug) printf("dhcp_data_req\n");

  /* Ethernet header */
  memcpy(packet.ethh.dst, conn->hismac, DHCP_ETH_ALEN);
  memcpy(packet.ethh.src, this->hwaddr, DHCP_ETH_ALEN);
  packet.ethh.prot = htons(DHCP_ETH_IP);

  /* IP Packet */
  memcpy(&packet.iph, pack, len);

  switch(conn->authstate)
  {
    case DHCP_AUTH_PASS:
    case DHCP_AUTH_UNAUTH_TOS:
    case DHCP_AUTH_AUTH_TOS:
      /* Pass packets unmodified */
      break;
    case DHCP_AUTH_DNAT:
      /* Undo destination NAT */
      if(dhcp_undoDNAT(conn, &packet, length))
        return 0;
      break;
    case DHCP_AUTH_DROP:
    default:
      return 0;
  }
  return dhcp_send(this, this->fd, DHCP_ETH_IP, conn->hismac, this->ifindex,
                   &packet, length);
}

/**
 * \brief Send ARP reply message to peer.
 * \param conn connection that sent previous ARP request
 * \param pack ARP request
 * \param len length of packet
 * \return 0
 */
static int dhcp_sendARP(struct dhcp_conn_t *conn,
                        struct dhcp_arp_fullpacket_t *pack, int len)
{
  struct dhcp_t *this = conn->parent;
  struct dhcp_arp_fullpacket_t packet;
  uint16_t length = sizeof(packet);
  struct in_addr reqaddr;

  /* To avoid unused parameter warning */
  len = 0;

  /* Get local copy */
  memcpy(&reqaddr.s_addr, pack->arp.tpa, DHCP_IP_ALEN);

  /* Check that request is within limits */

  /* Is ARP request for clients own address: Ignore */
  if(conn->hisip.s_addr == reqaddr.s_addr)
    return 0;

  /* If ARP request outside of mask: Ignore */
  if((conn->hisip.s_addr & conn->hismask.s_addr) !=
      (reqaddr.s_addr & conn->hismask.s_addr))
    return 0;

  /* Get packet default values */
  memset(&packet, 0, sizeof(packet));

  /* ARP Payload */
  packet.arp.hrd = htons(DHCP_HTYPE_ETH);
  packet.arp.pro = htons(DHCP_ETH_IP);
  packet.arp.hln = DHCP_ETH_ALEN;
  packet.arp.pln = DHCP_IP_ALEN;
  packet.arp.op  = htons(DHCP_ARP_REPLY);

  /* Source address */
  memcpy(packet.arp.sha, this->arp_hwaddr, DHCP_ETH_ALEN);
  memcpy(packet.arp.spa, &reqaddr.s_addr, DHCP_IP_ALEN);

  /* Target address */
  memcpy(packet.arp.tha, &conn->hismac, DHCP_ETH_ALEN);
  memcpy(packet.arp.tpa, &conn->hisip.s_addr, DHCP_IP_ALEN);

  /* Ethernet header */
  memcpy(packet.ethh.dst, conn->hismac, DHCP_ETH_ALEN);
  memcpy(packet.ethh.src, this->hwaddr, DHCP_ETH_ALEN);
  packet.ethh.prot = htons(DHCP_ETH_ARP);

  return dhcp_send(this, this->arp_fd, DHCP_ETH_ARP, conn->hismac,
                   this->arp_ifindex, &packet, length);
}

/**
 * \brief Process ARP requests.
 * \param this dhcp_t instance
 * \param pack ARP packet
 * \param len length of packet
 * \return 0
 */
static int dhcp_receive_arp(struct dhcp_t *this,
                            struct dhcp_arp_fullpacket_t *pack, int len)
{
  struct dhcp_conn_t *conn = NULL;
  unsigned char const bmac[DHCP_ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

  /* Check that this is ARP request */
  if(pack->arp.op != htons(DHCP_ARP_REQUEST))
  {
    /*if(this->debug)*/
    printf("Received other ARP than request!\n");
    return 0;
  }

  /* Check that MAC address is our MAC or Broadcast */
  if((memcmp(pack->ethh.dst, this->hwaddr, DHCP_ETH_ALEN)) && (memcmp(pack->ethh.dst, bmac, DHCP_ETH_ALEN)))
  {
    if(this->debug) printf("Received ARP request for other destination!\n");
    return 0;
  }

  /* Check to see if we know MAC address. */
  if(dhcp_hashget(this, &conn, pack->ethh.src))
  {
    if(this->debug) printf("Address not found\n");

    /* Do we allow dynamic allocation of IP addresses? */
    if(!this->allowdyn)  /* TODO: Experimental */
      return 0;

    /* Allocate new connection */
    if(dhcp_newconn(this, &conn, pack->ethh.src)) /* TODO: Experimental */
      return 0; /* Out of connections */
  }

  gettimeofday(&conn->lasttime, NULL);

  if(!conn->hisip.s_addr)
  {
    if(this->debug) printf("ARP request did not come from known client!\n");
    return 0; /* Only reply if he was allocated an address */
  }

  if(memcmp(&conn->ourip.s_addr, pack->arp.tpa, 4))
  {
    if(this->debug) printf("Did not ask for router address: %.8x - %.2x%.2x%.2x%.2x\n", conn->ourip.s_addr,
                              pack->arp.tpa[0],
                              pack->arp.tpa[1],
                              pack->arp.tpa[2],
                              pack->arp.tpa[3]);
    return 0; /* Only reply if he asked for his router address */
  }

  (void)dhcp_sendARP(conn, pack, len);

  return 0;
}

int dhcp_arp_ind(struct dhcp_t *this)  /* ARP Indication */
{
  struct dhcp_arp_fullpacket_t packet;
  int length = 0;

  if(this->debug) printf("ARP Packet Received!\n");

  if((length = recv(this->arp_fd, &packet, sizeof(packet), 0)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "recv(fd=%d, len=%d) failed",
            this->arp_fd, sizeof(packet));
    return -1;
  }

  dhcp_receive_arp(this, &packet, length);

  return 0;
}

/**
 * \brief Send 802.1X packet.
 * \param conn low-level connection
 * \param pack 802.1X packet
 * \param len length of packet
 * \return 0 if success, -1 otherwise
 */
static int dhcp_senddot1x(struct dhcp_conn_t *conn,
                          struct dhcp_dot1xpacket_t *pack, int len)
{
  struct dhcp_t *this = conn->parent;

  return dhcp_send(this, this->ipv6_fd, DHCP_ETH_EAPOL, conn->hismac, this->ifindex,
                   pack, len);
}

int dhcp_sendEAP(struct dhcp_conn_t *conn, void *pack, int len)
{
  struct dhcp_t *this = conn->parent;
  struct dhcp_dot1xpacket_t packet;

  /* Ethernet header */
  memcpy(packet.ethh.dst, conn->hismac, DHCP_ETH_ALEN);
  memcpy(packet.ethh.src, this->hwaddr, DHCP_ETH_ALEN);
  packet.ethh.prot = htons(DHCP_ETH_EAPOL);

  /* 802.1x header */
  packet.dot1x.ver  = 1;
  packet.dot1x.type = 0; /* EAP */
  packet.dot1x.len =  ntohs(len);

  memcpy(&packet.eap, pack, len);

  return dhcp_send(this, this->ipv6_fd, DHCP_ETH_EAPOL, conn->hismac, this->ifindex,
                   &packet, (DHCP_ETH_HLEN + 4 + len));
}

int dhcp_sendEAPreject(struct dhcp_conn_t *conn, void *pack, int len)
{
  /*struct dhcp_t *this = conn->parent;*/

  struct dhcp_eap_t packet;

  if(pack)
  {
    (void)dhcp_sendEAP(conn, pack, len);
  }
  else
  {
    memset(&packet, 0, sizeof(packet));
    packet.code      =  4;
    packet.id        =  1; /* TODO ??? */
    packet.length    =  ntohs(4);

    dhcp_sendEAP(conn, &packet, 4);
  }

  return 0;
}

int dhcp_eapol_ind(struct dhcp_t *this)  /* EAPOL Indication */
{
  struct dhcp_dot1xpacket_t packet;
  int length = 0;
  struct dhcp_conn_t *conn = NULL;
  unsigned char const bmac[DHCP_ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  unsigned char const amac[DHCP_ETH_ALEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

  if(this->debug) printf("EAPOL packet received\n");

  if((length = recv(this->eapol_fd, &packet, sizeof(packet), 0)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "recv(fd=%d, len=%d) failed",
            this->fd, sizeof(packet));
    return -1;
  }

  /* Check to see if we know MAC address. */
  if(!dhcp_hashget(this, &conn, packet.ethh.src))
  {
    if(this->debug) printf("Address found\n");
  }
  else
  {
    if(this->debug) printf("Address not found\n");
  }

  /* Check that MAC address is our MAC, Broadcast or authentication MAC */
  if((memcmp(packet.ethh.dst, this->hwaddr, DHCP_ETH_ALEN)) && (memcmp(packet.ethh.dst, bmac, DHCP_ETH_ALEN)) && (memcmp(packet.ethh.dst, amac, DHCP_ETH_ALEN)))
    return 0;

  if(this->debug) printf("IEEE 802.1x Packet: %.2x, %.2x %d\n",
                            packet.dot1x.ver, packet.dot1x.type,
                            ntohs(packet.dot1x.len));

  if(packet.dot1x.type == 1)   /* Start */
  {
    struct dhcp_dot1xpacket_t pack;
    memset(&pack, 0, sizeof(pack));

    /* Allocate new connection */
    if(conn == NULL)
    {
      if(dhcp_newconn(this, &conn, packet.ethh.src))
        return 0; /* Out of connections */
    }

    /* Ethernet header */
    memcpy(pack.ethh.dst, packet.ethh.src, DHCP_ETH_ALEN);
    memcpy(pack.ethh.src, this->hwaddr, DHCP_ETH_ALEN);
    pack.ethh.prot = htons(DHCP_ETH_EAPOL);

    /* 802.1x header */
    pack.dot1x.ver  = 1;
    pack.dot1x.type = 0; /* EAP */
    pack.dot1x.len =  ntohs(5);

    /* EAP Packet */
    pack.eap.code      =  1;
    pack.eap.id        =  1;
    pack.eap.length    =  ntohs(5);
    pack.eap.type      =  1; /* Identity */
    (void)dhcp_senddot1x(conn, &pack, DHCP_ETH_HLEN + 4 + 5);
    return 0;
  }
  else if(packet.dot1x.type == 0)   /* EAP */
  {
    /* TODO: Currently we only support authentications starting with a
       client sending a EAPOL start message. Need to also support
       authenticator initiated communications. */
    if(!conn)
      return 0;

    gettimeofday(&conn->lasttime, NULL);

    if(this ->cb_eap_ind)
      this ->cb_eap_ind(conn, &packet.eap, ntohs(packet.eap.length));
    return 0;
  }
  else   /* Check for logoff */
  {
    return 0;
  }
}

int dhcp_set_cb_requestv6(struct dhcp_t *this,  int (*cb_request) (struct dhcp_conn_t *conn, struct in6_addr *addr))
{
  this->cb_requestv6 = cb_request;
  return 0;
}

int dhcp_set_cb_connectv6(struct dhcp_t *this,  int (*cb_connect) (struct dhcp_conn_t *conn))
{
  this->cb_connectv6 = cb_connect;
  return 0;
}

int dhcp_set_cb_disconnectv6(struct dhcp_t *this,  int (*cb_disconnect) (struct dhcp_conn_t *conn))
{
  this->cb_disconnectv6 = cb_disconnect;
  return 0;
}

int dhcp_set_cb_ipv6_ind(struct dhcp_t *this, int (*cb_ind) (struct dhcp_conn_t *conn, void *pack, unsigned len))
{
  this->cb_ipv6_ind = cb_ind;
  return 0;
}

/* [SG] */
int dhcp_set_cb_unauth_dnat(struct dhcp_t *this,
                            int (*cb_unauth_dnat) (struct dhcp_conn_t *conn))
{
  this->cb_unauth_dnat = cb_unauth_dnat;
  return 0;
}

int dhcp_set_cb_eap_ind(struct dhcp_t *this,
                        int (*cb_eap_ind) (struct dhcp_conn_t *conn, void *pack, unsigned len))
{
  this ->cb_eap_ind = cb_eap_ind;
  return 0;
}

int dhcp_set_cb_data_ind(struct dhcp_t *this,
                         int (*cb_data_ind) (struct dhcp_conn_t *conn, void *pack, unsigned len))
{
  this ->cb_data_ind = cb_data_ind;
  return 0;
}

int dhcp_set_cb_request(struct dhcp_t *this,
                        int (*cb_request) (struct dhcp_conn_t *conn, struct in_addr *addr))
{
  this ->cb_request = cb_request;
  return 0;
}

int dhcp_set_cb_connect(struct dhcp_t *this,
                        int (*cb_connect) (struct dhcp_conn_t *conn))
{
  this ->cb_connect = cb_connect;
  return 0;
}

int dhcp_set_cb_disconnect(struct dhcp_t *this,
                           int (*cb_disconnect) (struct dhcp_conn_t *conn))
{
  this ->cb_disconnect = cb_disconnect;
  return 0;
}

#if defined(__FreeBSD__) || defined (__OpenBSD__) || defined (__APPLE__)

int dhcp_receive(struct dhcp_t *this)
{
  /*
     struct interface_info *interface, unsigned char *buf,
     size_t len, struct sockaddr_in *from, struct hardware *hfrom)
     {*/
  int length = 0;
  struct bpf_hdr *hdrp = NULL;
  struct dhcp_ethhdr_t *ethhdr = NULL;

  if(this->rbuf_offset == this->rbuf_len)
  {
    length = read(this->fd, this->rbuf, this->rbuf_max);
    if(length <= 0)
      return (length);
    this->rbuf_offset = 0;
    this->rbuf_len = length;
  }

  while(this->rbuf_offset != this->rbuf_len)
  {
    if(this->rbuf_len - this->rbuf_offset < sizeof(struct bpf_hdr))
    {
      this->rbuf_offset = this->rbuf_len;
      continue;
    }

    hdrp = (struct bpf_hdr *) &this->rbuf[this->rbuf_offset];

    if(this->rbuf_offset + hdrp->bh_hdrlen + hdrp->bh_caplen >  this->rbuf_len)
    {
      this->rbuf_offset = this->rbuf_len;
      continue;
    }

    if(hdrp->bh_caplen != hdrp->bh_datalen)
    {
      this->rbuf_offset += hdrp->bh_hdrlen + hdrp->bh_caplen;
      continue;
    }

    ethhdr = (struct dhcp_ethhdr_t *)
             (this->rbuf + this->rbuf_offset + hdrp->bh_hdrlen);

    switch(ntohs(ethhdr->prot))
    {
      case DHCP_ETH_IP:
        dhcp_receive_ip(this, (struct dhcp_ippacket_t*) ethhdr, hdrp->bh_caplen);
        break;
      case DHCP_ETH_ARP:
        dhcp_receive_arp(this, (struct dhcp_arp_fullpacket_t*) ethhdr,
                         hdrp->bh_caplen);
        break;
        /* [SV] */
      case DHCP_ETH_IPV6:
        dhcp_receive_ipv6(this, (struct dhcp_ipv6packet_t*)ethhdr, hdrp->bh_caplen);
        break;
      case DHCP_ETH_EAPOL:
      default:
        break;
    }
    this->rbuf_offset += hdrp->bh_hdrlen + hdrp->bh_caplen;
  };
  return (0);
}
#endif

