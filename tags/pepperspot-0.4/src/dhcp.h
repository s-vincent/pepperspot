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
 * DHCP library functions
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
 * The initial developer of the original code is
 * Jens Jakobsen <jj@chillispot.org>
 *
 */

/**
 * \file dhcp.h
 * \brief Packet authenticator and DHCP module.
 */

#ifndef _DHCP_H
#define _DHCP_H

#include <net/if.h>

/* DHCP Ethernet frame types */
#define DHCP_ETH_IP                 0x0800 /**< IPv4 protocol number */
/* [SV] */
#define DHCP_ETH_IPV6               0x86dd /**< IPv6 protocol number */
#define DHCP_ETH_ARP                0x0806 /**< ARP protocol number */
#define DHCP_ETH_EAPOL              0x888e /**< EAPOL protocol number */

/* Misc decl */
#define DHCP_DEBUG        0      /**< Print debug information */
#define DHCP_MTU       1492      /**< Maximum MTU size */

#define DHCP_TAG_VLEN 255        /**< Tag value always shorter than this */

/**
 * \struct dhcp_tag_t
 * \brief DHCP tag.
 */
struct dhcp_tag_t
{
  uint8_t t; /**< Type */
  uint8_t l; /**< Length */
  uint8_t v[DHCP_TAG_VLEN]; /**< Value */
} __attribute__((packed));

/* Option constants */
#define DHCP_OPTION_MAGIC          0x63825363 /**< DHCP magic number */
#define DHCP_OPTION_MAGIC_LEN       4 /**< DHCP magic number length */

#define DHCP_OPTION_PAD             0 /**< Padding option */
#define DHCP_OPTION_SUBNET_MASK     1 /**< IPv4 mask option */
#define DHCP_OPTION_ROUTER_OPTION   3 /**< Router option */
#define DHCP_OPTION_DNS             6 /**< DNS information option */
#define DHCP_OPTION_DOMAIN_NAME    15 /**< Domain name information option */
#define DHCP_OPTION_INTERFACE_MTU  26 /**< MTU option */
#define DHCP_OPTION_REQUESTED_IP   50 /**< Requested IPv4 option */
#define DHCP_OPTION_LEASE_TIME     51 /**< DHCP lease time option */
#define DHCP_OPTION_MESSAGE_TYPE   53 /**< Message type option */
#define DHCP_OPTION_SERVER_ID      54 /**< DHCP server ID */
#define DHCP_OPTION_END           255 /**< End of options */

/* BOOTP Message Types */
#define DHCP_BOOTREQUEST  1 /**< BOOTP request code */
#define DHCP_BOOTREPLY    2 /**< BOOTP reply code */

/* DHCP Message Types */
#define DHCPDISCOVER      1 /**< DISCOVER message type */
#define DHCPOFFER         2 /**< OFFER message type */
#define DHCPREQUEST       3 /**< REQUEST message type */
#define DHCPDECLINE       4 /**< DECLINE message type */
#define DHCPACK           5 /**< ACK message type */
#define DHCPNAK           6 /**< NAK message type */
#define DHCPRELEASE       7 /**< RELEASE message type */

/* UDP Ports */
#define DHCP_BOOTPS 67 /**< BOOTPS protocol number */
#define DHCP_BOOTPC 68 /**< BOOTPC protocol number */
#define DHCP_DNS    53 /**< DNS protocol number */

/* TCP Ports */
#define DHCP_HTTP   80 /**< HTTP protocol number */
#define DHCP_HTTPS 443 /**< HTTPS protocol number */

/* Length constants for Ethernet packet */
#define DHCP_ETH_ALEN  6 /**< Ethernet address length */
#define DHCP_ETH_HLEN 14 /**< Ethernet header length */

/**
 * \struct dhcp_ethhdr_t
 * \brief Ethernet header.
 */
struct dhcp_ethhdr_t
{
  uint8_t  dst[DHCP_ETH_ALEN]; /**< Destination address. */
  uint8_t  src[DHCP_ETH_ALEN]; /**< Source address. */
  uint16_t prot; /**< Layer 3 protocol. */
};

/* Constants for IP packet */
#define DHCP_IP_ALEN   4 /**< IPv4 address length */
#define DHCP_IP_HLEN  20 /**< IPv4 header length */
#define DHCP_IP_ICMP   1 /**< ICMP Protocol number */
#define DHCP_IP_TCP    6 /**< TCP Protocol number */
#define DHCP_IP_UDP   17 /**< UDP Protocol number */

/* Constants for IPv6 packet */
#define DHCP_IPV6_ICMPV6 58 /**< ICMPv6 protocol number */
#define DHCP_IPV6_UDP 17 /**< UDP protocol number */
#define DHCP_IPV6_TCP 6 /**< TCP protocol number */

/**
 * \struct dhcp_iphdr_t
 * \brief IPv4 header.
 */
struct dhcp_iphdr_t
{
  uint32_t  ihl : 4; /**< Internet header length (number of 32 bits words in header) */
  uint32_t  version : 4; /**< Version (always 4) */
  uint32_t  tos : 8; /**< Type of service */
  uint32_t tot_len : 16; /**< Total length */
  uint16_t id; /**< ID number */
  uint16_t frag_off; /**< Fragmentation offset */
  uint8_t  ttl; /**< Time to live */
  uint8_t  protocol; /**< Protocol */
  uint16_t check; /**< Checksum */
  uint32_t saddr; /**< Source IPv4 address */
  uint32_t daddr; /**< Destination IPv4 address */
} __attribute__((packed));

/* [SV] */
/**
 * \struct dhcp_ipv6hdr_t
 * \brief IPv6 header.
 */
struct dhcp_ipv6hdr_t
{
  uint32_t version:4; /**< Version (always 6) */
  uint32_t traffic_class:8; /**< Priority field */
  uint32_t flow_label:20; /**< Flow label field */
  uint16_t payload_length; /**< Payload length */
  uint8_t next_header; /**< Next header number (protocol or IPv6 extension) */
  uint8_t hop_limit; /**< Hop limit (i.e TTL) */
  uint8_t src_addr[16]; /**< IPv6 source address */
  uint8_t dst_addr[16]; /**< IPv6 destination address */
} __attribute__((packed));

#define DHCP_IP_PLEN 1500 /**< IPv4 payload length */

/**
 * \struct dhcp_ippacket_t
 * \brief Complete IPv4 packet including ethernet header.
 */
struct dhcp_ippacket_t
{
  struct dhcp_ethhdr_t ethh; /**< Ethernet header */
  struct dhcp_iphdr_t iph; /**< IPv4 header */
  uint8_t payload[DHCP_IP_PLEN]; /**< Data */
} __attribute__((packed));

/* [SV] */
/**
 * \def DHCP_IPV6_PLEN
 * \brief IPv6 payload length.
 */
#define DHCP_IPV6_PLEN 1500

/**
 * \struct dhcp_ipv6packet_t
 * \brief Full IPv6 packet including ethernet header.
 */
struct dhcp_ipv6packet_t
{
  struct dhcp_ethhdr_t ethh; /**< Ethernet header. */
  struct dhcp_ipv6hdr_t ip6h; /**< IPv6 header. */
  uint8_t payload[DHCP_IPV6_PLEN]; /**< Data. */
} __attribute__((packed));

/**
 * \struct dhcp_icmpv6packet_t
 * \brief ICMPv6 header.
 */
struct dhcp_icmpv6packet_t
{
  uint8_t type; /**< Type of message. */
  uint8_t code; /**< Code of message. */
  uint16_t checksum; /**< Checksum */
};

/**
 * \def DHCP_UDP_HLEN
 * \brief UDP header length.
 */
#define DHCP_UDP_HLEN 8

/**
 * \struct dhcp_udphdr_t
 * \brief UDP header.
 */
struct dhcp_udphdr_t
{
  uint16_t src; /**< Source port. */
  uint16_t dst; /**< Destination port. */
  uint16_t len; /**< Length. */
  uint16_t check; /**< Checksum. */
};

/**
 * \struct dhcp_tcphdr_t
 * \brief TCP header.
 */
struct dhcp_tcphdr_t
{
  uint16_t src; /**< Source port. */
  uint16_t dst; /**< Destination port. */
  uint32_t seq; /**< Sequence number. */
  uint32_t ack; /**< Acknowledgement number. */
  uint8_t flags; /**< TCP flags (SYN, ACK, ...). */
  uint16_t win; /**< Window size. */
  uint16_t check; /**< Checksum. */
  uint8_t options[1]; /**< TCP Options (TODO). */
};

/* Length constants for DHCP packet */
#define DHCP_CHADDR_LEN    16    /**< Length of client hardware address */
#define DHCP_SNAME_LEN     64    /**< Length of server host name */
#define DHCP_FILE_LEN     128    /**< Length of boot file name*/
#define DHCP_OPTIONS_LEN  312    /**< Length of optional parameters field */
#define DHCP_MIN_LEN 28 + 16 + 64 + 128 /**< Length of packet excluding options */
#define DHCP_LEN DHCP_MIN_LEN + DHCP_OPTIONS_LEN /**< Total length of DHCP packet */

/* Value Constants */

#define DHCP_HTYPE_ETH 1 /**< DHCP hardware type for ethernet network */

/**
 * \struct dhcp_packet_t
 * \brief DHCP packet from RFC 2131.
 */
struct dhcp_packet_t   /* From RFC 2131 */
{
  uint8_t op;       /**< 1 Message op code / message type.  1 =
                       BOOTREQUEST, 2 = BOOTREPLY */
  uint8_t htype;    /**< 1 Hardware address type, see ARP section
                       in "Assigned Numbers" RFC; e.g., '1' =
                       10mb ethernet.*/
  uint8_t hlen;     /**< 1 Hardware address length (e.g.  '6' for
                       10mb ethernet).*/
  uint8_t hops;     /**< 1 Client sets to zero, optionally used
                       by relay agents when booting via a
                       relay agent.*/
  uint32_t xid;    /**< 4 Transaction ID, a random number chosen
                      by the client, used by the client and
                      server to associate messages and
                      responses between a client and a
                      server.*/
  uint16_t secs;   /**< 2 Filled in by client, seconds elapsed since
                      client began address acquisition or renewal
                      process.*/
  uint16_t flags;  /**< 2  Flags (see figure 2).*/
  uint32_t ciaddr; /**< 4 Client IP address; only filled in if
                      client is in BOUND, RENEW or REBINDING state
                      and can respond to ARP requests.*/
  uint32_t yiaddr; /**< 4 'your' (client) IP address.*/
  uint32_t siaddr; /**< 4 IP address of next server to use in
                      bootstrap; returned in DHCPOFFER,
                      DHCPACK by server.*/
  uint32_t giaddr; /**< 4 Relay agent IP address, used in
                      booting via a relay agent.*/
  uint8_t  chaddr[DHCP_CHADDR_LEN]; /**< 16 Client hardware address.*/
  uint8_t sname[DHCP_SNAME_LEN]; /**< 64 Optional server host name,
                                    null terminated string.*/
  uint8_t file[DHCP_FILE_LEN]; /**< 128 Boot file name, null terminated
                                  string; "generic" name or null in
                                  DHCPDISCOVER, fully qualified directory-path
                                  name in DHCPOFFER.*/
  uint8_t options[DHCP_OPTIONS_LEN]; /**< var Optional parameters
                                        field.  See the options documents for a list
                                        of defined options.*/
} __attribute__((packed));

/**
 * \struct dhcp_fullpacket_t
 * \brief Complete DHCP packet including ethernet and
 * IPv4 header.
 */
struct dhcp_fullpacket_t
{
  struct dhcp_ethhdr_t ethh; /**< Ethernet header */
  struct dhcp_iphdr_t iph; /**< IPv4 header */
  struct dhcp_udphdr_t udph; /**< UDP header */
  struct dhcp_packet_t dhcp; /**< DHCP packet */
} __attribute__((packed));

#define DHCP_ARP_REQUEST 1 /**< ARP request code */
#define DHCP_ARP_REPLY   2 /**< ARP reply code */

/**
 * \struct dhcp_arp_packet_t
 * \brief ARP packet.
 */
struct dhcp_arp_packet_t   /* From RFC 826 */
{
  uint16_t hrd; /**< 16.bit: (ar$hrd) Hardware address space (e.g.,
                   Ethernet, Packet Radio Net.) */
  uint16_t pro; /**< 16.bit: (ar$pro) Protocol address space.  For
                   Ethernet hardware, this is from the set of type
                   fields ether_typ$ (protocol). */
  uint8_t hln;  /**< 8.bit: (ar$hln) byte length of each hardware address */
  uint8_t pln;  /**< 8.bit: (ar$pln) byte length of each protocol address */
  uint16_t op;  /**< 16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY) */
  uint8_t sha[DHCP_ETH_ALEN]; /**< nbytes: (ar$sha) Hardware address of
                                 sender of this packet, n from the ar$hln field. */
  uint8_t spa[DHCP_IP_ALEN];  /**< mbytes: (ar$spa) Protocol address of
                                 sender of this packet, m from the ar$pln field. */
  uint8_t tha[DHCP_ETH_ALEN]; /**< nbytes: (ar$tha) Hardware address of
                                 target of this packet (if known). */
  uint8_t tpa[DHCP_IP_ALEN]; /**< mbytes: (ar$tpa) Protocol address of
                                target.*/
} __attribute__((packed));

/**
 * \struct dhcp_arp_fullpacket_t
 * \brief Complete ARP packet including ethernet header.
 */
struct dhcp_arp_fullpacket_t
{
  struct dhcp_ethhdr_t ethh; /**< Ethernet header */
  struct dhcp_arp_packet_t arp; /**< ARP packet */
} __attribute__((packed));

#ifdef DHCP_CHECKDNS

#define DHCP_DNS_HLEN  12 /**< DNS header length */

/**
 * \struct dhcp_dns_packet_t
 * \brief DNS packet.
 */
struct dhcp_dns_packet_t   /* From RFC 1035 */
{
  uint16_t id;      /**< 16 bit: Generated by requester. Copied in reply */
  uint16_t flags;   /**< 16 bit: Flags */
  uint16_t qdcount; /**< 16 bit: Number of questions */
  uint16_t ancount; /**< 16 bit: Number of answer records */
  uint16_t nscount; /**< 16 bit: Number of name servers */
  uint16_t arcount; /**< 16 bit: Number of additional records */
  uint8_t  records[DHCP_IP_PLEN]; /**< DNS records */
} __attribute__((packed));

/**
 * \struct dhcp_dns_fullpacket_t
 * \brief Complete DNS packet including ethernet and
 * IPv4 header.
 */
struct dhcp_dns_fullpacket_t
{
  struct dhcp_ethhdr_t ethh; /**< Ethernet header */
  struct dhcp_iphdr_t iph; /**< IPv4 header */
  struct dhcp_udphdr_t udph; /**< UDP header */
  struct dhcp_dns_packet_t dns; /**< DNS packet */
} __attribute__((packed));

/**
 * \struct dhcp_dns_fullpacket6_t
 * \brief Complete DNS packet including ethernet and
 * IPv6 header.
 */
struct dhcp_dns_fullpacket6_t
{
  struct dhcp_ethhdr_t ethh; /**< Ethernet header */
  struct dhcp_ipv6hdr_t iph; /**< IPv4 header */
  struct dhcp_udphdr_t udph; /**< UDP header */
  struct dhcp_dns_packet_t dns; /**< DNS packet */
} __attribute__((packed));

int dhcp_checkDNS(struct dhcp_conn_t *conn,
                  struct dhcp_ippacket_t *pack, int len);

#endif

struct dhcp_t; /* Forward declaration */

/* Authentication states */
#define DHCP_AUTH_NONE        0 /**< None state */
#define DHCP_AUTH_DROP        1 /**< Drop all packet */
#define DHCP_AUTH_PASS        2 /**< Authorized, packet pass */
#define DHCP_AUTH_UNAUTH_TOS  3 /**< Type of service */
#define DHCP_AUTH_AUTH_TOS    4 /**< Type of service */
#define DHCP_AUTH_DNAT        5 /**< Packet are redirected to UAM server */

#define DHCP_DOMAIN_LEN      30 /**< DNS domain name length */

#define DHCP_DNAT_MAX 10 /**< Maximum IPv4 DNAT table size */

#define DHCP_DNATV6_MAX 10 /**< Maximum IPv6 DNAT table size */

/**
 * \struct dhcp_conn_t
 * \brief Low-level connection.
 */
struct dhcp_conn_t
{
  int inuse;                  /**< Free = 0; Inuse = 1 */
  int ipv6;                    /**< use IPv6 = 1; use IPv4 only = 0 */
  struct timeval lasttime;      /**< Last time we heard anything from client */
  struct dhcp_conn_t *nexthash; /**< Linked list part of hash table */
  struct dhcp_conn_t *next;    /**< Next in linked list. 0: Last */
  struct dhcp_conn_t *prev;    /**< Previous in linked list. 0: First */
  struct dhcp_t *parent;       /**< Parent of all connections */
  void *peer;                  /**< Peer protocol handler */
  uint8_t ourmac[DHCP_ETH_ALEN];    /**< Our MAC address */
  uint8_t hismac[DHCP_ETH_ALEN];    /**< Peer's MAC address */
  struct in_addr ourip;        /**< IP address to listen to */
  struct in_addr hisip;        /**< Client IP address */
  struct in_addr hismask;      /**< Client Network Mask */
  struct in6_addr ouripv6;     /**< IPv6 address to listen to */
  struct in6_addr hisipv6;     /**< client IPv6 address */
  struct in_addr dns1;         /**< Client DNS address */
  struct in_addr dns2;         /**< Client DNS address */
  char domain[DHCP_DOMAIN_LEN];/**< Domain name to use for DNS lookups */
  int authstate;               /**< 0: Unauthenticated, 1: Authenticated */
  uint8_t unauth_cp;           /**< Unauthenticated codepoint */
  uint8_t auth_cp;             /**< Authenticated codepoint */
  int nextdnat;                /**< Next location to use for DNAT */
  uint32_t dnatip[DHCP_DNAT_MAX]; /**< Destination NAT destination IP address */
  uint16_t dnatport[DHCP_DNAT_MAX]; /**< Destination NAT source port */

  /* [SV] */
  int nextdnatv6;                   /**< Next location to use for DNATv6 */
  struct in6_addr dnatipv6[DHCP_DNATV6_MAX]; /**< Destination NAT destination IPv6 address */
  uint16_t dnatportv6[DHCP_DNATV6_MAX]; /**< Destination NAT source port */

  /*  uint16_t mtu;                 Maximum transfer unit */
};

#define DHCP_EAPOL_TAG_VLEN 255        /**< Tag value always shorter than this */

/**
 * \struct dhcp_eapol_tag_t
 * \brief EAPOL tag element.
 */
struct dhcp_eapol_tag_t
{
  uint8_t t; /**< EAPOL tag type */
  uint8_t l; /**< Length of attribute */
  uint8_t v[DHCP_EAPOL_TAG_VLEN]; /**< Payload */
} __attribute__((packed));

/**
 * \struct dhcp_dot1xhdr_t
 * \brief 802.1x packet header.
 */
struct dhcp_dot1xhdr_t
{
  uint8_t  ver; /**< Version */
  uint8_t  type; /**< Type */
  uint16_t len; /**< Length */
} __attribute__((packed));

#define DHCP_EAP_PLEN 1500 /**< Dot1x Payload length */

/**
 * \struct dhcp_eap_t
 * \brief EAP header.
 */
struct dhcp_eap_t
{
  uint8_t  code; /**< EAP code */
  uint8_t  id; /**< EAP ID */
  uint16_t length; /**< Length */
  uint8_t  type; /**< EAP type */
  uint8_t payload[DHCP_EAP_PLEN]; /**< Data */
} __attribute__((packed));

/**
 * \struct dhcp_dot1xpacket_t
 * \brief Complete 802.1X packet.
 */
struct dhcp_dot1xpacket_t
{
  struct dhcp_ethhdr_t ethh; /**< Ethernet header */
  struct dhcp_dot1xhdr_t dot1x; /**< 802.1X header */
  struct dhcp_eap_t eap; /**< EAPOL header */
} __attribute__((packed));

/**
 * \struct dhcp_t
 * \brief Information storage for each dhcp instance.
 *
 * Normally each instance of the application corresponds to
 * one instance of a dhcp instance.
 *
 */
struct dhcp_t
{
  /* Parameters related to the network interface */

  int numconn;          /**< Maximum number of connections for IPv4 */
  /* [SV] */
  int numconnv6; /**< Maximum number of connections for IPv6 */
  int fd;               /**< File descriptor to network interface */
  char devname[IFNAMSIZ];/**< Name of the network interface */
  int devflags;         /**< Original flags of network interface */
  unsigned char hwaddr[DHCP_ETH_ALEN]; /**< Hardware address of interface */
  int ifindex;  /**< Interface index for l2 socket */
#if defined(__FreeBSD__) || defined (__OpenBSD__) || defined (__APPLE__)
  char *rbuf;
  unsigned int rbuf_max;
  unsigned int rbuf_offset;
  unsigned int rbuf_len;
#endif
  int arp_fd;           /**< File descriptor to network interface */
  unsigned char arp_hwaddr[DHCP_ETH_ALEN]; /**< Hardware address of interface */
  int arp_ifindex;      /**< ARP-related l2 interface index */
  int eapol_fd;         /**< File descriptor to network interface */
  unsigned char eapol_hwaddr[DHCP_ETH_ALEN]; /**< Hardware address of interface */
  int eapol_ifindex;    /**< EAP-related interface index */
  /* [SV] : IPv6 support */
  unsigned char ipv6_hwaddr[DHCP_ETH_ALEN]; /**< Hardware address of interface */
  int ipv6_fd; /**< File descriptor to network interface */
  int ipv6_ifindex; /**< IPv6-related interface index */
  int debug;            /**< Set to print debug messages */
  struct in6_addr ouripv6; /**< IPv6 address to listen to */
  struct in_addr ourip; /**< IPv4 address to listen to */
  int mtu;              /**< Maximum transfer unit */
  uint32_t lease;       /**< Seconds before reneval */
  int usemac;           /**< Use given mac address */
  int promisc;          /**< Set interface in promisc mode */
  int allowdyn;         /**< Allow allocation of IP address on DHCP request */
  struct in_addr uamlisten; /**< IP address to redirect HTTP requests to */
  struct in6_addr uamlisten6; /**< IPv6 address to redirect HTTP requests to */
  uint16_t uamport;     /**< TCP port to redirect HTTP requests to */
  struct in_addr *authip; /**< IP address of authentication server */
  struct in6_addr *authip6; /**< IPv6 address of authentification server */
  int authiplen;        /**< Number of authentication server IP addresses */
  int authiplen6;        /**< Number of authentication server IPv6 addresses */
  int anydns;           /**< Allow client to use any DNS */
  struct ippool_t *iphash; /**< Hash table for uamallowed */
  struct ippoolm_t *iphashm; /**< Hash table members for uamallowed */
  struct ippool_t *iphash6; /**< Hash table for IPv6 uamallowed */
  struct ippoolm_t *iphashm6; /**< Hash table members for IPv6 uamallowed */
  struct in_addr *uamokaddr; /**< Allowed network IP addresses */
  struct in_addr *uamokmask; /**< Allowed network IP masks */
  struct in6_addr *uamokaddr6; /**< Allowed network IPv6 addresses */
  struct in6_addr *uamokmask6; /**< Allowed network IPv6 masks */
  int uamoknetlen;          /**< Number of allowed networks */
  int uamoknetlen6;          /**< Number of allowed networks */

  /* Connection management */
  struct dhcp_conn_t *conn; /**< Linked list of IPv4 addresses */
  struct dhcp_conn_t *firstfreeconn; /**< First free in linked list */
  struct dhcp_conn_t *lastfreeconn;  /**< Last free in linked list */
  struct dhcp_conn_t *firstusedconn; /**< First used in linked list */
  struct dhcp_conn_t *lastusedconn;  /**< Last used in linked list */

  /* connection IPv6 managment */
  struct dhcp_conn_t* connv6; /**< Linked list of IPv6 addresses */
  struct dhcp_conn_t* firstfreeconnv6; /**< First free in IPv6 linked list */
  struct dhcp_conn_t* lastfreeconnv6; /**< Last free in IPv6 linked list */
  struct dhcp_conn_t* firstusedconnv6; /**< First used in IPv6 linked list */
  struct dhcp_conn_t* lastusedconnv6; /**< Last used in IPv6 linked list */

  /* Hash related parameters */
  int hashsize;                 /**< Size of hash table */
  int hashlog;                  /**< Log2 size of hash table */
  int hashmask;                 /**< Bitmask for calculating hash */
  struct dhcp_conn_t **hash;    /**< Hashsize array of pointer to member */

  struct dhcp_conn_t** hashv6; /**< Hashsize array of pointer to IPv6 member */

  /* Call back functions */

  /**
   * \brief Callback function when receive IPv6 packet.
   */
  int (*cb_ipv6_ind) (struct dhcp_conn_t *conn, void *pack, unsigned len);

  /**
   * \brief Callback function when receive IPv4 packet.
   */
  int (*cb_data_ind) (struct dhcp_conn_t *conn, void *pack, unsigned len);

  /**
   * \brief Callback function when receive EAP packet.
   */
  int (*cb_eap_ind)  (struct dhcp_conn_t *conn, void *pack, unsigned len);

  /**
   * \brief Callback function when peers request an IPv6 address.
   */
  int (*cb_request) (struct dhcp_conn_t *conn, struct in_addr *addr);

  /**
   * \brief Callback function when peers connect.
   */
  int (*cb_connect) (struct dhcp_conn_t *conn);

  /**
   * \brief Callback function when peers disconnect.
   */
  int (*cb_disconnect) (struct dhcp_conn_t *conn);

  /* [SG] */
  /**
   * \brief Callback to check if a peer is already authenticated
   * in IPv4 or IPv6.
   */
  int (*cb_unauth_dnat) (struct dhcp_conn_t *conn);

  /* [SV] */
  /**
   * \brief Callback function when peers request an IPv6 address.
   */
  int (*cb_requestv6)(struct dhcp_conn_t *conn, struct in6_addr *addr);

  /**
   * \brief Callback function when IPv6 peers connect.
   */
  int (*cb_connectv6) (struct dhcp_conn_t *conn);

  /**
   * \brief Callback function when IPv6 peers disconnect.
   */
  int (*cb_disconnectv6) (struct dhcp_conn_t *conn); /**< Callback after */
};

/* External API functions */

/**
 * \brief Returns the current version of the program.
 * \return current version of the program
 */
const char* dhcp_version(void);

/**
 * \brief Allocates a new instance of the library.
 * \param dhcp resulting pointer will be stored in this variable
 * \param numconn maximum number of connections
 * \param interface listening interface (i.e. wlan0)
 * \param usemac use interface MAC
 * \param mac MAC address to use (only used if usemac is true)
 * \param promisc set interface into promiscuous mode
 * \param listen listen IPv4 address
 * \param listenv6 listen IPv6 address
 * \param lease IPv4 DHCP lease
 * \param allowdyn allow DHCP to provide address for every client
 * \param uamlisten IPv4 address of UAM server
 * \param uamlisten6 IPv6 address of UAM server
 * \param uamport UAM port
 * \param useeapol Use or not EAPOL
 * \param ipversion "ipv4", "ipv6" or "dual" mode
 * \return 0 if success, -1 otherwise
 */
int dhcp_new(struct dhcp_t **dhcp, int numconn, char *interface,
             int usemac, uint8_t *mac, int promisc,
             struct in_addr *listen, struct in6_addr* listenv6, int lease, int allowdyn,
             struct in_addr *uamlisten, struct in6_addr *uamlisten6, uint16_t uamport, int useeapol, char *ipversion);

/**
 * \brief Set dhcp parameters for IPv4 which can be altered at runtime.
 * \param dhcp dhcp_t instance
 * \param debug print extra information or not
 * \param authip
 * \param authiplen length of authip
 * \param anydns
 * \param uamokip
 * \param uamokiplen
 * \param uamokaddr
 * \param uamokmask
 * \param uamoknetlen
 * \return 0 if success, -1 otherwise
 */
int dhcp_set(struct dhcp_t *dhcp, int debug,
             struct in_addr *authip, int authiplen, int anydns,
             struct in_addr *uamokip, int uamokiplen, struct in_addr *uamokaddr,
             struct in_addr *uamokmask, int uamoknetlen);

/**
 * \brief Set dhcp parameters for IPv6 which can be altered at runtime.
 * \param dhcp dhcp_t instance
 * \param debug print debug information or not
 * \param authip
 * \param authiplen length of authip
 * \param anydns
 * \param uamokip
 * \param uamokiplen
 * \param uamokaddr
 * \param uamokmask
 * \param uamoknetlen
 * \return 0 if success, -1 otherwise
 */
int dhcp_setv6(struct dhcp_t *dhcp, int debug,
               struct in6_addr *authip, int authiplen, int anydns,
               struct in6_addr *uamokip, int uamokiplen, struct in6_addr *uamokaddr,
               struct in6_addr *uamokmask, int uamoknetlen);

/**
 * \brief Release ressources allocated to the instance of the library.
 * \param dhcp dhcp_t instance
 * \return 0
 */
int dhcp_free(struct dhcp_t *dhcp);

/**
 * \brief Need to call this function at regular intervals to clean up old connections.
 * \param this dhcp_t instance
 * \return 0
 */
int dhcp_timeout(struct dhcp_t *this);

/**
 * \brief Get time when to call dhcp_timeout().
 *
 * Use this function to find out when to call dhcp_timeout()
 * If service is needed after the value given by tvp then tvp
 * is left unchanged.
 * \param this dhcp_t instance
 * \param tvp time when to call dhcp_timeout
 * \return tvp
 */
struct timeval* dhcp_timeleft(struct dhcp_t *this, struct timeval *tvp);

/**
 * \brief Valides reference structures of IPv4 connections.
 * \param this dhcp_t instance
 * \return number of active IPv4 connections
 */
int dhcp_validate(struct dhcp_t *this);

/**
 * \brief Set various IP addresses of a connection.
 * \param conn client connection
 * \param hisip connection IPv6 address
 * \param ourip portal captive IPv6 address
 * \param domain domain name
 * \return 0 if success, -1 otherwise
 */
int dhcp_set_addrsv6(struct dhcp_conn_t *conn,
                     struct in6_addr *hisip,
                     struct in6_addr *ourip, char *domain);

/**
 * \brief Set various IP addresses of a connection.
 * \param conn client connection
 * \param hisip connection IPv4 address
 * \param hismask connection IPv4 mask
 * \param ourip captive portal IPv4 address
 * \param dns1 DNS address
 * \param dns2 DNS address
 * \param domain domain name
 * \return 0 if success, -1 otherwise
 */
int dhcp_set_addrs(struct dhcp_conn_t *conn,
                   struct in_addr *hisip,
                   struct in_addr *hismask,
                   struct in_addr *ourip,
                   struct in_addr *dns1,
                   struct in_addr *dns2,
                   char *domain);

/**
 * \brief Call this function when a new IP packet has arrived.
 *
 * This function should be part of a select() loop in the application.
 * \param this dhcp_t instance
 * \return 0 if success, -1 otherwise
 */
int dhcp_decaps(struct dhcp_t *this);

/**
 * \brief Call this function to send an IP packet to the peer.
 * \param conn connection
 * \param pack IP packet
 * \param len length of packet
 * \return 0 or number of bytes written
 */
int dhcp_data_req(struct dhcp_conn_t *conn, void *pack, unsigned len);

/* [SV] */
/**
 * \brief Set callback which is called when IPv6 data has arrived on tun6 interface.
 *
 * This function should be part of a select() loop in the application.
 * \param this dhcp_t instance
 * \param cb_ind the callback
 * \return 0
 */
int dhcp_set_cb_ipv6_ind(struct dhcp_t *this, int (*cb_ind) (struct dhcp_conn_t *conn, void *pack, unsigned len));

/**
 * \brief Set the callback which is called when a machine requests an IPv6 address.
 * \param this dhcp_t instance
 * \param cb_request the callback
 * \return 0
 */
int dhcp_set_cb_requestv6(struct dhcp_t *this,  int (*cb_request) (struct dhcp_conn_t *conn, struct in6_addr *addr));

/**
 * \brief Set the callback which is called when an IPv6 connection is created.
 * \param this dhcp_t instance
 * \param cb_connect the callback
 * \return 0
 */
int dhcp_set_cb_connectv6(struct dhcp_t *this,  int (*cb_connect) (struct dhcp_conn_t *conn));

/**
 * \brief Set the callback which is called when a IPv6 connection is deleted.
 * \param this dhcp_t instance
 * \param cb_disconnect the callback
 * \return 0
 */
int dhcp_set_cb_disconnectv6(struct dhcp_t *this,  int (*cb_disconnect) (struct dhcp_conn_t *conn));

/* [SG] */
/**
 * \brief iSet callback function which is called to check if
 * a client is already logged in another IP version.
 * \param this dhcp_t instance
 * \param cb_unauth_dnat callback
 * \return 0
 */
int dhcp_set_cb_unauth_dnat(struct dhcp_t *this,
                            int (*cb_unauth_dnat) (struct dhcp_conn_t *conn));

/**
 * \brief Set callback function which is called when packet has arrived
 * \param this dhcp_t instance
 * \param cb_data_ind the callback
 * \return 0
 */
int dhcp_set_cb_data_ind(struct dhcp_t *this,
                         int (*cb_data_ind) (struct dhcp_conn_t *conn, void *pack, unsigned len));

/**
 * \brief Set callback function which is called when a dhcp request is received
 * \param this dhcp_t instance
 * \param cb_request the callback
 * \return 0
 */
int dhcp_set_cb_request(struct dhcp_t *this,
                        int (*cb_request) (struct dhcp_conn_t *conn, struct in_addr *addr));

/**
 * \brief Set callback function which is called when a connection is deleted.
 * \param this dhcp_t instance
 * \param cb_disconnect the callback
 * \return 0
 */
int dhcp_set_cb_disconnect(struct dhcp_t *this,
                           int (*cb_disconnect) (struct dhcp_conn_t *conn));

/**
 * \brief Set callback function which is called when a connection is created
 * \param this dhcp_t instance
 * \param cb_connect the callback
 * \return 0
 */
int dhcp_set_cb_connect(struct dhcp_t *this,
                        int (*cb_connect) (struct dhcp_conn_t *conn));

/**
 * \brief Set callback function which is called when packet has arrived
 * Used for eap packets.
 * \param this dhcp_t instance
 * \param cb_eap_ind the callback
 * \return 0
 */
int dhcp_set_cb_eap_ind(struct dhcp_t *this,
                        int (*cb_eap_ind) (struct dhcp_conn_t *conn, void *pack, unsigned len));

/**
 * \brief Use the hash tables to find IPv4 connection based on the mac address.
 * \param this dhcp_t instance
 * \param conn it will be filled with connection if found
 * \param hwaddr MAC address to find
 * \return 0 if success, -1 if not found.
 */
int dhcp_hashget(struct dhcp_t *this, struct dhcp_conn_t **conn,
                 uint8_t *hwaddr);

/**
 * \brief Use the hash tables to find IPv6 connection based on the mac address.
 * \param this dhcp_t instance
 * \param conn it will be filled with connection if found
 * \param hwaddr MAC address to find
 * \return 0 if success, -1 if not found.
 * \author Sebastien Vincent
 */
int dhcp_hashgetv6(struct dhcp_t *this, struct dhcp_conn_t **conn,
                   uint8_t *hwaddr);

/**
 * \brief Get the MAC address of the interface.
 * \param ifname interface name
 * \param macaddr MAC address will be filled in it
 * \return 0 if success, -1 otherwise
 */
int dhcp_getmac(const char *ifname, unsigned char *macaddr);

/**
 * \brief Allocate a new IPv4 client connection.
 * \param this dhcp_t instance
 * \param conn pointer to receive the newly allocate object
 * \param hwaddr hardware address
 * \return 0 if success, -1 otherwise
 */
int dhcp_newconn(struct dhcp_t *this, struct dhcp_conn_t **conn,
                 uint8_t *hwaddr);

/**
 * \brief Allocate a new IPv6 connection.
 * \param this dhcp_t instance
 * \param conn pointer to receive the newly allocate object
 * \param hwaddr hardware address
 * \return 0 if success, -1 otherwise
 * \author Sebastien Vincent
 */
int dhcp_newconn6(struct dhcp_t* this, struct dhcp_conn_t** conn, uint8_t* hwaddr);

/**
 * \brief Remove an IPv4 client connection.
 * \param conn client connection to remove
 * \return 0
 */
int dhcp_freeconn(struct dhcp_conn_t *conn);

/**
 * \brief Remove an IPv6 client connection.
 * \param conn client connection to remove
 * \return 0
 */
int dhcp_freeconnv6(struct dhcp_conn_t *conn);

/**
 * \brief Call this function when a new ARP packet has arrived.
 *
 * This function should be part of a select() loop in the application.
 * \param this dhcp_t instance
 * \return 0 if success, -1 otherwise
 */
int dhcp_arp_ind(struct dhcp_t *this);  /* ARP Indication */

/**
 * \brief Send EAP frame.
 * \param conn low-level connection
 * \param pack packet to send
 * \param len length of packet
 * \return 0 if success, -1 otherwise
 */
int dhcp_sendEAP(struct dhcp_conn_t *conn, void *pack, int len);

/**
 * \brief Send EAP reject frame.
 * \param conn low-level connection
 * \param pack packet to send
 * \param len length of packet
 * \return 0 if success, -1 otherwise
 */
int dhcp_sendEAPreject(struct dhcp_conn_t *conn, void *pack, int len);

/**
 * \brief Call this functino when a new EAPOL packet has arrived
 * \param this dhcp_t instance
 * \return 0 if success, -1 otherwise
 */
int dhcp_eapol_ind(struct dhcp_t *this);

/* [SV] */
/**
 * \brief Call this function when a new IPv6 packet has arrived.
 * This function should be part of a select() loop in the application.
 * \param this the dhcp_t instance
 * \return 0 if success, -1 otherwise
 * \author Sebastien Vincent
 */
int dhcp_ipv6_ind(struct dhcp_t* this);

/**
 * \brief Call this function to send an IPv6 packet to the peer.
 * \param conn the connection
 * \param pack the packet to send
 * \param len length of the packet
 * \return 0 or number of bytes written
 * \author Sebastien Vincent
 */
int dhcp_ipv6_req(struct dhcp_conn_t* conn, void* pack, unsigned len);

#if defined(__FreeBSD__) || defined (__OpenBSD__) || defined (__APPLE__)
/**
 * \brief Receive packets from layer 2 socket.
 * \param this dhcp_t instance
 * \return 0 if success, -1 otherwise
 */
int dhcp_receive(struct dhcp_t *this);
#endif

#endif  /* !_DHCP_H */

