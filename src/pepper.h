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
 * chilli - ChilliSpot.org. A Wireless LAN Access Point Controller.
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
 * \file pepper.h
 * \brief PepperSpot: next generation captive portal.
 */

#ifndef _PEPPER_H
#define _PEPPER_H

/* If the constants below are defined packets which have been dropped
   by the traffic shaper will be counted towards accounting and
   volume limitation */
/* #define COUNT_DOWNLINK_DROP 1 */
/* #define COUNT_UPLINK_DROP 1 */

#define APP_NUM_CONN 1024 /**< Maximum number of hight-level connections */
#define EAP_LEN 2048 /**< EAP challenge length (rather large) */

#define MACOK_MAX 16 /**< Authorized MAC table size */

#define MACSTRLEN 17 /**< Length of MAC address in string format */

#define MS2SUCCSIZE 40  /**< MS-CHAPv2 authenticator response as ASCII */

#define DATA_LEN 1500 /**< Max we allow */

#define USERNAMESIZE 256 /**< Max length of username */
#define CHALLENGESIZE 24 /**< From chap.h MAX_CHALLENGE_LENGTH */
#define USERURLSIZE 256  /**< Max length of URL requested by user */

#define BUCKET_SIZE  300000 /**< Size of leaky bucket (~200 packets) */

/* Bucket size = BUCKET_TIME * Bandwidth-Max radius attribute */
/* Not used if BUCKET_SIZE is defined */
#define BUCKET_TIME  5000  /**< Time length of leak bucket in milliseconds */
#define BUCKET_SIZE_MIN  15000 /**< Minimum size of leaky bucket (~10 packets) */

#define CHECK_INTERVAL 3   /**< Time between checking connections */

/* Authtype defs */
#define CHAP_DIGEST_MD5   0x05 /**< Code for using CHAP-MD5 */
#define CHAP_MICROSOFT    0x80 /**< Code for using MS-CHAP  */
#define CHAP_MICROSOFT_V2 0x81 /**< Code for using MS-CHAPv2 */
#define PAP_PASSWORD       256 /**< Code for using PAP */
#define EAP_MESSAGE        257 /**< Code for using EAP */

#define MPPE_KEYSIZE  16 /**< Size of MPE key */
#define NT_KEYSIZE    16 /**< Size of NT key */

#define DNPROT_DHCP_NONE  2 /**< Client has requested IP address */
#define DNPROT_UAM        3 /**< Use UAM server for downlink authentication */
#define DNPROT_WPA        4 /**< Use WPA for downlink authentication */
#define DNPROT_EAPOL      5 /**< Use EAPOL for downlink authentication */
#define DNPROT_MAC        6 /**< Use MAC address for downlink authentication */

/* Debug facility */
#define DEBUG_DHCP        2 /**< Allow debug print for DHCP module */
#define DEBUG_RADIUS      4 /**< Allow debug print for RADIUS module */
#define DEBUG_REDIR       8 /**< Allow debug print for redir module */
#define DEBUG_CONF       16 /**< Allow debug print for configuration module */

/**
 * \struct app_conn_t
 * \brief Struct information for each connection.
 */
struct app_conn_t
{
  /* Management of connections */
  int inuse; /**< If the connection is in use */
  int unit; /**< Used for NAS port */
  int ipv6; /**< If IPv6 is used */
  struct app_conn_t *next; /**< Next in linked list. 0: Last */
  struct app_conn_t *prev; /**< Previous in linked list. 0: First */

  /* Pointers to protocol handlers */
  void *uplink;             /**< Uplink network interface (Internet) */
  void *dnlink;             /**< Downlink network interface (Wireless) */
  int dnprot;               /**< Downlink protocol */

  /* Radius authentication stuff */
  /* Parameters are initialised whenever a reply to an access request
   *  is received.
   */
  uint8_t chal[EAP_LEN];      /**< EAP challenge */
  int challen;                /**< Length of EAP challenge */
  uint8_t sendkey[RADIUS_ATTR_VLEN]; /**< Key used to encode message to send */
  uint8_t recvkey[RADIUS_ATTR_VLEN]; /**< Key used to decode received message */
  uint8_t lmntkeys[RADIUS_MPPEKEYSSIZE]; /**< LMNT key */
  int sendlen; /**< Length of sendkey */
  int recvlen; /**< Length of recvkey */
  int lmntlen; /**< Length of LMNT key */
  uint32_t policy; /**< Encryption policy */
  uint32_t types; /**< Encryption types */
  uint8_t ms2succ[MS2SUCCSIZE]; /**< MS-CHAPv2 SUCCESS attribute */
  /* int ms2succlen; */
  char sessionid[REDIR_SESSIONID_LEN]; /**< Accounting session ID */
  long int sessiontimeout; /**< RADIUS session timeout */
  long int idletimeout; /**< RADIUS idle timeout */
  uint8_t statebuf[RADIUS_ATTR_VLEN + 1]; /**< Radius state */
  int statelen; /**< Length of statebuf */
  uint8_t classbuf[RADIUS_ATTR_VLEN + 1]; /**< Class attribute received from radius server and used in Accounting-Request packet */
  int classlen; /**< Length of classbuf */
  int bandwidthmaxup; /**< Maximum upload bandwith */
  int bandwidthmaxdown; /**< Maximum download bandwidth */
  uint64_t maxinputoctets; /**< Maximum input bytes */
  uint64_t maxoutputoctets; /**< Maximum output bytes */
  uint64_t maxtotaloctets; /**< Maximum bytes allowed */
  time_t sessionterminatetime; /**< Time when session terminates */
  char filteridbuf[RADIUS_ATTR_VLEN + 1]; /**< Filter ID */
  int filteridlen; /**< Length of filter ID */

  /* Radius proxy stuff */
  /* Parameters are initialised whenever a radius proxy request is received */
  /* Only one outstanding request allowed at a time */
  int radiuswait;                /**< Radius request in progres */
  struct sockaddr_storage radiuspeer; /**< Where to send reply */
  uint8_t radiusid;              /**< ID to reply with */
  uint8_t authenticator[RADIUS_AUTHLEN]; /**< Radius authenticator */
  int authtype; /**< Authentication method used (CHAP-MD5, MS-CHAPv2, ... */
  char proxyuser[USERNAMESIZE];     /**< Unauthenticated user: */
  uint8_t proxyuserlen;             /**< Length of unauthenticated user */
  uint32_t proxynasip;              /**< Set by access request */
  uint32_t proxynasport;            /**< Set by access request */
  uint8_t proxyhismac[DHCP_ETH_ALEN]; /**< His MAC address */
  uint8_t proxyourmac[DHCP_ETH_ALEN]; /**< Our MAC address */

  /* Parameters for radius accounting */
  /* These parameters are set when an access accept is sent back to the
     NAS */
  int authenticated;           /**< 1 if user was authenticated */
  char user[USERNAMESIZE];     /**< User: */
  uint8_t userlen;             /**< Length of user */
  struct sockaddr_storage nasip; /**< Set by access request */
  uint32_t nasport;            /**< Set by access request */
  uint8_t hismac[DHCP_ETH_ALEN]; /**< His MAC address */
  uint8_t ourmac[DHCP_ETH_ALEN]; /**< Our MAC address */
  struct in_addr ourip;    /**< IP address to listen to */
  struct in6_addr ouripv6; /**< IPv6 address to listen to */
  struct in_addr hisip;    /**< Client IP address */
  struct in6_addr hisipv6; /**< Client IPv6 address */
  struct in_addr reqip;    /**< IP requested by client */
  uint16_t mtu;            /**< MTU of the link */

  /* Accounting */
  struct timeval start_time; /**< Start time of connection */
  struct timeval interim_time; /**< interim accounting time */
  long int interim_interval;   /**< Seconds. 0 = No interim accounting */
  uint32_t input_packets; /**< Packets received */
  uint32_t output_packets; /**< Packets sent */
  uint64_t input_octets; /**< Bytes received */
  uint64_t output_octets; /**< Bytes sent */
  uint32_t terminate_cause; /**< RADIUS cause of termination */
  uint32_t session_id; /**< Accounting session ID */

  /* Information for each connection */
  struct in_addr net; /**< IPv4 network address */
  struct in_addr mask; /**< IPv4 mask */
  struct in_addr dns1; /**< Primary DNS address */
  struct in_addr dns2; /**< Secondary DNS address */
  struct timeval last_time; /**< Last time a packet was received or sent */

  /* Leaky bucket */
  uint32_t bucketup; /**< Current leaky bucket upload size */
  uint32_t bucketdown; /**< Current leaky bucket download size */
  uint32_t bucketupsize; /**< Leaky bucket maximum upload size */
  uint32_t bucketdownsize; /**< Leaky bucket maximum download size */

  /* UAM information */
  uint8_t uamchal[REDIR_MD5LEN]; /**< UAM challenge number */
  int uamtime; /**< UAM time */
  char userurl[USERURLSIZE]; /**< Requested user URL */
  int uamabort; /**< If UAM authentication is aborted */
};

/* #define IPADDRLEN 256 */
#define IDLETIME  10 /**< Idletime between each select */

#define UAMOKIP_MAX 256 /**< Max number of allowed UAM IP addresses */
#define UAMOKNET_MAX 10 /**< Max number of allowed UAM networks */

#define UAMSERVER_MAX 8 /**< Maximum UAM servers */

/**
 * \struct options_t
 * \brief Struct with local versions of gengetopt options.
 */
struct options_t
{
  /* fg */
  int debug;                     /**< If debug message is enabled */

  /* conf */
  int interval;                  /**< Time between checking connections */
  char* pidfile;                 /**< Process ID file */
  /* statedir */
  char *ipversion;               /**< IP version used ("ipv4", "ipv6" or "dual") */

  /* TUN parameters */
  /*
    char netc[IPADDRLEN];
    char maskc[IPADDRLEN];
  */
  struct in_addr net;            /**< Network IP address */
  struct in_addr mask;           /**< Network mask */
  int prefixlen;                 /**< IPv6 prefix length */
  int ipv6mask;                  /**< IPv6 mask */
  char *dynip;                   /**< Dynamic IP address pool */
  char *statip;                  /**< Static IP address pool */
  int allowdyn;                  /**< Allow dynamic address allocation */
  int allowstat;                 /**< Allow static address allocation */
  struct in_addr dns1;           /**< Primary DNS server IP address */
  struct in6_addr dns1ip6;       /**< Primary DNS server IPv6 address */
  struct in_addr dns2;           /**< Secondary DNS server IP address */
  struct in6_addr dns2ip6;       /**< Secondary DNS server IPv6 address */
  char *domain;                  /**< Domain to use for DNS lookups */
  char* ipup;                    /**< Script to run after link-up */
  char* ipdown;                  /**< Script to run after link-down */
  char* conup;                   /**< Script to run after user logon */
  char* condown;                 /**< Script to run after user logoff */

  /* Radius parameters */
  struct sockaddr_storage radiuslisten;  /**< IP address to listen to */
  struct sockaddr_storage radiusserver1; /**< IP address of radius server 1 */
  struct sockaddr_storage radiusserver2; /**< IP address of radius server 2 */
  uint16_t radiusauthport;       /**< Authentication UDP port */
  uint16_t radiusacctport;       /**< Accounting UDP port */
  char* radiussecret;            /**< Radius shared secret */
  char* radiusnasid;             /**< Radius NAS-Identifier */
  char* radiuscalled;            /**< Radius Called-Station-ID */
  struct sockaddr_storage radiusnasip; /**< Radius NAS-IP-Address */
  char* radiuslocationid;        /**< WISPr location ID */
  char* radiuslocationname;      /**< WISPr location name */
  int radiusnasporttype;         /**< NAS-Port-Type */
  uint16_t coaport;              /**< UDP port to listen to */
  int coanoipcheck;              /**< Allow disconnect from any IP */

  /* Radius proxy parameters */
  struct sockaddr_storage proxylisten; /**< IP address to listen to */
  int proxyport;                       /**< UDP port to listen to */
  struct sockaddr_storage proxyaddr;   /**< IP address of proxy client(s) */
  struct sockaddr_storage proxymask;   /**< IP mask of proxy client(s) */
  char* proxysecret;                   /**< Proxy shared secret */

  /* Radius configuration management parameters */
  char* confusername;            /**< Username for remote config */
  char* confpassword;            /**< Password for remote config */

  /* DHCP parameters */
  int nodhcp;                    /**< Do not use DHCP */
  char* dhcpif;                  /**< Interface: eth0 */
  unsigned char dhcpmac[DHCP_ETH_ALEN]; /**< Interface MAC address */
  int dhcpusemac;                /**< Use given MAC or interface default */
  struct in_addr dhcplisten;     /**< IP address to listen to */
  int lease;                     /**< DHCP lease time */

  /* IPv6 parameters */
  struct in6_addr ip6listen;     /**< IPv6 address to listen to */
  struct in6_addr prefix;        /**< IPv6 prefix */

  /* EAPOL parameters */
  int eapolenable;               /**< Use eapol */

  /* UAM parameters */
  struct in_addr uamserver[UAMSERVER_MAX]; /**< IP address of UAM server */
  struct in6_addr uamserver6[UAMSERVER_MAX]; /**< IPv6 address of UAM server */
  int uamserverlen;              /**< Number of IPv4 UAM servers */
  int uamserverlen6;             /**< Number of IPv6 UAM servers */
  int uamserverport;             /**< Port of IPv4 UAM server */
  int uamserverport6;            /**< Port of IPv6 UAM server */
  char* uamsecret;               /**< Shared secret */
  char* uamurl;                  /**< URL of authentication server */
  char* uamurl6;                 /**< URL of authentication IPv6 server */
  char* uamhomepage;             /**< URL of redirection homepage */
  int uamhomepageport;           /**< Port of redirection homepage */

  struct in_addr uamlisten;      /**< IP address of local authentication */
  struct in6_addr uamlisten6;    /**< IPv6 address of local authentication */
  int uamport;                   /**< TCP port to listen to */
  struct in_addr uamokip[UAMOKIP_MAX]; /**< List of allowed IP addresses */
  struct in6_addr uamokip6[UAMOKIP_MAX]; /**< List of allowed IPv6 addresses */
  int uamokiplen;                /**< Number of allowed IP addresses */
  int uamokiplen6;               /**< Number of allowed IP addresses */
  struct in_addr uamokaddr[UAMOKNET_MAX]; /**< List of allowed network IPv4 */
  struct in_addr uamokmask[UAMOKNET_MAX]; /**< List of allowed network mask */
  struct in6_addr uamokaddr6[UAMOKNET_MAX]; /**< List of allowed network IPv6 */
  struct in6_addr uamokmask6[UAMOKNET_MAX]; /**< List of allowed network IPv6 prefix */
  int uamoknetlen;               /**< Number of networks */
  int uamoknetlen6;              /**< Number of networks */
  int uamanydns;                 /**< Allow client to use any DNS server */

  /* MAC Authentication */
  int macauth;                   /**< Use MAC authentication */
  unsigned char macok[MACOK_MAX][DHCP_ETH_ALEN]; /**< Allowed MACs */
  int macoklen;                  /**< Number of MAC addresses */
  char* macsuffix;               /**< Suffix to add to MAC address */
  char* macpasswd;               /**< Password to use for MAC authentication */
};

#endif /*_PEPPER_H */

