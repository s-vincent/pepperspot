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


#ifndef _PEPPER_H
#define _PEPPER_H

/* If the constants below are defined packets which have been dropped
   by the traffic shaper will be counted towards accounting and
   volume limitation */
/* #define COUNT_DOWNLINK_DROP 1 */
/* #define COUNT_UPLINK_DROP 1 */

#define APP_NUM_CONN 1024
#define EAP_LEN 2048            /* TODO: Rather large */

#define MACOK_MAX 16

#define MACSTRLEN 17

#define MS2SUCCSIZE 40	/* MS-CHAPv2 authenticator response as ASCII */

#define DATA_LEN 1500    /* Max we allow */

#define USERNAMESIZE 256 /* Max length of username */
#define CHALLENGESIZE 24 /* From chap.h MAX_CHALLENGE_LENGTH */
#define USERURLSIZE 256  /* Max length of URL requested by user */

#define BUCKET_SIZE  300000 /* Size of leaky bucket (~200 packets) */

/* Time length of leaky bucket in milliseconds */
/* Bucket size = BUCKET_TIME * Bandwidth-Max radius attribute */
/* Not used if BUCKET_SIZE is defined */
#define BUCKET_TIME  5000  /* 5 seconds */
#define BUCKET_SIZE_MIN  15000 /* Minimum size of leaky bucket (~10 packets) */

#define CHECK_INTERVAL 3   /* Time between checking connections */


/* Authtype defs */
#define CHAP_DIGEST_MD5   0x05
#define CHAP_MICROSOFT    0x80
#define CHAP_MICROSOFT_V2 0x81
#define PAP_PASSWORD       256
#define EAP_MESSAGE        257

#define MPPE_KEYSIZE  16
#define NT_KEYSIZE    16


#define DNPROT_DHCP_NONE  2
#define DNPROT_UAM        3
#define DNPROT_WPA        4
#define DNPROT_EAPOL      5
#define DNPROT_MAC        6

/* Debug facility */
#define DEBUG_DHCP        2
#define DEBUG_RADIUS      4
#define DEBUG_REDIR       8
#define DEBUG_CONF       16

/* Struct information for each connection */
struct app_conn_t {
  
  /* Management of connections */
  int inuse;
  int unit;
  int ipv6;
  struct app_conn_t *next;    /* Next in linked list. 0: Last */
  struct app_conn_t *prev;    /* Previous in linked list. 0: First */

  /* Pointers to protocol handlers */
  void *uplink;                  /* Uplink network interface (Internet) */
  void *dnlink;                  /* Downlink network interface (Wireless) */
  int dnprot;                    /* Downlink protocol */

  /* Radius authentication stuff */
  /* Parameters are initialised whenever a reply to an access request
     is received. */
  uint8_t chal[EAP_LEN];         /* EAP challenge */
  int challen;                   /* Length of EAP challenge */
  uint8_t sendkey[RADIUS_ATTR_VLEN];
  uint8_t recvkey[RADIUS_ATTR_VLEN];
  uint8_t lmntkeys[RADIUS_MPPEKEYSSIZE];
  int sendlen;
  int recvlen;
  int lmntlen;
  uint32_t policy;
  uint32_t types;
  uint8_t ms2succ[MS2SUCCSIZE];
  int ms2succlen;
  char sessionid[REDIR_SESSIONID_LEN]; /* Accounting session ID */
  long int sessiontimeout;
  long int idletimeout;
  uint8_t statebuf[RADIUS_ATTR_VLEN+1];
  int statelen;
  uint8_t classbuf[RADIUS_ATTR_VLEN+1];
  int classlen;
  int bandwidthmaxup;
  int bandwidthmaxdown;
  uint64_t maxinputoctets;
  uint64_t maxoutputoctets;
  uint64_t maxtotaloctets;
  time_t sessionterminatetime;
  char filteridbuf[RADIUS_ATTR_VLEN+1];
  int filteridlen;
  
  /* Radius proxy stuff */
  /* Parameters are initialised whenever a radius proxy request is received */
  /* Only one outstanding request allowed at a time */
  int radiuswait;                /* Radius request in progres */
  struct sockaddr_storage radiuspeer; /* Where to send reply */
  uint8_t radiusid;              /* ID to reply with */
  uint8_t authenticator[RADIUS_AUTHLEN];
  int authtype; /* TODO */
  char proxyuser[USERNAMESIZE];     /* Unauthenticated user: */
  uint8_t proxyuserlen;             /* Length of unauthenticated user */
  uint32_t proxynasip;              /* Set by access request */
  uint32_t proxynasport;            /* Set by access request */
  uint8_t proxyhismac[DHCP_ETH_ALEN];    /* His MAC address */
  uint8_t proxyourmac[DHCP_ETH_ALEN];    /* Our MAC address */

  /* Parameters for radius accounting */
  /* These parameters are set when an access accept is sent back to the
     NAS */
  int authenticated;           /* 1 if user was authenticated */  
  char user[USERNAMESIZE];     /* User: */
  uint8_t userlen;             /* Length of user */
  struct sockaddr_storage nasip;              /* Set by access request */
  uint32_t nasport;            /* Set by access request */
  uint8_t hismac[DHCP_ETH_ALEN];    /* His MAC address */
  uint8_t ourmac[DHCP_ETH_ALEN];    /* Our MAC address */
  struct in_addr ourip;        /* IP address to listen to */
  struct in6_addr ouripv6; /**< IPv6 address to listen to */
  struct in_addr hisip;        /* Client IP address */
  struct in6_addr hisipv6; /**< Client IPv6 address */
  struct in_addr reqip;        /* IP requested by client */
  uint16_t mtu;
  
  /* Accounting */
  struct timeval start_time;
  struct timeval interim_time;
  long int interim_interval;   /* Seconds. 0 = No interim accounting */
  uint32_t input_packets;
  uint32_t output_packets;
  uint64_t input_octets;
  uint64_t output_octets;
  uint32_t terminate_cause;
  uint32_t session_id;

  /* Information for each connection */
  struct in_addr net;
  struct in_addr mask;
  struct in_addr dns1;
  struct in_addr dns2;
  struct timeval last_time; /* Last time a packet was received or sent */

  /* Leaky bucket */
  uint32_t bucketup;
  uint32_t bucketdown;
  uint32_t bucketupsize;
  uint32_t bucketdownsize;

  /* UAM information */
  uint8_t uamchal[REDIR_MD5LEN];
  int uamtime;
  char userurl[USERURLSIZE];
  int uamabort;
};


#define IPADDRLEN 256
#define IDLETIME  10  /* Idletime between each select */

#define UAMOKIP_MAX 256 /* Max number of allowed UAM IP addresses */
#define UAMOKNET_MAX 10 /* Max number of allowed UAM networks */

#define UAMSERVER_MAX 8

/* Struct with local versions of gengetopt options */
struct options_t {
  /* fg */
  int debug;
  /* conf */
  int interval;
  char* pidfile;                 /* Process ID file */
  /* statedir */
  char *ipversion;

  /* TUN parameters */
  struct in_addr net;            /* Network IP address */
  char netc[IPADDRLEN];
  struct in_addr mask;           /* Network mask */
  char maskc[IPADDRLEN];
  int prefixlen;
  int ipv6mask;
  char *dynip;                   /* Dynamic IP address pool */
  char *statip;                  /* Static IP address pool */
  int allowdyn;                  /* Allow dynamic address allocation */
  int allowstat;                 /* Allow static address allocation */
  struct in_addr dns1;           /* Primary DNS server IP address */
  struct in6_addr dns1ip6;
  struct in_addr dns2;           /* Secondary DNS server IP address */
  struct in6_addr dns2ip6;
  char *domain;                  /* Domain to use for DNS lookups */
  char* ipup;                    /* Script to run after link-up */
  char* ipdown;                  /* Script to run after link-down */
  char* conup;                    /* Script to run after user logon */
  char* condown;                  /* Script to run after user logoff */

  /* Radius parameters */
  struct sockaddr_storage radiuslisten;   /* IP address to listen to */
  struct sockaddr_storage radiusserver1;  /* IP address of radius server 1 */
  struct sockaddr_storage radiusserver2;  /* IP address of radius server 2 */
  uint16_t radiusauthport;       /* Authentication UDP port */
  uint16_t radiusacctport;       /* Accounting UDP port */
  char* radiussecret;            /* Radius shared secret */
  char* radiusnasid;             /* Radius NAS-Identifier */
  char* radiuscalled;            /* Radius Called-Station-ID */
  struct sockaddr_storage radiusnasip;    /* Radius NAS-IP-Address */
  char* radiuslocationid;        /* WISPr location ID */
  char* radiuslocationname;      /* WISPr location name */
  int radiusnasporttype;         /* NAS-Port-Type */
  uint16_t coaport;              /* UDP port to listen to */
  int coanoipcheck;              /* Allow disconnect from any IP */

  /* Radius proxy parameters */
  struct sockaddr_storage proxylisten;    /* IP address to listen to */
  int proxyport;                 /* UDP port to listen to */
  struct sockaddr_storage proxyaddr;      /* IP address of proxy client(s) */
  struct sockaddr_storage proxymask;      /* IP mask of proxy client(s) */
  char* proxysecret;             /* Proxy shared secret */

  /* Radius configuration management parameters */
  char* confusername;            /* Username for remote config */
  char* confpassword;            /* Password for remote config */

  /* DHCP parameters */
  int nodhcp;                    /* Do not use DHCP */
  char* dhcpif;                 /* Interface: eth0 */
  unsigned char dhcpmac[DHCP_ETH_ALEN]; /* Interface MAC address */
  int dhcpusemac;               /* Use given MAC or interface default */
  struct in_addr dhcplisten;     /* IP address to listen to */
  int lease;                     /* DHCP lease time */

  /* IPv6 parameters */
  struct in6_addr ip6listen; /**< IPv6 address to listen to */
  struct in6_addr prefix;

  /* EAPOL parameters */
  int eapolenable;               /* Use eapol */

  /* UAM parameters */
  struct in_addr uamserver[UAMSERVER_MAX]; /* IP address of UAM server */
  struct in6_addr uamserver6[UAMSERVER_MAX]; /* IPv6 address of UAM server */
  int uamserverlen;              /* Number of IPv4 UAM servers */
  int uamserverlen6;              /* Number of IPv6 UAM servers */
  int uamserverport;             /* Port of IPv4 UAM server */
  int uamserverport6;             /* Port of IPv6 UAM server */
  char* uamsecret;               /* Shared secret */
  char* uamurl;                  /* URL of authentication server */
  char* uamurl6; /**< URL of authentication IPv6 server */
  char* uamhomepage;             /* URL of redirection homepage */
  int uamhomepageport;		 /* Port of redirection homepage */

  struct in_addr uamlisten;      /* IP address of local authentication */
  struct in6_addr uamlisten6;      /* IPv6 address of local authentication */
  int uamport;                   /* TCP port to listen to */
  struct in6_addr uamokip6[UAMOKIP_MAX]; /* List of allowed IP addresses */
  struct in_addr uamokip[UAMOKIP_MAX]; /* List of allowed IP addresses */
  int uamokiplen;                /* Number of allowed IP addresses */
  int uamokiplen6;                /* Number of allowed IP addresses */
  struct in6_addr uamokaddr6[UAMOKNET_MAX]; /* List of allowed network IP */
  struct in6_addr uamokmask6[UAMOKNET_MAX]; /* List of allowed network mask */
  struct in_addr uamokaddr[UAMOKNET_MAX]; /* List of allowed network IP */
  struct in_addr uamokmask[UAMOKNET_MAX]; /* List of allowed network mask */
  int uamoknetlen;               /* Number of networks */
  int uamoknetlen6;               /* Number of networks */
  int uamanydns;                 /* Allow client to use any DNS server */

  /* MAC Authentication */
  int macauth;                   /* Use MAC authentication */
  unsigned char macok[MACOK_MAX][DHCP_ETH_ALEN]; /* Allowed MACs */
  int macoklen;                   /* Number of MAC addresses */
  char* macsuffix;               /* Suffix to add to MAC address */
  char* macpasswd;               /* Password to use for MAC authentication */  
};

extern struct app_conn_t connection[2*APP_NUM_CONN];
extern struct options_t options;

extern struct app_conn_t *firstfreeconn; /* First free in linked list */
extern struct app_conn_t *lastfreeconn;  /* Last free in linked list */
extern struct app_conn_t *firstusedconn; /* First used in linked list */
extern struct app_conn_t *lastusedconn;  /* Last used in linked list */

extern struct radius_t *radius;          /* Radius client instance */
extern struct dhcp_t *dhcp;              /* DHCP instance */

#endif /*_PEPPER_H */
