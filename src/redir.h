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
 * HTTP redirection functions.
 * Copyright (C) 2004, 2005 Mondru AB.
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#ifndef _REDIR_H
#define _REDIR_H

#define REDIR_MAXLISTEN 3

#define REDIR_MAXTIME 100  /* Seconds */

#define REDIR_HTTP_MAX_TIME 5  /* Seconds */
#define REDIR_HTTP_SELECT_TIME 500000  /* microseconds = 0.5 seconds */

#define REDIR_RADIUS_MAX_TIME 60  /* Seconds */
#define REDIR_RADIUS_SELECT_TIME 500000  /* microseconds = 0.5 seconds */

#define REDIR_TERM_INIT     0  /* Nothing done yet */
#define REDIR_TERM_GETREQ   1  /* Before calling redir_getreq */
#define REDIR_TERM_GETSTATE 2  /* Before calling cb_getstate */
#define REDIR_TERM_PROCESS  3  /* Started to process request */
#define REDIR_TERM_RADIUS   4  /* Calling radius */
#define REDIR_TERM_REPLY    5  /* Sending response to client */

#define REDIR_CHALLEN 16
#define REDIR_MD5LEN 16

#define REDIR_MACSTRLEN 17

/*#define REDIR_MAXCHAR 1024*/
#define REDIR_MAXCHAR 64

#define REDIR_MAXBUFFER 4096

#define REDIR_USERNAMESIZE 256 /* Max length of username */
#define REDIR_USERURLSIZE 256  /* Max length of URL requested by user */

#define REDIR_MAXCONN 16

#define REDIR_CHALLENGETIMEOUT1 300 /* Seconds */
#define REDIR_CHALLENGETIMEOUT2 600 /* Seconds */

#define REDIR_SESSIONID_LEN 17

#define REDIR_URL_LEN 250

#define REDIR_LOGIN      1
#define REDIR_PRELOGIN   2
#define REDIR_LOGOUT     3
#define REDIR_CHALLENGE  4
#define REDIR_ABORT      5
#define REDIR_ABOUT      6
#define REDIR_STATUS     7
#define REDIR_MSDOWNLOAD 25


#define REDIR_ALREADY        50 /* Reply to /logon while allready logged on */
#define REDIR_FAILED_REJECT  51 /* Reply to /logon if authentication reject */
#define REDIR_FAILED_OTHER   52 /* Reply to /logon if authentication timeout */
#define REDIR_SUCCESS    53 /* Reply to /logon if authentication successful */
#define REDIR_LOGOFF     54 /* Reply to /logff */
#define REDIR_NOTYET     55 /* Reply to /prelogin or any GET request */
#define REDIR_ABORT_ACK  56 /* Reply to /abortlogin */
#define REDIR_ABORT_NAK  57 /* Reply to /abortlogin */

#define REDIR_ETH_ALEN  6

struct redir_conn_t {

  /* Parameters from HTTP request */
  int type; /* REDIR_LOGOUT, LOGIN, PRELOGIN, CHALLENGE, MSDOWNLOAD */
  char username[REDIR_USERNAMESIZE];
  char userurl[REDIR_USERURLSIZE];
  int chap; /* 0 if using normal password; 1 if using CHAP */
  uint8_t chappassword[REDIR_MAXCHAR];
  uint8_t password[REDIR_MAXCHAR];
  
  /* Challenge as sent to web server */
  uint8_t uamchal[REDIR_MD5LEN];
  int uamtime;

  int authenticated;           /* 1 if user was authenticated */  
  struct sockaddr_storage nasip;
  uint32_t nasport;
  uint8_t hismac[REDIR_ETH_ALEN];    /* His MAC address */
  uint8_t ourmac[REDIR_ETH_ALEN];    /* Our MAC address */
  struct in_addr ourip;        /* IP address to listen to */
  struct in_addr hisip;        /* Client IP address */
  struct in6_addr ouripv6; /**< IPv6 address to listen to */
  struct in6_addr hisipv6; /**< Client IPv6 address */
  int ipv6; /**< If connection is IPv6 */
  char sessionid[REDIR_SESSIONID_LEN]; /* Accounting session ID */
  int response; /* 0: No adius response yet; 1:Reject; 2:Accept; 3:Timeout */
  long int sessiontimeout;
  long int idletimeout;
  long int interim_interval;  /* Interim accounting */
  char redirurlbuf[RADIUS_ATTR_VLEN+1];
  int redirurllen;
  char *redirurl;
  char replybuf[RADIUS_ATTR_VLEN+1];
  char *reply;
  uint8_t statebuf[RADIUS_ATTR_VLEN+1];
  int statelen;
  uint8_t classbuf[RADIUS_ATTR_VLEN+1];
  int classlen;
  int bandwidthmaxup;
  int bandwidthmaxdown;
  int maxinputoctets;
  int maxoutputoctets;
  int maxtotaloctets;
  time_t sessionterminatetime;
  char filteridbuf[RADIUS_ATTR_VLEN+1];
  int filteridlen;
  char *filterid;
  uint64_t input_octets;     /* Transferred in callback */
  uint64_t output_octets;    /* Transferred in callback */
  struct timeval start_time; /* Transferred in callback */
};

struct redir_t {
  int fd;                /* File descriptor */
  int fdv6; /**< File descriptor for IPv6 */
  int debug;
  int msgid;             /* Message Queue */
  struct in_addr addr;
  struct in6_addr addrv6; /**< IPv6 address */
  struct in6_addr prefix;
  int prefixlen;
  int port;
  char *url;
  char* url6; /**< URL of IPv6 webserver */
  char *homepage;
  char *secret;
  struct sockaddr_storage radiuslisten;
  struct sockaddr_storage radiusserver0;
  struct sockaddr_storage radiusserver1;
  uint16_t radiusauthport;
  uint16_t radiusacctport;
  char *radiussecret;
  char *radiusnasid;
  struct sockaddr_storage radiusnasip;
  char *radiuscalled;
  char* radiuslocationid;
  char* radiuslocationname;
  int radiusnasporttype;
  int starttime;
  int (*cb_getstate) (struct redir_t *redir, struct in_addr *addr,
		      struct redir_conn_t *conn);
  /* [SV] */
  int (*cb_getstatev6) (struct redir_t *redir, struct in6_addr *addr, struct redir_conn_t *conn);
};


struct redir_msg_t {
  long int type;
  long int interim_interval;
  long int sessiontimeout;
  long int idletimeout;
  struct in_addr addr;
  struct in6_addr addrv6; /**< client IPv6 address */
  char username[REDIR_USERNAMESIZE];
  char userurl[REDIR_USERURLSIZE];
  uint8_t uamchal[REDIR_MD5LEN];
  uint8_t statebuf[RADIUS_ATTR_VLEN+1];
  int statelen;
  uint8_t classbuf[RADIUS_ATTR_VLEN+1];
  int classlen;
  int bandwidthmaxup;
  int bandwidthmaxdown;
  int maxinputoctets;
  int maxoutputoctets;
  int maxtotaloctets;
  int sessionterminatetime;
  char filteridbuf[RADIUS_ATTR_VLEN+1];
  int filteridlen;
  int ipv6; /**< If connection is IPv6 */
};


extern int redir_new(struct redir_t **redir,
		     struct in_addr *addr, struct in6_addr* addrv6, int port);

extern int redir_free(struct redir_t *redir);

extern void redir_set(struct redir_t *redir, int debug, struct in6_addr *prefix, int prefixlen,
		      char *url, char* url6, char *homepage, char* secret,
		      struct sockaddr_storage *radiuslisten, 
		      struct sockaddr_storage *radiusserver0,
		      struct sockaddr_storage *radiusserver1,
		      uint16_t radiusauthport, uint16_t radiusacctport,
		      char* radiussecret, char* radiusnasid,
		      struct sockaddr_storage *radiusnasip, char* radiuscalled,
		      char* radiuslocationid, char* radiuslocationname,
		      int radiusnasporttype);


extern int redir_accept(struct redir_t *redir, int ipv6);


extern int redir_setchallenge(struct redir_t *redir, struct in_addr *addr,
			      unsigned char *challenge);

/* [SV] */
int redir_set_cb_getstatev6(struct redir_t* redir, int (*cb_getstatev6)(struct redir_t* redir, struct in6_addr* addr, struct redir_conn_t* conn));

extern int redir_set_cb_getstate(struct redir_t *redir,
  int (*cb_getstate) (struct redir_t *redir, struct in_addr *addr,
		      struct redir_conn_t *conn));


#endif	/* !_REDIR_H */
