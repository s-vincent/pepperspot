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
 * HTTP redirection functions.
 * Copyright (C) 2004, 2005 Mondru AB.
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

/**
 * \file redir.h
 * \brief HTTP redirection module.
 */

#ifndef _REDIR_H
#define _REDIR_H

#define REDIR_MAXLISTEN 3 /**< Backlog argument of listen() */

#define REDIR_MAXTIME 100  /**< Maximum lifetime for a child process in seconds */

#define REDIR_HTTP_MAX_TIME 5  /**< Maximum wait time for a request in seconds */
#define REDIR_HTTP_SELECT_TIME 500000  /**< HTTP select() timeout in microseconds = 0.5 seconds */

#define REDIR_RADIUS_MAX_TIME 60  /**< Timeout for RADIUS request in seconds */
#define REDIR_RADIUS_SELECT_TIME 500000  /**< RADIUS select() timeout in microseconds = 0.5 seconds */

#define REDIR_TERM_INIT     0  /**< Nothing done yet */
#define REDIR_TERM_GETREQ   1  /**< Before calling redir_getreq */
#define REDIR_TERM_GETSTATE 2  /**< Before calling cb_getstate */
#define REDIR_TERM_PROCESS  3  /**< Started to process request */
#define REDIR_TERM_RADIUS   4  /**< Calling radius */
#define REDIR_TERM_REPLY    5  /**< Sending response to client */

#define REDIR_CHALLEN 16 /**< Challenge length */
#define REDIR_MD5LEN 16 /**< MD5 hash length */

#define REDIR_MACSTRLEN 17 /**< MAC address in string format */

/*#define REDIR_MAXCHAR 1024*/
#define REDIR_MAXCHAR 128 /**< Maximum size for passwords */

#define REDIR_MAXBUFFER 4096 /**< Maximum buffer size */

#define REDIR_USERNAMESIZE 256 /**< Max length of username */
#define REDIR_USERURLSIZE 256  /**< Max length of URL requested by user */

#define REDIR_CHALLENGETIMEOUT1 300 /**< First challenge timeout in seconds */
#define REDIR_CHALLENGETIMEOUT2 600 /**< Second challenge timeout in seconds */

#define REDIR_SESSIONID_LEN 17 /**< Session ID length */

#define REDIR_URL_LEN 250 /**< Maximum URL length */

#define REDIR_LOGIN      1 /**< Login state */
#define REDIR_PRELOGIN   2 /**< Pre-login state */
#define REDIR_LOGOUT     3 /**< Logout state */
#define REDIR_CHALLENGE  4 /**< Challenge state */
#define REDIR_ABORT      5 /**< Abort state */
#define REDIR_ABOUT      6 /**< About state */
#define REDIR_STATUS     7 /**< Status state */
#define REDIR_MSDOWNLOAD 25 /**< MSDOWNLOAD state */


#define REDIR_ALREADY        50 /**< Reply to /logon while allready logged on */
#define REDIR_FAILED_REJECT  51 /**< Reply to /logon if authentication reject */
#define REDIR_FAILED_OTHER   52 /**< Reply to /logon if authentication timeout */
#define REDIR_SUCCESS    53 /**< Reply to /logon if authentication successful */
#define REDIR_LOGOFF     54 /**< Reply to /logff */
#define REDIR_NOTYET     55 /**< Reply to /prelogin or any GET request */
#define REDIR_ABORT_ACK  56 /**< Reply to /abortlogin */
#define REDIR_ABORT_NAK  57 /**< Reply to /abortlogin */

#define REDIR_ETH_ALEN  6 /**< Ethernet address length */

/**
 * \struct redir_conn_t
 * \brief Redirection connection.
 */
struct redir_conn_t
{
  /* Parameters from HTTP request */
  int type; /**< REDIR_LOGOUT, LOGIN, PRELOGIN, CHALLENGE, MSDOWNLOAD */
  char username[REDIR_USERNAMESIZE]; /**< User name */
  char userurl[REDIR_USERURLSIZE]; /**< Original client requested webpage */
  int chap; /**< 0 if using normal password; 1 if using CHAP */
  uint8_t chappassword[REDIR_MD5LEN]; /**< CHAP password */
  uint8_t password[REDIR_MAXCHAR]; /**< Client password */
  int passwordlen; /**< Client password length */
  uint8_t uamchal[REDIR_MD5LEN]; /**< Challenge as sent to web server */
  int uamtime; /**< UAM time */

  int authenticated; /**< 1 if user was authenticated */
  struct sockaddr_storage nasip; /**< Address of NAS */
  uint32_t nasport; /**< Port of NAS */
  uint8_t hismac[REDIR_ETH_ALEN]; /**< His MAC address */
  uint8_t ourmac[REDIR_ETH_ALEN]; /**< Our MAC address */
  struct in_addr ourip; /**< IP address to listen to */
  struct in_addr hisip; /**< Client IP address */
  struct in6_addr ouripv6; /**< IPv6 address to listen to */
  struct in6_addr hisipv6; /**< Client IPv6 address */
  int ipv6; /**< If connection is IPv6 */
  char sessionid[REDIR_SESSIONID_LEN]; /**< Accounting session ID */
  int response; /**< 0: No adius response yet; 1:Reject; 2:Accept; 3:Timeout */
  long int sessiontimeout; /**< Session timeout */
  long int idletimeout; /**< Idle timeout */
  long int interim_interval;  /**< Interim accounting */
  char redirurlbuf[RADIUS_ATTR_VLEN + 1]; /**< Redirection URL obtained from radius server */
  int redirurllen; /**< Length of redirurl */
  char *redirurl; /**< Redirection URL (point on redirurlbuf) */
  char replybuf[RADIUS_ATTR_VLEN + 1]; /**< Reply message */
  char *reply; /**< Reply message (point on replybuf) */
  uint8_t statebuf[RADIUS_ATTR_VLEN + 1]; /**< Radius state */
  int statelen; /**< Length of state */
  uint8_t classbuf[RADIUS_ATTR_VLEN + 1]; /**< Class attribute received from radius server and used in Accounting-Request packet */
  int classlen; /**< Length of classbuf */
  int bandwidthmaxup; /**< Maximum upload bandwith */
  int bandwidthmaxdown; /**< Maximum download bandwith */
  int maxinputoctets;  /**< Maximum output bytes that can be received */
  int maxoutputoctets; /**< Maximum output bytes that can be sent */
  int maxtotaloctets; /**< Maximum bytes allowed */
  time_t sessionterminatetime; /**< Time when session terminate */
  char filteridbuf[RADIUS_ATTR_VLEN + 1]; /**< Filter ID */
  int filteridlen; /**< Length of filter ID */
  char *filterid; /**< Radius filter ID */
  uint64_t input_octets;     /**< Transferred in callback */
  uint64_t output_octets;    /**< Transferred in callback */
  struct timeval start_time; /**< Transferred in callback */
};

/**
 * \struct redir_t
 * \brief Redirection manager.
 */
struct redir_t
{
  int fd; /**< File descriptor */
  int fdv6; /**< File descriptor for IPv6 */
  int debug; /**< Print debug information or not */
  int msgid; /**< Message Queue ID */
  struct in_addr addr; /**< Listen IPv4 address */
  struct in6_addr addrv6; /**< IPv6 address */
  struct in6_addr prefix; /**< IPv6 prefix */
  int prefixlen; /**< IPv6 prefix length */
  int port; /**< Listen port */
  char *url; /**< URL of IPv4 webserver */
  char* url6; /**< URL of IPv6 webserver */
  char *homepage; /**< URL of homepage */
  char *secret; /**< Shared secret with CGI script */
  struct sockaddr_storage radiuslisten; /**< Listen address to communicate with RADIUS server */
  struct sockaddr_storage radiusserver0; /**< Address of primary RADIUS server */
  struct sockaddr_storage radiusserver1; /**< Address of secondary RADIUS server */
  uint16_t radiusauthport; /**< Authentication port of RADIUS server */
  uint16_t radiusacctport; /**< Accounting port of RADIUS server */
  char *radiussecret; /**< RADIUS secret */
  char *radiusnasid; /**< NAS ID */
  struct sockaddr_storage radiusnasip; /**< Address of NAS */
  char *radiuscalled; /**< Called station */
  char* radiuslocationid; /**< Location ID */
  char* radiuslocationname; /**< Location name */
  int radiusnasporttype; /**< NAS port type of NAS */
  int starttime; /**< Start time */

  /**
   * \brief Callback to retrieve state of an IPv4 connection.
   */
  int (*cb_getstate) (struct redir_t *redir, struct in_addr *addr,
                      struct redir_conn_t *conn);

  /* [SV] */
  /**
   * \brief Callback to retrieve state of an IPv6 connection.
   */
  int (*cb_getstatev6) (struct redir_t *redir, struct in6_addr *addr, struct redir_conn_t *conn);
};

/**
 * \struct redir_msg_t
 * \brief Redirection message (passed via message queue).
 */
struct redir_msg_t
{
  long int type; /**< Type of message */
  long int interim_interval; /**< Interval */
  long int sessiontimeout; /**< Session timeout */
  long int idletimeout; /**< Idle timeuot */
  struct in_addr addr; /**< Client IPv4 address */
  struct in6_addr addrv6; /**< Client IPv6 address */
  char username[REDIR_USERNAMESIZE]; /**< User name */
  char userurl[REDIR_USERURLSIZE]; /**< Requested user URL */
  uint8_t uamchal[REDIR_MD5LEN]; /**< UAM challenge */
  uint8_t statebuf[RADIUS_ATTR_VLEN + 1]; /**< Radius state */
  int statelen; /**< Length of state */
  uint8_t classbuf[RADIUS_ATTR_VLEN + 1]; /**< Class attribute received from radius server and used in Accounting-Request packet */
  int classlen; /**< Length of classbuf */
  int bandwidthmaxup; /**< Maximum upload bandwidth */
  int bandwidthmaxdown; /**< Maximum download bandwidth */
  int maxinputoctets; /**< Maximum bytes that can be received */
  int maxoutputoctets; /**< Maximum bytes that can be sent */
  int maxtotaloctets; /**< Maximum bytes allowed */
  int sessionterminatetime; /**< Time when session terminate */
  char filteridbuf[RADIUS_ATTR_VLEN + 1]; /**< Filter ID */
  int filteridlen; /**< Length of filter ID */
  int ipv6; /**< If connection use IPv6 */
};

/**
 * \brief Create a new redirection manager.
 * \param redir pointer will be filled with newly redirection manager if success
 * \param addr our IPv4 address
 * \param addrv6 our IPv6 address
 * \param port port
 * \return 0 if success, -1 otherwise
 */
int redir_new(struct redir_t **redir,
              struct in_addr *addr, struct in6_addr* addrv6, int port);

/**
 * \brief Release redirection manager.
 * \param redir redirection manager to release
 * \return 0
 */
int redir_free(struct redir_t *redir);

/**
 * \brief Set various parameters.
 * \param redir redir_t instance
 * \param debug print debug information or not
 * \param prefix IPv6 prefix
 * \param prefixlen length of IPv6 prefix
 * \param url redirection URL for IPv4
 * \param url6 redirection URL for IPv6
 * \param homepage URL home page
 * \param secret shared secret for CGI script
 * \param radiuslisten listen address for RADIUS communication
 * \param radiusserver0 address of primary RADIUS server
 * \param radiusserver1 address of secondary RADIUS server
 * \param radiusauthport authentication port of RADIUS server
 * \param radiusacctport accounting port of RADIUS server
 * \param radiussecret RADIUS shared secret
 * \param radiusnasid ID of NAS
 * \param radiusnasip address of NAS
 * \param radiuscalled called station ID
 * \param radiuslocationid location ID
 * \param radiuslocationname location name
 * \param radiusnasporttype type of NAS port
 */
void redir_set(struct redir_t *redir, int debug, struct in6_addr *prefix, int prefixlen,
               char *url, char* url6, char *homepage, char* secret,
               struct sockaddr_storage *radiuslisten,
               struct sockaddr_storage *radiusserver0,
               struct sockaddr_storage *radiusserver1,
               uint16_t radiusauthport, uint16_t radiusacctport,
               char* radiussecret, char* radiusnasid,
               struct sockaddr_storage *radiusnasip, char* radiuscalled,
               char* radiuslocationid, char* radiuslocationname,
               int radiusnasporttype);

/**
 * \brief Accept connection and redirect URL.
 *
 *  1) forks a child process
 *  2) Accepts the tcp connection
 *  3) Analyses a HTTP get request
 *  4) GET request can be one of the following:
 *  a) Logon request with username and challenge response
 *  - Does a radius request
 *  - If OK send result to parent and redirect to welcome page
 *  - Else redirect to error login page
 *  b) Logoff request
 *  - Send logoff request to parent
 *  - Redirect to login page?
 *  c) Request for another server
 *  - Redirect to login server.
 *
 *   Incoming requests are identified only by their IP address. No MAC
 *   address information is obtained. The main security problem is denial
 *   of service attacks by malicious hosts sending logoff requests for
 *   clients. This can be prevented by checking incoming packets for
 *   matching MAC and src IP addresses.
 * \param redir redir_t instance
 * \param ipv6 if client use IPv6
 * \return 0 if success, -1 otherwise
 */
int redir_accept(struct redir_t *redir, int ipv6);

/* [SV] */
/**
 * \brief Set callback to determine state information for the IPv6 connection.
 * \param redir redir_t instance
 * \param cb_getstatev6 callback
 * \return 0
 */
int redir_set_cb_getstatev6(struct redir_t* redir, int (*cb_getstatev6)(struct redir_t* redir, struct in6_addr* addr, struct redir_conn_t* conn));

/**
 * \brief Set callback to determine state information for the IPv4 connection.
 * \param redir redir_t instance
 * \param cb_getstate callback
 * \return 0
 */
int redir_set_cb_getstate(struct redir_t *redir,
                          int (*cb_getstate) (struct redir_t *redir, struct in_addr *addr,
                                              struct redir_conn_t *conn));

#endif  /* !_REDIR_H */

