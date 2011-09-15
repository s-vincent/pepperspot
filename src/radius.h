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
 * Radius client functions.
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
 */

/**
 * \file radius.h
 * \brief RADIUS client.
 */

#ifndef _RADIUS_H
#define _RADIUS_H

#define RADIUS_SECRETSIZE 128  /**< Size of radius size, there are no secrets that long */
#define RADIUS_MD5LEN  16      /**< Length of MD5 hash */
#define RADIUS_AUTHLEN 16      /**< RFC 2865: Length of authenticator */
#define RADIUS_PWSIZE  128     /**< RFC 2865: Max 128 octets in password */
#define RADIUS_QUEUESIZE 256   /**< Same size as id address space */
#define RADIUS_TIMEOUT 1500000 /**< Time between requests in micro seconds */
#define RADIUS_RETRY1 3        /**< Number of times to retry primary */
#define RADIUS_RETRY2 6        /**< Total number of retries */

#define RADIUS_ATTR_VLEN 253   /**< Maximum size of an attribute payload */
#define RADIUS_AUTHPORT 1812   /**< Radius authentication listen port */
#define RADIUS_ACCTPORT 1813   /**< Radius accounting listen port */
#define RADIUS_PACKSIZE 4096   /**< Maximum radius packet size */
#define RADIUS_HDRSIZE 20      /**< Radius header size */
#define RADIUS_PASSWORD_LEN 16 /**< Length of password */
#define RADIUS_MPPEKEYSSIZE 32 /**< Length of MS_CHAP_MPPE_KEYS attribute */

/* Radius packet types */
#define RADIUS_CODE_ACCESS_REQUEST            1 /**< Code of an radius access request message */
#define RADIUS_CODE_ACCESS_ACCEPT             2 /**< Code of an radius access-accept message */
#define RADIUS_CODE_ACCESS_REJECT             3 /**< Code of an radius access-reject message */
#define RADIUS_CODE_ACCOUNTING_REQUEST        4 /**< Code of an radius accounting request message */
#define RADIUS_CODE_ACCOUNTING_RESPONSE       5 /**< Code of an radius accouting response message */
#define RADIUS_CODE_ACCESS_CHALLENGE         11 /**< Code of an radius access-challenge message */
#define RADIUS_CODE_STATUS_SERVER            12 /**< Code of an radius status-server message */
#define RADIUS_CODE_STATUS_CLIENT            13 /**< Code of an radius status-client message */
#define RADIUS_CODE_DISCONNECT_REQUEST       40 /**< Code of an radius disconnect request message */
#define RADIUS_CODE_DISCONNECT_ACK           41 /**< Code of an radius disconnect acknowledgement message */
#define RADIUS_CODE_DISCONNECT_NAK           42 /**< Code of an radius disconnect NAK message */
#define RADIUS_CODE_COA_REQUEST              43 /**< Code of an radius COA request message */
#define RADIUS_CODE_COA_ACK                  44 /**< Code of an radius COA acknowledgment message */
#define RADIUS_CODE_COA_NAK                  45 /**< Code of an radius COA NAK message */
#define RADIUS_CODE_STATUS_REQUEST           46 /**< Code of an radius status request message */
#define RADIUS_CODE_STATUS_ACCEPT            47 /**< Code of an radius status-accept message */
#define RADIUS_CODE_STATUS_REJECT            48 /**< Code of an radius status-reject message */

/* Radius attributes */
#define RADIUS_ATTR_USER_NAME                 1     /**< string */
#define RADIUS_ATTR_USER_PASSWORD             2     /**< string (encrypt) */
#define RADIUS_ATTR_CHAP_PASSWORD             3     /**< octets */
#define RADIUS_ATTR_NAS_IP_ADDRESS            4     /**< ipaddr */
#define RADIUS_ATTR_NAS_PORT                  5     /**< integer */
#define RADIUS_ATTR_SERVICE_TYPE              6     /**< integer */
#define RADIUS_ATTR_FRAMED_PROTOCOL           7     /**< integer */
#define RADIUS_ATTR_FRAMED_IP_ADDRESS         8     /**< ipaddr */
#define RADIUS_ATTR_FRAMED_IP_NETMASK         9     /**< ipaddr */
#define RADIUS_ATTR_FRAMED_ROUTING           10     /**< integer */
#define RADIUS_ATTR_FILTER_ID                11     /**< string */
#define RADIUS_ATTR_FRAMED_MTU               12     /**< integer */
#define RADIUS_ATTR_FRAMED_COMPRESSION       13     /**< integer */
#define RADIUS_ATTR_LOGIN_IP_HOST            14     /**< ipaddr */
#define RADIUS_ATTR_LOGIN_SERVICE            15     /**< integer */
#define RADIUS_ATTR_LOGIN_TCP_PORT           16     /**< integer */
#define RADIUS_ATTR_REPLY_MESSAGE            18     /**< string */
#define RADIUS_ATTR_CALLBACK_NUMBER          19     /**< string */
#define RADIUS_ATTR_CALLBACK_ID              20     /**< string */
#define RADIUS_ATTR_FRAMED_ROUTE             22     /**< string */
#define RADIUS_ATTR_FRAMED_IPX_NETWORK       23     /**< ipaddr */
#define RADIUS_ATTR_STATE                    24     /**< octets */
#define RADIUS_ATTR_CLASS                    25     /**< octets */
#define RADIUS_ATTR_VENDOR_SPECIFIC          26     /**< octets */
#define RADIUS_ATTR_SESSION_TIMEOUT          27     /**< integer */
#define RADIUS_ATTR_IDLE_TIMEOUT             28     /**< integer */
#define RADIUS_ATTR_TERMINATION_ACTION       29     /**< integer */
#define RADIUS_ATTR_CALLED_STATION_ID        30     /**< string */
#define RADIUS_ATTR_CALLING_STATION_ID       31     /**< string */
#define RADIUS_ATTR_NAS_IDENTIFIER           32     /**< string */
#define RADIUS_ATTR_PROXY_STATE              33     /**< octets */
#define RADIUS_ATTR_LOGIN_LAT_SERVICE        34     /**< string */
#define RADIUS_ATTR_LOGIN_LAT_NODE           35     /**< string */
#define RADIUS_ATTR_LOGIN_LAT_GROUP          36     /**< octets */
#define RADIUS_ATTR_FRAMED_APPLETALK_LINK    37     /**< integer */
#define RADIUS_ATTR_FRAMED_APPLETALK_NETWORK 38     /**< integer */
#define RADIUS_ATTR_FRAMED_APPLETALK_ZONE    39     /**< string */
#define RADIUS_ATTR_ACCT_STATUS_TYPE         40     /**< integer */
#define RADIUS_ATTR_ACCT_DELAY_TIME          41     /**< integer */
#define RADIUS_ATTR_ACCT_INPUT_OCTETS        42     /**< integer */
#define RADIUS_ATTR_ACCT_OUTPUT_OCTETS       43     /**< integer */
#define RADIUS_ATTR_ACCT_SESSION_ID          44     /**< string */
#define RADIUS_ATTR_ACCT_AUTHENTIC           45     /**< integer */
#define RADIUS_ATTR_ACCT_SESSION_TIME        46     /**< integer */
#define RADIUS_ATTR_ACCT_INPUT_PACKETS       47     /**< integer */
#define RADIUS_ATTR_ACCT_OUTPUT_PACKETS      48     /**< integer */
#define RADIUS_ATTR_ACCT_TERMINATE_CAUSE     49     /**< integer */
#define RADIUS_ATTR_ACCT_MULTI_SESSION_ID    50     /**< string */
#define RADIUS_ATTR_ACCT_LINK_COUNT          51     /**< integer */
#define RADIUS_ATTR_ACCT_INPUT_GIGAWORDS     52     /**< integer */
#define RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS    53     /**< integer */
#define RADIUS_ATTR_EVENT_TIMESTAMP          55     /**< date */
#define RADIUS_ATTR_CHAP_CHALLENGE           60     /**< string */
#define RADIUS_ATTR_NAS_PORT_TYPE            61     /**< integer */
#define RADIUS_ATTR_PORT_LIMIT               62     /**< integer */
#define RADIUS_ATTR_LOGIN_LAT_PORT           63     /**< integer */
#define RADIUS_ATTR_ACCT_TUNNEL_CONNECTION   68     /**< string */
#define RADIUS_ATTR_ARAP_PASSWORD            70     /**< string */
#define RADIUS_ATTR_ARAP_FEATURES            71     /**< string */
#define RADIUS_ATTR_ARAP_ZONE_ACCESS         72     /**< integer */
#define RADIUS_ATTR_ARAP_SECURITY            73     /**< integer */
#define RADIUS_ATTR_ARAP_SECURITY_DATA       74     /**< string */
#define RADIUS_ATTR_PASSWORD_RETRY           75     /**< integer */
#define RADIUS_ATTR_PROMPT                   76     /**< integer */
#define RADIUS_ATTR_CONNECT_INFO             77     /**< string */
#define RADIUS_ATTR_CONFIGURATION_TOKEN      78     /**< string */
#define RADIUS_ATTR_EAP_MESSAGE              79     /**< string */
#define RADIUS_ATTR_MESSAGE_AUTHENTICATOR    80     /**< octets */
#define RADIUS_ATTR_ARAP_CHALLENGE_RESPONSE  84     /**< string # 10 octets */
#define RADIUS_ATTR_ACCT_INTERIM_INTERVAL    85     /**< integer */
#define RADIUS_ATTR_NAS_PORT_ID              87     /**< string */
#define RADIUS_ATTR_FRAMED_POOL              88     /**< string */
#define RADIUS_ATTR_NAS_IPV6_ADDRESS         95     /**< octets (IPv6) */
#define RADIUS_ATTR_FRAMED_INTERFACE_ID      96     /**< octets # 8 octets */
#define RADIUS_ATTR_FRAMED_IPV6_PREFIX       97     /**< octets ??? */
#define RADIUS_ATTR_LOGIN_IPV6_HOST          98     /**< octets (IPv6) */
#define RADIUS_ATTR_FRAMED_IPV6_ROUTE        99     /**< string */
#define RADIUS_ATTR_FRAMED_IPV6_POOL        100     /**< string */
#define RADIUS_ATTR_DIGEST_RESPONSE         206     /**< string */
#define RADIUS_ATTR_DIGEST_ATTRIBUTES       207     /**< octets  ??? */

#define RADIUS_VENDOR_MS                    311 /**< Microsoft vendor-specific code */
#define RADIUS_ATTR_MS_CHAP_RESPONSE          1 /**< CHAP response message type */
#define RADIUS_ATTR_MS_MPPE_ENCRYPTION_POLICY 7 /**< MPPE policy message type */
#define RADIUS_ATTR_MS_MPPE_ENCRYPTION_TYPES  8 /**< MPPE encryption types message type */
#define RADIUS_ATTR_MS_CHAP_CHALLENGE        11 /**< CHAP challenge message type */
#define RADIUS_ATTR_MS_CHAP_MPPE_KEYS        12 /**< CHAP MPPE message type */
#define RADIUS_ATTR_MS_MPPE_SEND_KEY         16 /**< MPPE send message type */
#define RADIUS_ATTR_MS_MPPE_RECV_KEY         17 /**< MPPE receive message type */
#define RADIUS_ATTR_MS_CHAP2_RESPONSE        25 /**< CHAPv2 response message type */
#define RADIUS_ATTR_MS_CHAP2_SUCCESS         26 /**< CHAPv2 success message type */

#define RADIUS_SERVICE_TYPE_LOGIN             1 /**< Login service */

#define RADIUS_STATUS_TYPE_START              1 /**< Start a service */
#define RADIUS_STATUS_TYPE_STOP               2 /**< Stop a service */
#define RADIUS_STATUS_TYPE_INTERIM_UPDATE     3 /**< Update interim time of a service */

#define RADIUS_NAS_PORT_TYPE_VIRTUAL          5 /**< NAS port is a virtual interface */
#define RADIUS_NAS_PORT_TYPE_WIRELESS_802_11 19 /**< NAS port is a 802.11 wireless interface */
#define RADIUS_NAS_PORT_TYPE_WIRELESS_UMTS   23 /**< NAS port is a UMTS wireless interface */

/* various possible causes for a terminated session */
#define RADIUS_TERMINATE_CAUSE_USER_REQUEST          1 /**< User request session to terminate */
#define RADIUS_TERMINATE_CAUSE_LOST_CARRIER          2 /**< Modem lost carrier */
#define RADIUS_TERMINATE_CAUSE_LOST_SERVICE          3 /**< Server has problem (interface down, network access, ...) */
#define RADIUS_TERMINATE_CAUSE_IDLE_TIMEOUT          4 /**< Idle timeout expires */
#define RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT       5 /**< Session timeout */
#define RADIUS_TERMINATE_CAUSE_ADMIN_RESET           6 /**< Administrator reset client */
#define RADIUS_TERMINATE_CAUSE_ADMIN_REBOOT          7 /**< Administrator reboot client */
#define RADIUS_TERMINATE_CAUSE_PORT_ERROR            8 /**< Error from NAS port */
#define RADIUS_TERMINATE_CAUSE_NAS_ERROR             9 /**< Session terminated because of a NAS error */
#define RADIUS_TERMINATE_CAUSE_NAS_REQUEST          10 /**< NAS request session to terminate */
#define RADIUS_TERMINATE_CAUSE_NAS_REBOOT           11 /**< NAS server reboot */
#define RADIUS_TERMINATE_CAUSE_PORT_UNNEEDED        12 /**< Unneeded port */
#define RADIUS_TERMINATE_CAUSE_PORT_PREEMPTED       13 /**< Preempted port */
#define RADIUS_TERMINATE_CAUSE_PORT_SUSPEND         14 /**< Port suspended */
#define RADIUS_TERMINATE_CAUSE_SERVICE_UNAVAILABLE  15 /**< Service is unavailable so terminate */
#define RADIUS_TERMINATE_CAUSE_CALLBACK             16 /**< Callback user is disconnected */
#define RADIUS_TERMINATE_CAUSE_USER_ERROR           17 /**< Session terminated because of a user error */
#define RADIUS_TERMINATE_CAUSE_HOST_REQUEST         18 /**< Disconnected or logged out from host, could be caused if a host has crashed */

/**
 * \struct radius_packet_t
 * \brief Radius packet.
 */
struct radius_packet_t
{
  uint8_t code; /**< Code */
  uint8_t id; /**< Packet ID */
  uint16_t length; /**< Length */
  uint8_t authenticator[RADIUS_AUTHLEN]; /**< authenticator */
  uint8_t payload[RADIUS_PACKSIZE-RADIUS_HDRSIZE]; /**< The payload */
} __attribute__((packed));

/**
 * \struct radius_queue_t
 * \brief Holder for queued packets.
 */
struct radius_queue_t
{
  int state;                 /**< 0=empty, 1=full */
  void *cbp;                 /**< Pointer used for callbacks */
  struct timeval timeout;    /**< When do we retransmit this packet? */
  int retrans;               /**< How many times did we retransmit this? */
  int lastsent;              /**< 0 or 1 indicates last server used */
  struct sockaddr_storage peer; /**< Address packet was sent to / received from */
  struct radius_packet_t p;  /**< The packet stored */
  uint16_t seq;              /**< The sequence number */
  uint8_t type;              /**< The type of packet */
  int l;                     /**< Length of the packet */
  struct qmsg_t *seqnext;    /**< Pointer to next in sequence hash list */
  int next;                  /**< Pointer to the next in queue. -1: Last */
  int prev;                  /**< Pointer to the previous in queue. -1: First */
  int this;                  /**< Pointer to myself */
};

/**
 * \struct radius_t
 * \brief Describes radius_t instance.
 */
struct radius_t
{
  int fd;                    /**< Socket file descriptor */
  FILE *urandom_fp;          /**< /dev/urandom FILE pointer */
  struct sockaddr_storage ouraddr; /**< Address to listen to */
  uint16_t ourport;          /**< Port to listen to */
  int coanocheck;            /**< Accept coa from all IP addresses */
  int lastreply;             /**< 0 or 1 indicates last server reply */
  uint16_t authport;         /**< His port for authentication */
  uint16_t acctport;         /**< His port for accounting */
  struct sockaddr_storage hisaddr0; /**< Server address */
  struct sockaddr_storage hisaddr1; /**< Server address */
  char secret[RADIUS_SECRETSIZE]; /**< Shared secret */
  int secretlen;                  /**< Length of sharet secret */
  int proxyfd;                    /**< Proxy socket file descriptor */
  struct sockaddr_storage proxylisten; /**< Proxy address to listen to */
  uint16_t proxyport;        /**< Proxy port to listen to */
  struct sockaddr_storage proxyaddr; /**< Proxy client address */
  struct sockaddr_storage proxymask; /**< Proxy client mask */
  char proxysecret[RADIUS_SECRETSIZE]; /**< Proxy secret */
  int proxysecretlen;        /**< Length of sharet secret */

  int debug;                 /**< Print debug messages */
  struct radius_queue_t queue[RADIUS_QUEUESIZE]; /**< Outstanding replies */
  uint8_t next;              /**< Next location in queue to use */
  int first;                 /**< First packet in queue (oldest timeout) */
  int last;                  /**< Last packet in queue (youngest timeout) */

  int listsize;              /**< Total number of addresses */
  int hashsize;              /**< Size of hash table */
  int hashlog;               /**< Log2 size of hash table */
  int hashmask;              /**< Bitmask for calculating hash */
  int (*cb_ind)  (struct radius_t *radius, struct radius_packet_t *pack,
                  struct sockaddr_storage *peer); /**< Callback for received request */
  int (*cb_auth_conf) (struct radius_t *radius, struct radius_packet_t *pack,
                       struct radius_packet_t *pack_req, void *cbp); /**< Callback for response
                                                                       to access request */
  int (*cb_acct_conf) (struct radius_t *radius, struct radius_packet_t *pack,
                       struct radius_packet_t *pack_req, void *cbp); /**< Callback for response 
                                                                       to accounting request */
  int (*cb_coa_ind)   (struct radius_t *radius, struct radius_packet_t *pack,
                       struct sockaddr_storage *peer); /**< Callback for coa and disconnect request */
};

/**
 * \struct radiusm_t
 * \brief Radius member.
 */
struct radiusm_t
{
  struct in_addr addr;           /**< IP address of this member */
  struct in6_addr addrv6;        /**< IPv6 address of this member */
  int inuse;                     /**< 0=available; 1= inuse */
  struct RADIUSm_t *nexthash;    /**< Linked list part of hash table */
  struct RADIUSm_t *prev;        /**< Previous member (for double linked list of available members) */
  struct RADIUSm_t *next;        /**< Next member (for double linked list of available members) */
  struct RADIUS_t *parent;       /**< Pointer to parent */
  void *peer;                    /**< Pointer to peer protocol handler */
};

/**
 * \struct radius_attr_t
 * \brief Radius attribute.
 */
struct radius_attr_t
{
  uint8_t t; /**< Type */
  uint8_t l; /**< Length */
  union
  {
    uint32_t i;
    uint8_t  t[RADIUS_ATTR_VLEN];
    struct
    {
      uint32_t i;
      uint8_t t;
      uint8_t l;
      union
      {
        uint32_t i;
        uint8_t  t[RADIUS_ATTR_VLEN - 4];
      } v;
    } vv;
  } v; /**< Variable-size payload */
} __attribute__((packed));

/**
 * \struct radius_attrv6_t
 * \brief Radius specific IPv6 attribute.
 */
struct radius_attrv6_t
{
  uint8_t t; /**< Type */
  uint8_t l; /**< Length */
  union
  {
    uint32_t i;
    uint8_t  t[RADIUS_ATTR_VLEN];
    struct
    {
      uint32_t i;
      uint8_t t;
      uint8_t l;
      union
      {
        struct in6_addr i;
        uint8_t  t[RADIUS_ATTR_VLEN - 4];
      } v;
    } vv;
  } v; /**< Variable-size payload */
} __attribute__((packed));

/**
 * \brief Create new radius instance.
 * \param this pointer will be filled with new radius_t instance
 * \param listen address to listen
 * \param port listen port 
 * \param coanocheck accept coa from all IP addresses
 * \param proxylisten proxy radius address
 * \param proxyport proxy radius port
 * \param proxyaddr proxy radius address
 * \param proxymask proxy mask 
 * \param proxysecret secret to use with proxy
 * \return 0 if success, -1 otherwise
 */
int radius_new(struct radius_t **this,
               struct sockaddr_storage *listen, uint16_t port, int coanocheck,
               struct sockaddr_storage *proxylisten, uint16_t proxyport,
               struct sockaddr_storage *proxyaddr, struct sockaddr_storage *proxymask,
               char* proxysecret);

/**
 * \brief Delete existing radius instance.
 * \param this radius_t instance pointer to free
 * \return 0
 */
int radius_free(struct radius_t *this);

/**
 * \brief Set radius parameters which can later be changed.
 * \param this radius_t instance
 * \param debug enable or not debug
 * \param server0 first radius server
 * \param server1 second radius server
 * \param authport authentication port
 * \param acctport accounting port
 * \param secret secret to use
 */
void radius_set(struct radius_t *this, int debug,
                struct sockaddr_storage *server0, struct sockaddr_storage *server1,
                uint16_t authport, uint16_t acctport, char* secret);

/**
 * \brief Set allback function for received request.
 * \param this radius_t instance
 * \param cb_ind callback to set
 * \return 0
 */
int radius_set_cb_ind(struct radius_t *this,
                      int (*cb_ind) (struct radius_t *radius, struct radius_packet_t *pack,
                                    struct sockaddr_storage *peer));
/**
 * \brief Set callback function for coa and disconnect request.
 * \param this radius_t instance
 * \param cb_coa_ind callback to set
 * \return 0
 */
int radius_set_cb_coa_ind(struct radius_t *this,
                          int (*cb_coa_ind) (struct radius_t *radius, struct radius_packet_t *pack,
                                             struct sockaddr_storage *peer)) ;

/**
 * \brief Set callback function for response to access request.
 * \param this radius_t instance
 * \param cb_auth_conf callback to set
 * \return 0
 */
int radius_set_cb_auth_conf(struct radius_t *this,
                            int (*cb_auth_conf) (struct radius_t *radius, struct radius_packet_t *pack,
                                                 struct radius_packet_t *pack_req, void *cbp));

/**
 * \brief Callback function for response to accounting request.
 * \param this radius_t instance
 * \param cb_acct_conf callback to set
 * \return 0
 */
int radius_set_cb_acct_conf(struct radius_t *this,
                            int (*cb_acct_conf) (struct radius_t *radius, struct radius_packet_t *pack,
                                                 struct radius_packet_t *pack_req, void *cbp));

/**
 * \brief Send of a request.
 * \param this radius_t instance
 * \param pack radius packet to send 
 * \param cbp pointer used for callback
 * \return 0 if success, -1 otherwise
 */
int radius_req(struct radius_t *this,
               struct radius_packet_t *pack,
               void *cbp);

/**
 * \brief Send of a response.
 * \param this radis_t instance
 * \param pack radius packet to send
 * \param peer destination peer
 * \param req_auth authenticator
 * \return 0 if success, -1 otherwise 
 */
int radius_resp(struct radius_t *this,
                struct radius_packet_t *pack,
                struct sockaddr_storage *peer, uint8_t *req_auth);

/**
 * \brief Send of a coa response.
 * \param this radius_t instance
 * \param pack radius packet to send
 * \param peer destination peer
 * \param req_auth authenticator
 * \return 0 if success, -1 otherwise
 */
int radius_coaresp(struct radius_t *this,
                   struct radius_packet_t *pack,
                   struct sockaddr_storage *peer, uint8_t *req_auth);

/**
 * \brief Process an incoming packet.
 * \param this radius_t instance
 * \return 0 if success, -1 otherwise
 */
int radius_decaps(struct radius_t *this);

/** 
 * \brief Process an incoming packet.
 * \param this radius_t instance
 * \return 0 if success, -1 otherwise
 */
int radius_proxy_ind(struct radius_t *this);

/**
 * \brief Add an attribute to a packet.
 * 
 * Add an attribute to a packet. The packet length is modified
 * accordingly. If data == NULL and dlen != 0 insert null attribute.
 * \param this radius_t instance
 * \param pack radius packet to add
 * \param type type
 * \param vendor_id vendor ID
 * \param vendor_type vendor type
 * \param value value to set
 * \param data data payload
 * \param dlen data length
 * \return 0 if success, -1 otherwise
 */
int radius_addattr(struct radius_t *this, struct radius_packet_t *pack,
                   uint8_t type, uint32_t vendor_id, uint8_t vendor_type,
                   uint32_t value, uint8_t *data, uint16_t dlen);

/**
 * \brief Add an IPv6 specific attribute to a packet.
 * 
 * Add an attribute to a packet. The packet length is modified
 * accordingly. If data == NULL and dlen != 0 insert null attribute.
 * \param this radius_t instance
 * \param pack radius packet to add
 * \param type type
 * \param vendor_id vendor ID
 * \param vendor_type vendor type
 * \param value value to set
 * \param data data payload
 * \param dlen data length
 * \return 0 if success, -1 otherwise
 */
int radius_addattrv6(struct radius_t *this, struct radius_packet_t *pack,
                     uint8_t type, uint32_t vendor_id, uint8_t vendor_type,
                     struct in6_addr value, uint8_t *data, uint16_t dlen);

/**
 * \brief Generate a packet for use with radius_addattr().
 * \param this radius_t instance
 * \param pack radius packet
 * \param code radius code
 * \return 0 if success, -1 otherwise
 */
int radius_default_pack(struct radius_t *this,
                        struct radius_packet_t *pack,
                        int code);

/**
 * \brief Extract an attribute from a packet.
 *
 * Search for an attribute in a packet. Returns -1 if attribute is not found.
 * The first instance matching attributes will be skipped
 * \param pack radius packet
 * \param attr pointer to be filled with attribute if found 
 * \param type attribute type to get
 * \param vendor_id vendor ID
 * \param vendor_type vendor type
 * \param instance if 1 the first matching attribute will be skipped
 * \return 0 if found, -1 otherwise
 */
int radius_getattr(struct radius_packet_t *pack, struct radius_attr_t **attr,
                   uint8_t type, uint32_t vendor_id, uint8_t vendor_type,
                   int instance);

/**
 * \brief Extract an attribute from a packet.
 *
 * Search for an attribute in a packet. Returns -1 if attribute is not found.
 * The first instance matching attributes will be skipped
 * \param pack radius packet
 * \param attr pointer to be filled with attribute if found 
 * \param type attribute type to get
 * \param vendor_id vendor ID
 * \param vendor_type vendor type
 * \param instance if 1 the first matching attribute will be skipped
 * \return 0 if found, -1 otherwise
 */
int radius_getattrv6(struct radius_packet_t *pack, struct radius_attrv6_t **attr,
                     uint8_t type, uint32_t vendor_id, uint8_t vendor_type,
                     int instance);

/**
 * \brief Encode a password using MD5.
 * \param this radius_t instance
 * \param dst password buffer
 * \param dstsize size of dst
 * \param dstlen length that will be updated with the encoded password length
 * \param src buffer to encode
 * \param srclen buffer length 
 * \param authenticator authenticator
 * \param secret radius secret
 * \param secretlen radius secret length
 * \return 0 if password encoded successfully, -1 otherwise
 */
int radius_pwencode(struct radius_t *this, uint8_t *dst, int dstsize,
                    int *dstlen, uint8_t *src, int srclen,
                    uint8_t *authenticator, char *secret, int secretlen);

/**
 * \brief Decode a password using MD5 (also used for MSCHAPv1 MPPE keys).
 * \param this radius_t instance
 * \param dst decoded password buffer
 * \param dstsize size of dst
 * \param dstlen length that will be updated with the encoded password length
 * \param src buffer to decode
 * \param srclen buffer length 
 * \param authenticator authenticator
 * \param secret radius secret
 * \param secretlen radius secret length
 * \return 0 if password decoded successfully, -1 otherwise
 */
int radius_pwdecode(struct radius_t *this, uint8_t *dst, int dstsize,
                    int *dstlen, uint8_t *src, int srclen,
                    uint8_t *authenticator, char *secret, int secretlen);

/**
 * \brief Decode MPPE key.
 * \param this radius_t instance
 * \param dst decoded password buffer
 * \param dstsize size of dst
 * \param dstlen length that will be updated with the encoded password length
 * \param src buffer to decode
 * \param srclen buffer length 
 * \param authenticator authenticator
 * \param secret radius secret
 * \param secretlen radius secret length
 * \return 0 if password decoded successfully, -1 otherwise
 */
int radius_keydecode(struct radius_t *this, uint8_t *dst, int dstsize,
                     int *dstlen, uint8_t *src, int srclen,
                     uint8_t *authenticator, char *secret, int secretlen);

/**
 * \brief Encode MPPE key.
 * \param this radius_t instance
 * \param dst decoded password buffer
 * \param dstsize size of dst
 * \param dstlen length that will be updated with the encoded password length
 * \param src buffer to decode
 * \param srclen buffer length 
 * \param authenticator authenticator
 * \param secret radius secret
 * \param secretlen radius secret length
 * \return 0 if password decoded successfully, -1 otherwise
 */
int radius_keyencode(struct radius_t *this, uint8_t *dst, int dstsize,
                     int *dstlen, uint8_t *src, int srclen,
                     uint8_t *authenticator, char *secret, int secretlen);

/**
 * \brief Call this function to process packets needing retransmission.
 * 
 * Retransmit any outstanding packets. This function should be called at
 * regular intervals. Use radius_timeleft() to determine how much time is
 * left before this function should be called.
 * \param this radius_t instance
 * \return 0
 i*/
int radius_timeout(struct radius_t *this);

/**
 * \brief Figure out when to call radius_calltimeout().
 * 
 * Determines how nuch time is left until we need to call
 * radius_timeout().
 * Only modifies timeout if new value is lower than current value.
 * \param this radius_t instance
 * \param timeout timeleft will be stored in it
 * \return 0 
 */
int radius_timeleft(struct radius_t *this, struct timeval *timeout);

#endif  /* !_RADIUS_H */

