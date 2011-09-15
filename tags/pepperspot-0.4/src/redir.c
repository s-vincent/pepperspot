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
 * Copyright (C) 2004, 2005 Mondru AB.
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

/**
 * \file redir.c
 * \brief HTTP redirection module.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>

#include <sys/ipc.h>
#include <sys/msg.h>

#include <time.h>
#include <sys/time.h>

#include <signal.h>

#include "syserr.h"
#include "radius.h"
#include "radius_wispr.h"
#include "radius_pepperspot.h"
#include "redir.h"
#include "md5.h"
#include "ippool.h"
#include "../config.h"

static int optionsdebug = 1; /**< Print debug information while running */

static int keep_going = 1;   /**< OK as global variable for child process */

static int termstate = REDIR_TERM_INIT;    /**< When we were terminated */

/**
 * \brief Credits for PepperSpot.
 */
char credits[] =
  "<H1>PepperSpot " VERSION "</H1><p>Copyright 2008-2009 University of Strasbourg</p><p> "
  "PepperSpot is an Open Source captive portal or wireless LAN access point "
  "controller developed by the community at "
  "<a href=\"http://www.pepperspot.info\">www.pepperspot.info</a> and licensed "
  "under the GPL.</p><p>PepperSpot acknowledges all community members and original Chillispot contributors</p>";

/**
 * \brief Redir signal handler.
 * \param signum Signal code
 */
static void redir_sig_handler(int signum)
{
  switch(signum)
  {
    case SIGTERM:
      if(optionsdebug) printf("Terminating redir client!\n");
      keep_going = 0;
      break;
    case SIGINT:
      if(optionsdebug) printf("Terminating redir client!\n");
      keep_going = 0;
      break;
    case SIGALRM:
      sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
              "Client process timed out: %d", termstate);
      exit(0);
      break;
  }
}

/**
 * \brief Generate a 16 bytes random challenge.
 * \param dst 2 bytes array to store random challenge
 * \return 0 if success, -1 otherwise
 */
static int redir_challenge(unsigned char *dst)
{
  FILE *file = NULL;

  if((file = fopen("/dev/urandom", "r")) == NULL)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "fopen(/dev/urandom, r) failed");
    return -1;
  }

  if(fread(dst, 1, REDIR_MD5LEN, file) != REDIR_MD5LEN)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "fread() failed");
    return -1;
  }

  fclose(file);
  return 0;
}

/**
 * \brief Convert len octet ASCII hex string to len / 2 octet unsigned char.
 * \param src hex string to convert
 * \param len source length
 * \param dst destination to store result
 * \return 0 if success, -1 otherwise
 */
static int redir_hextochar(char *src, int len, unsigned char * dst)
{
  char x[3];
  int n = 0;
  int y = 0;
  int nb = len / 2;

  for(n = 0 ; n < nb ; n++)
  {
    x[0] = src[n * 2 + 0];
    x[1] = src[n * 2 + 1];
    x[2] = 0;
    if(sscanf(x, "%2x", &y) != 1)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0, "HEX conversion failed!");
      return -1;
    }
    dst[n] = (unsigned char) y;
  }

  return 0;
}

/**
 * \brief Convert len octet unsigned char to 2*len + 1 octet ASCII hex string.
 * \param src source to convert
 * \param len source length
 * \param dst destination to store result
 * \return 0
 */
static int redir_chartohex(unsigned char *src, int len, char *dst)
{
  char x[3];
  int n = 0;

  for(n = 0; n < len; n++)
  {
    snprintf(x, 3, "%.2x", src[n]);
    dst[n * 2 + 0] = x[0];
    dst[n * 2 + 1] = x[1];
  }
  dst[len * 2] = 0;
  return 0;
}

/**
 * \brief Encode src as urlencoded and place null terminated result in dst.
 * \param src string to convert
 * \param srclen length of src
 * \param dst destination to store result
 * \param dstsize size of dst
 * \return 0 if success, -1 otherwise
 */
static int redir_urlencode( char *src, int srclen, char *dst, int dstsize)
{
  char x[3];
  int n = 0;
  int i = 0;

  for(n = 0; n < srclen; n++)
  {
    if((('A' <= src[n]) && (src[n] <= 'Z')) ||
        (('a' <= src[n]) && (src[n] <= 'z')) ||
        (('0' <= src[n]) && (src[n] <= '9')) ||
        ('-' == src[n]) ||
        ('_' == src[n]) ||
        ('.' == src[n]) ||
        ('!' == src[n]) ||
        ('~' == src[n]) ||
        ('*' == src[n]) ||
        ('\'' == src[n]) ||
        ('(' == src[n]) ||
        (')' == src[n]))
    {
      if(i < dstsize - 1)
      {
        dst[i++] = src[n];
      }
    }
    else
    {
      snprintf(x, 3, "%.2x", src[n]);
      if(i < dstsize - 3)
      {
        dst[i++] = '%';
        dst[i++] = x[0];
        dst[i++] = x[1];
      }
    }
  }
  dst[i] = 0;
  return 0;
}

/**
 * \brief Decode urlencoded src and place null terminated result in dst.
 * \param src URL to decode
 * \param srclen length of src
 * \param dst destination to store result (undecoded URL)
 * \param dstsize siz of dst
 * \return 0
 */
static int redir_urldecode(  char *src, int srclen, char *dst, unsigned int dstsize)
{
  char x[3];
  int n = 0;
  unsigned int i = 0;
  unsigned int c = 0;

  while(n < srclen)
  {
    if(src[n] == '%')
    {
      if((n + 2) < srclen)
      {
        x[0] = src[n + 1];
        x[1] = src[n + 2];
        x[2] = 0;
        c = '_';
        sscanf(x, "%x", &c);
        if(i < (dstsize - 1)) dst[i++] = c;
      }
      n += 3;
    }
    else
    {
      if(i < (dstsize - 1)) dst[i++] = src[n];
      n++;
    }
  }
  dst[i] = 0;
  return 0;
}

/**
 * \brief Concatenate src to dst and place result dst.
 * \param dst destination
 * \param dstsize size of dst
 * \param fmt format
 * \param ... argument to concatenate with dst
 * \return 0
 */
static int redir_stradd(char *dst, unsigned int dstsize, char *fmt, ...)
{
  va_list args;
  char buf[REDIR_MAXBUFFER];

  va_start(args, fmt);
  vsnprintf(buf, REDIR_MAXBUFFER, fmt, args);
  va_end(args);
  buf[REDIR_MAXBUFFER - 1] = 0; /* Make sure it is null terminated */

  if((strlen(dst) + strlen(buf)) > dstsize - 1)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "redir_stradd() failed");
    return -1;
  }

  strcpy(dst + strlen(dst), buf);
  return 0;
}

/**
 * \brief Make an XML Reply.
 * \param redir redit_t instance
 * \param conn redir connection
 * \param res state of XML reply (reject, ...)
 * \param timeleft session time left
 * \param hexchal challenge number
 * \param reply reply message
 * \param redirurl redirection URL
 * \param dst destination which will store XML reply
 * \param dstsize size of dst
 * \return 0
 */
static int redir_xmlreply(struct redir_t *redir, struct redir_conn_t *conn,
                          int res, long int timeleft, char* hexchal,
                          char* reply, char* redirurl,
                          char *dst, int dstsize)
{
  char buf[INET6_ADDRSTRLEN];

  snprintf(dst, dstsize,
           "<!--\r\n"
           "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
           "<WISPAccessGatewayParam\r\n"
           "  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\r\n"
           "  xsi:noNamespaceSchemaLocation=\"http://www.acmewisp.com/WISPAccessGatewayParam.xsd\""
           ">\r\n");
  dst[dstsize - 1] = 0;

  switch(res)
  {
    case REDIR_ALREADY:
      redir_stradd(dst, dstsize, "<AuthenticationPollReply>\r\n");
      redir_stradd(dst, dstsize, "<MessageType>140</MessageType>\r\n");
      redir_stradd(dst, dstsize, "<ResponseCode>102</ResponseCode>\r\n");
      redir_stradd(dst, dstsize,
                   "<ReplyMessage>Already logged on</ReplyMessage>\r\n");
      redir_stradd(dst, dstsize, "</AuthenticationPollReply>\r\n");
      break;
    case REDIR_FAILED_REJECT:
      redir_stradd(dst, dstsize, "<AuthenticationPollReply>\r\n");
      redir_stradd(dst, dstsize, "<MessageType>140</MessageType>\r\n");
      redir_stradd(dst, dstsize, "<ResponseCode>100</ResponseCode>\r\n");
      if(reply)
      {
        redir_stradd(dst, dstsize, "<ReplyMessage>%s</ReplyMessage>\r\n", reply);
      }
      else
      {
        redir_stradd(dst, dstsize,
                     "<ReplyMessage>Invalid Password</ReplyMessage>\r\n");
      }
      redir_stradd(dst, dstsize, "</AuthenticationPollReply>\r\n");
      break;
    case REDIR_FAILED_OTHER:
      redir_stradd(dst, dstsize, "<AuthenticationPollReply>\r\n");
      redir_stradd(dst, dstsize, "<MessageType>140</MessageType>\r\n");
      redir_stradd(dst, dstsize, "<ResponseCode>102</ResponseCode>\r\n");
      if(reply)
      {
        redir_stradd(dst, dstsize, "<ReplyMessage>%s</ReplyMessage>\r\n", reply);
      }
      else
      {
        redir_stradd(dst, dstsize,
                     "<ReplyMessage>Radius error</ReplyMessage>\r\n");
      }
      redir_stradd(dst, dstsize, "</AuthenticationPollReply>\r\n");
      break;
    case REDIR_SUCCESS:
      redir_stradd(dst, dstsize, "<AuthenticationPollReply>\r\n");
      redir_stradd(dst, dstsize, "<MessageType>140</MessageType>\r\n");
      redir_stradd(dst, dstsize, "<ResponseCode>50</ResponseCode>\r\n");
      if(reply)
      {
        redir_stradd(dst, dstsize, "<ReplyMessage>%s</ReplyMessage>\r\n", reply);
      }
      redir_stradd(dst, dstsize,
                   "<LogoffURL>http://%s:%d/logoff</LogoffURL>\r\n",
                   inet_ntop(AF_INET, &redir->addr, buf, sizeof(buf)), redir->port);
      if(redirurl)
      {
        redir_stradd(dst, dstsize,
                     "<RedirectionURL>%s</RedirectionURL>\r\n", redirurl);
      }
      redir_stradd(dst, dstsize, "</AuthenticationPollReply>\r\n");
      break;
    case REDIR_LOGOFF:
      redir_stradd(dst, dstsize, "<LogoffReply>\r\n");
      redir_stradd(dst, dstsize, "<MessageType>130</MessageType>\r\n");
      redir_stradd(dst, dstsize, "<ResponseCode>150</ResponseCode>\r\n");
      redir_stradd(dst, dstsize, "</LogoffReply>\r\n");
      break;
    case REDIR_NOTYET:
      redir_stradd(dst, dstsize, "<Redirect>\r\n");
      redir_stradd(dst, dstsize, "<AccessProcedure>1.0</AccessProcedure>\r\n");
      if(redir->radiuslocationid)
      {
        redir_stradd(dst, dstsize,
                     "<AccessLocation>%s</AccessLocation>\r\n",
                     redir->radiuslocationid);
      }
      if(redir->radiuslocationname)
      {
        redir_stradd(dst, dstsize,
                     "<LocationName>%s</LocationName>\r\n",
                     redir->radiuslocationname);
      }

      /* [SV] */
      if(conn->ipv6)
      {
        redir_stradd(dst, dstsize,
                     "<LoginURL>%s?res = smartclient&uamip=[%s]&uamport=%d&challenge=%s</LoginURL>\r\n",
                     redir->url6, inet_ntop(AF_INET6, &conn->ouripv6, buf, sizeof(buf)), redir->port, hexchal);

        printf("<LoginURL>%s?res = smartclient&uamip=[%s]&uamport=%d&challenge=%s</LoginURL>\r\n",
               redir->url6, inet_ntop(AF_INET6, &conn->ouripv6, buf, sizeof(buf)), redir->port, hexchal);
        redir_stradd(dst, dstsize,
                     "<AbortLoginURL>http://[%s]:%d/abort</AbortLoginURL>\r\n",
                     inet_ntop(AF_INET6, &redir->addrv6, buf, sizeof(buf)), redir->port);
      }
      else
      {
        redir_stradd(dst, dstsize,
                     "<LoginURL>%s?res = smartclient&uamip=%s&uamport=%d&challenge=%s</LoginURL>\r\n",
                     redir->url, inet_ntop(AF_INET, &redir->addr, buf, sizeof(buf)), redir->port, hexchal);
        redir_stradd(dst, dstsize,
                     "<AbortLoginURL>http://%s:%d/abort</AbortLoginURL>\r\n",
                     inet_ntop(AF_INET, &redir->addr, buf, sizeof(buf)), redir->port);
      }

      redir_stradd(dst, dstsize, "<MessageType>100</MessageType>\r\n");
      redir_stradd(dst, dstsize, "<ResponseCode>0</ResponseCode>\r\n");
      redir_stradd(dst, dstsize, "</Redirect>\r\n");
      break;
    case REDIR_ABORT_ACK:
      redir_stradd(dst, dstsize, "<AbortLoginReply>\r\n");
      redir_stradd(dst, dstsize, "<MessageType>150</MessageType>\r\n");
      redir_stradd(dst, dstsize, "<ResponseCode>151</ResponseCode>\r\n");
      redir_stradd(dst, dstsize, "</AbortLoginReply>\r\n");
      break;
    case REDIR_ABORT_NAK:
      redir_stradd(dst, dstsize, "<AbortLoginReply>\r\n");
      redir_stradd(dst, dstsize, "<MessageType>150</MessageType>\r\n");
      redir_stradd(dst, dstsize, "<ResponseCode>50</ResponseCode>\r\n");
      redir_stradd(dst, dstsize,
                   "<LogoffURL>http://%s:%d/logoff</LogoffURL>\r\n",
                   inet_ntop(AF_INET, &redir->addr, buf, sizeof(buf)), redir->port);
      redir_stradd(dst, dstsize, "</AbortLoginReply>\r\n");
      break;
    case REDIR_STATUS:
      redir_stradd(dst, dstsize, "<AuthenticationPollReply>\r\n");
      redir_stradd(dst, dstsize, "<MessageType>140</MessageType>\r\n");
      if(conn->authenticated != 1)
      {
        redir_stradd(dst, dstsize, "<ResponseCode>150</ResponseCode>\r\n");
        redir_stradd(dst, dstsize,
                     "<ReplyMessage>Not logged on</ReplyMessage>\r\n");
      }
      else
      {
        redir_stradd(dst, dstsize, "<ResponseCode>50</ResponseCode>\r\n");
        redir_stradd(dst, dstsize,
                     "<ReplyMessage>Already logged on</ReplyMessage>\r\n");
      }
      redir_stradd(dst, dstsize, "</AuthenticationPollReply>\r\n");

      if(conn->authenticated == 1)
      {
        struct timeval timenow;
        uint32_t sessiontime;
        gettimeofday(&timenow, NULL);
        sessiontime = timenow.tv_sec - conn->start_time.tv_sec;
        sessiontime += (timenow.tv_usec - conn->start_time.tv_usec) / 1000000;
        redir_stradd(dst, dstsize, "<SessionStatus>\r\n");
        if(timeleft)
        {
          redir_stradd(dst, dstsize, "<SessionTimeLeft>%d</SessionTimeLeft>\r\n",
                       timeleft);
        }
        redir_stradd(dst, dstsize, "<Acct-Session-Time>%d</Acct-Session-Time>\r\n", sessiontime);
        redir_stradd(dst, dstsize, "<Start-Time>%d</Start-Time>\r\n", conn->start_time);
        redir_stradd(dst, dstsize, "<Acct-Input-Octets>%d</Acct-Input-Octets>\r\n",
                     conn->input_octets);
        redir_stradd(dst, dstsize, "<Acct-Output-Octets>%d</Acct-Output-Octets>\r\n",
                     conn->output_octets);
        redir_stradd(dst, dstsize, "<Session-Timeout>%d</Session-Timeout>\r\n",
                     conn->sessiontimeout);
        redir_stradd(dst, dstsize, "<PepperSpot-Max-Input-Octets>%d</PepperSpot-Max-Input-Octets>\r\n",
                     conn->maxinputoctets);

        redir_stradd(dst, dstsize, "<PepperSpot-Max-Output-Octets>%d</PepperSpot-Max-Output-Octets>\r\n",
                     conn->maxoutputoctets);
        redir_stradd(dst, dstsize, "<PepperSpot-Max-Total-Octets>%d</PepperSpot-Max-Total-Octets>\r\n",
                     conn->maxtotaloctets);
        redir_stradd(dst, dstsize,
                     "<LogoffURL>http://%s:%d/logoff</LogoffURL>\r\n",
                     inet_ntop(AF_INET, &redir->addr, buf, sizeof(buf)), redir->port);
        redir_stradd(dst, dstsize,
                     "<StatusURL>http://%s:%d/status</StatusURL>\r\n",
                     inet_ntop(AF_INET, &redir->addr, buf, sizeof(buf)), redir->port);
        redir_stradd(dst, dstsize, "</SessionStatus>\r\n");
      }
      break;
    default:
      sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Unknown res in switch");
      return -1;
  }

  redir_stradd(dst, dstsize, "</WISPAccessGatewayParam>\r\n");
  redir_stradd(dst, dstsize, "-->\r\n");
  return 0;
}

/**
 * \brief Make an HTTP redirection reply and send it to the client.
 * \param redir redir_t instance
 * \param fd file descriptor to send response
 * \param conn client connection
 * \param res reply state (reject, logoff, ...)
 * \param timeleft session time left
 * \param hexchal challenge number
 * \param uid user ID
 * \param userurl original client wanted webpage
 * \param reply reply message
 * \param redirurl redirection URL
 * \param hismac client MAC address
 * \return 0
 */
static int redir_reply(struct redir_t *redir, int fd,
                       struct redir_conn_t *conn, int res,
                       long int timeleft,
                       char* hexchal, char* uid, char* userurl, char* reply,
                       char* redirurl, uint8_t *hismac)
{
  char buffer[REDIR_MAXBUFFER];
  char xmlreply[REDIR_MAXBUFFER];
  char *resp = NULL;
  char buf[INET6_ADDRSTRLEN];

  buffer[0] = 0;
  xmlreply[0] = 0;

  (void) redir_xmlreply(redir, conn, res, timeleft, hexchal, reply, redirurl,
                        xmlreply, sizeof(xmlreply));

  switch(res)
  {
    case REDIR_ALREADY:
      resp = "already";
      break;
    case REDIR_FAILED_REJECT:
    case REDIR_FAILED_OTHER:
      resp = "failed";
      break;
    case REDIR_SUCCESS:
      resp = "success";
      break;
    case REDIR_LOGOFF:
      resp = "logoff";
      break;
    case REDIR_NOTYET:
      resp = "notyet";
      break;
    case REDIR_ABORT_ACK:
      resp = "logoff";
      break;
    case REDIR_ABORT_NAK:
      resp = "already";
      break;
    case REDIR_ABOUT:
      break;
    case REDIR_STATUS:
      if(conn->authenticated == 1)
        resp = "already";
      else
        resp = "notyet";
      break;
    default:
      sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Unknown res in switch");
      return -1;
  }

  if(resp)
  {
    /* [SV] */
    if(conn->ipv6)
    {
      snprintf(buffer, sizeof(buffer),
               "HTTP/1.0 302 Moved Temporarily\r\n"
               "Location: %s?res=%s&uamip=[%s]&uamport=%d",
               redir->url6, resp, inet_ntop(AF_INET6, &conn->ouripv6, buf, sizeof(buf)), redir->port);
      /* printf("HTTP/1.0 302 Moved Temporarily\r\n"
          "Location: %s?res=%s&uamip=[%s]&uamport=%d",
          redir->url6, resp, inet_ntop(AF_INET6, &conn->ouripv6, buf, sizeof(buf)), redir->port); */
    }
    else
    {
      snprintf(buffer, sizeof(buffer),
               "HTTP/1.0 302 Moved Temporarily\r\n"
               "Location: %s?res=%s&uamip=%s&uamport=%d",
               redir->url, resp, inet_ntop(AF_INET, &redir->addr, buf, sizeof(buf)), redir->port);
    }
    buffer[sizeof(buffer) - 1] = 0;
  }
  else
  {
    snprintf(buffer, sizeof(buffer), "HTTP/1.0 200 OK\r\n");
    buffer[sizeof(buffer) - 1] = 0;
  }

  if(hexchal)
  {
    redir_stradd(buffer, sizeof(buffer), "&challenge=%s", hexchal);
  }

  if(uid)
  {
    char mid2[REDIR_MAXBUFFER];
    mid2[0] = 0;
    (void)redir_urlencode(uid, strlen(uid), mid2, sizeof(mid2));
    redir_stradd(buffer, sizeof(buffer), "&uid=%s", mid2);
  }

  if(timeleft)
  {
    redir_stradd(buffer, sizeof(buffer), "&timeleft=%ld", timeleft);
  }

  if(userurl)
  {
    char mid2[REDIR_MAXBUFFER];
    mid2[0] = 0;
    (void)redir_urlencode(userurl, strlen(userurl), mid2, sizeof(mid2));
    redir_stradd(buffer, sizeof(buffer), "&userurl=%s", mid2);
  }

  if(reply)
  {
    char mid2[REDIR_MAXBUFFER];
    mid2[0] = 0;
    (void)redir_urlencode(reply, strlen(reply), mid2, sizeof(mid2));
    redir_stradd(buffer, sizeof(buffer), "&reply=%s", mid2);
  }

  if(redir->radiusnasid)
  {
    char mid2[REDIR_MAXBUFFER];
    mid2[0] = 0;
    (void)redir_urlencode(redir->radiusnasid, strlen(redir->radiusnasid),
                          mid2, sizeof(mid2));
    redir_stradd(buffer, sizeof(buffer), "&nasid=%s", mid2);
  }

  if(redirurl)
  {
    char mid2[REDIR_MAXBUFFER];
    mid2[0] = 0;
    (void)redir_urlencode(redirurl, strlen(redirurl),
                          mid2, sizeof(mid2));
    redir_stradd(buffer, sizeof(buffer), "&redirurl=%s", mid2);
  }

  if(hismac)
  {
    char mac[REDIR_MACSTRLEN + 1];
    char mid2[REDIR_MAXBUFFER];
    mid2[0] = 0;
    snprintf(mac, REDIR_MACSTRLEN + 1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
             hismac[0], hismac[1],
             hismac[2], hismac[3],
             hismac[4], hismac[5]);
    (void)redir_urlencode(mac, strlen(mac), mid2, sizeof(mid2));
    redir_stradd(buffer, sizeof(buffer), "&mac=%s", mid2);
  }

  redir_stradd(buffer, sizeof(buffer),
               "\r\n"
               "Content-type: text/html"
               "\r\n\r\n"
               "<HTML>\r\n"
               "<HEAD><TITLE>PepperSpot</TITLE></HEAD>");
  redir_stradd(buffer, sizeof(buffer), credits);

  if(resp)
  {
    redir_stradd(buffer, sizeof(buffer),
                 "<BODY><H2>Browser error!</H2>"
                 "Browser does not support redirects!</BODY>\r\n");
    redir_stradd(buffer, sizeof(buffer), xmlreply);
  }
  redir_stradd(buffer, sizeof(buffer), "</HTML>\r\n");

  if(optionsdebug) printf("redir_reply: Sending http reply: %s\n",
                             buffer);

  if(send(fd, buffer, strlen(buffer), 0) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno, "send() failed!");
    return -1;
  }
  return 0;
}

/* Allocate new instance of redir */
int redir_new(struct redir_t **redir,
              struct in_addr *addr, struct in6_addr* addrv6, int port)
{
  struct sockaddr_in address;
  struct sockaddr_in6 addressv6;
  int optval = 1;
  int n = 0;

  if(!(*redir = calloc(1, sizeof(struct redir_t))))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno, "calloc() failed");
    return EOF;
  }

  (*redir)->port = port;
  (*redir)->starttime = 0;
  (*redir)->fdv6 = -1;
  (*redir)->fd = -1;

  if(addr)
  {
    /* Set up address */
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = addr->s_addr;
    address.sin_port = htons(port);
    memset(&address.sin_zero, 0x00, sizeof(address.sin_zero));
#if defined(__FreeBSD__)  || defined (__APPLE__)
    address.sin_len = sizeof(struct sockaddr_in);
#endif
    (*redir)->addr = *addr;

    if(((*redir)->fd  = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "socket() failed");
      return -1;
    }

#if defined(__FreeBSD__)  || defined (__APPLE__)
    /* TODO: FreeBSD */
    if(setsockopt((*redir)->fd, SOL_SOCKET, SO_REUSEPORT,
                   &optval, sizeof(optval)))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "setsockopt() failed");
      close((*redir)->fd);
      return -1;
    }
#endif

    if(setsockopt((*redir)->fd, SOL_SOCKET, SO_REUSEADDR,
                   &optval, sizeof(optval)))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "setsockopt() failed");
      close((*redir)->fd);
      return -1;
    }

    while(bind((*redir)->fd, (struct sockaddr *)&address, sizeof(address)))
    {
      if((EADDRINUSE == errno) && (10 > n++))
      {
        sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
                "UAM port already in use. Waiting for retry.");
        if(sleep(30))   /* In case we got killed */
        {
          close((*redir)->fd);
          return -1;
        }
      }
      else
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, errno, "bind() failed");
        close((*redir)->fd);
        return -1;
      }
    }

    if(listen((*redir)->fd, REDIR_MAXLISTEN))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "listen() failed");
      close((*redir)->fd);
      return -1;
    }

  }

  if(addrv6)
  {
    /* [SV] */
    memset(&addressv6, 0x00, sizeof(struct sockaddr_in6));
    addressv6.sin6_family = AF_INET6;
    memcpy(&addressv6.sin6_addr, addrv6, sizeof(struct in6_addr));
    addressv6.sin6_port = htons(port);
    addressv6.sin6_flowinfo = htonl(1);
    /*addressv6.sin6_scope_id = htons(0);*/
#if defined(__FreeBSD__)  || defined (__APPLE__)
    addressv6.sin6_len = sizeof(struct sockaddr_in6);
#endif

    memcpy(&(*redir)->addrv6, &addressv6.sin6_addr, sizeof(struct in6_addr));

    if(((*redir)->fdv6 = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "socket6() failed");
      return -1;
    }

    if(setsockopt((*redir)->fdv6, SOL_SOCKET, SO_REUSEADDR,
                   &optval, sizeof(optval)))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "setsockopt6() failed");
      close((*redir)->fdv6);
      if((*redir)->fd != -1)
      {
        close((*redir)->fd);
      }
      return -1;
    }

    if(bind((*redir)->fdv6, (struct sockaddr*)&addressv6, sizeof(addressv6))==-1)
    {
      sys_err(LOG_WARNING, __FILE__, __LINE__, errno, "Error bind6().");
      if((*redir)->fd != -1)
      {
        close((*redir)->fd);
      }
      close((*redir)->fdv6);
      return -1;
    }

    if(listen((*redir)->fdv6, REDIR_MAXLISTEN))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "listen6() failed");
      if((*redir)->fd != -1)
      {
        close((*redir)->fd);
      }
      close((*redir)->fdv6);
      return -1;
    }

  }

  if(((*redir)->msgid = msgget(IPC_PRIVATE, 0)) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno, "msgget() failed");
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Most likely your computer does not have System V IPC installed");
    if((*redir)->fd != -1)
    {
      close((*redir)->fd);
    }
    close((*redir)->fdv6);
    return -1;
  }
  return 0;
}

/* Free instance of redir */
int redir_free(struct redir_t *redir)
{
  if(redir->fd != -1)
  {
    if(close(redir->fd))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "close() failed");
    }
  }

  /* [SV] */
  if(redir->fdv6 != -1)
  {
    if(close(redir->fdv6))
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "close6() failed");
    }
  }

  if(msgctl(redir->msgid, IPC_RMID, NULL))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno, "msgctl() failed");
  }

  free(redir);
  return 0;
}

/* Set redir parameters */
void redir_set(struct redir_t *redir, int debug, struct in6_addr *prefix, int prefixlen,
               char *url, char* url6, char *homepage, char* secret,
               struct sockaddr_storage *radiuslisten,
               struct sockaddr_storage *radiusserver0, struct sockaddr_storage *radiusserver1,
               uint16_t radiusauthport, uint16_t radiusacctport,
               char* radiussecret, char* radiusnasid,
               struct sockaddr_storage *radiusnasip, char* radiuscalled,
               char* radiuslocationid, char* radiuslocationname,
               int radiusnasporttype)
{
  optionsdebug = 1; /* TODO: Do not change static variable from instance */

  redir->debug = debug;
  memcpy(&redir->prefix, prefix, prefixlen);
  redir->prefixlen = prefixlen;
  redir->url = url;
  redir->url6 = url6;
  redir->homepage = homepage;
  redir->secret = secret;
  memcpy(&redir->radiuslisten, radiuslisten, sizeof(struct sockaddr_storage));
  redir->radiuslisten.ss_family = radiuslisten->ss_family;
  redir->radiusserver0 = *radiusserver0;
  redir->radiusserver0.ss_family = radiusserver0->ss_family;
  redir->radiusserver1 = *radiusserver1;
  redir->radiusserver1.ss_family = radiusserver1->ss_family;
  redir->radiusauthport = radiusauthport;
  redir->radiusacctport = radiusacctport;
  redir->radiussecret  = radiussecret;
  redir->radiusnasid  = radiusnasid;
  redir->radiusnasip  = *radiusnasip;
  redir->radiuscalled  = radiuscalled;
  redir->radiuslocationid  = radiuslocationid;
  redir->radiuslocationname  = radiuslocationname;
  redir->radiusnasporttype = radiusnasporttype;
  return;
}

/**
 * \brief Get the path of an HTTP request (GET).
 * \param redir redir_t instance
 * \param src request
 * \param dst path will be stored in this variable
 * \param dstsize size of dst
 * \return 0 if success, -1 otherwise
 */
static int redir_getpath(struct redir_t *redir, char *src, char *dst, int dstsize)
{
  char *p1 = NULL;
  char *p2 = NULL;
  char *p3 = NULL;
  char *peol = NULL;
  int dstlen = 0;

  /* To avoid unused parameter warning */
  redir = NULL;

  if(!(peol = strstr(src, "\n"))) /* End of the first line */
    return -1;

  if(!strncmp("GET ", src, 4))
  {
    p1 = src + 4;
  }
  else if(!strncmp("HEAD ", src, 5))
  {
    p1 = src + 5;
  }
  else
  {
    return -1;
  }

  while(*p1 == ' ') p1++; /* Advance through additional white space */

  if(*p1 == '/')
    p1++;
  else
    return -1;

  /* The path ends with a ? or a space */
  p2 = strstr(p1, "?");
  p3 = strstr(p1, " ");

  if((p2 == NULL) && (p3 == NULL))  /* Not found at all */
    return -1;

  if((p2 >= peol) && (p3 >= peol)) /* Not found on first line */
    return -1;

  if(p2 && !p3)
  {
    dstlen = p2 - p1;
  }
  else if(!p2 && p3)
  {
    dstlen = p3 - p1;
  }
  else if(p3 > p2)
    dstlen = p2 - p1;
  else
    dstlen = p3 - p1;

  if(dstlen >= dstsize)
    return -1;

  strncpy(dst, p1, dstlen);
  dst[dstlen] = 0;

  printf("The path is: %s\n", dst);

  return 0;
}

/**
 * \brief Get the url of an HTTP request.
 */
static int redir_geturl(struct redir_t *redir, char *src, char *dst, int dstsize)
{
  char *p1 = NULL;
  char *p3 = NULL;
  char *peol = NULL;
  char *path = NULL;
  int pathlen = 0;
  char *host = NULL;
  int hostlen = 0;

  /* To avoid unused parameter warning */
  redir = NULL;

  dst[0] = 0; /* Null terminate in case of error return */

  if(!(peol = strstr(src, "\r\n"))) /* End of the line */
    return -1;

  /* HTTP Request can be
     GET and HEAD: OK
     POST, PUT, DELETE, TRACE, CONNECT: Not OK
     */

  if(!strncmp("GET ", src, 4))
  {
    p1 = src + 4;
  }
  else if(!strncmp("HEAD ", src, 5))
  {
    p1 = src + 5;
  }
  else
  {
    return -1;
  }

  while(*p1 == ' ') p1++; /* Advance through additional white space */

  p3 = strstr(p1, " ");   /* The path ends with a space */

  if((p3 == NULL) || (p3 >= peol))  /* Not found at all or at first line */
    return -1;

  path = p1;
  pathlen = p3 - p1;

  if(!(p1 = strstr(p3, "\r\nHost:")))
    return -1;

  p1 += 7;
  while(*p1 == ' ') p1++; /* Advance through additional white space */

  if(!(peol = strstr(p1, "\r\n"))) /* End of the line */
    return -1;

  hostlen = peol - p1;
  host = p1;

  if((7 + hostlen + pathlen) >= dstsize)
  {
    return -1;
  }

  strncpy(dst, "http://", 7);
  strncpy(dst + 7, host, hostlen);
  strncpy(dst + 7 + hostlen, path, pathlen);
  dst[7 + hostlen + pathlen] = 0;

  if(optionsdebug) printf("Userurl: %s\n", dst);

  return 0;
}

/**
 * \brief Get a parameter of an HTTP request. Parameter is url decoded.
 * \param redir redir_t instance
 * \param src source buffer
 * \param param parameter name
 * \param dst parameter destination buffer
 * \param dstsize length of dst C-string
 * \return 0 if found, -1 otherwise (not found, malformed HTTP response)
 */
/* TODO: Should be merged with other parsers */
static int redir_getparam(struct redir_t *redir, char *src,
                          char *param,
                          char *dst, int dstsize)
{
  char *p1 = NULL;
  char *p2 = NULL;
  char *p3 = NULL;
  char *peol = NULL;
  char sstr[255];
  int len = 0;

  /* To avoid unused parameter warning */
  redir = NULL;

  printf("Looking for: %s\n", param); /*TODO*/

  if(!(peol = strstr(src, "\n"))) /* End of the first line */
    return -1;

  if(strncmp("GET ", src, 4))
  {
    return -1;
  }

  strncpy(sstr, param, sizeof(sstr));
  sstr[sizeof(sstr) - 1] = 0;
  strncat(sstr, "=", sizeof(sstr));
  sstr[sizeof(sstr) - 1] = 0;

  if(!(p1 = strstr(src, sstr)))
    return -1;

  p1 += strlen(sstr);

  /* The parameter ends with a & or a space */
  p2 = strstr(p1, "&");
  p3 = strstr(p1, " ");

  printf("p1:\n%s\n\np2\n%s\n\np3:%s\n\n", p1, p2, p3);

  if((p2 == NULL) && (p3 == NULL))  /* Not found at all */
    return -1;

  if((p2 >= peol) && (p3 >= peol)) /* Not found on first line */
    return -1;

  if(p2 && !p3)
  {
    len = p2 - p1;
  }
  else if(!p2 && p3)
  {
    len = p3 - p1;
  }
  else if(p3 > p2)
    len = p2 - p1;
  else
    len = p3 - p1;

  (void)redir_urldecode(p1, len, dst, dstsize);

  printf("The parameter is: %s\n", dst);

  return 0;
}

/**
 * \brief Read the an HTTP request from a client.
 * \param redir redir_t instance
 * \param fd file descriptor to read client message
 * \param conn client connection
 * \return 0 if success, -1 otherwise
 */
static int redir_getreq(struct redir_t *redir, int fd, struct redir_conn_t *conn)
{
  int maxfd = 0; /* For select() */
  fd_set fds;  /* For select() */
  struct timeval idleTime; /* How long to select() */
  int status = 0;
  char buffer[REDIR_MAXBUFFER];
  int buflen = 0;
  int recvlen = 0;
  char path[REDIR_MAXBUFFER];
  char resp[REDIR_MAXBUFFER];
  int i = 0;

  maxfd = fd;

  memset(buffer, 0, sizeof(buffer));
  memset(path, 0, sizeof(path));

  /* Read whatever the client send to us */
  while((redir->starttime + REDIR_HTTP_MAX_TIME) > time(NULL))
  {
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    idleTime.tv_sec = 0;
    idleTime.tv_usec = REDIR_HTTP_SELECT_TIME;

    switch(status = select(maxfd + 1, &fds, NULL, NULL, &idleTime))
    {
      case -1:
        sys_err(LOG_ERR, __FILE__, __LINE__, errno,
                "select() returned -1!");
        return -1;
      case 0:
        break;
      default:
        break;
    }

    if((status > 0) && FD_ISSET(fd, &fds))
    {
      if((recvlen =
             recv(fd, buffer + buflen, sizeof(buffer) - 1 - buflen, 0)) < 0)
      {
        if(errno != ECONNRESET)
          sys_err(LOG_ERR, __FILE__, __LINE__, errno, "recv() failed!");
        return -1;
      }
      buflen += recvlen;
      buffer[buflen] = 0;
      if(strstr(buffer, "\n")) break; /* Only interested in first line */
    }
  }

  for(i = 0; i < buflen; i++) if(buffer[i] == 0) buffer[i] = 0x0a; /* TODO: Hack to make Flash work */

  if(buflen <= 0)
  {
    if(optionsdebug) printf("No HTTP request received!\n");
    return -1;
  }

  if(redir_getpath(redir, buffer, path, sizeof(path)))
  {
    if(optionsdebug) printf("Could not parse path!\n");
    return -1;
  }

  if(!redir_getparam(redir, buffer, "userurl",
                      conn->userurl, sizeof(conn->userurl)))
  {
    if(optionsdebug) printf("User URL: %s!\n", conn->userurl);
  }

  if((!strcmp(path, "logon")) || (!strcmp(path, "login")))
  {
    if(redir_getparam(redir, buffer, "username",
                       conn->username, sizeof(conn->username)))
    {
      if(optionsdebug) printf("No username found!\n");
      return -1;
    }

    /* SV */
    /* printf("username = %s\n", conn->username); */

    if(!redir_getparam(redir, buffer, "response",
                        resp, sizeof(resp)))
    {
      (void)redir_hextochar(resp, 2 * REDIR_MD5LEN, conn->chappassword);
      conn->chap = 1;
      conn->password[0] = 0;
    }
    else if(!redir_getparam(redir, buffer, "password",
                             resp, sizeof(resp)))
    {
      int len = strlen(resp);
      len = (len > REDIR_MAXCHAR) ? REDIR_MAXCHAR : len;
      (void)redir_hextochar(resp, len, conn->password);
      conn->passwordlen = len;
      conn->chap = 0;
      conn->chappassword[0] = 0;

    }
    else
    {
      if(optionsdebug) printf("No password found!\n");
      return -1;
    }

    conn->type = REDIR_LOGIN;
    return 0;
  }
  else if((!strcmp(path, "logoff")) || (!strcmp(path, "logout")))
  {
    conn->type = REDIR_LOGOUT;
    return 0;
  }
  else if(!strncmp(path, "msdownload", 10))
  {
    conn->type = REDIR_MSDOWNLOAD;
    return 0;
  }
  else if(!strcmp(path, "prelogin"))
  {
    conn->type = REDIR_PRELOGIN;
    return 0;
  }
  else if(!strcmp(path, "abort"))
  {
    conn->type = REDIR_ABORT;
    return 0;
  }
  else if(!strcmp(path, "about"))
  {
    conn->type = REDIR_ABOUT;
    return 0;
  }
  else if(!strcmp(path, "status"))
  {
    conn->type = REDIR_STATUS;
    return 0;
  }
  else
  {
    if(redir_geturl(redir, buffer, conn->userurl, sizeof(conn->userurl)))
    {
      if(optionsdebug) printf("Could not parse URL!\n");
      return -1;
    }
    return 0;
  }
}

/**
 * \brief Radius callback when access accept/reject/challenge has been received.
 * \param radius radius_t instance
 * \param pack radius packet
 * \param pack_req original radius request packet
 * \param cbp pointer for callback
 * \return 0
 */
static int redir_cb_radius_auth_conf(struct radius_t *radius,
                                     struct radius_packet_t *pack,
                                     struct radius_packet_t *pack_req, void *cbp)
{
  struct radius_attr_t *interimattr = NULL;
  struct radius_attr_t *stateattr = NULL;
  struct radius_attr_t *classattr = NULL;
  struct radius_attr_t *attr = NULL;
  char attrs[RADIUS_ATTR_VLEN + 1];
  struct tm stt;
  int tzhour = 0;
  int tzmin = 0;
  char *tz = NULL;
  int result = 0;
  struct redir_conn_t *conn = (struct redir_conn_t*) cbp;

  /* To avoid unused parameter warning */
  radius = NULL;
  pack_req = NULL;

  if(optionsdebug)
    printf("Received access request confirmation from radius server\n");

  if(!conn)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "No peer protocol defined");
    return 0;
  }

  if(!pack)   /* Timeout */
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Radius request timed out");
    conn->response = REDIR_FAILED_OTHER;
    return 0;
  }

  /* We expect ACCESS-ACCEPT, ACCESS-REJECT (or ACCESS-CHALLENGE) */
  if((pack->code != RADIUS_CODE_ACCESS_REJECT) &&
      (pack->code != RADIUS_CODE_ACCESS_CHALLENGE) &&
      (pack->code != RADIUS_CODE_ACCESS_ACCEPT))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Unknown radius access reply code %d", pack->code);
    conn->response = REDIR_FAILED_OTHER;
    return 0;
  }

  /* Reply message (might be present in both ACCESS-ACCEPT and ACCESS-REJECT */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_REPLY_MESSAGE, 0, 0, 0))
  {
    memcpy(conn->replybuf, attr->v.t, attr->l - 2);
    conn->replybuf[attr->l - 2] = 0;
    conn->reply = conn->replybuf;
  }
  else
  {
    conn->replybuf[0] = 0;
    conn->reply = NULL;
  }

  /* ACCESS-ACCEPT */
  if(pack->code != RADIUS_CODE_ACCESS_ACCEPT)
  {
    conn->response = REDIR_FAILED_REJECT;
    return 0;
  }

  /* Get Service Type */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_SERVICE_TYPE, 0, 0, 0))
  {
    if(ntohl(attr->v.i) == RADIUS_SERVICE_TYPE_PEPPERSPOT_AUTHORIZE_ONLY)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Pepperspot-Authorize-Only Service-Type in Access-Accept");
      conn->response = REDIR_FAILED_REJECT;
      return 0;
    }
  }

  /* State */
  if(!radius_getattr(pack, &stateattr, RADIUS_ATTR_STATE, 0, 0, 0))
  {
    conn->statelen = stateattr->l - 2;
    memcpy(conn->statebuf, stateattr->v.t, stateattr->l - 2);
  }
  else
  {
    conn->statelen = 0;
  }

  /* Class */
  if(!radius_getattr(pack, &classattr, RADIUS_ATTR_CLASS, 0, 0, 0))
  {
    conn->classlen = classattr->l - 2;
    memcpy(conn->classbuf, classattr->v.t, classattr->l - 2);
  }
  else
  {
    conn->classlen = 0;
  }

  /* Session timeout */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_SESSION_TIMEOUT,
                      0, 0, 0))
  {
    conn->sessiontimeout = ntohl(attr->v.i);
  }
  else
  {
    conn->sessiontimeout = 0;
  }

  /* Idle timeout */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_IDLE_TIMEOUT,
                      0, 0, 0))
  {
    conn->idletimeout = ntohl(attr->v.i);
  }
  else
  {
    conn->idletimeout = 0;
  }

  /* Filter ID */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_FILTER_ID,
                      0, 0, 0))
  {
    conn->filteridlen = attr->l - 2;
    memcpy(conn->filteridbuf, attr->v.t, attr->l - 2);
    conn->filteridbuf[attr->l - 2] = 0;
    conn->filterid = conn->filteridbuf;
  }
  else
  {
    conn->filteridlen = 0;
    conn->filteridbuf[0] = 0;
    conn->filterid = NULL;
  }

  /* Interim interval */
  if(!radius_getattr(pack, &interimattr, RADIUS_ATTR_ACCT_INTERIM_INTERVAL,
                      0, 0, 0))
  {
    conn->interim_interval = ntohl(interimattr->v.i);
    if(conn->interim_interval < 60)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "Received too small radius Acct-Interim-Interval value: %d. Disabling interim accounting",
              conn->interim_interval);
      conn->interim_interval = 0;
    }
    else if(conn->interim_interval < 600)
    {
      sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
              "Received small radius Acct-Interim-Interval value: %d",
              conn->interim_interval);
    }
  }
  else
  {
    conn->interim_interval = 0;
  }

  /* Redirection URL */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
                      RADIUS_VENDOR_WISPR,
                      RADIUS_ATTR_WISPR_REDIRECTION_URL, 0))
  {
    conn->redirurllen = attr->l - 2;
    memcpy(conn->redirurlbuf, attr->v.t, attr->l - 2);
    conn->redirurlbuf[attr->l - 2] = 0;
    conn->redirurl = conn->redirurlbuf;
  }
  else
  {
    conn->redirurllen = 0;
    conn->redirurlbuf[0] = 0;
    conn->redirurl = NULL;
  }

  /* Bandwidth up */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
                      RADIUS_VENDOR_WISPR,
                      RADIUS_ATTR_WISPR_BANDWIDTH_MAX_UP, 0))
  {
    conn->bandwidthmaxup = ntohl(attr->v.i);
  }
  else
  {
    conn->bandwidthmaxup = 0;
  }

  /* Bandwidth down */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
                      RADIUS_VENDOR_WISPR,
                      RADIUS_ATTR_WISPR_BANDWIDTH_MAX_DOWN, 0))
  {
    conn->bandwidthmaxdown = ntohl(attr->v.i);
  }
  else
  {
    conn->bandwidthmaxdown = 0;
  }

#ifdef RADIUS_ATTR_PEPPERSPOT_BANDWIDTH_MAX_UP
  /* Bandwidth up */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
                      RADIUS_VENDOR_PEPPERSPOT,
                      RADIUS_ATTR_PEPPERSPOT_BANDWIDTH_MAX_UP, 0))
  {
    conn->bandwidthmaxup = ntohl(attr->v.i) * 1000;
  }
#endif

#ifdef RADIUS_ATTR_PEPPERSPOT_BANDWIDTH_MAX_DOWN
  /* Bandwidth down */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
                      RADIUS_VENDOR_PEPPERSPOT,
                      RADIUS_ATTR_PEPPERSPOT_BANDWIDTH_MAX_DOWN, 0))
  {
    conn->bandwidthmaxdown = ntohl(attr->v.i) * 1000;
  }
#endif

  /* Max input octets */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
                      RADIUS_VENDOR_PEPPERSPOT,
                      RADIUS_ATTR_PEPPERSPOT_MAX_INPUT_OCTETS, 0))
  {
    conn->maxinputoctets = ntohl(attr->v.i);
  }
  else
  {
    conn->maxinputoctets = 0;
  }

  /* Max output octets */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
                      RADIUS_VENDOR_PEPPERSPOT,
                      RADIUS_ATTR_PEPPERSPOT_MAX_OUTPUT_OCTETS, 0))
  {
    conn->maxoutputoctets = ntohl(attr->v.i);
  }
  else
  {
    conn->maxoutputoctets = 0;
  }

  /* Max total octets */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
                      RADIUS_VENDOR_PEPPERSPOT,
                      RADIUS_ATTR_PEPPERSPOT_MAX_TOTAL_OCTETS, 0))
  {
    conn->maxtotaloctets = ntohl(attr->v.i);
  }
  else
  {
    conn->maxtotaloctets = 0;
  }

  /* Session-Terminate-Time */
  if(!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
                      RADIUS_VENDOR_WISPR,
                      RADIUS_ATTR_WISPR_SESSION_TERMINATE_TIME, 0))
  {
    struct timeval timenow;
    gettimeofday(&timenow, NULL);
    memcpy(attrs, attr->v.t, attr->l - 2);
    attrs[attr->l - 2] = 0;
    memset(&stt, 0, sizeof(stt));
    result = sscanf(attrs, "%d-%d-%dT%d:%d:%d %d:%d",
                    &stt.tm_year, &stt.tm_mon, &stt.tm_mday,
                    &stt.tm_hour, &stt.tm_min, &stt.tm_sec,
                    &tzhour, &tzmin);
    if(result == 8)   /* Timezone */
    {
      /* tzhour and tzmin is hours and minutes east of GMT */
      /* timezone is defined as seconds west of GMT. Excludes DST */
      stt.tm_year -= 1900;
      stt.tm_mon  -= 1;
      stt.tm_hour -= tzhour; /* Adjust for timezone */
      stt.tm_min  -= tzmin;  /* Adjust for timezone */
      /*      stt.tm_hour += daylight;*/
      /*stt.tm_min  -= (timezone / 60);*/
      tz = getenv("TZ");
      setenv("TZ", "", 1); /* Set environment to UTC */
      tzset();
      conn->sessionterminatetime = mktime(&stt);
      if(tz)
        setenv("TZ", tz, 1);
      else
        unsetenv("TZ");
      tzset();
    }
    else if(result >= 6)   /* Local time */
    {
      tzset();
      stt.tm_year -= 1900;
      stt.tm_mon  -= 1;
      stt.tm_isdst = -1; /*daylight;*/
      conn->sessionterminatetime = mktime(&stt);
    }
    else
    {
      conn->sessionterminatetime = 0;
      sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
              "Illegal WISPr-Session-Terminate-Time received: %s", attrs);
    }
    if((conn->sessionterminatetime) &&
        (timenow.tv_sec > conn->sessionterminatetime))
    {
      conn->response = REDIR_FAILED_OTHER;
      sys_err(LOG_WARNING, __FILE__, __LINE__, 0,
              "WISPr-Session-Terminate-Time in the past received: %s", attrs);
      return 0;
    }
  }
  else
  {
    conn->sessionterminatetime = 0;
  }

  conn->response = REDIR_SUCCESS;
  return 0;
}

/**
 * \brief Send radius Access-Request and wait for answer.
 * \param redir redir_t instance
 * \param addr peer address
 * \param conn redir connection
 * \return 0 if success, -1 otherwise
 */
static int redir_radius(struct redir_t *redir, struct sockaddr_storage *addr,
                        struct redir_conn_t *conn)
{
  struct radius_t *radius = NULL;      /* Radius client instance */
  struct radius_packet_t radius_pack;
  int maxfd = 0;          /* For select() */
  fd_set fds;      /* For select() */
  struct timeval idleTime;  /* How long to select() */
  int status = 0;
  unsigned char chap_password[REDIR_MD5LEN + 1];
  unsigned char chap_challenge[REDIR_MD5LEN];
  unsigned char user_password[REDIR_MAXCHAR + 1];
  uint64_t suf = 0;
  struct in6_addr idv6;
  char buf[INET6_ADDRSTRLEN];

  MD5_CTX context;

  char mac[REDIR_MACSTRLEN + 1];
  char url[REDIR_URL_LEN];
  int n = 0;

  /* To avoid unused parameter warning */
  addr = NULL;

  if(radius_new(&radius,
                 &redir->radiuslisten, 0, 0,
                 NULL, 0, NULL, NULL, NULL))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
            "Failed to create radius");
    return -1;
  }

  if(radius->fd > maxfd)
    maxfd = radius->fd;

  radius_set(radius, 1,
             &redir->radiusserver0, &redir->radiusserver1,
             redir->radiusauthport, redir->radiusacctport,
             redir->radiussecret);

  radius_set_cb_auth_conf(radius, redir_cb_radius_auth_conf);

  radius_default_pack(radius, &radius_pack, RADIUS_CODE_ACCESS_REQUEST);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_NAME, 0, 0, 0,
                 (uint8_t*) conn->username, strlen(conn->username));

  if(conn->chap == 0)
  {
    int i = 0;
    char buff[2 * REDIR_MAXCHAR + 1];
    int nbSeg = conn->passwordlen / 2 / REDIR_MD5LEN;

    if(optionsdebug) printf("NSEG: %d\n", nbSeg);
    uint8_t* binCipher = conn->uamchal;

    if(optionsdebug)
    {
        redir_chartohex(binCipher, REDIR_MD5LEN, buff);
        printf("C(%d): [%s]\n", 0, buff);
    }

    memset(user_password, 0, REDIR_MAXCHAR + 1);
    for(i = 0 ; i < nbSeg ; i++)
    {
        MD5Init(&context);
        MD5Update(&context, binCipher, REDIR_MD5LEN);
        MD5Update(&context, (uint8_t*)redir->secret, strlen(redir->secret));
        MD5Final(chap_challenge, &context);

        if(optionsdebug)
        {
            redir_chartohex(chap_challenge, REDIR_MD5LEN, buff);
            printf("H(%d): [%s]\n", i, buff);
        }

        binCipher = &(conn->password[i * REDIR_MD5LEN]);
        
        if(optionsdebug)
        {
            redir_chartohex(binCipher, REDIR_MD5LEN, buff);
            printf("C(%d): [%s]\n", i + 1, buff);
        }
        
        for(n = 0 ; n < REDIR_MD5LEN ; n++)
        {
            user_password[i * REDIR_MD5LEN + n] = binCipher[n] ^ chap_challenge[n];
        }

        if(optionsdebug)
        {
            redir_chartohex(&user_password[i * REDIR_MD5LEN], REDIR_MD5LEN, buff);
            printf("P(%d): [%s]\n", i, buff);
        }
    }
    
    if(optionsdebug)
    {
        redir_chartohex(user_password, nbSeg * REDIR_MD5LEN, buff);
        printf("PWD: [%s]\n", buff);
        printf("PWD: [%s]\n", user_password);
    }
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_PASSWORD, 0, 0, 0,
                   user_password, strlen((char*)user_password));
  }
  else if(conn->chap == 1)
  {
    memcpy(chap_challenge, conn->uamchal, REDIR_MD5LEN);
    chap_password[0] = 0; /* Chap ident */
    memcpy(chap_password + 1, conn->chappassword, REDIR_MD5LEN);
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_CHAP_CHALLENGE, 0, 0, 0,
                   chap_challenge, REDIR_MD5LEN);
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_CHAP_PASSWORD, 0, 0, 0,
                   chap_password, REDIR_MD5LEN + 1);
  }

  if(redir->radiuslisten.ss_family == AF_INET)
  {
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_IP_ADDRESS, 0, 0,
                   ntohl(((struct sockaddr_in *)&redir->radiusnasip)->sin_addr.s_addr), NULL, 0); /* WISPr_V1.0 */
  }
  else
  {
    radius_addattrv6(radius, &radius_pack, RADIUS_ATTR_NAS_IPV6_ADDRESS, 0, 0,
                     ((struct sockaddr_in6 *)&redir->radiusnasip)->sin6_addr, NULL, 0); /* WISPr_V1.0 */
  }

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_SERVICE_TYPE, 0, 0,
                 RADIUS_SERVICE_TYPE_LOGIN, NULL, 0); /* WISPr_V1.0 */

  if(!conn->ipv6)
  {
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_FRAMED_IP_ADDRESS, 0, 0,
                          ntohl(conn->hisip.s_addr), NULL, 0);
  }
  else
  {
    (void) radius_addattrv6(radius, &radius_pack, RADIUS_ATTR_FRAMED_IPV6_PREFIX, 0, 0,
                            redir->prefix, NULL, redir->prefixlen + 2);
    /* todo: interface id */

    ippool_getv6suffix(&idv6, &conn->hisipv6, 64);

    suf = ((uint32_t*)idv6.s6_addr)[3];
    suf <<= 32;
    suf |= ((uint32_t*)idv6.s6_addr)[2];

    memcpy(idv6.s6_addr, (void *)&suf, 8);

    (void) radius_addattrv6(radius, &radius_pack, RADIUS_ATTR_FRAMED_INTERFACE_ID, 0, 0, idv6, NULL, 8);
  }

  /* Include his MAC address */
  snprintf(mac, REDIR_MACSTRLEN + 1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
           conn->hismac[0], conn->hismac[1],
           conn->hismac[2], conn->hismac[3],
           conn->hismac[4], conn->hismac[5]);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLING_STATION_ID, 0, 0, 0,
                 (uint8_t*) mac, REDIR_MACSTRLEN);

  if(redir->radiuscalled)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLED_STATION_ID, 0, 0, 0,
                   (uint8_t*) redir->radiuscalled, strlen(redir->radiuscalled)); /* WISPr_V1.0 */

  if(redir->radiusnasid)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_IDENTIFIER, 0, 0, 0,
                   (uint8_t*) redir->radiusnasid,
                   strlen(redir->radiusnasid)); /* WISPr_V1.0 */

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_SESSION_ID, 0, 0, 0,
                 (uint8_t*) conn->sessionid, REDIR_SESSIONID_LEN - 1);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_TYPE, 0, 0,
                 redir->radiusnasporttype, NULL, 0);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT, 0, 0,
                 conn->nasport, NULL, 0);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_MESSAGE_AUTHENTICATOR,
                 0, 0, 0, NULL, RADIUS_MD5LEN);

  if(redir->radiuslocationid)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
                   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_ID, 0,
                   (uint8_t*) redir->radiuslocationid,
                   strlen(redir->radiuslocationid));

  if(redir->radiuslocationname)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
                   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_NAME, 0,
                   (uint8_t*) redir->radiuslocationname,
                   strlen(redir->radiuslocationname));

  if(!conn->ipv6)
  {
    snprintf(url, REDIR_URL_LEN - 1, "http://%s:%d/logoff",
             inet_ntop(AF_INET, &redir->addr, buf, sizeof(buf)), redir->port);
    url[REDIR_URL_LEN - 1] = 0;
  }
  else
  {
    snprintf(url, REDIR_URL_LEN - 1, "http://[%s]:%d/logoff",
             inet_ntop(AF_INET6, &redir->addrv6, buf, sizeof(buf)), redir->port);
    url[REDIR_URL_LEN - 1] = 0;
  }

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
                 RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOGOFF_URL, 0,
                 (uint8_t*) url, strlen(url));

  radius_req(radius, &radius_pack, conn);

  while((redir->starttime + REDIR_RADIUS_MAX_TIME) > time(NULL))
  {
    FD_ZERO(&fds);
    if(radius->fd != -1) FD_SET(radius->fd, &fds);
    if(radius->proxyfd != -1) FD_SET(radius->proxyfd, &fds);

    idleTime.tv_sec = 0;
    idleTime.tv_usec = REDIR_RADIUS_SELECT_TIME;
    radius_timeleft(radius, &idleTime);

    switch(status = select(maxfd + 1, &fds, NULL, NULL, &idleTime))
    {
      case -1:
        sys_err(LOG_ERR, __FILE__, __LINE__, errno,
                "select() returned -1!");
        break;
      case 0:
        if(optionsdebug) printf("Select returned 0\n");
        radius_timeout(radius);
        break;
      default:
        break;
    }

    if(status > 0)
    {
      if((radius->fd != -1) && FD_ISSET(radius->fd, &fds) &&
          radius_decaps(radius) < 0)
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, 0,
                "radius_ind() failed!");
      }

      if((radius->proxyfd != -1) && FD_ISSET(radius->proxyfd, &fds) &&
          radius_proxy_ind(radius) < 0)
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, 0,
                "radius_proxy_ind() failed!");
      }

    }

    if(conn->response)
    {
      radius_free(radius);
      return 0;
    }
  }
  return 0;
}

/**
 * \brief Close of socket.
 * \param new_socket socket to close
 */
static void redir_close(int new_socket)
{
  if(!keep_going) shutdown(new_socket, SHUT_RDWR);
  close(new_socket);
  return;
}

/**
 * \brief Copy client information into message (to send to pepper process).
 * \param msg_type type of message
 * \param challenge challenge number
 * \param hexchal challenge in hex format
 * \param msg will be filled with information
 * \param address IPv4 address
 * \param addressv6 IPv6 address
 * \param addrstorage to see if client use IPv6 connection
 */
static void redir_memcopy(int msg_type, unsigned char *challenge, char *hexchal, struct redir_msg_t *msg, struct sockaddr_in address, struct sockaddr_in6 addressv6, struct sockaddr_storage addrstorage)
{
  redir_challenge(challenge);
  (void)redir_chartohex(challenge, REDIR_MD5LEN, hexchal);
  msg->type = msg_type;
  msg->addr = address.sin_addr;
  memcpy(&msg->addrv6, &addressv6.sin6_addr, sizeof(struct in6_addr));
  msg->ipv6 = (addrstorage.ss_family == AF_INET6);
  /* [SV] TODO */
  memcpy(&msg->uamchal, challenge, REDIR_MD5LEN);
  return;
}

int redir_accept(struct redir_t *redir, int ipv6)
{
  int new_socket = -1;
  struct sockaddr_in address;
  /* [SV] */
  struct sockaddr_in6 addressv6;
  struct sockaddr_storage addrstorage;
  int addrlen = sizeof(addrstorage);

  int bufsize = REDIR_MAXBUFFER;
  char buffer[bufsize];
  int buflen = 0;
  int status = 0;
  char hexchal[1 + (2 * REDIR_MD5LEN)];
  unsigned char challenge[REDIR_MD5LEN];
  struct redir_msg_t msg;
  int state = 0;

  struct redir_conn_t conn;

  struct sigaction act, oldact;
  struct itimerval itval;

  memset(&conn, 0, sizeof(conn));
  memset(&msg, 0, sizeof(msg));

  if((new_socket = accept((ipv6 ? redir->fdv6 : redir->fd), (struct sockaddr *)&addrstorage,
                           (socklen_t*) &addrlen))
      < 0)
  {
    if(errno != ECONNABORTED && errno != EINTR)
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "accept() failed!");
    return 0;
  }

  memcpy(&address, (struct sockaddr_in*)&addrstorage, sizeof(struct sockaddr_in));
  memcpy(&addressv6, (struct sockaddr_in6*)&addrstorage, sizeof(struct sockaddr_in6));

  /* This forks a new process. The child really should close all
     unused file descriptors and free memory allocated. This however
     is performed when the process exits, so currently we don't
     care */

  if((status = fork()) < 0)
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "fork() returned -1!");
    return 0;
  }

  if(status > 0)   /* Parent */
  {
    close(new_socket);
    return 0;
  }

  memset(&act, 0, sizeof(act));
  act.sa_handler = redir_sig_handler;
  sigaction(SIGTERM, &act, &oldact);
  sigaction(SIGINT, &act, &oldact);
  sigaction(SIGALRM, &act, &oldact);

  memset(&itval, 0, sizeof(itval));
  itval.it_interval.tv_sec = REDIR_MAXTIME;
  itval.it_interval.tv_usec = 0;
  itval.it_value.tv_sec = REDIR_MAXTIME;
  itval.it_value.tv_usec = 0;
  if(setitimer(ITIMER_REAL, &itval, NULL))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
            "setitimer() failed!");
  }

  redir->starttime = time(NULL);

  if(fcntl(new_socket, F_SETFL, O_NONBLOCK))
  {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno, "fcntl() failed");
    exit(0);
  }

  termstate = REDIR_TERM_GETREQ;
  if(optionsdebug) printf("Calling redir_getreq()\n");

  if(redir_getreq(redir, new_socket, &conn))
  {
    if(optionsdebug) printf("Error calling get_req. Terminating\n");
    exit(0);
  }

  termstate = REDIR_TERM_GETSTATE;
  if(optionsdebug) printf("Calling cb_getstate()\n");

  if(addrstorage.ss_family == AF_INET)
  {
    msg.ipv6 = 0;
    if(!redir->cb_getstate)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0,
              "No cb_getstate() defined!");
      exit(0);
    }
    state = redir->cb_getstate(redir, &address.sin_addr, &conn);
  }
  else if(addrstorage.ss_family == AF_INET6)
  {
    msg.ipv6 = 1;
    if(!redir->cb_getstatev6)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, 0, "No cb_getstate6() defined!");
      exit(0);
    }
    memcpy(&msg.addrv6, &addressv6.sin6_addr, sizeof(struct in6_addr));
    state = redir->cb_getstatev6(redir, &addressv6.sin6_addr, &conn);

    printf("redir_accept IPv6!\n");
  }

  termstate = REDIR_TERM_PROCESS;
  if(optionsdebug) printf("Processing received request\n");

  if(conn.type == REDIR_LOGIN)
  {
    /* Was client was already logged on? */
    if(state == 1)
    {
      if(optionsdebug) printf("redir_accept: Already logged on\n");
      redir_reply(redir, new_socket, &conn, REDIR_ALREADY, 0,
                  NULL, NULL, conn.userurl, NULL,
                  NULL, conn.hismac);
      redir_close(new_socket);
      exit(0);
    }

    /* Did the challenge expire? */
    if((conn.uamtime + REDIR_CHALLENGETIMEOUT2) < time(NULL))
    {
      if(optionsdebug) printf("redir_accept: Challenge expired: %d : %d\n",
                                 conn.uamtime, time(NULL));
      redir_memcopy(REDIR_CHALLENGE, challenge, hexchal, &msg, address, addressv6, addrstorage);
      if(msgsnd(redir->msgid, &msg, sizeof(struct redir_msg_t) - sizeof(msg.type), 0) < 0)
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, errno, "msgsnd() failed!");
        exit(0);
      }

      redir_reply(redir, new_socket, &conn, REDIR_FAILED_OTHER, 0,
                  hexchal, NULL, conn.userurl, NULL,
                  NULL, conn.hismac);
      redir_close(new_socket);
      exit(0);
    }

    termstate = REDIR_TERM_RADIUS;
    if(optionsdebug) printf("Calling radius\n");

    if(optionsdebug) printf("redir_accept: Sending radius request\n");
    redir_radius(redir, &addrstorage, &conn);

    termstate = REDIR_TERM_REPLY;
    if(optionsdebug) printf("Received radius reply\n");

    if(conn.response == REDIR_SUCCESS)   /* Radius-Accept */
    {
      redir_reply(redir, new_socket, &conn, conn.response, conn.sessiontimeout,
                  NULL, conn.username, conn.userurl, conn.reply,
                  conn.redirurl, conn.hismac);

      msg.type = REDIR_LOGIN;
      strncpy(msg.username, conn.username, sizeof(msg.username));
      msg.username[sizeof(msg.username) - 1] = 0;
      msg.statelen = conn.statelen;
      memcpy(msg.statebuf, conn.statebuf, conn.statelen);
      msg.classlen = conn.classlen;
      memcpy(msg.classbuf, conn.classbuf, conn.classlen);
      msg.sessiontimeout = conn.sessiontimeout;
      msg.idletimeout = conn.idletimeout;
      msg.interim_interval = conn.interim_interval;
      msg.addr = address.sin_addr;
      msg.bandwidthmaxup = conn.bandwidthmaxup;
      msg.bandwidthmaxdown = conn.bandwidthmaxdown;
      msg.maxinputoctets = conn.maxinputoctets;
      msg.maxoutputoctets = conn.maxoutputoctets;
      msg.maxtotaloctets = conn.maxtotaloctets;
      msg.sessionterminatetime = conn.sessionterminatetime;
      msg.filteridlen = conn.filteridlen;
      strncpy(msg.filteridbuf, conn.filteridbuf, sizeof(msg.filteridbuf));

      if(msgsnd(redir->msgid, &msg, sizeof(struct redir_msg_t) - sizeof(msg.type), 0) < 0)
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, errno, "msgsnd() failed!");
        exit(0);
      }
    }
    else
    {
      redir_memcopy(REDIR_CHALLENGE, challenge, hexchal, &msg, address, addressv6, addrstorage);
      if(msgsnd(redir->msgid, &msg,
                 sizeof(struct redir_msg_t) - sizeof(msg.type), 0) < 0)
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, errno, "msgsnd() failed!");
        exit(0);
      }

      redir_reply(redir, new_socket, &conn, conn.response, 0,
                  hexchal, NULL, conn.userurl, conn.reply,
                  NULL, conn.hismac);
      redir_close(new_socket);
      exit(0);
    }

    redir_close(new_socket);
    exit(0); /* Terminate the client */
  }
  else if(conn.type == REDIR_LOGOUT)
  {
    redir_memcopy(REDIR_LOGOUT, challenge, hexchal, &msg, address, addressv6, addrstorage);
    if(msgsnd(redir->msgid, &msg,
               sizeof(struct redir_msg_t) - sizeof(msg.type), 0) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "msgsnd() failed!");
      exit(0);
    }

    redir_reply(redir, new_socket, &conn, REDIR_LOGOFF, 0,
                hexchal, NULL, conn.userurl, NULL,
                NULL, conn.hismac);
    redir_close(new_socket);
    exit(0); /* Terminate the client */
  }
  else if(conn.type == REDIR_PRELOGIN)
  {
    redir_memcopy(REDIR_CHALLENGE, challenge, hexchal, &msg, address, addressv6, addrstorage);
    if(msgsnd(redir->msgid, &msg, sizeof(struct redir_msg_t) - sizeof(msg.type), 0) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "msgsnd() failed!");
      exit(0);
    }

    if(state == 1)
    {
      redir_reply(redir, new_socket, &conn, REDIR_ALREADY, 0,
                  NULL, NULL, conn.userurl, NULL,
                  NULL, conn.hismac);
    }
    else
    {
      redir_reply(redir, new_socket, &conn, REDIR_NOTYET, 0,
                  hexchal, NULL, conn.userurl, NULL,
                  NULL, conn.hismac);
    }
    redir_close(new_socket);
    exit(0);
  }
  else if(conn.type == REDIR_ABORT)
  {
    if(state == 1)
    {
      redir_reply(redir, new_socket, &conn, REDIR_ABORT_NAK, 0,
                  NULL, NULL, conn.userurl, NULL,
                  NULL, conn.hismac);
    }
    else
    {
      redir_memcopy(REDIR_ABORT, challenge, hexchal, &msg, address, addressv6, addrstorage);
      if(msgsnd(redir->msgid, &msg, sizeof(struct redir_msg_t) - sizeof(msg.type), 0) < 0)
      {
        sys_err(LOG_ERR, __FILE__, __LINE__, errno, "msgsnd() failed!");
        exit(0);
      }
      redir_reply(redir, new_socket, &conn, REDIR_ABORT_ACK, 0,
                  hexchal, NULL, conn.userurl, NULL,
                  NULL, conn.hismac);
    }
    redir_close(new_socket);
    exit(0);
  }
  else if(conn.type == REDIR_ABOUT)
  {
    redir_reply(redir, new_socket, &conn, REDIR_ABOUT, 0,
                NULL, NULL, NULL, NULL,
                NULL, NULL);
    redir_close(new_socket);
    exit(0);
  }
  else if(conn.type == REDIR_STATUS)
  {
    struct timeval timenow;
    uint32_t sessiontime;
    uint32_t timeleft;
    gettimeofday(&timenow, NULL);
    sessiontime = timenow.tv_sec - conn.start_time.tv_sec;
    sessiontime += (timenow.tv_usec - conn.start_time.tv_usec) / 1000000;
    if(conn.sessiontimeout)
      timeleft = conn.sessiontimeout - sessiontime;
    else
      timeleft = 0;
    redir_reply(redir, new_socket, &conn, REDIR_STATUS, timeleft,
                NULL, NULL, NULL, NULL,
                NULL, NULL);
    redir_close(new_socket);
    exit(0);
  }
  else if(conn.type == REDIR_MSDOWNLOAD)
  {
    buflen = snprintf(buffer, bufsize,
                      "HTTP/1.0 403 Forbidden\r\n\r\n");

    send(new_socket, buffer, buflen, 0);

    redir_close(new_socket);
    exit(0);
  }

  /* It was not a request for a known path. It must be an original request */

  if(optionsdebug) printf("redir_accept: Original request\n");

  /* Did the challenge expire? */
  if((conn.uamtime + REDIR_CHALLENGETIMEOUT1) < time(NULL))
  {
    redir_memcopy(REDIR_CHALLENGE, challenge, hexchal, &msg, address, addressv6, addrstorage);
    strncpy(msg.userurl, conn.userurl, sizeof(msg.userurl));
    msg.userurl[sizeof(msg.userurl) - 1] = 0;
    if(msgsnd(redir->msgid, &msg,
               sizeof(struct redir_msg_t) - sizeof(msg.type), 0) < 0)
    {
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "msgsnd() failed!");
      exit(0);
    }
  }
  else
  {
    (void)redir_chartohex(conn.uamchal, REDIR_MD5LEN, hexchal);
  }

  if(redir->homepage)
  {
    buflen = snprintf(buffer, bufsize,
                      "HTTP/1.0 302 Moved Temporarily\r\n"
                      "Location: "
                      "%s\r\n"
                      "Content-type: text/html"
                      "\r\n\r\n"
                      "<HTML>"
                      "<HEAD><TITLE>302 Moved Temporarily</TITLE></HEAD>"
                      "<BODY><H1>Browser error!</H1>"
                      "Browser does not support redirects!</BODY></HTML>",
                      redir->homepage);
    buffer[bufsize - 1] = 0;
    if(buflen>bufsize) buflen = bufsize;

    if(optionsdebug) printf("redir_reply: Sending http reply: %s\n",
                               buffer);

    send(new_socket, buffer, buflen, 0);
  }
  else if(state == 1)
  {
    redir_reply(redir, new_socket, &conn, REDIR_ALREADY, 0,
                NULL, NULL, conn.userurl, NULL,
                NULL, conn.hismac);
  }
  else
  {
    redir_reply(redir, new_socket, &conn, REDIR_NOTYET, 0,
                hexchal, NULL, conn.userurl, NULL,
                NULL, conn.hismac);
  }

  redir_close(new_socket);
  exit(0);

  /*  close(redir->fd);*/
}

int redir_set_cb_getstatev6(struct redir_t* redir, int (*cb_getstatev6)(struct redir_t* redir, struct in6_addr* addr, struct redir_conn_t* conn))
{
  redir->cb_getstatev6 = cb_getstatev6;
  return 0;
}

/* Set callback to determine state information for the connection */
int redir_set_cb_getstate(struct redir_t *redir,
                          int (*cb_getstate) (struct redir_t *redir, struct in_addr *addr,
                                              struct redir_conn_t *conn))
{
  redir->cb_getstate = cb_getstate;
  return 0;
}

