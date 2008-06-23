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
 * tun6.h - IPv6 tunnel interface declaration
 * $Id: tun6.h 1552 2006-07-04 15:38:38Z remi $
 */

/***********************************************************************
 *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license.         *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               *
 *  See the GNU General Public License for more details.               *
 *                                                                     *
 *  You should have received a copy of the GNU General Public License  *
 *  along with this program; if not, you can get it from:              *
 *  http://www.gnu.org/copyleft/gpl.html                               *
 ***********************************************************************/

#ifndef LIBTUN6_TUN6_H
# define LIBTUN6_TUN6_H

# include <stddef.h> /* NULL */
# include <sys/types.h>
# include <sys/select.h>

#include <net/if.h>
#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE
#endif

# define LIBTUN6_ERRBUF_SIZE 4096

# if __STDC_VERSION__ < 199901L
#  ifndef inline
#   define inline
#  endif
#  ifndef restrict
#   define restrict
#  endif
# endif

# ifdef __GNUC__
#  define LIBTUN6_NONNULL __attribute__ ((nonnull))
#  if __GNUC__ >= 3
#   define LIBTUN6_PURE __attribute__ ((pure))
#  else
#   define LIBTUN6_PURE
#  endif
#  if __GNUC__ >= 4
#   define LIBTUN6_WARN_UNUSED __attribute__ ((warn_unused_result))
#  else
#   define LIBTUN6_WARN_UNUSED
#  endif
# else
#  define LIBTUN6_NONNULL
#  define LIBTUN6_WARN_UNUSED
#  define LIBTUN6_PURE
# endif

struct ip6_hdr;
struct in6_addr;

typedef struct tun6 tun6;

/* [SV] : do similar struct as tun.h 
 * in two word : makes wrapper for the libtun6
 * that match function name of tun.h.
 */

/**
 * \struct tun6_packet_t
 * \brief Destribe a IPv6 packet.
 * \author Sebastien Vincent
 */
struct tun6_packet_t
{
  uint32_t version:4;
  uint32_t class:8;
  uint32_t flow_label:20;
  uint16_t payload_length;
  uint8_t next_header;
  uint8_t hop_limit;
  uint8_t src_addr[16];
  uint8_t dst_addr[16];
};

/**
 * \struct tun6_t 
 * \brief tun6_t interface information.
 * \author Sebastien Vincent
 */
typedef struct tun6_t
{
  int fdv6; /**< File descriptor to IPv6 tun interface */
  int ifindex; /**< Interface index */
  struct in6_addr addrv6; /**< Our IPv6 address */
  uint8_t prefixlen; /**< Prefix length of the IPv6 address (64 by default) */
  int addrsv6;             /**< Number of allocated IP addresses */
  int routesv6;            /**< One if we allocated an automatic route */
  char devnamev6[IFNAMSIZ]; /**< Name of the IPv6 tun device */
  int (*cb_indv6)(struct tun6_t* tun, void* pack, unsigned len); /**< Callback when receiving IPv6 packet */
  struct tun6* device; /**< The tun6 device */
}tun6_t;

/**
 * \brief Create a tun6_t instance
 * \param tun a pointer on a pointer of tun6_t
 * \return 0 if success, -1 otherwise
 * \author Sebastien Vincent
 */
int tun6_new(struct tun6_t** tun);

/**
 * \brief Free the ressource associated with the tun6_t instance
 * \param tun the tun6_t instance
 * \return 0 if success, -1 otherwis
 * \author Sebastien Vincent
 */
int tun6_free(struct tun6_t *tun);

/**
 * \brief Decapsulate a packet.
 * \param this the tun6_t instance
 * \return number of bytes readen or -1 if error
 * \author Sebastien Vincent
 */
int tun6_decaps(struct tun6_t *this);

/**
 * \brief Encapsulate a packet.
 * \param tun the tun6_t instance
 * \param pack the packet to encapsulate
 * \param len length of the packet
 * \return number of bytes written or -1 if error
 * \author Sebastien Vincent
 */
int tun6_encaps(struct tun6_t *tun, void *pack, unsigned len);


/**
 * \brief Set an IPv6 address on the interface.
 * \param this the tun6_t instance
 * \param addr IPv6 address to set
 * \param prefixlen prefix length of the address
 * \return 0 if success, -1 otherwise
 * \author Sebastien Vincent
 */
int tun6_setaddr(struct tun6_t *this, struct in6_addr *addr, uint8_t prefixlen);

/**
 * \brief Set an IPv6 route on the interface.
 * \param this the tun6_t instance
 * \param dst destnation IPv6 address
 * \param gateway gateway for IPv6 destination
 * \param prefixlen prefix length of the address
 * \return 0 if success, -1 otherwise
 * \author Sebastien Vincent
 */ 
int tun6_addroute(struct tun6_t *this, struct in6_addr *dst, struct in6_addr *gateway, uint8_t prefixlen);

/**
 * \brief Set an IPv6 address on the interface.
 * \param this the tun6_t instance
 * \param cb_ind callbacl when receiving packet
 * \return 0 if success, -1 otherwise
 * \author Sebastien Vincent
 */ 
int tun6_set_cb_ind(struct tun6_t *this, int (*cb_ind) (struct tun6_t *tun, void *pack, unsigned len));


/**
 * \brief Set an IPv6 address on the interface.
 * \param tun the tun6_t instance
 * \param script path of the script
 * \return 0 if success, -1 otherwise
 * \author Sebastien Vincent
 */ 
int tun6_runscript(struct tun6_t *tun, char* script);

int tun6_sifflags(struct tun6_t *this, int flags);

# ifdef __cplusplus
extern "C" {
# endif
int tun6_driver_diagnose (char *errbuf) LIBTUN6_NONNULL;

/*
 * All functions are thread-safe.
 *
 * All functions reports error messages via syslog(). You should hence call
 * openlog() before you create a tunnel.
 */

tun6 *tun6_create (const char *req_name) LIBTUN6_WARN_UNUSED;
void tun6_destroy (tun6 *t) LIBTUN6_NONNULL;

int tun6_getId (const tun6 *t) LIBTUN6_NONNULL;

int tun6_setState (tun6 *t, int up) LIBTUN6_NONNULL;

int tun6_addAddress (tun6 *restrict t, const struct in6_addr *restrict addr,
                     unsigned prefix_len) LIBTUN6_NONNULL;
int tun6_delAddress (tun6 *restrict t, const struct in6_addr *restrict addr,
                     unsigned prefix_len) LIBTUN6_NONNULL;

int tun6_setMTU (tun6 *t, unsigned mtu) LIBTUN6_NONNULL;

int tun6_addRoute (tun6 *restrict t, const struct in6_addr *restrict addr,
                   unsigned prefix_len, int relative_metric) LIBTUN6_NONNULL;
int tun6_delRoute (tun6 *restrict t, const struct in6_addr *restrict addr,
                   unsigned prefix_len, int relative_metric) LIBTUN6_NONNULL;

int tun6_registerReadSet (const tun6 *restrict t, fd_set *restrict readset)
	LIBTUN6_NONNULL LIBTUN6_PURE;

int tun6_recv (tun6 *restrict t, const fd_set *restrict readset,
               void *buf, size_t len) LIBTUN6_NONNULL;
int tun6_wait_recv (tun6 *restrict t, void *buf, size_t len) LIBTUN6_NONNULL;
int tun6_send (tun6 *restrict t, const void *packet, size_t len)
	LIBTUN6_NONNULL;

# ifdef __cplusplus
}
# endif /* C++ */

#endif /* ifndef LIBTUN6_TUN6_H */
