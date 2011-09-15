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

/* tun6.c - IPv6 tunnel interface definition
 * $Id: tun6.c 1894 2006-12-31 11:15:54Z remi $
 */

/**
 * \file tun6.c
 * \brief IPv6 tunnel interface (tun).
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* #include <gettext.h> */

#include <assert.h>
#include <stdio.h> /* snprintf() for BSD drivers */
#include <string.h>
#include <stdlib.h> /* free() */
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/uio.h> /* readv() & writev() */
#include <poll.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h> /* htons(), struct in6_addr */

#include <sys/socket.h> /* socket(AF_INET6, SOCK_DGRAM, 0) */

#include <net/if.h> /* struct ifreq, if_nametoindex(), if_indextoname() */

#if defined (__linux__)
/**
 * \brief Linux tunneling driver
 */
const char os_driver[] = "Linux";
#define USE_LINUX 1
/* #include <linux/if.h> */
#include <linux/if_tun.h> /* TUNSETIFF - Linux tunnel driver */

/**
 * \struct in6_ifreq
 * \brief <linux/ipv6.h> conflicts with <netinet/in.h> and <arpa/inet.h>,
 * so we've got to declare this structure by hand.
 */
struct in6_ifreq
{
  struct in6_addr ifr6_addr; /**< IPv6 address */
  uint32_t ifr6_prefixlen; /**< Prefix length */
  int ifr6_ifindex; /**< Interface index */
};

#include <net/route.h> /* struct in6_rtmsg */
#include <netinet/if_ether.h> /* ETH_P_IPV6 */

typedef struct
{
  uint16_t flags;
  uint16_t proto;
} tun_head_t;

#define TUN_HEAD_IPV6_INITIALIZER { 0, htons(ETH_P_IPV6) }
#define tun_head_is_ipv6(h) (h.proto == htons(ETH_P_IPV6))

#elif defined (__FreeBSD__) || defined (__FreeBSD_kernel__) || \
  defined (__NetBSD__)  || defined (__NetBSD_kernel__)  || \
defined (__OpenBSD__) || defined (__OpenBSD_kernel__) || \
defined (__DragonFly__) || \
defined (__APPLE__) /* Darwin */
/**
 * \brief BSD tunneling driver
 * NOTE: the driver is NOT tested on Darwin (Mac OS X).
 */
const char os_driver[] = "BSD";
#define USE_BSD 1

/* TUNSIFHEAD or TUNSLMODE */
#if defined (HAVE_NET_IF_TUN_H)
#include <net/if_tun.h>
#elif defined (HAVE_NET_TUN_IF_TUN_H)
#include <net/tun/if_tun.h>
#elif defined (__APPLE__)
#define TUNSIFHEAD _IOW('t', 96, int)
#endif

#ifdef HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif

#include <net/if_dl.h> /* struct sockaddr_dl */
#include <net/route.h> /* AF_ROUTE things */
#include <netinet6/in6_var.h> /* struct in6_aliasreq */
#include <netinet6/nd6.h> /* ND6_INFINITE_LIFETIME */

#include <pthread.h>

typedef uint32_t tun_head_t;

#define TUN_HEAD_IPV6_INITIALIZER htonl(AF_INET6)
#define tun_head_is_ipv6(h) (h == htonl(AF_INET6))

#else
/**
 * \brief Tunneling driver
 */
const char os_driver[] = "Generic";

#warning Unknown host OS. The driver will probably not work.
#endif

#include "tun6.h"
#include "syserr.h"

#define PACKET_MAX 8196 /**< Maximum packet size */

/**
 * Originally there was strlcpy but it lacks in Linux libc... replace this latter!
 * for the moment cross the finger... this function is not safe...
 */
#define safe_strcpy(tgt, src) \
  (strncpy(tgt, src, sizeof(tgt)))

/**
 * \struct tun6
 * \brief tun6 descriptor.
 */
struct tun6
{
  int id; /**< Interface index */
  int fd; /**< File descriptor to tun interface */
  int reqfd; /**< File descriptor for ioctl() */
#if defined (USE_BSD)
  char orig_name[IFNAMSIZ]; /**< Name of interface */
#endif
};

/**
 * Tries to allocate a tunnel interface from the kernel.
 *
 * @param req_name may be an interface name for the virtual network device
 * (it might be ignored on some OSes).
 * If NULL, an internal default will be used.
 *
 * @return NULL on error.
 */
static struct tun6 *tun6_create(const char *req_name)
{
  /*  (void)bindtextdomain (PACKAGE_NAME, LOCALEDIR); */
  struct tun6 *t = (struct tun6 *)malloc(sizeof(*t));
  if(t == NULL)
    return NULL;
  memset(t, 0, sizeof(*t));

  int reqfd = t->reqfd = socket(AF_INET6, SOCK_DGRAM, 0);
  if(reqfd == -1)
  {
    free(t);
    return NULL;
  }

  fcntl(reqfd, F_SETFD, FD_CLOEXEC);

#if defined (USE_LINUX)
  /*
   * TUNTAP (Linux) tunnel driver initialization
   */
  static const char tundev[] = "/dev/net/tun";
  struct ifreq req =
  {
    .ifr_flags = IFF_TUN
  };

  if((req_name != NULL) && safe_strcpy(req.ifr_name, req_name))
  {
    free(t);
    return NULL;
  }

  int fd = open(tundev, O_RDWR);
  if(fd == -1)
  {
    syslog(LOG_ERR, "Tunneling driver error (%s): %s", tundev, strerror(errno));
    (void)close(reqfd);
    free(t);
    return NULL;
  }

  /* Allocates the tunneling virtual network interface */
  if(ioctl(fd, TUNSETIFF, (void *)&req))
  {
    syslog(LOG_ERR, "Tunneling driver error (%s): %s", "TUNSETIFF", strerror(errno));
    goto error;
  }

  int id = if_nametoindex(req.ifr_name);
  if(id == 0)
    goto error;
#elif defined (USE_BSD)
  /*
   * BSD tunnel driver initialization
   * (see BSD src/sys/net/if_tun.{c,h})
   */
  int fd = open("/dev/tun", O_RDWR);
  if((fd == -1) && (errno == ENOENT))
  {
    /*
     * Some BSD variants or older kernel versions do not support /dev/tun,
     * so fallback to the old scheme.
     */
    int saved_errno = 0;
    for(unsigned i = 0; fd == -1; i++)
    {
      char tundev[5 + IFNAMSIZ];
      snprintf(tundev, sizeof(tundev), "/dev/tun%u", i);

      fd = open(tundev, O_RDWR);
      if((fd == -1) && (errno == ENOENT))
        /* If /dev/tun<i> does not exist,
         * /dev/tun<i + 1> won't exist either
         */
        break;

      saved_errno = errno;
    }
    errno = saved_errno;
  }

  if(fd == -1)
  {
    syslog(LOG_ERR, "Tunneling driver error (%s): %s", "/dev/tun*", strerror(errno));
    goto error;
  }
  else
  {
    struct stat st;
    fstat(fd, &st);
#ifdef HAVE_DEVNAME_R
    devname_r(st.st_rdev, S_IFCHR, t->orig_name, sizeof(t->orig_name));
#else
  const char *name = devname(st.st_rdev, S_IFCHR);
  if(safe_strcpy(t->orig_name, name))
    goto error;
#endif
  }

  int id = if_nametoindex(t->orig_name);
  if(id == 0)
  {
    syslog(LOG_ERR, "Tunneling driver error (%s): %s",
            t->orig_name, strerror(errno));
    goto error;
  }

#ifdef TUNSIFMODE
  /* Sets sensible tunnel type (broadcast rather than point-to-point) */
  (void)ioctl(fd, TUNSIFMODE, &(int)
  {
    IFF_BROADCAST
  });
#endif

#if defined (TUNSIFHEAD)
  /* Enables TUNSIFHEAD */
  if(ioctl(fd, TUNSIFHEAD, &(int)
{
  1
}))
  {
    syslog(LOG_ERR, "Tunneling driver error (%s): %s",
            "TUNSIFHEAD", strerror(errno));
#if defined (__APPLE__)
    if(errno == EINVAL)
      syslog(LOG_NOTICE,
              "*** Ignoring tun-tap-osx spurious error ***");
    else
#endif
      goto error;
  }
#elif defined (TUNSLMODE)
  /* Disables TUNSLMODE (deprecated opposite of TUNSIFHEAD) */
  if(ioctl(fd, TUNSLMODE, &(int)
{
  0
}))
  {
    syslog(LOG_ERR, "Tunneling driver error (%s): %s",
            "TUNSLMODE", strerror(errno));
    goto error;
  }
#endif

  /* Customizes interface name */
  if(req_name != NULL)
  {
    struct ifreq req;
    memset(&req, 0, sizeof(req));

    if(if_indextoname(id, req.ifr_name) == NULL)
    {
      syslog(LOG_ERR, "Tunneling driver error (%s): %s",
              "if_indextoname", strerror(errno));
      goto error;
    }
    else if(strcmp(req.ifr_name, req_name))
    {
#ifdef SIOCSIFNAME
      char ifname[IFNAMSIZ];
      req.ifr_data = ifname;

      errno = ENAMETOOLONG;
      if(safe_strcpy(ifname, req_name)
          || ioctl(reqfd, SIOCSIFNAME, &req))
#else
  syslog(LOG_DEBUG,
          "Tunnel interface renaming is not supported on your operating system.\n"
          "To run miredo or isatapd properly, you need to remove the\n"
          "InterfaceName directive from their respective configuration file.\n");
  errno = ENOSYS;
#endif
      {
        syslog(LOG_ERR, "Tunneling driver error (%s): %s",
        "SIOCSIFNAME", strerror(errno));
        goto error;
      }
    }
  }
#else
#error No tunneling driver implemented on your platform!
#endif /* HAVE_os */

  fcntl(fd, F_SETFD, FD_CLOEXEC);
  int val = fcntl(fd, F_GETFL);
  fcntl(fd, F_SETFL, ((val != -1) ? val : 0) | O_NONBLOCK);

  t->id = id;
  t->fd = fd;
  return t;

error:
  (void)close(reqfd);
  if(fd != -1)
    (void)close(fd);
  syslog(LOG_ERR, "%s tunneling interface creation failure", os_driver);
  free(t);
  return NULL;
}

/**
 * Brings a tunnel interface up or down.
 *
 * \param t tun6 descriptor
 * \param up if 1 bring this interface UP, DOWN otherwise
 * @return 0 on success, -1 on error (see errno).
 */
static int tun6_setState(struct tun6 *t, int up)
{
  assert(t != NULL);
  assert(t-> id != 0);

  struct ifreq req;
  memset(&req, 0, sizeof(req));
  if((if_indextoname(t->id, req.ifr_name) == NULL)
      || ioctl(t->reqfd, SIOCGIFFLAGS, &req))
    return -1;

  /* settings we want/don't want: */
  req.ifr_flags |= IFF_NOARP;
  req.ifr_flags &= ~(IFF_MULTICAST | IFF_BROADCAST);
  if(up)
    req.ifr_flags |= IFF_UP | IFF_RUNNING;
  else
    req.ifr_flags &= ~(IFF_UP | IFF_RUNNING);

  /* Sets up the interface */
  if((if_indextoname(t->id, req.ifr_name) == NULL)
      || ioctl(t->reqfd, SIOCSIFFLAGS, &req))
    return -1;

  return 0;
}

/**
 * Removes a tunnel from the kernel.
 * BEWARE: if you fork, child processes must call tun6_destroy() too.
 *
 * The kernel will destroy the tunnel interface once all processes called
 * tun6_destroy and/or were terminated.
 * \param t tun6 descriptor to destroy
 */
static void tun6_destroy(struct tun6* t)
{
  assert(t != NULL);
  assert(t->fd != -1);
  assert(t->reqfd != -1);
  assert(t->id != 0);

  (void)tun6_setState(t, 0);

#ifdef USE_BSD
#ifdef SIOCSIFNAME
  /*
   * SIOCSIFDESTROY doesn't work for tunnels (see FreeBSD PR/73673).
   * We rename the tunnel to its canonical name to ease the life of other
   * programs that may re-open the tunnel after us.
   */
  struct ifreq req;
  memset(&req, 0, sizeof(req));
  if(if_indextoname(t->id, req.ifr_name) != NULL)
  {
    if(ioctl(t->reqfd, SIOCIFDESTROY, &req))
    {
      if((if_indextoname(t->id, req.ifr_name) != NULL)
          && strcmp(t->orig_name, req.ifr_name))
      {
        req.ifr_data = t->orig_name;
        (void)ioctl(t->reqfd, SIOCSIFNAME, &req);
      }
    }
  }
#endif
#endif

  (void)close(t->fd);
  (void)close(t->reqfd);
  free(t);
}

/*
 * Unless otherwise stated, all the methods thereafter should return -1 on
 * error, and 0 on success. Similarly, they should require root privileges.
 */

#if defined (USE_LINUX)
static int proc_write_zero(const char *path)
{
  int fd = open(path, O_WRONLY);
  if(fd == -1)
    return -1;

  int retval = 0;

  if(write(fd, "0", 1) != 1)
    retval = -1;
  if(close(fd))
    retval = -1;

  return retval;
}
#endif

#if defined (USE_BSD)
/**
 * Converts a prefix length to a netmask (used for the BSD routing)
 */
static void plen_to_mask(unsigned plen, struct in6_addr *mask)
{
  assert(plen <= 128);

  div_t d = div(plen, 8);
  int i = 0;

  while(i < d.quot)
    mask->s6_addr[i++] = 0xff;

  if(d.rem)
    mask->s6_addr[i++] = 0xff << (8 - d.rem);

  while(i < 16)
    mask->s6_addr[i++] = 0;
}

static void plen_to_sin6(unsigned plen, struct sockaddr_in6 *sin6)
{
  memset(sin6, 0, sizeof(struct sockaddr_in6));

  /* NetBSD kernel strangeness:
     sin6->sin6_family = AF_INET6;*/
#ifdef HAVE_SA_LEN
  sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
  plen_to_mask(plen, &sin6->sin6_addr);
}
#endif /* ifdef SOCAIFADDR_IN6 */

/**
 * \brief Add/remove an address on interface.
 * \param reqfd socket descriptor to handle ioctl request(s).
 * \param id interface index
 * \param add if 1 add address, 0 remove address
 * \param addr IPv6 address to add/remove
 * \param prefix_len IPv6 prefix length
 * \return 0 if success, -1 otherwise
 */
static int _iface_addr(int reqfd, int id, int add,
                        const struct in6_addr *addr, unsigned prefix_len)
{
  void *req = NULL;
  long cmd = 0;

  assert(reqfd != -1);
  assert(id != 0);

  if((prefix_len > 128) || (addr == NULL))
    return -1;

#if defined (USE_LINUX)
  /*
   * Linux ioctl interface
   */
  union
  {
    struct in6_ifreq req6;
    struct ifreq req;
  } r;

  memset(&r, 0, sizeof(r));
  r.req6.ifr6_ifindex = id;
  memcpy(&r.req6.ifr6_addr, addr, sizeof(r.req6.ifr6_addr));
  r.req6.ifr6_prefixlen = prefix_len;

  cmd = add ? SIOCSIFADDR : SIOCDIFADDR;
  req = &r;
#elif defined (USE_BSD)
  /*
   * BSD ioctl interface
   */
  union
  {
    struct in6_aliasreq addreq6;
    struct in6_ifreq delreq6;
  } r;

  if(add)
  {
    memset(&r.addreq6, 0, sizeof(r.addreq6));
    if(if_indextoname(id, r.addreq6.ifra_name) == NULL)
      return -1;
    r.addreq6.ifra_addr.sin6_family = AF_INET6;
    r.addreq6.ifra_addr.sin6_len = sizeof(r.addreq6.ifra_addr);
    memcpy(&r.addreq6.ifra_addr.sin6_addr, addr,
            sizeof(r.addreq6.ifra_addr.sin6_addr));

    plen_to_sin6(prefix_len, &r.addreq6.ifra_prefixmask);

    r.addreq6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
    r.addreq6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

    cmd = SIOCAIFADDR_IN6;
    req = &r.addreq6;
  }
  else
  {
    memset(&r.delreq6, 0, sizeof(r.delreq6));
    if(if_indextoname(id, r.delreq6.ifr_name) == NULL)
      return -1;
    r.delreq6.ifr_addr.sin6_family = AF_INET6;
    r.delreq6.ifr_addr.sin6_len = sizeof(r.delreq6.ifr_addr);
    memcpy(&r.delreq6.ifr_addr.sin6_addr, addr,
            sizeof(r.delreq6.ifr_addr.sin6_addr));

    cmd = SIOCDIFADDR_IN6;
    req = &r.delreq6;
  }
#else
#error FIXME tunnel address setup not implemented
#endif

  return ioctl(reqfd, cmd, req) >= 0 ? 0 : -1;
}

/**
 * Adds an address with a netmask to a tunnel.
 * Requires CAP_NET_ADMIN or root privileges.
 * @param t tun6 instance
 * @param addr address to add
 * @param prefixlen length of IPv6 prefix
 * @return 0 on success, -1 in case error.
 */
static int tun6_addAddress(struct tun6 *t, const struct in6_addr *addr, unsigned prefixlen)
{
  assert(t != NULL);

  int res = _iface_addr(t->reqfd, t->id, 1, addr, prefixlen);

#if defined (USE_LINUX)
  char ifname[IFNAMSIZ];
  if((res == 0)
      && (if_indextoname(t->id, ifname) != NULL))
  {
    char proc_path[24 + IFNAMSIZ + 16 + 1] = "/proc/sys/net/ipv6/conf/";
#if 0
    /* Disable Autoconfiguration */
    snprintf(proc_path + 24, sizeof(proc_path) - 24,
              "%s/accept_ra", ifname);
    proc_write_zero(proc_path);

    snprintf(proc_path + 24, sizeof(proc_path) - 24,
              "%s/autoconf", ifname);
    proc_write_zero(proc_path);
#endif
    /* Disable ICMPv6 Redirects. */
    snprintf(proc_path + 24, sizeof(proc_path) - 24,
              "%s/accept_redirects", ifname);
    proc_write_zero(proc_path);

  }
#endif

  return res;
}

#if 0

static int _iface_route(int reqfd, int id, int add, const struct in6_addr *addr,
                         unsigned prefix_len, int rel_metric)
{
  assert(reqfd != -1);
  assert(id != 0);

  if((prefix_len > 128) || (addr == NULL))
    return -1;

  int retval = -1;

#if defined (USE_LINUX)
  /*
   * Linux ioctl interface
   */
  struct in6_rtmsg req6 =
  {
    .rtmsg_flags = RTF_UP,
    .rtmsg_ifindex = id,
    .rtmsg_dst_len = (unsigned short)prefix_len,
    /* By default, the Linux kernel's metric is 256 for subnets,
     * and 1024 for gatewayed route. */
    .rtmsg_metric = 1024 + rel_metric
  };

  /* Adds/deletes route */
  memcpy(&req6.rtmsg_dst, addr, sizeof(req6.rtmsg_dst));
  if(prefix_len == 128)
    req6.rtmsg_flags |= RTF_HOST;
  /* no gateway */

  if(ioctl(reqfd, add ? SIOCADDRT : SIOCDELRT, &req6) == 0)
    retval = 0;
#elif defined (USE_BSD)
  /*
   * BSD routing socket interface
   * FIXME: metric unimplemented
   */
  (void)rel_metric;

  int s = socket(AF_ROUTE, SOCK_RAW, AF_INET6);
  if(s == -1)
  {
    syslog(LOG_ERR, "Error (%s): %s\n", "socket(AF_ROUTE)",
            strerror(errno));
    return -1;
  }

  static int rtm_seq = 0;
  static pthread_mutex_t rtm_seq_mutex = PTHREAD_MUTEX_INITIALIZER;
  struct
  {
    struct rt_msghdr hdr;
    struct sockaddr_in6 dst;
    struct sockaddr_dl gw;
    struct sockaddr_in6 mask;
  } msg;

  shutdown(s, 0);

  memset(&msg, 0, sizeof(msg));
  msg.hdr.rtm_msglen = sizeof(msg);
  msg.hdr.rtm_version = RTM_VERSION;
  msg.hdr.rtm_type = add ? RTM_ADD : RTM_DELETE;
  msg.hdr.rtm_index = id;
  msg.hdr.rtm_flags = RTF_UP | RTF_STATIC;
  msg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
  if(prefix_len == 128)
    msg.hdr.rtm_flags |= RTF_HOST;
  msg.hdr.rtm_pid = getpid();

  pthread_mutex_lock(&rtm_seq_mutex);
  msg.hdr.rtm_seq = ++rtm_seq;
  pthread_mutex_unlock(&rtm_seq_mutex);

  msg.dst.sin6_family = AF_INET6;
  msg.dst.sin6_len = sizeof(msg.dst);
  memcpy(&msg.dst.sin6_addr, addr, sizeof(msg.dst.sin6_addr));

  msg.gw.sdl_family = AF_LINK;
  msg.gw.sdl_len = sizeof(msg.gw);
  msg.gw.sdl_index = id;

  plen_to_sin6(prefix_len, &msg.mask);

  errno = 0;

  if((write(s, &msg, sizeof(msg)) == sizeof(msg))
      && (errno == 0))
    retval = 0;
  else if(errno == EEXIST)
    syslog(LOG_NOTICE,
            "Miredo could not configure its network tunnel device properly.\n"
            "There is probably another tunnel with a conflicting route present,\n"
            "most likely left from a previous instance of Miredo (see also FreeBSD\n"
            "Problem Report kern/100080); that is a common bug on BSD kernels.\n"
            "Please cleanup your closed tunnel devices manually or reboot to fix\n"
            "this issue. You might also want to check if this issue has been dealt\n"
            "with in newer version of your BSD of choice.\n");

  (void)close(s);
#else
#error FIXME route setup not implemented
#endif

  return retval;
}
/**
 * Get the scope ID of tun interface.
 * @param t tun6 instance
 * @return the scope id of the tunnel device
 */
static int tun6_getId(const struct tun6 *t)
{
  assert(t != NULL);
  assert(t-> id != 0);

  return t->id;
}

/**
 * Deletes an address from a tunnel.
 * Requires CAP_NET_ADMIN or root privileges.
 *
 * @param t tun6 instance
 * @param addr address to remove
 * @param prefixlen length of prefix
 * @return 0 on success, -1 in case error.
 */
static int tun6_delAddress(struct tun6 *t, const struct in6_addr *addr, unsigned prefixlen)
{
  assert(t != NULL);

  return _iface_addr(t->reqfd, t->id, 0, addr, prefixlen);
}

/**
 * Inserts a route through a tunnel into the IPv6 routing table.
 * Requires CAP_NET_ADMIN or root privileges.
 *
 * @param t tun6 instance
 * @param addr destination address for the route
 * @param prefix_len prefix length
 * @param rel_metric difference between the system's default metric
 * for route with the speficied prefix length (positive = higher priority,
 * negative = lower priority).
 *
 * @return 0 on success, -1 in case error.
 */
static int tun6_addRoute(struct tun6 *t, const struct in6_addr *addr, unsigned prefix_len,
                          int rel_metric)
{
  assert(t != NULL);

  return _iface_route(t->reqfd, t->id, 1, addr, prefix_len, rel_metric);
}

/**
 * Removes a route through a tunnel from the IPv6 routing table.
 * Requires CAP_NET_ADMIN or root privileges.
 *
 * @param t tun6 instance
 * @param addr route destination to remove
 * @param prefix_len length of IPv6 prefix
 * @param rel_metric metric
 * @return 0 on success, -1 in case error.
 */
static int tun6_delRoute(struct tun6 *t, const struct in6_addr *addr, unsigned prefix_len,
                          int rel_metric)
{
  assert(t != NULL);

  return _iface_route(t->reqfd, t->id, 0, addr, prefix_len, rel_metric);
}

/**
 * \brief Add an IPv6 route.
 * \param this the tun_t structure
 * \param dst the destination address
 * \param gateway the gateway to route the packet for the "dst"
 * \param prefixlen length of the prefix
 * \return 0 if success, -1 otherwise
 * \author Sebastien Vincent
 */
static int tun6_addroutegw(struct tun6* this, struct in6_addr* dst, struct in6_addr* gateway, uint8_t prefixlen)
{
  int code = -1;
  char buf[1024];
  struct in6_rtmsg* rtm = NULL;

  rtm = (struct in6_rtmsg*)buf;
  memset(buf, 0x00, sizeof(buf));
  rtm->rtmsg_type = 0;
  rtm->rtmsg_metric = 1024;
  rtm->rtmsg_dst_len = prefixlen;
  rtm->rtmsg_src_len = 0;
  rtm->rtmsg_ifindex = this->id;
  rtm->rtmsg_flags = RTF_UP | RTF_GATEWAY;

  memcpy(&rtm->rtmsg_dst, dst, sizeof(struct in6_addr));
  memcpy(&rtm->rtmsg_gateway, gateway, sizeof(struct in6_addr));

  code = ioctl(this->reqfd, SIOCADDRT, rtm);

  return code!=-1 ? 0 : -1;
}

/**
 * Defines the tunnel interface Max Transmission Unit (bytes).
 * @param t tun6 instance
 * @param mtu MTU to set
 * @return 0 on success, -1 in case of error.
 */
static int tun6_setMTU(struct tun6 *t, unsigned mtu)
{
  assert(t != NULL);

  if((mtu < 1280) || (mtu > 65535))
    return -1;

  struct ifreq req =
  {
    .ifr_mtu = mtu
  };
  
  if(if_indextoname(t->id, req.ifr_name) == NULL)
    return -1;

  return ioctl(t->reqfd, SIOCSIFMTU, &req) ? -1 : 0;
}

/**
 * Registers file descriptors in an fd_set for use with select().
 * If any of the file descriptors is out of range (>= FD_SETSIZE), it
 * will not be registered.
 *
 * @param t tun6 instance
 * @param readset a fd_set (with FD_SETSIZE no smaller than the default
 * libc value libtun6 was compiled with).
 *
 * @return the "biggest" file descriptor registered (useful as the
 * first parameter to select()). -1 if any of the file descriptors was
 * bigger than FD_SETSIZE - 1.
 */
static int tun6_registerReadSet(const struct tun6 *t, fd_set *readset)
{
  assert(t != NULL);

  if(t->fd >= (int)FD_SETSIZE)
    return -1;

  FD_SET(t->fd, readset);
  return t->fd;
}

/**
 * Checks an fd_set, and receives a packet if available.
 * @param t tun6 instance
 * @param readset select()'s fd_set
 * @param buffer address to store packet
 * @param maxlen buffer length in bytes (should be 65535)
 *
 * This function will not block if there is no input.
 * Use tun6_wait_recv() if you want to wait until a packet arrives.
 *
 * @return the packet length on success, -1 if no packet were to be received.
 */
static int tun6_recv(struct tun6 *t, const fd_set *readset, void *buffer, size_t maxlen)
{
  assert(t != NULL);

  int fd = t->fd;
  if((fd < (int)FD_SETSIZE) && !FD_ISSET(fd, readset))
  {
    errno = EAGAIN;
    return -1;
  }
  return tun6_recv_inner(fd, buffer, maxlen);
}

/**
 * Waits for a packet, and receives it.
 *
 * This function will block until a packet arrives or an error occurs.
 * @param t tun6 instance
 * @param buffer address to store packet
 * @param maxlen buffer length in bytes (should be 65535)
 * @return the packet length on success, -1 if no packet were to be received.
 */
static int tun6_wait_recv(struct tun6 *t, void *buffer, size_t maxlen)
{
  return tun6_recv_inner(t->fd, buffer, maxlen);
}

#endif

/**
 * Receives a packet from a tunnel device.
 * @param fd socket descriptor
 * @param buffer address to store packet
 * @param maxlen buffer length in bytes (should be 65535)
 *
 * This function will block if there is no input.
 *
 * @return the packet length on success, -1 if no packet were to be received.
 */
static inline int tun6_recv_inner(int fd, void *buffer, size_t maxlen)
{
  struct iovec vect[2];
  tun_head_t head;

  vect[0].iov_base = (char *)&head;
  vect[0].iov_len = sizeof(head);
  vect[1].iov_base = (char *)buffer;
  vect[1].iov_len = maxlen;

  int len = readv(fd, vect, 2);
  if((len < (int)sizeof(head))
      || !tun_head_is_ipv6(head))
    return -1; /* only accept IPv6 packets */

  return len - sizeof(head);
}

/**
 * Sends an IPv6 packet.
 * @param t tun6 instance
 * @param packet pointer to packet
 * @param len packet length (bytes)
 *
 * @return the number of bytes succesfully transmitted on success,
 * -1 on error.
 */
static int tun6_send(struct tun6 *t, const void *packet, size_t len)
{
  assert(t != NULL);

  if(len > 65535)
    return -1;

  tun_head_t head = TUN_HEAD_IPV6_INITIALIZER;
  struct iovec vect[2];
  vect[0].iov_base = (char *)&head;
  vect[0].iov_len = sizeof(head);
  vect[1].iov_base = (char *)packet; /* necessary cast to non-const */
  vect[1].iov_len = len;

  int val = writev(t->fd, vect, 2);
  if(val == -1)
    return -1;

  val -= sizeof(head);
  if(val < 0)
    return -1;

  return val;
}

int tun6_new(struct tun6_t** tun)
{
  *tun = malloc(sizeof(struct tun6_t));

  if(!(*tun))
  {
    return -1;
  }

  memset(*tun, 0x00, sizeof(struct tun6_t));
  (*tun)->cb_indv6 = NULL;
  (*tun)->addrsv6 = 0;
  (*tun)->routesv6 = 0;

  if(!((*tun)->device = tun6_create(NULL)))
  {
    free(*tun);
    return -1;
  }

  (*tun)->fdv6 = (*tun)->device->fd;
  (*tun)->ifindex = (*tun)->device->id;

  return 0;
}

int tun6_free(struct tun6_t* tun)
{
  tun6_destroy(tun->device);
  free(tun);
  return 0;
}

int tun6_decaps(struct tun6_t* this)
{
#if defined(__linux__) || defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__APPLE__)

  unsigned char buffer[PACKET_MAX];
  int status;

  if((status = tun6_recv_inner(this->device->fd, buffer, sizeof(buffer)))==-1)
  {
    return 0;
  }

  if(this->cb_indv6)
  {
    return this->cb_indv6(this, buffer, status);
  }
  return 0;

#endif
  return -1;
}

int tun6_encaps(struct tun6_t* this, void* pack, unsigned int len)
{
  return tun6_send(this->device, pack, len);
}

int tun6_setaddr(struct tun6_t *this, struct in6_addr *addr, uint8_t prefixlen)
{
  int code = tun6_addAddress(this->device, addr, prefixlen);
  /* turn the interface on */
  tun6_sifflags(this, IFF_UP | IFF_RUNNING);
  return code;
}

int tun6_addroute(struct tun6_t *this, struct in6_addr *dst, struct in6_addr *gateway, uint8_t prefixlen)
{
  /* TODO : use _iface_route */
  this = NULL;
  dst = NULL;
  gateway = NULL;
  prefixlen = 0;
  return -1;
}

int tun6_set_cb_ind(struct tun6_t *this, int (*cb_ind) (struct tun6_t *tun, void *pack, unsigned len))
{
  this->cb_indv6 = cb_ind;
  return 0;
}

int tun6_runscript(struct tun6_t *tun, char* script)
{
  /* TODO */
  tun = NULL;
  script = NULL;
  return 0;
}

/**
 * \brief Set the flags on the interface.
 * \param this the tun6_t instance
 * \param flags the flags to set
 * \return 0 if success, -1 otherwise
 */
int tun6_sifflags(struct tun6_t *this, int flags)
{
  struct ifreq ifr;
  int fd = -1;

  memset(&ifr, '\0', sizeof(ifr));
  ifr.ifr_flags = flags;

  if(if_indextoname(this->ifindex, ifr.ifr_name)==NULL)
  {
    return -1;
  }

  ifr.ifr_name[IFNAMSIZ - 1] = 0; /* Make sure to terminate */

  if((fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
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

